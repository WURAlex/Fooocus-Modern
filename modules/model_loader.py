import errno
import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

try:
    import fcntl
except ImportError:
    fcntl = None

# ---------------------------------------------------------
# Default security and network settings
# ---------------------------------------------------------

DEFAULT_ALLOWED_HOSTS: Set[str] = {
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "hf.co",
}

DEFAULT_ALLOWED_DOMAINS: Set[str] = {
    "huggingface.co",
    "hf.co",
    "hf.space",
}

DEFAULT_DOWNLOAD_TIMEOUT: float = 30.0
DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MiB
DEFAULT_MAX_REDIRECTS: int = 5
DEFAULT_MAX_RETRIES: int = 3
DEFAULT_RETRY_BACKOFF: float = 1.0  # seconds
DEFAULT_MAX_DOWNLOAD_SIZE: int = 50 * 1024 * 1024 * 1024  # 50 GiB
DEFAULT_MAX_DURATION: float = 1800.0  # 30 minutes

# Explicit opt-in channel for HTTPS proxies. Proxy use is rejected by default;
# this is deliberately kept separate from the destination allowlist
# (FOOOCUS_ALLOWED_DOWNLOAD_HOSTS): authorizing a download host must never
# silently authorize proxying traffic through it.
HTTPS_PROXY_ALLOW_ENV = "FOOOCUS_ALLOWED_HTTPS_PROXIES"


# ---------------------------------------------------------
# Process and thread synchronization for concurrent downloads
# ---------------------------------------------------------

_THREAD_LOCKS: dict = {}
_THREAD_LOCKS_MUTEX = threading.Lock()


class DestinationLock:
    """
    Advisory file lock and thread lock to protect concurrent downloads
    to the same destination path from collisions and race conditions.

    Thread locks are reference counted so the registry does not grow without
    bound when many distinct destinations are downloaded (resource exhaustion).
    """

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self.fd: Optional[int] = None
        self._thread_lock: Optional[threading.Lock] = None
        self._lock_key: Optional[str] = None

    def __enter__(self):
        # Thread synchronization (registry entry is refcounted under the mutex so
        # an entry can never be dropped while another thread still needs it)
        lock_key = str(self.lock_path.resolve())
        with _THREAD_LOCKS_MUTEX:
            entry = _THREAD_LOCKS.get(lock_key)
            if entry is None:
                entry = {"lock": threading.Lock(), "refs": 0}
                _THREAD_LOCKS[lock_key] = entry
            entry["refs"] += 1
            self._thread_lock = entry["lock"]
            self._lock_key = lock_key

        self._thread_lock.acquire()

        # Inter-process synchronization via flock if available. Any failure here
        # must undo the thread-lock registration above, otherwise `__exit__` is
        # never called (a failing `__enter__` does not enter the context) and the
        # lock would stay held forever.
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            open_flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                # Never follow a planted symlink (lock-file tampering).
                open_flags |= os.O_NOFOLLOW
            self.fd = os.open(str(self.lock_path), open_flags, 0o600)
            if fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError as exc:
            if getattr(exc, "errno", None) == getattr(errno, "ELOOP", None):
                # A planted symlink: abort and undo the thread-lock registration,
                # because a failing `__enter__` never reaches `__exit__`.
                self._release()
                raise ValueError(
                    f"Refusing symlinked lock file: {self.lock_path}"
                ) from exc
            # Other failures (e.g. read-only volume) degrade to the thread lock
            # only; the lock is a collision guard, not a security boundary.
            pass
        except Exception:
            self._release()
            raise

        return self

    def _release(self) -> None:
        """
        Release the file lock, the thread lock and the registry reference.
        """
        if self.fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

        if self._thread_lock is not None:
            self._thread_lock.release()

        if self._lock_key is not None:
            with _THREAD_LOCKS_MUTEX:
                entry = _THREAD_LOCKS.get(self._lock_key)
                if entry is not None:
                    entry["refs"] -= 1
                    if entry["refs"] <= 0:
                        _THREAD_LOCKS.pop(self._lock_key, None)
            self._lock_key = None
            self._thread_lock = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._release()


# ---------------------------------------------------------
# Host and URL validation helpers
# ---------------------------------------------------------

# Special-purpose address blocks that must never be dialled even when a given
# Python version reports them as "global" (registry coverage differs between
# Python releases, so they are listed explicitly).
_NON_PUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "100.64.0.0/10",  # carrier-grade NAT (shared address space)
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "240.0.0.0/4",  # reserved + broadcast
        "100::/64",  # discard-only
        "2001::/23",  # TEREDO, benchmarking, documentation, ORCHID, ...
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation
        "5f00::/16",  # segment routing SIDs
    )
)

# IPv6 transition prefixes that embed an IPv4 address in their payload.
# The prefix itself may legitimately appear via DNS64, so only the embedded
# IPv4 address decides whether the target is blocked.
_EMBEDDED_V4_NETWORKS = (
    (ipaddress.ip_network("64:ff9b::/96"), 0),  # NAT64 well-known prefix
    (ipaddress.ip_network("64:ff9b:1::/48"), 0),  # NAT64 local-use prefix
    (ipaddress.ip_network("2002::/16"), 80),  # 6to4
)


def _ipv4_is_non_public(ip: ipaddress.IPv4Address) -> bool:
    """
    True when an IPv4 address must not be dialled (SSRF mitigation).
    """
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or not ip.is_global
    )


def _ip_address_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    """
    True when an already-parsed IP address must not be dialled.
    Handles IPv4, IPv6, IPv4-mapped IPv6 and IPv6 transition prefixes.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _ipv4_is_non_public(mapped)

    if ip.version == 4:
        return _ipv4_is_non_public(ipaddress.IPv4Address(ip))

    if ip in _NON_PUBLIC_NETWORKS:
        return True

    for network, shift in _EMBEDDED_V4_NETWORKS:
        if ip in network:
            embedded = ipaddress.IPv4Address((int(ip) >> shift) & 0xFFFFFFFF)
            if _ipv4_is_non_public(embedded):
                return True

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or not ip.is_global
    )


def _is_private_or_local_host(hostname: str) -> bool:
    """
    Check if a hostname resolves to a local or private network address (SSRF mitigation).
    Handles IPv4, IPv6 (including bracketed syntax and zone IDs), IPv4-mapped IPv6,
    carrier-grade NAT space and IPv6 transition prefixes embedding IPv4 addresses.
    Returns False for DNS names (they are validated after resolution instead).
    """
    if not hostname:
        return True

    hostname = hostname.lower().strip()
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    if "%" in hostname:
        hostname = hostname.split("%")[0]

    if hostname in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return _ip_address_is_blocked(ip)


def _get_effective_allowed_targets(
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_domains: Optional[Iterable[str]] = None,
) -> Tuple[Set[str], Set[str]]:
    """
    Combine built-in, environment, and explicitly supplied allowed hosts/domains.
    """
    hosts = set(DEFAULT_ALLOWED_HOSTS)
    domains = set(DEFAULT_ALLOWED_DOMAINS)

    mirror = os.environ.get("HF_MIRROR")
    if mirror:
        mirror_host = (urlparse(mirror).hostname or "").lower().strip()
        if mirror_host:
            hosts.add(mirror_host)

    env_hosts = os.environ.get("FOOOCUS_ALLOWED_DOWNLOAD_HOSTS")
    if env_hosts:
        for item in env_hosts.split(","):
            item = item.strip().lower()
            if item:
                hosts.add(item)
                domains.add(item)

    if allowed_hosts:
        for host in allowed_hosts:
            host = host.strip().lower()
            if host:
                hosts.add(host)

    if allowed_domains:
        for domain in allowed_domains:
            domain = domain.strip().lower()
            if domain:
                domains.add(domain)

    return hosts, domains


def _is_host_allowed(
    hostname: str,
    allowed_hosts: Set[str],
    allowed_domains: Set[str],
) -> bool:
    """
    Check if hostname is explicitly allowed or belongs to an allowed domain suffix.
    """
    hostname = (hostname or "").lower().strip()
    if not hostname:
        return False

    if hostname.startswith("[") and hostname.endswith("]"):
        clean_hostname = hostname[1:-1]
    else:
        clean_hostname = hostname

    if clean_hostname in allowed_hosts or hostname in allowed_hosts:
        return True

    for domain in allowed_domains:
        if clean_hostname == domain or clean_hostname.endswith("." + domain):
            return True

    return False


def _resolve_and_validate_addresses(
    host: str,
    port: int,
    allowed_hosts: Optional[Set[str]] = None,
) -> Tuple[str, int]:
    """
    Resolve host via DNS and validate that ALL resolved IPv4/IPv6 addresses are public.
    Prevents SSRF through DNS rebinding (eliminates TOCTOU between validation and connection).
    Returns the first validated IP address string and port.

    `allowed_hosts` only permits an explicit opt-in for a *literal IP address* that was
    deliberately configured as an internal mirror. A DNS name that merely appears in the
    allowlist can never make a private resolution legal: that short-circuit was the
    DNS-rebinding/SSRF bypass (an allowlisted hostname resolving to 127.0.0.1,
    169.254.169.254, ... was previously accepted).
    """
    clean_host = host.strip("[]").strip()

    try:
        ipaddress.ip_address(clean_host)
    except ValueError:
        is_literal_ip = False
    else:
        is_literal_ip = True

    if is_literal_ip:
        # Literal IP: block unless this exact address is explicitly allowlisted.
        if _is_private_or_local_host(clean_host):
            allowed_literals = {
                entry.strip().lower().strip("[]") for entry in (allowed_hosts or set())
            }
            if clean_host.lower() not in allowed_literals:
                raise ValueError(
                    f"Refusing connection to private/local address: {host!r}"
                )
        return (clean_host, port)

    try:
        addrinfo = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {host!r}: {exc}") from exc

    if not addrinfo:
        raise ValueError(f"DNS resolution returned no addresses for {host!r}")

    validated_ip = None
    for entry in addrinfo:
        ip_str = entry[4][0]
        if _is_private_or_local_host(ip_str):
            raise ValueError(
                f"DNS resolution for {host!r} resolved to private/local address {ip_str!r}. "
                "Potential SSRF or DNS rebinding attack blocked."
            )
        if validated_ip is None:
            validated_ip = ip_str

    if validated_ip is None:
        raise ValueError(f"No valid public IP found for {host!r}")

    return (validated_ip, port)


def _resolve_huggingface_mirror(url: str) -> str:
    """
    Validate and apply HF_MIRROR if configured.
    """
    mirror = os.environ.get("HF_MIRROR")

    if not mirror:
        return url

    mirror = mirror.rstrip("/")
    parsed_mirror = urlparse(mirror)

    if parsed_mirror.scheme.lower() != "https":
        raise ValueError("HF_MIRROR must use HTTPS.")

    if parsed_mirror.username or parsed_mirror.password:
        raise ValueError("HF_MIRROR must not contain credentials.")

    if parsed_mirror.query or parsed_mirror.fragment:
        raise ValueError("HF_MIRROR must not contain query or fragment data.")

    if not parsed_mirror.hostname:
        raise ValueError("HF_MIRROR must contain a valid hostname.")

    mirror_host = parsed_mirror.hostname.lower().strip()
    if _is_private_or_local_host(mirror_host):
        raise ValueError(
            f"HF_MIRROR cannot point to local or private host: {mirror_host!r}"
        )

    return url.replace(
        "https://huggingface.co",
        mirror,
        1,
    )


def _validate_url(
    url: str,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_domains: Optional[Iterable[str]] = None,
) -> None:
    """
    Validate that the given URL uses HTTPS, does not contain user credentials,
    has no control characters, and targets an authorized remote host without accessing
    private/loopback networks.
    """
    if not url or not url.strip():
        raise ValueError("Refusing empty model URL.")

    if any(c in url for c in ("\0", "\r", "\n")):
        raise ValueError("Refusing model URL containing control or null characters.")

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        raise ValueError(
            f"Refusing insecure model URL: {url!r}. "
            "Model downloads must use HTTPS."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            f"Refusing model URL with embedded credentials: {url!r}"
        )

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise ValueError(f"URL has no valid hostname: {url!r}")

    eff_hosts, eff_domains = _get_effective_allowed_targets(
        allowed_hosts=allowed_hosts,
        allowed_domains=allowed_domains,
    )

    if _is_private_or_local_host(hostname):
        if not (allowed_hosts and (hostname in eff_hosts or f"[{hostname}]" in eff_hosts)):
            raise ValueError(
                f"Refusing download from local or private host: {hostname!r}"
            )

    if not _is_host_allowed(hostname, eff_hosts, eff_domains):
        raise ValueError(
            f"Refusing download from untrusted host: {hostname!r}"
        )

    if parsed.port is not None and parsed.port != 443:
        if not (
            allowed_hosts
            and (hostname in eff_hosts or f"{hostname}:{parsed.port}" in eff_hosts)
        ):
            raise ValueError(
                f"Refusing download on non-standard port: {parsed.port}"
            )


# ---------------------------------------------------------
# HTTPS proxy policy (fail closed)
# ---------------------------------------------------------


def _parse_proxy_endpoint(
    endpoint: Optional[str],
    *,
    require_clean: bool = True,
) -> Optional[Tuple[Optional[str], str, Optional[int]]]:
    """
    Parse a proxy endpoint into (scheme, host, port); scheme/port are None when
    not explicitly specified. Returns None when the endpoint is unparseable.

    `require_clean=True` (used for approval entries) additionally rejects
    endpoints carrying a path/query/fragment, which are never meaningful in an
    authorization list. With `require_clean=False` they are ignored, mirroring
    urllib, whose `_parse_proxy` dials the netloc only.
    """
    if not endpoint or not str(endpoint).strip():
        return None

    value = str(endpoint).strip()
    if "://" in value:
        parsed = urlparse(value)
        scheme = (parsed.scheme or "").lower() or None
    else:
        parsed = urlparse("//" + value)
        scheme = None

    if require_clean and (
        parsed.path not in ("", "/") or parsed.query or parsed.fragment
    ):
        return None

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host:
        return None

    return (scheme, host.lower(), port)


def _parse_approved_proxy_entries(
    entries: Iterable[str],
) -> List[Tuple[Optional[str], str, Optional[int]]]:
    """
    Parse approval entries from FOOOCUS_ALLOWED_HTTPS_PROXIES. Fail closed:
    a malformed entry is a configuration error, not something to ignore.
    """
    approved: List[Tuple[Optional[str], str, Optional[int]]] = []
    for entry in entries:
        entry = (entry or "").strip()
        if not entry:
            continue
        parsed = _parse_proxy_endpoint(entry, require_clean=True)
        if parsed is None:
            # Redacted: an approval entry may itself carry credentials, and
            # configuration errors end up in logs and consoles.
            raise ValueError(
                f"Invalid {HTTPS_PROXY_ALLOW_ENV} entry: "
                f"{_redact_proxy_display(entry)!r}. Expected "
                "'host', 'host:port' or 'scheme://host:port'."
            )
        approved.append(parsed)
    return approved


def _load_approved_proxy_entries() -> List[str]:
    """Raw (unparsed) approval entries from the environment, empties dropped."""
    raw = os.environ.get(HTTPS_PROXY_ALLOW_ENV) or ""
    return [entry.strip() for entry in raw.split(",") if entry.strip()]


def _proxy_endpoint_allowed(
    host: str,
    port: Optional[int],
    approved: Iterable[Tuple[Optional[str], str, Optional[int]]],
) -> bool:
    """
    Match a proxy endpoint (host, port) against approved entries. An approval
    entry without a port matches any port on that host; an entry with a port
    must match exactly. Schemes are not compared: for HTTPS requests urllib
    always dials the proxy's TCP endpoint and issues CONNECT regardless of the
    scheme in the proxy URL (verified against urllib.request), so host:port is
    the authorization unit.
    """
    host = (host or "").lower().strip("[]")
    if not host:
        return False
    if port is None:
        port = 443  # https connection default when no port is specified

    for _scheme, approved_host, approved_port in approved:
        if approved_host == host and (approved_port is None or approved_port == port):
            return True
    return False


def _configured_https_proxy(hostname: str) -> Optional[str]:
    """
    Return the proxy urllib itself would use for an HTTPS request to
    `hostname`, or None when the request would go direct.

    `hostname` is the request authority host[:port] exactly as urllib's
    Request.host carries it -- including any explicit URL port, which a
    port-qualified NO_PROXY entry needs in order to match.

    Mirrors urllib's selection rules exactly (same API calls its ProxyHandler
    makes): only the "https" entry of getproxies() applies to https:// URLs --
    HTTP_PROXY, ALL_PROXY and FTP_PROXY entries are ignored for HTTPS requests
    and cannot cause a tunnel -- and a NO_PROXY entry covering this destination
    bypasses the proxy entirely. Any error while evaluating the bypass is
    treated as "not bypassed" (fail closed).
    """
    proxy_url = urllib.request.getproxies().get("https")
    if not proxy_url:
        return None

    try:
        if urllib.request.proxy_bypass(hostname):
            return None
    except Exception:
        pass

    return proxy_url


def _redact_proxy_display(value: str) -> str:
    """Render a proxy URL for error messages with credentials stripped."""
    value = str(value)
    if "://" in value:
        scheme, _, rest = value.partition("://")
        if "@" in rest:
            # rsplit: a password may itself contain "@"; everything up to the
            # last "@" is userinfo.
            return f"{scheme}://***@{rest.rsplit('@', 1)[1]}"
    elif "@" in value:
        return "***@" + value.rsplit("@", 1)[1]
    return value


def _enforce_proxy_policy(
    hostname: str,
) -> List[str]:
    """
    Phase A (fail closed): refuse the download unless every proxy urllib would
    use for this HTTPS request is explicitly authorized through
    FOOOCUS_ALLOWED_HTTPS_PROXIES (kept separate from the destination
    allowlist), is not private/local, and resolves to public IPs only.

    `hostname` is the request authority host[:port], passed through unchanged
    to _configured_https_proxy so the bypass decision matches urllib's
    Request.host exactly.

    Returns the raw approval entries so the connection layer can re-check them
    at CONNECT time (defense in depth against any detection gap or proxy
    configuration change between validation and connection).
    """
    approved_entries = _load_approved_proxy_entries()
    # Parse even when no proxy is configured so a malformed approval list is a
    # deterministic configuration error, independent of ambient proxy state.
    approved = _parse_approved_proxy_entries(approved_entries)

    proxy_url = _configured_https_proxy(hostname)
    if not proxy_url:
        return approved_entries

    parsed = _parse_proxy_endpoint(proxy_url, require_clean=False)
    if parsed is None:
        raise ValueError(
            f"Refusing unparseable HTTPS proxy: {_redact_proxy_display(proxy_url)!r}."
        )

    _scheme, proxy_host, proxy_port = parsed
    effective_port = proxy_port if proxy_port is not None else 443
    display = _redact_proxy_display(proxy_url)

    if not _proxy_endpoint_allowed(proxy_host, effective_port, approved):
        raise ValueError(
            f"Refusing to use unapproved HTTPS proxy: {display!r}. "
            f"Set {HTTPS_PROXY_ALLOW_ENV} to authorize this proxy endpoint."
        )

    if _is_private_or_local_host(proxy_host):
        raise ValueError(
            f"Refusing proxy connection to local or private address: {display!r}"
        )

    # Approval is not enough: an approved proxy endpoint must still resolve to
    # public addresses, exactly like a direct destination.
    _resolve_and_validate_addresses(proxy_host, effective_port)

    return approved_entries


def _safe_destination(model_dir: str, file_name: str) -> Path:
    """
    Validate destination directory and filename against path traversal.
    """
    if not file_name or not file_name.strip():
        raise ValueError("Destination filename cannot be empty.")

    root = Path(model_dir).resolve()
    destination = (root / file_name).resolve()

    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Refusing model path outside model directory: {file_name!r}"
        ) from exc

    if destination == root:
        raise ValueError(
            f"Refusing model path resolving to directory root: {file_name!r}"
        )

    return destination


# ---------------------------------------------------------
# Connection and redirect handlers
# ---------------------------------------------------------

def _hostname_without_port(host: str) -> str:
    """
    Strip an optional port suffix while keeping IPv6 literals intact.
    """
    host = (host or "").strip()
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[1:end]
    if host.count(":") == 1:
        name, _, port_suffix = host.partition(":")
        if port_suffix.isdigit():
            return name
    return host


class SafeHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPS connection that validates all resolved DNS addresses against SSRF/rebinding
    and pins the socket to the pre-validated IP address while verifying TLS hostname.

    When the connection runs through a CONNECT proxy, the proxy performs its own DNS
    resolution, so the validated target address cannot be pinned on our side. The target
    is therefore resolved and validated *before* the tunnel is opened and the request
    fails closed if that validation cannot be satisfied. Opening a tunnel additionally
    requires the proxy endpoint to be authorized via FOOOCUS_ALLOWED_HTTPS_PROXIES;
    an unapproved proxy is refused before any address validation or connection.
    Remaining limitation: a proxy that re-resolves the target after our validation
    could still be pointed elsewhere (TOCTOU through the proxy). Only use proxies
    you control.
    """

    def __init__(
        self,
        host,
        port=None,
        allowed_hosts=None,
        allowed_domains=None,
        allowed_proxies=None,
        **kwargs,
    ):
        super().__init__(host, port=port, **kwargs)
        self.allowed_hosts = allowed_hosts
        self.allowed_domains = allowed_domains
        self.allowed_proxies = list(allowed_proxies) if allowed_proxies else []

    def _validate_target_host(self, target_host: str) -> None:
        """
        Defense in depth: reject any destination that is not explicitly allowlisted
        when an allowlist is configured (independent of `_validate_url`).
        """
        if self.allowed_hosts is None and self.allowed_domains is None:
            return

        hosts = self.allowed_hosts if self.allowed_hosts is not None else set()
        domains = self.allowed_domains if self.allowed_domains is not None else set()
        if not _is_host_allowed(target_host, set(hosts), set(domains)):
            raise ValueError(
                f"Refusing connection to untrusted host: {target_host!r}"
            )

    def connect(self):
        if self._tunnel_host:
            # `self.host` is already split from the port by http.client; splitting it
            # again on ":" corrupted IPv6 literals ("fe80::1" became "fe80").
            proxy_host = _hostname_without_port(self.host).strip("[]")
            proxy_port = self.port or 443

            # Defense in depth: a CONNECT tunnel requires explicit approval even
            # when download_file's Phase A check already passed, so no code path
            # (including a proxy configuration swapped in after validation) can
            # tunnel through an unauthorized proxy.
            approved = _parse_approved_proxy_entries(self.allowed_proxies)
            if not _proxy_endpoint_allowed(proxy_host, proxy_port, approved):
                display = (
                    f"[{proxy_host}]:{proxy_port}"
                    if ":" in proxy_host
                    else f"{proxy_host}:{proxy_port}"
                )
                raise ValueError(
                    f"Refusing to use unapproved HTTPS proxy: {display!r}. "
                    f"Set {HTTPS_PROXY_ALLOW_ENV} to authorize this proxy endpoint."
                )

            # Private/local proxy endpoints are rejected even when approved
            # and even when their address appears in the *destination*
            # allowlist: proxy authorization is a separate decision from
            # destination authorization (identical rule in Phase A).
            if _is_private_or_local_host(proxy_host):
                raise ValueError(
                    f"Refusing proxy connection to local or private address: {self.host!r}"
                )

            # Fail closed: a proxy *name* is resolved and validated as well, so a
            # host name pointing at loopback/link-local is not a way around the
            # literal-IP check above -- and the socket is then pinned to that
            # validated address, so `super().connect()` cannot re-resolve the
            # name into a different (e.g. private) address in between. This is
            # the same rebinding TOCTOU protection the direct path applies;
            # TLS is unaffected because the certificate is validated against
            # `_tunnel_host` (the destination), never the proxy address.
            proxy_ip, _ = _resolve_and_validate_addresses(
                proxy_host,
                self.port or 443,
                allowed_hosts=self.allowed_hosts,
            )
            pinned_ip = proxy_ip

            def _pinned_create_connection(addr, timeout=None, source_address=None):
                return socket.create_connection(
                    (pinned_ip, addr[1]), timeout, source_address
                )

            self._create_connection = _pinned_create_connection

            # Fail closed: the tunnel destination must be validated exactly like a
            # direct destination, otherwise the proxy would bypass SSRF checks.
            tunnel_host = _hostname_without_port(self._tunnel_host)
            self._validate_target_host(tunnel_host)
            _resolve_and_validate_addresses(
                tunnel_host,
                self._tunnel_port or 443,
                allowed_hosts=self.allowed_hosts,
            )

            super().connect()
            return

        target_host = _hostname_without_port(self.host)
        self._validate_target_host(target_host)

        target_ip, target_port = _resolve_and_validate_addresses(
            self.host,
            self.port or 443,
            allowed_hosts=self.allowed_hosts,
        )

        sock = socket.create_connection(
            (target_ip, target_port),
            timeout=self.timeout,
            source_address=self.source_address,
        )

        server_hostname = target_host
        self.sock = self._context.wrap_socket(
            sock,
            server_hostname=server_hostname,
        )


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    """
    HTTPS handler that uses SafeHTTPSConnection to enforce DNS pinning and SSRF validation.
    """

    def __init__(
        self,
        allowed_hosts=None,
        allowed_domains=None,
        allowed_proxies=None,
        context=None,
        **kwargs,
    ):
        super().__init__(context=context, **kwargs)
        self.allowed_hosts = allowed_hosts
        self.allowed_domains = allowed_domains
        self.allowed_proxies = allowed_proxies

    def https_open(self, req):
        def connection_factory(host, **kwargs):
            return SafeHTTPSConnection(
                host,
                allowed_hosts=self.allowed_hosts,
                allowed_domains=self.allowed_domains,
                allowed_proxies=self.allowed_proxies,
                context=self._context,
                **kwargs,
            )
        return self.do_open(connection_factory, req)


class HardenedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that strictly enforces security during redirects:
    - Target scheme must be HTTPS (blocks downgrade to plain HTTP)
    - Target host must be authorized (blocks redirects to arbitrary third-party servers)
    - Target host cannot be a private or loopback IP (SSRF mitigation)
    - URL cannot contain embedded credentials
    - Detects cycles and limits max redirect count
    - Strips sensitive headers when crossing domain boundaries
    """

    def __init__(
        self,
        allowed_hosts: Optional[Iterable[str]] = None,
        allowed_domains: Optional[Iterable[str]] = None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ):
        super().__init__()
        self.allowed_hosts = allowed_hosts
        self.allowed_domains = allowed_domains
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self.visited_urls: Set[str] = set()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise RuntimeError(
                f"Too many redirects ({self.redirect_count} > {self.max_redirects})"
            )

        target_url = urljoin(req.full_url, newurl)

        if not self.visited_urls:
            self.visited_urls.add(req.full_url)

        if target_url in self.visited_urls:
            raise RuntimeError(f"Redirect loop detected: {target_url}")
        self.visited_urls.add(target_url)

        _validate_url(
            target_url,
            allowed_hosts=self.allowed_hosts,
            allowed_domains=self.allowed_domains,
        )

        new_req = super().redirect_request(req, fp, code, msg, headers, target_url)
        if new_req is None:
            return None

        orig_host = urlparse(req.full_url).hostname
        target_host = urlparse(target_url).hostname
        if orig_host and target_host and orig_host.lower() != target_host.lower():
            # `Request.headers` stores header names with a capitalised first letter only
            # ("Proxy-authorization"), so a case-sensitive delete silently missed
            # Proxy-Authorization and leaked proxy credentials across the redirect.
            sensitive_headers = ("authorization", "proxy-authorization", "cookie")
            for container in (
                new_req.headers,
                getattr(new_req, "unredirected_hdrs", {}),
            ):
                for key in [k for k in container if k.lower() in sensitive_headers]:
                    del container[key]

        return new_req


# ---------------------------------------------------------
# Checksum and integrity verification
# ---------------------------------------------------------

def _matches_hash(actual_hash: str, expected_hash: str) -> bool:
    """
    Compare actual and expected cryptographic hash digests (case-insensitive).
    Supports exact matching and prefix matching (for torch.hub hash_prefix compatibility).
    """
    actual = actual_hash.strip().lower()
    expected = expected_hash.strip().lower()

    if not expected:
        return False

    if len(expected) < len(actual):
        return actual.startswith(expected)

    return actual == expected


def calculate_file_hash(
    file_path: Union[Path, str],
    hash_algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Calculate cryptographic hash of a file using chunked streaming.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.new(hash_algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


def verify_file_hash(
    file_path: Union[Path, str],
    expected_hash: str,
    hash_algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bool:
    """
    Verify that an existing file matches the expected hash.
    """
    try:
        actual_hash = calculate_file_hash(
            file_path,
            hash_algorithm=hash_algorithm,
            chunk_size=chunk_size,
        )
        return _matches_hash(actual_hash, expected_hash)
    except Exception:
        return False


# ---------------------------------------------------------
# Progress bar helper
# ---------------------------------------------------------

class DownloadProgressBar:
    """
    Progress reporter that integrates with tqdm if installed,
    falling back to periodic console updates.
    """

    def __init__(self, desc: str, total: Optional[int]):
        self.desc = desc
        self.total = total
        self.tqdm_bar = None
        self.last_print_time = 0.0

        try:
            from tqdm import tqdm
            self.tqdm_bar = tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=desc,
                leave=True,
            )
        except Exception:
            self.tqdm_bar = None

    def update(self, chunk_len: int, downloaded: int):
        if self.tqdm_bar is not None:
            self.tqdm_bar.update(chunk_len)
        else:
            now = time.time()
            if now - self.last_print_time >= 5.0 or (self.total and downloaded >= self.total):
                self.last_print_time = now
                mb_downloaded = downloaded / (1024 * 1024)
                if self.total:
                    mb_total = self.total / (1024 * 1024)
                    pct = (downloaded / self.total) * 100
                    print(
                        f"Downloading {self.desc}: "
                        f"{mb_downloaded:.1f}/{mb_total:.1f} MB ({pct:.1f}%)"
                    )
                else:
                    print(f"Downloading {self.desc}: {mb_downloaded:.1f} MB")

    def close(self):
        if self.tqdm_bar is not None:
            self.tqdm_bar.close()


# ---------------------------------------------------------
# Error classification for retries
# ---------------------------------------------------------

class DownloadDeadlineExceeded(TimeoutError):
    """
    Raised when the single global download deadline for one `download_file()` call
    expires. A deadline covers the whole operation (including retries and backoff
    sleeps), therefore it is terminal and must never be retried.
    """


def _is_transient_error(exc: Exception) -> bool:
    """
    Determine if an exception represents a transient failure eligible for retry.
    Validation errors, checksum mismatches, client HTTP errors (4xx), path errors,
    and deadline expiries are non-transient and must fail immediately without retrying.
    """
    if isinstance(exc, DownloadDeadlineExceeded):
        return False

    if isinstance(exc, (ValueError, FileNotFoundError, PermissionError)):
        return False

    if isinstance(exc, urllib.error.HTTPError):
        if 400 <= exc.code < 500 and exc.code != 429:
            return False
        return True

    if isinstance(exc, (
        socket.timeout,
        TimeoutError,
        http.client.RemoteDisconnected,
        http.client.IncompleteRead,
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
    )):
        return True

    if isinstance(exc, urllib.error.URLError):
        if isinstance(exc.reason, ssl.SSLError):
            return False
        return True

    if isinstance(exc, RuntimeError) and "incomplete download" in str(exc).lower():
        return True

    return False


# ---------------------------------------------------------
# Secure download implementation
# ---------------------------------------------------------

def download_file(
    url: str,
    destination: Union[Path, str],
    *,
    progress: bool = True,
    expected_hash: Optional[str] = None,
    hash_algorithm: str = "sha256",
    timeout: Optional[float] = None,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_domains: Optional[Iterable[str]] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_retries: Optional[int] = None,
    retry_backoff: Optional[float] = None,
    max_size: Optional[int] = None,
    max_duration: Optional[float] = None,
) -> str:
    """
    Download a file from `url` to `destination` with:
    - Enforced HTTPS and host/domain validation
    - Fail-closed proxy policy: environment proxies are rejected unless the
      endpoint is authorized via FOOOCUS_ALLOWED_HTTPS_PROXIES (separate from
      the destination allowlist), public-address validated in both the
      pre-flight check and at CONNECT time
    - Socket-level DNS rebinding and SSRF protection
    - Hardened redirect inspection (blocks insecure or untrusted hops)
    - Memory-efficient chunked streaming
    - Connection and read timeouts
    - Total download duration deadline
    - Maximum download size enforcement (with and without Content-Length)
    - Exponential backoff retry on transient network errors
    - Inter-process and inter-thread concurrency safety
    - Temporary file in the same directory and atomic replacement
    - Preservation of existing valid files on replacement failure
    - Incremental checksum computation and integrity verification
    - Guaranteed cleanup of temporary files on error
    """
    dest_path = Path(destination).resolve()
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    url = _resolve_huggingface_mirror(url)
    _validate_url(
        url,
        allowed_hosts=allowed_hosts,
        allowed_domains=allowed_domains,
    )
    # Fail-closed proxy policy: rejected before any lock, temporary file, DNS
    # lookup of the destination, or other network activity. The gate receives
    # the authority exactly as urllib's Request.host carries it -- with any
    # explicit URL port (userinfo is impossible here: _validate_url rejected
    # it above) -- so a port-qualified NO_PROXY entry bypasses the proxy for
    # the gate on precisely the same cases urllib itself bypasses it.
    approved_proxy_entries = _enforce_proxy_policy(
        (urlparse(url).netloc or "").strip()
    )

    # Resolve limits and timeouts
    effective_timeout = timeout
    if effective_timeout is None:
        timeout_env = os.environ.get("FOOOCUS_DOWNLOAD_TIMEOUT")
        if timeout_env:
            try:
                effective_timeout = float(timeout_env)
            except ValueError:
                effective_timeout = DEFAULT_DOWNLOAD_TIMEOUT
        else:
            effective_timeout = DEFAULT_DOWNLOAD_TIMEOUT

    effective_retries = max_retries
    if effective_retries is None:
        retries_env = os.environ.get("FOOOCUS_DOWNLOAD_MAX_RETRIES")
        if retries_env:
            try:
                effective_retries = int(retries_env)
            except ValueError:
                effective_retries = DEFAULT_MAX_RETRIES
        else:
            effective_retries = DEFAULT_MAX_RETRIES

    effective_backoff = retry_backoff
    if effective_backoff is None:
        backoff_env = os.environ.get("FOOOCUS_DOWNLOAD_RETRY_BACKOFF")
        if backoff_env:
            try:
                effective_backoff = float(backoff_env)
            except ValueError:
                effective_backoff = DEFAULT_RETRY_BACKOFF
        else:
            effective_backoff = DEFAULT_RETRY_BACKOFF

    effective_max_size = max_size
    if effective_max_size is None:
        max_size_env = os.environ.get("FOOOCUS_MAX_DOWNLOAD_SIZE")
        if max_size_env:
            try:
                effective_max_size = int(max_size_env)
            except ValueError:
                effective_max_size = DEFAULT_MAX_DOWNLOAD_SIZE
        else:
            effective_max_size = DEFAULT_MAX_DOWNLOAD_SIZE

    effective_max_duration = max_duration
    if effective_max_duration is None:
        duration_env = os.environ.get("FOOOCUS_DOWNLOAD_MAX_DURATION")
        if duration_env:
            try:
                effective_max_duration = float(duration_env)
            except ValueError:
                effective_max_duration = DEFAULT_MAX_DURATION
        else:
            effective_max_duration = DEFAULT_MAX_DURATION

    # One global deadline for the entire operation: it is started here and never
    # reset, so retries and backoff sleeps are charged against the same budget.
    download_deadline_start = time.monotonic()

    def _deadline_remaining() -> Optional[float]:
        if effective_max_duration is None:
            return None
        return effective_max_duration - (time.monotonic() - download_deadline_start)

    def _deadline_error() -> DownloadDeadlineExceeded:
        return DownloadDeadlineExceeded(
            f"Download exceeded total duration deadline of "
            f"{effective_max_duration} seconds"
        )

    # Synchronize concurrent downloads targeting the same destination
    lock_file = dest_path.parent / f".{dest_path.name}.lock"
    with DestinationLock(lock_file):
        # Cache verification: check existing file after acquiring lock
        if dest_path.is_file():
            if expected_hash is not None:
                if verify_file_hash(
                    dest_path,
                    expected_hash=expected_hash,
                    hash_algorithm=hash_algorithm,
                    chunk_size=chunk_size,
                ):
                    return str(dest_path)
                print(
                    f"[Integrity] Existing file {dest_path.name} failed "
                    f"{hash_algorithm} verification. Re-downloading."
                )
            else:
                if dest_path.stat().st_size > 0:
                    return str(dest_path)

        print(f'Downloading: "{url}"')
        print(f"Destination: {dest_path}")

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Fooocus-Modern",
                "Accept-Encoding": "identity",
            },
        )

        eff_hosts, eff_domains = _get_effective_allowed_targets(
            allowed_hosts=allowed_hosts,
            allowed_domains=allowed_domains,
        )

        attempt = 0
        while True:
            # Checked before every attempt: a retry must not restart the budget.
            remaining = _deadline_remaining()
            if remaining is not None and remaining <= 0:
                raise _deadline_error()

            attempt += 1
            attempt_timeout = (
                effective_timeout
                if remaining is None
                else max(min(effective_timeout, remaining), 0.001)
            )

            redirect_handler = HardenedRedirectHandler(
                allowed_hosts=allowed_hosts,
                allowed_domains=allowed_domains,
                max_redirects=max_redirects,
            )
            ssl_context = ssl.create_default_context()
            https_handler = SafeHTTPSHandler(
                allowed_hosts=eff_hosts,
                allowed_domains=eff_domains,
                allowed_proxies=approved_proxy_entries,
                context=ssl_context,
            )
            opener = urllib.request.build_opener(redirect_handler, https_handler)

            # A bad hash algorithm must fail before any file descriptor is created.
            hasher = hashlib.new(hash_algorithm) if expected_hash is not None else None

            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{dest_path.name}.",
                suffix=".download",
                dir=str(dest_path.parent),
            )
            temporary_path = Path(temporary_name)

            pbar = None
            bytes_downloaded = 0
            content_length = None

            try:
                with os.fdopen(fd, "wb") as temp_file:
                    fd = None  # ownership transferred to `temp_file`
                    try:
                        with opener.open(req, timeout=attempt_timeout) as resp:
                            status = getattr(resp, "status", getattr(resp, "code", 200))
                            if status != 200:
                                raise RuntimeError(
                                    f"HTTP request failed with status {status}: {url!r}"
                                )

                            content_length_hdr = resp.headers.get("Content-Length")
                            content_length = (
                                int(content_length_hdr)
                                if content_length_hdr and content_length_hdr.isdigit()
                                else None
                            )

                            # Early size enforcement with Content-Length
                            if (
                                content_length is not None
                                and effective_max_size is not None
                                and content_length > effective_max_size
                            ):
                                raise ValueError(
                                    f"Download size ({content_length} bytes) exceeds "
                                    f"maximum allowed limit ({effective_max_size} bytes)"
                                )

                            if progress:
                                pbar = DownloadProgressBar(
                                    desc=dest_path.name,
                                    total=content_length,
                                )

                            bytes_downloaded = 0
                            while True:
                                # Global total duration deadline enforcement
                                remaining = _deadline_remaining()
                                if remaining is not None and remaining <= 0:
                                    raise _deadline_error()

                                try:
                                    chunk = resp.read(chunk_size)
                                except (socket.timeout, TimeoutError) as exc:
                                    raise TimeoutError(
                                        f"Download timed out while reading data from {url!r}"
                                    ) from exc
                                except OSError as exc:
                                    raise RuntimeError(
                                        f"Network error during download from {url!r}: {exc}"
                                    ) from exc

                                if not chunk:
                                    break

                                bytes_downloaded += len(chunk)

                                # Maximum size enforcement without Content-Length
                                if (
                                    effective_max_size is not None
                                    and bytes_downloaded > effective_max_size
                                ):
                                    raise ValueError(
                                        f"Download exceeded maximum allowed limit of "
                                        f"{effective_max_size} bytes"
                                    )

                                temp_file.write(chunk)

                                if hasher is not None:
                                    hasher.update(chunk)

                                if pbar is not None:
                                    pbar.update(len(chunk), bytes_downloaded)

                    finally:
                        if pbar is not None:
                            pbar.close()

                if not temporary_path.is_file():
                    raise RuntimeError(
                        f"Download completed without creating file: {url!r}"
                    )

                if bytes_downloaded == 0:
                    raise RuntimeError(f"Downloaded file is empty: {url!r}")

                if content_length is not None and bytes_downloaded != content_length:
                    raise RuntimeError(
                        f"Incomplete download for {dest_path.name}: "
                        f"expected {content_length} bytes, received {bytes_downloaded} bytes."
                    )

                if expected_hash is not None and hasher is not None:
                    actual_hash = hasher.hexdigest()
                    if not _matches_hash(actual_hash, expected_hash):
                        raise ValueError(
                            f"Integrity check failed for {dest_path.name}: "
                            f"expected {expected_hash}, got {actual_hash}"
                        )

                # Atomic replacement - existing file remains completely preserved until this point!
                os.replace(temporary_path, dest_path)
                return str(dest_path)

            except Exception as exc:
                # Close the descriptor if it never reached `temp_file`
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    fd = None

                # Clean up the failed temporary file immediately
                if temporary_path.is_file():
                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass

                # Check if this error is retryable
                if not _is_transient_error(exc) or attempt > effective_retries:
                    raise

                # Never spend a backoff sleep the global deadline cannot cover.
                remaining = _deadline_remaining()
                if remaining is not None and remaining <= 0:
                    raise _deadline_error() from exc

                sleep_time = effective_backoff * (2 ** (attempt - 1))
                if remaining is not None:
                    sleep_time = min(sleep_time, remaining)
                print(
                    f"[Retry] Download interrupted ({exc}). "
                    f"Retrying ({attempt}/{effective_retries}) in {sleep_time:.1f}s..."
                )
                time.sleep(sleep_time)


def load_file_from_url(
    url: str,
    *,
    model_dir: str,
    progress: bool = True,
    file_name: Optional[str] = None,
    expected_hash: Optional[str] = None,
    hash_algorithm: str = "sha256",
    timeout: Optional[float] = None,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_domains: Optional[Iterable[str]] = None,
    max_retries: Optional[int] = None,
    retry_backoff: Optional[float] = None,
    max_size: Optional[int] = None,
    max_duration: Optional[float] = None,
) -> str:
    """
    Download a model file securely and return its local path.

    Existing files are verified and reused. New files are downloaded using
    hardened HTTPS, redirect validation, streaming, timeouts, retry logic,
    size limits, deadlines, temporary files, atomic replacement, and integrity verification.
    """
    if not file_name:
        parsed = urlparse(url)
        file_name = os.path.basename(parsed.path)

    if not file_name:
        raise ValueError(f"Could not determine filename from URL: {url!r}")

    destination = _safe_destination(model_dir, file_name)

    return download_file(
        url=url,
        destination=destination,
        progress=progress,
        expected_hash=expected_hash,
        hash_algorithm=hash_algorithm,
        timeout=timeout,
        allowed_hosts=allowed_hosts,
        allowed_domains=allowed_domains,
        max_retries=max_retries,
        retry_backoff=retry_backoff,
        max_size=max_size,
        max_duration=max_duration,
    )


def download_url_to_file(
    url: str,
    dst: str,
    hash_prefix: Optional[str] = None,
    progress: bool = True,
) -> None:
    """
    Drop-in secure replacement for torch.hub.download_url_to_file.
    Downloads url to dst securely using hardened downloader.
    """
    dst_path = Path(dst).resolve()
    download_file(
        url=url,
        destination=dst_path,
        progress=progress,
        expected_hash=hash_prefix,
        hash_algorithm="sha256",
    )
