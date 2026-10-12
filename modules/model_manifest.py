"""
Model integrity manifest access (Stage 7).

Reads models/manifest.json and exposes helpers that download application-managed
artifacts through the hardened downloader (modules.model_loader) with trusted
expected hashes. Stdlib-only; no third-party imports.
"""

import json
import os
import re
from typing import Any, Dict, Optional

from modules.model_loader import load_file_from_url

STATUS_VERIFIED = "verified"
STATUS_UNRESOLVED = "unresolved"

_VALID_STATUSES = {STATUS_VERIFIED, STATUS_UNRESOLVED}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_PREFIX_RE = re.compile(r"^[0-9a-f]{4,64}$")
# DNS hostnames: lowercase RFC-1123 labels joined by dots, <=253 chars.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
# Characters that are separators, traversal aids, control codes, or invalid in
# filenames on POSIX/Windows alike. Applied to manifest file_name values only;
# the downloader's _safe_destination checks remain in force as defence in depth.
_FILENAME_INVALID_CHARS = frozenset('/\\<>:"|?*') | {
    chr(code) for code in range(32)
} | {"\x7f"}

_MANIFEST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "manifest.json",
)

_manifest_cache: Optional[Dict[str, Any]] = None
_unverified_warned: set = set()


class ManifestError(RuntimeError):
    """Raised when the integrity manifest is missing, invalid, or refused."""


class MissingManifestEntryError(ManifestError):
    """Raised when a requested artifact id is not present in the manifest."""


def _validate_file_name(file_name: Any, where: str) -> None:
    """
    Reject empty names, non-strings, path separators, traversal components,
    control/NUL bytes, and other filename values unsafe for a model directory.
    """
    if not isinstance(file_name, str):
        raise ManifestError(
            f"{where}: file_name must be a string, got {type(file_name).__name__}"
        )
    if not file_name or file_name != file_name.strip():
        raise ManifestError(
            f"{where}: file_name must be a non-empty name without surrounding "
            f"whitespace (got {file_name!r})"
        )
    if file_name in (".", ".."):
        raise ManifestError(
            f"{where}: file_name must not be a traversal component "
            f"({file_name!r})"
        )
    invalid = sorted({ch for ch in file_name if ch in _FILENAME_INVALID_CHARS})
    if invalid:
        raise ManifestError(
            f"{where}: file_name contains path separators, control codes, or "
            f"otherwise invalid characters: {invalid!r}"
        )
    if len(file_name) > 255:
        raise ManifestError(f"{where}: file_name is too long")


def _validate_allowed_domains(value: Any, where: str) -> None:
    """
    Reject malformed allowed_domains values: anything other than a non-empty
    list of valid DNS domain strings fails manifest loading.
    """
    if not isinstance(value, list) or not value:
        raise ManifestError(
            f"{where}: allowed_domains must be a non-empty list of domain "
            f"strings, got {value!r}"
        )
    for item in value:
        if not isinstance(item, str) or not item:
            raise ManifestError(
                f"{where}: allowed_domains entries must be non-empty strings, "
                f"got {item!r}"
            )
        if not _DOMAIN_RE.match(item.lower()):
            raise ManifestError(
                f"{where}: allowed_domains entry {item!r} is not a valid "
                f"domain name (no scheme, port, path, wildcard, or "
                f"underscores)"
            )


def manifest_path() -> str:
    return _MANIFEST_PATH


def _validate_entry(entry: Any, position: int) -> None:
    if not isinstance(entry, dict):
        # L1: a malformed (non-object) artifact must fail as a documented
        # ManifestError, never as an uncaught AttributeError.
        raise ManifestError(
            f"artifacts[{position}] must be a JSON object, got "
            f"{type(entry).__name__}"
        )
    where = f"artifacts[{position}] (id={entry.get('id', '<missing>')!r})"
    for key in ("id", "status", "file_name", "purpose", "source", "url_mutable",
                "evidence", "mandatory", "user_substitutable"):
        if key not in entry:
            raise ManifestError(f"{where}: missing required field {key!r}")

    # L2/L3: structural validation of optional allowlist and of file_name.
    _validate_file_name(entry["file_name"], where)
    if "allowed_domains" in entry:
        _validate_allowed_domains(entry["allowed_domains"], where)

    if entry["status"] not in _VALID_STATUSES:
        raise ManifestError(f"{where}: invalid status {entry['status']!r}")

    source = entry["source"]
    if not isinstance(source, dict) or "url" not in source:
        raise ManifestError(f"{where}: source.url is required")

    sha256 = entry.get("sha256")
    if entry["status"] == STATUS_VERIFIED:
        if not isinstance(sha256, str) or not _SHA256_RE.match(sha256.lower()):
            raise ManifestError(
                f"{where}: verified entries require a 64-hex sha256"
            )
        url = source.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ManifestError(f"{where}: verified entries require an https URL")
        if entry["url_mutable"] is not False:
            raise ManifestError(
                f"{where}: verified entries must pin an immutable revision "
                "(url_mutable must be false)"
            )
        if "/resolve/main/" in url:
            raise ManifestError(
                f"{where}: verified entries must not use mutable /resolve/main URLs"
            )
    else:
        if sha256 is not None and not (
            isinstance(sha256, str) and _SHA256_RE.match(sha256.lower())
        ):
            raise ManifestError(f"{where}: sha256 must be null or 64-hex")
        if not isinstance(entry.get("allow_unverified"), bool):
            raise ManifestError(
                f"{where}: unresolved entries require an allow_unverified flag"
            )
        if entry["allow_unverified"] and not entry.get("unverified_justification"):
            raise ManifestError(
                f"{where}: allow_unverified requires unverified_justification"
            )

    prefix = entry.get("sha256_prefix")
    if prefix is not None and not (
        isinstance(prefix, str) and _HEX_PREFIX_RE.match(prefix.lower())
    ):
        raise ManifestError(f"{where}: sha256_prefix must be hex")


def load_manifest(refresh: bool = False) -> Dict[str, Any]:
    global _manifest_cache
    if _manifest_cache is not None and not refresh:
        return _manifest_cache

    if not os.path.isfile(_MANIFEST_PATH):
        raise ManifestError(f"Model integrity manifest not found: {_MANIFEST_PATH}")

    try:
        with open(_MANIFEST_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Cannot read model integrity manifest: {exc}") from exc

    if data.get("schema_version") != 1:
        raise ManifestError(
            f"Unsupported manifest schema_version: {data.get('schema_version')!r}"
        )
    if not isinstance(data.get("manifest_version"), str):
        raise ManifestError("manifest_version must be a string")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestError("manifest artifacts must be a non-empty list")

    seen = set()
    for position, entry in enumerate(artifacts):
        _validate_entry(entry, position)
        artifact_id = entry["id"]
        if artifact_id in seen:
            raise ManifestError(f"Duplicate manifest artifact id: {artifact_id!r}")
        seen.add(artifact_id)

    _manifest_cache = data
    return data


def get_artifact(artifact_id: str) -> Dict[str, Any]:
    for entry in load_manifest()["artifacts"]:
        if entry["id"] == artifact_id:
            return entry
    raise MissingManifestEntryError(
        f"Artifact {artifact_id!r} is not present in {_MANIFEST_PATH}"
    )


def match_file_name_url(file_name: str, url: str) -> Optional[Dict[str, Any]]:
    """
    Return the verified manifest entry matching a (file_name, url) pair used by
    user-configured download loops, or None when the pair is user-provided.
    Both the pinned revision URL and the recorded mutable alias match.
    """
    for entry in load_manifest()["artifacts"]:
        if entry["status"] != STATUS_VERIFIED:
            continue
        if entry["file_name"] != file_name:
            continue
        source = entry["source"]
        candidates = {source.get("url"), source.get("mutable_url")}
        if url in candidates:
            return entry
    return None


def match_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Return the manifest entry (any status) whose pinned source URL equals `url`,
    or None when the URL is not recorded in the manifest. Used by the legacy
    facexlib wrapper, which is keyed by download URL rather than artifact id.
    """
    if not isinstance(url, str):
        return None
    for entry in load_manifest()["artifacts"]:
        if entry["source"].get("url") == url:
            return entry
    return None


def download(
    artifact_id: str,
    model_dir: str,
    file_name: Optional[str] = None,
    progress: bool = True,
) -> str:
    """
    Download (or re-verify) a manifest artifact through the hardened downloader.

    verified       -> expected_hash enforced; cached-file mismatch fails closed.
    unresolved     -> refused unless allow_unverified is set (warning printed).
    """
    entry = get_artifact(artifact_id)
    source = entry["source"]
    url = source.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ManifestError(
            f"Artifact {artifact_id!r} has no downloadable URL "
            f"(source type {source.get('type')!r})"
        )

    expected_hash: Optional[str] = None
    cached_hash_mismatch = "redownload"
    if entry["status"] == STATUS_VERIFIED:
        expected_hash = entry["sha256"]
        cached_hash_mismatch = "fail"
    else:
        if not entry.get("allow_unverified"):
            raise ManifestError(
                f"Artifact {artifact_id!r} is unresolved and not allow_unverified; "
                "refusing to download without a trusted hash"
            )
        if artifact_id not in _unverified_warned:
            _unverified_warned.add(artifact_id)
            print(
                f"[Integrity] WARNING: {entry['file_name']} has no trusted "
                f"SHA-256 ({entry.get('unverified_justification', 'no justification')})"
            )

    return load_file_from_url(
        url=url,
        model_dir=model_dir,
        file_name=file_name or entry["file_name"],
        expected_hash=expected_hash,
        cached_hash_mismatch=cached_hash_mismatch,
        allowed_domains=entry.get("allowed_domains"),
        progress=progress,
    )


def download_user_supplied(file_name: str, url: str, model_dir: str) -> str:
    """
    Download a user-configured (file_name, url) pair. When the pair matches a
    verified manifest entry the pinned revision and trusted hash are enforced;
    otherwise it is treated as a user-provided model (transport hardening only).
    """
    entry = match_file_name_url(file_name, url)
    if entry is not None:
        return download(entry["id"], model_dir)
    return load_file_from_url(url=url, model_dir=model_dir, file_name=file_name)
