import concurrent.futures
import hashlib
import importlib
import inspect
import io
import os
import shutil
import socket
import ssl
import sys
import tempfile
import time
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from modules.model_loader import (
    DEFAULT_ALLOWED_DOMAINS,
    DEFAULT_ALLOWED_HOSTS,
    DEFAULT_DOWNLOAD_TIMEOUT,
    DestinationLock,
    DownloadDeadlineExceeded,
    HardenedRedirectHandler,
    SafeHTTPSConnection,
    _is_host_allowed,
    _is_private_or_local_host,
    _is_transient_error,
    _matches_hash,
    _resolve_and_validate_addresses,
    _resolve_huggingface_mirror,
    _safe_destination,
    _validate_url,
    calculate_file_hash,
    download_file,
    download_url_to_file,
    load_file_from_url,
    verify_file_hash,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _residual_files(directory) -> list:
    """
    Files left behind in a download directory, ignoring the persistent `.lock`
    file that `DestinationLock` keeps by design (removing it on release would
    reintroduce a check-to-use race between processes).
    """
    return sorted(
        p.name for p in Path(directory).iterdir() if not p.name.endswith(".lock")
    )


class TestURLValidation(unittest.TestCase):
    def test_valid_huggingface_urls(self):
        urls = [
            "https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            "https://cdn-lfs.huggingface.co/repos/123/model.safetensors",
            "https://us.aws.cdn.hf.co/xet-bridge-us/model.safetensors",
            "https://hf.co/user/repo/model.bin",
            "https://subdomain.hf.space/file.bin",
        ]
        for url in urls:
            try:
                _validate_url(url)
            except Exception as e:
                self.fail(f"Valid URL {url!r} failed validation: {e}")

    def test_custom_allowed_hosts(self):
        url = "https://custom-mirror.example.org/models/v1.safetensors"
        with self.assertRaises(ValueError):
            _validate_url(url)

        _validate_url(url, allowed_hosts={"custom-mirror.example.org"})

    def test_env_allowed_hosts(self):
        url = "https://my-internal-repo.corp/model.bin"
        with patch.dict(os.environ, {"FOOOCUS_ALLOWED_DOWNLOAD_HOSTS": "my-internal-repo.corp"}):
            _validate_url(url)

    def test_insecure_http_rejected(self):
        insecure_urls = [
            "http://huggingface.co/model.bin",
            "http://cdn-lfs.huggingface.co/model.bin",
            "ftp://huggingface.co/model.bin",
            "file:///etc/passwd",
            "gopher://huggingface.co/",
            "javascript:alert(1)",
            "data:text/plain;base64,SGVsbG8=",
        ]
        for url in insecure_urls:
            with self.assertRaises(ValueError) as ctx:
                _validate_url(url)
            self.assertIn("HTTPS", str(ctx.exception))

    def test_untrusted_hosts_rejected(self):
        untrusted_urls = [
            "https://evil.com/model.bin",
            "https://huggingface.co.evil.com/model.bin",
            "https://fake-huggingface.co/model.bin",
            "https://evil-hf.co/model.bin",
            "https://not-huggingface.co/model.bin",
        ]
        for url in untrusted_urls:
            with self.assertRaises(ValueError) as ctx:
                _validate_url(url)
            self.assertIn("untrusted", str(ctx.exception).lower())

    def test_credentials_in_url_rejected(self):
        urls_with_creds = [
            "https://user:pass@huggingface.co/model.bin",
            "https://admin@huggingface.co/model.bin",
            "https://foo:bar@cdn-lfs.huggingface.co/model.bin",
        ]
        for url in urls_with_creds:
            with self.assertRaises(ValueError) as ctx:
                _validate_url(url)
            self.assertIn("credentials", str(ctx.exception).lower())

    def test_malformed_urls_rejected(self):
        malformed = [
            "",
            "   ",
            "https://",
            "https:///foo",
            "https://huggingface.co/model\0.bin",
            "https://huggingface.co/model\r\n.bin",
            "https://huggingface.co/model\n.bin",
        ]
        for bad_url in malformed:
            with self.assertRaises(ValueError):
                _validate_url(bad_url)

    def test_non_standard_port_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_url("https://huggingface.co:8443/model.bin")
        self.assertIn("non-standard port", str(ctx.exception).lower())

        _validate_url("https://huggingface.co:443/model.bin")

    def test_ipv4_ssrf_rejected(self):
        ssrf_urls = [
            "https://127.0.0.1/model.bin",
            "https://localhost/model.bin",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/model.bin",
            "https://192.168.1.1/model.bin",
            "https://172.16.0.1/model.bin",
            "https://0.0.0.0/model.bin",
        ]
        for url in ssrf_urls:
            with self.assertRaises(ValueError) as ctx:
                _validate_url(url)
            self.assertTrue(
                "local or private" in str(ctx.exception).lower()
                or "untrusted" in str(ctx.exception).lower()
            )

    def test_ipv6_ssrf_rejected(self):
        ipv6_ssrf_urls = [
            "https://[::1]/model.bin",
            "https://[fe80::1]/model.bin",
            "https://[fe80::1%eth0]/model.bin",
            "https://[fc00::1]/model.bin",
            "https://[fd00::1]/model.bin",
            "https://[::]/model.bin",
            "https://[::ffff:127.0.0.1]/model.bin",
            "https://[::ffff:169.254.169.254]/model.bin",
            "https://[::ffff:10.0.0.1]/model.bin",
            "https://[::ffff:192.168.1.1]/model.bin",
        ]
        for url in ipv6_ssrf_urls:
            with self.assertRaises(ValueError) as ctx:
                _validate_url(url)
            self.assertTrue(
                "local or private" in str(ctx.exception).lower()
                or "untrusted" in str(ctx.exception).lower()
            )


class TestHFMirror(unittest.TestCase):
    def test_valid_mirror_resolution(self):
        with patch.dict(os.environ, {"HF_MIRROR": "https://hf-mirror.com"}):
            resolved = _resolve_huggingface_mirror(
                "https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth"
            )
            self.assertEqual(
                resolved,
                "https://hf-mirror.com/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            )
            _validate_url(resolved)

    def test_insecure_mirror_rejected(self):
        with patch.dict(os.environ, {"HF_MIRROR": "http://hf-mirror.com"}):
            with self.assertRaises(ValueError) as ctx:
                _resolve_huggingface_mirror("https://huggingface.co/model.bin")
            self.assertIn("HTTPS", str(ctx.exception))

    def test_mirror_with_credentials_rejected(self):
        with patch.dict(os.environ, {"HF_MIRROR": "https://user:pass@hf-mirror.com"}):
            with self.assertRaises(ValueError) as ctx:
                _resolve_huggingface_mirror("https://huggingface.co/model.bin")
            self.assertIn("credentials", str(ctx.exception).lower())

    def test_mirror_with_query_or_fragment_rejected(self):
        for invalid_mirror in ["https://hf-mirror.com?key=val", "https://hf-mirror.com#frag"]:
            with patch.dict(os.environ, {"HF_MIRROR": invalid_mirror}):
                with self.assertRaises(ValueError):
                    _resolve_huggingface_mirror("https://huggingface.co/model.bin")

    def test_mirror_with_private_host_rejected(self):
        for local_mirror in [
            "https://127.0.0.1",
            "https://localhost",
            "https://10.0.0.5",
            "https://[::1]",
            "https://[fe80::1]",
        ]:
            with patch.dict(os.environ, {"HF_MIRROR": local_mirror}):
                with self.assertRaises(ValueError) as ctx:
                    _resolve_huggingface_mirror("https://huggingface.co/model.bin")
                self.assertIn("private", str(ctx.exception).lower())


class TestSafeDestination(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_filename(self):
        dest = _safe_destination(self.temp_dir, "model.safetensors")
        self.assertEqual(dest, Path(self.temp_dir) / "model.safetensors")

    def test_valid_subfolder(self):
        dest = _safe_destination(self.temp_dir, "subfolder/model.safetensors")
        self.assertEqual(dest, Path(self.temp_dir) / "subfolder" / "model.safetensors")

    def test_path_traversal_rejected(self):
        traversals = [
            "../evil.safetensors",
            "../../etc/passwd",
            "sub/../../outside.bin",
            "/tmp/absolute_escape.bin",
        ]
        for target in traversals:
            with self.assertRaises(ValueError) as ctx:
                _safe_destination(self.temp_dir, target)
            self.assertIn("outside", str(ctx.exception).lower())

    def test_root_directory_as_destination_rejected(self):
        for empty_or_root in ["", "  ", ".", "./"]:
            with self.assertRaises(ValueError):
                _safe_destination(self.temp_dir, empty_or_root)


class TestHardenedRedirectHandler(unittest.TestCase):
    def setUp(self):
        self.handler = HardenedRedirectHandler(max_redirects=3)

    def test_valid_https_redirect_allowed(self):
        req = urllib.request.Request("https://huggingface.co/foo/bar")
        new_req = self.handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://cdn-lfs.huggingface.co/models/foo.bin",
        )
        self.assertIsNotNone(new_req)
        self.assertEqual(
            new_req.full_url,
            "https://cdn-lfs.huggingface.co/models/foo.bin",
        )

    def test_relative_redirect_resolved_and_allowed(self):
        req = urllib.request.Request("https://huggingface.co/foo/bar")
        new_req = self.handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="/redirected/path/model.bin",
        )
        self.assertIsNotNone(new_req)
        self.assertEqual(
            new_req.full_url,
            "https://huggingface.co/redirected/path/model.bin",
        )

    def test_insecure_http_redirect_rejected(self):
        req = urllib.request.Request("https://huggingface.co/foo/bar")
        with self.assertRaises(ValueError) as ctx:
            self.handler.redirect_request(
                req=req,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://huggingface.co/insecure.bin",
            )
        self.assertIn("HTTPS", str(ctx.exception))

    def test_untrusted_host_redirect_rejected(self):
        req = urllib.request.Request("https://huggingface.co/foo/bar")
        with self.assertRaises(ValueError) as ctx:
            self.handler.redirect_request(
                req=req,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="https://evil-attacker.com/malicious.bin",
            )
        self.assertIn("untrusted", str(ctx.exception).lower())

    def test_ssrf_ipv4_and_ipv6_redirect_rejected(self):
        req = urllib.request.Request("https://huggingface.co/foo/bar")
        for bad_target in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/internal",
            "https://[::1]/internal",
            "https://[fe80::1]/internal",
            "https://[::ffff:127.0.0.1]/internal",
        ]:
            handler = HardenedRedirectHandler(max_redirects=3)
            with self.assertRaises(ValueError) as ctx:
                handler.redirect_request(
                    req=req,
                    fp=None,
                    code=302,
                    msg="Found",
                    headers={},
                    newurl=bad_target,
                )
            self.assertTrue(
                "local or private" in str(ctx.exception).lower()
                or "untrusted" in str(ctx.exception).lower()
            )

    def test_self_redirect_loop_detected(self):
        handler = HardenedRedirectHandler(max_redirects=5)
        req = urllib.request.Request("https://huggingface.co/self-loop")
        with self.assertRaises(RuntimeError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "https://huggingface.co/self-loop")
        self.assertIn("loop", str(ctx.exception).lower())

    def test_multi_hop_redirect_loop_detected(self):
        handler = HardenedRedirectHandler(max_redirects=5)
        req = urllib.request.Request("https://huggingface.co/loop-start")
        handler.redirect_request(req, None, 302, "Found", {}, "https://huggingface.co/A")
        req_a = urllib.request.Request("https://huggingface.co/A")
        handler.redirect_request(req_a, None, 302, "Found", {}, "https://huggingface.co/B")
        req_b = urllib.request.Request("https://huggingface.co/B")
        with self.assertRaises(RuntimeError) as ctx:
            handler.redirect_request(req_b, None, 302, "Found", {}, "https://huggingface.co/A")
        self.assertIn("loop", str(ctx.exception).lower())

    def test_max_redirects_exceeded(self):
        handler = HardenedRedirectHandler(max_redirects=2)
        req = urllib.request.Request("https://huggingface.co/0")
        handler.redirect_request(req, None, 302, "Found", {}, "https://huggingface.co/1")
        req1 = urllib.request.Request("https://huggingface.co/1")
        handler.redirect_request(req1, None, 302, "Found", {}, "https://huggingface.co/2")
        req2 = urllib.request.Request("https://huggingface.co/2")
        with self.assertRaises(RuntimeError) as ctx:
            handler.redirect_request(req2, None, 302, "Found", {}, "https://huggingface.co/3")
        self.assertIn("too many redirects", str(ctx.exception).lower())

    def test_cross_origin_sensitive_headers_stripped(self):
        req = urllib.request.Request(
            "https://huggingface.co/repo/file",
            headers={
                "Authorization": "Bearer token123",
                "Proxy-Authorization": "Basic dXNlcjpwYXNz",
                "Cookie": "session=xyz",
                "User-Agent": "Fooocus-Modern",
            },
        )
        new_req = self.handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://us.aws.cdn.hf.co/direct-file",
        )
        self.assertNotIn("Authorization", new_req.headers)
        self.assertNotIn("Proxy-Authorization", new_req.headers)
        self.assertNotIn("Cookie", new_req.headers)
        self.assertIn("User-agent", new_req.headers)

        # `Request.headers` normalises names to "Proxy-authorization", so the
        # check has to be case-insensitive or it passes vacuously.
        lowered_headers = {k.lower() for k in new_req.headers}
        self.assertNotIn("authorization", lowered_headers)
        self.assertNotIn("proxy-authorization", lowered_headers)
        self.assertNotIn("cookie", lowered_headers)
        self.assertIn("user-agent", lowered_headers)

        # Nothing may survive in `unredirected_hdrs` either.
        lowered_unredirected = {k.lower() for k in getattr(new_req, "unredirected_hdrs", {})}
        self.assertNotIn("authorization", lowered_unredirected)
        self.assertNotIn("proxy-authorization", lowered_unredirected)
        self.assertNotIn("cookie", lowered_unredirected)

    def test_sensitive_headers_stripped_regardless_of_storage_case(self):
        req = urllib.request.Request(
            "https://huggingface.co/repo/file",
            headers={"Cookie": "session=xyz"},
        )
        # Simulate the header living in `unredirected_hdrs` under a lower-case key.
        req.unredirected_hdrs["proxy-authorization"] = "Basic dXNlcjpwYXNz"
        req.headers["AUTHORIZATION"] = "Bearer token123"

        new_req = self.handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://us.aws.cdn.hf.co/direct-file",
        )

        self.assertEqual(
            {k.lower() for k in new_req.headers}
            & {"authorization", "proxy-authorization", "cookie"},
            set(),
        )
        self.assertEqual(
            {k.lower() for k in getattr(new_req, "unredirected_hdrs", {})}
            & {"authorization", "proxy-authorization", "cookie"},
            set(),
        )

    def test_same_origin_headers_preserved(self):
        req = urllib.request.Request(
            "https://huggingface.co/repo/file",
            headers={"Authorization": "Bearer token123"},
        )
        new_req = self.handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://huggingface.co/repo/file2",
        )
        self.assertIn("Authorization", new_req.headers)


class TestDNSRebindingAndSSRFConnection(unittest.TestCase):
    def test_dns_rebinding_resolving_to_private_ip_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses("huggingface.co", 443)
            self.assertIn("private/local address", str(ctx.exception).lower())

    def test_dns_rebinding_resolving_to_ipv6_loopback_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses("huggingface.co", 443)
            self.assertIn("private/local address", str(ctx.exception).lower())

    def test_dns_rebinding_resolving_to_metadata_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses("huggingface.co", 443)
            self.assertIn("private/local address", str(ctx.exception).lower())

    def test_dns_rebinding_dual_stack_with_private_ip_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("18.239.50.80", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses("huggingface.co", 443)
            self.assertIn("private/local address", str(ctx.exception).lower())

    def test_safe_https_connection_direct_connects_to_validated_ip(self):
        conn = SafeHTTPSConnection("huggingface.co", port=443)
        conn._context = MagicMock()
        mock_raw_sock = MagicMock()
        mock_tls_sock = MagicMock()
        conn._context.wrap_socket.return_value = mock_tls_sock

        with patch("modules.model_loader._resolve_and_validate_addresses") as mock_resolve, \
             patch("socket.create_connection") as mock_create_conn:
            mock_resolve.return_value = ("18.239.50.80", 443)
            mock_create_conn.return_value = mock_raw_sock

            conn.connect()

            mock_resolve.assert_called_once_with("huggingface.co", 443, allowed_hosts=None)
            mock_create_conn.assert_called_once_with(("18.239.50.80", 443), timeout=conn.timeout, source_address=conn.source_address)
            conn._context.wrap_socket.assert_called_once_with(mock_raw_sock, server_hostname="huggingface.co")
            self.assertEqual(conn.sock, mock_tls_sock)


class TestProxyDestinationValidation(unittest.TestCase):
    def test_proxy_cannot_bypass_untrusted_destination(self):
        with self.assertRaises(ValueError) as ctx:
            download_file(
                "https://evil-hacker.com/malicious.bin",
                destination="/tmp/test.bin",
            )
        self.assertIn("untrusted", str(ctx.exception).lower())

    def test_proxy_pointing_to_private_ip_blocked(self):
        conn = SafeHTTPSConnection("169.254.169.254:8080")
        conn.set_tunnel("huggingface.co", 443)
        with self.assertRaises(ValueError) as ctx:
            conn.connect()
        self.assertIn("refusing proxy connection to local or private address", str(ctx.exception).lower())


class TestDownloadSizeLimits(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("urllib.request.build_opener")
    def test_max_size_enforced_with_content_length(self, mock_build_opener):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": "2000000"}  # 2 MB
        # The response is used as a context manager by the downloader.
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "too_big.bin"
        with self.assertRaises(ValueError) as ctx:
            download_file(
                "https://huggingface.co/test/too_big.bin",
                destination=dest,
                max_size=1000000,  # 1 MB limit
                progress=False,
            )
        self.assertIn("exceeds maximum allowed limit", str(ctx.exception).lower())
        self.assertFalse(dest.exists())
        self.assertEqual(_residual_files(self.temp_dir), [])

    @patch("urllib.request.build_opener")
    def test_max_size_enforced_without_content_length(self, mock_build_opener):
        buffer = io.BytesIO(b"X" * 5000)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.side_effect = lambda amt: buffer.read(amt)
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "stream_too_big.bin"
        with self.assertRaises(ValueError) as ctx:
            download_file(
                "https://huggingface.co/test/stream_too_big.bin",
                destination=dest,
                max_size=2000,
                chunk_size=500,
                progress=False,
            )
        self.assertIn("exceeded maximum allowed limit", str(ctx.exception).lower())
        self.assertFalse(dest.exists())
        self.assertEqual(_residual_files(self.temp_dir), [])

    @patch("urllib.request.build_opener")
    def test_max_size_enforced_when_content_length_understates(self, mock_build_opener):
        # A server that advertises a small Content-Length but streams more data
        # must still be stopped by the running byte counter.
        buffer = io.BytesIO(b"Y" * 5000)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": "100"}
        mock_resp.read.side_effect = lambda amt: buffer.read(amt)
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "lying_content_length.bin"
        with self.assertRaises(ValueError) as ctx:
            download_file(
                "https://huggingface.co/test/lying_content_length.bin",
                destination=dest,
                max_size=2000,
                chunk_size=500,
                progress=False,
            )
        self.assertIn("exceeded maximum allowed limit", str(ctx.exception).lower())
        self.assertFalse(dest.exists())
        self.assertEqual(_residual_files(self.temp_dir), [])


class TestDownloadDeadline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("urllib.request.build_opener")
    def test_total_download_deadline_enforced(self, mock_build_opener):
        def slow_read(amt):
            time.sleep(0.06)
            return b"chunk"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.side_effect = slow_read
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "slow.bin"
        with self.assertRaises(TimeoutError) as ctx:
            download_file(
                "https://huggingface.co/test/slow.bin",
                destination=dest,
                max_duration=0.04,
                progress=False,
            )
        self.assertIn("exceeded total duration deadline", str(ctx.exception).lower())
        # The deadline is terminal: it must not be retried and must not back off.
        self.assertIsInstance(ctx.exception, DownloadDeadlineExceeded)
        self.assertEqual(mock_opener.open.call_count, 1)
        self.assertFalse(dest.exists())
        self.assertEqual(_residual_files(self.temp_dir), [])

    @patch("urllib.request.build_opener")
    def test_deadline_spans_retries_and_backoff(self, mock_build_opener):
        """
        The deadline is a single budget for the whole operation: retries and their
        backoff sleeps are charged against it, and the budget is never restarted.
        """
        clock = {"now": 0.0}

        def mono():
            return clock["now"]

        def fake_sleep(seconds):
            clock["now"] += seconds

        fake_time = types.SimpleNamespace(
            monotonic=mono, sleep=fake_sleep, time=mono
        )

        mock_opener = MagicMock()

        def slow_failing_open(*args, **kwargs):
            clock["now"] += 20.0  # first attempt burns 20s of the 30s budget
            raise socket.timeout("connection reset")

        mock_opener.open.side_effect = slow_failing_open
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "deadline_span.bin"
        with patch("modules.model_loader.time", fake_time):
            with self.assertRaises(TimeoutError) as ctx:
                download_file(
                    "https://huggingface.co/test/deadline_span.bin",
                    destination=dest,
                    max_duration=30.0,
                    max_retries=5,
                    retry_backoff=15.0,
                    progress=False,
                )

        self.assertIn("exceeded total duration deadline", str(ctx.exception).lower())
        # 1st attempt (20s) + clamped backoff (10s) = 30s -> no second attempt.
        self.assertEqual(mock_opener.open.call_count, 1)
        self.assertFalse(dest.exists())
        self.assertEqual(_residual_files(self.temp_dir), [])


class TestDeadlineErrorIsNotRetried(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_deadline_expiry_is_classified_as_terminal(self):
        self.assertFalse(
            _is_transient_error(
                DownloadDeadlineExceeded("Download exceeded total duration deadline")
            )
        )

    def test_plain_read_timeout_stays_retryable(self):
        self.assertTrue(_is_transient_error(TimeoutError("read timed out")))
        self.assertTrue(_is_transient_error(socket.timeout("read timed out")))


class TestConcurrentDownloadSafety(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.content = b"Concurrent Download Multi-Thread Safety Data 12345\n" * 50
        self.content_sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_response(self):
        buffer = io.BytesIO(self.content)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": str(len(self.content))}
        mock_resp.read.side_effect = lambda amt: buffer.read(amt)
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp

    def test_concurrent_downloads_thread_safety(self):
        dest = Path(self.temp_dir) / "concurrent_model.safetensors"
        results = []
        errors = []
        original_build_opener = urllib.request.build_opener

        def worker():
            return download_file(
                "https://huggingface.co/test/concurrent_model.safetensors",
                destination=dest,
                expected_hash=self.content_sha256,
                progress=False,
            )

        # A single patch scope for all workers: entering/exiting `patch` from four
        # threads concurrently leaks the mock (one thread's `__exit__` restores the
        # real function while another's still holds a mock as "original").
        with patch("urllib.request.build_opener") as mock_build_opener:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = lambda *a, **k: self._create_mock_response()
            mock_build_opener.return_value = mock_opener

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(worker) for _ in range(4)]
                for f in concurrent.futures.as_completed(futures):
                    try:
                        results.append(f.result())
                    except Exception as e:
                        errors.append(e)

        # The patch must have been restored after all threads finished.
        self.assertIs(urllib.request.build_opener, original_build_opener)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        for r in results:
            self.assertEqual(r, str(dest))

        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), self.content)
        # DestinationLock serialises the work: one download, three cache hits.
        self.assertEqual(mock_build_opener.call_count, 1)
        self.assertEqual(mock_opener.open.call_count, 1)


class TestFileHashingAndIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sample_data = b"Fooocus Modern Model Checksum Test 1234567890"
        self.sample_file = Path(self.temp_dir) / "test_model.bin"
        self.sample_file.write_bytes(self.sample_data)
        self.expected_sha256 = hashlib.sha256(self.sample_data).hexdigest()
        self.expected_md5 = hashlib.md5(self.sample_data).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_calculate_file_hash(self):
        sha256_hash = calculate_file_hash(self.sample_file, "sha256")
        self.assertEqual(sha256_hash, self.expected_sha256)

        md5_hash = calculate_file_hash(self.sample_file, "md5")
        self.assertEqual(md5_hash, self.expected_md5)

    def test_verify_file_hash_full(self):
        self.assertTrue(
            verify_file_hash(self.sample_file, self.expected_sha256, "sha256")
        )
        self.assertTrue(
            verify_file_hash(self.sample_file, self.expected_sha256.upper(), "sha256")
        )
        self.assertFalse(
            verify_file_hash(self.sample_file, "0" * 64, "sha256")
        )

    def test_verify_file_hash_prefix(self):
        prefix = self.expected_sha256[:10]
        self.assertTrue(verify_file_hash(self.sample_file, prefix, "sha256"))
        self.assertFalse(verify_file_hash(self.sample_file, "badprefix99", "sha256"))

    def test_matches_hash_logic(self):
        self.assertTrue(_matches_hash("abcdef1234", "abcdef1234"))
        self.assertTrue(_matches_hash("abcdef1234", "ABCDEF1234"))
        self.assertTrue(_matches_hash("abcdef1234", "abcd"))
        self.assertFalse(_matches_hash("abcdef1234", "xyz"))
        self.assertFalse(_matches_hash("abcdef1234", ""))


class TestDownloadReliabilityAndFailures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.content = b"Model Weights Content Simulation 1234567890\n" * 100
        self.content_sha256 = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_response(self, data: bytes, status: int = 200, chunk_size: int = 256):
        buffer = io.BytesIO(data)
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.headers = {"Content-Length": str(len(data))}

        def mock_read(amt=-1):
            if amt is None or amt < 0:
                return buffer.read()
            return buffer.read(min(amt, chunk_size))

        mock_resp.read.side_effect = mock_read
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp

    @patch("urllib.request.build_opener")
    def test_preserve_existing_valid_file_when_replacement_fails(self, mock_build_opener):
        dest = Path(self.temp_dir) / "vital_model.safetensors"
        initial_payload = b"ORIGINAL_EXISTING_VALID_MODEL_DATA"
        dest.write_bytes(initial_payload)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": "1000"}
        mock_resp.read.side_effect = socket.timeout("connection dropped")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        with self.assertRaises(TimeoutError):
            download_file(
                url="https://huggingface.co/test/vital_model.safetensors",
                destination=dest,
                expected_hash=self.content_sha256,
                max_retries=1,
                retry_backoff=0.01,
                progress=False,
            )

        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), initial_payload)
        # Lock file may be present in folder; check destination file specifically
        self.assertIn(dest, list(Path(self.temp_dir).iterdir()))

    @patch("time.sleep", return_value=None)
    @patch("urllib.request.build_opener")
    def test_retry_on_transient_failure_then_succeeds(self, mock_build_opener, mock_sleep):
        mock_resp_fail = MagicMock()
        mock_resp_fail.status = 200
        mock_resp_fail.headers = {"Content-Length": str(len(self.content))}
        mock_resp_fail.read.side_effect = socket.timeout("temporary glitch")
        mock_resp_fail.__enter__.return_value = mock_resp_fail
        mock_resp_fail.__exit__.return_value = None

        mock_resp_ok = self._create_mock_response(self.content)

        mock_opener = MagicMock()
        mock_opener.open.side_effect = [mock_resp_fail, mock_resp_ok]
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "retry_success.safetensors"
        result = download_file(
            url="https://huggingface.co/test/retry_success.safetensors",
            destination=dest,
            expected_hash=self.content_sha256,
            max_retries=3,
            retry_backoff=0.01,
            progress=False,
        )

        self.assertEqual(result, str(dest))
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), self.content)
        self.assertEqual(mock_opener.open.call_count, 2)
        mock_sleep.assert_called_once()

    @patch("time.sleep", return_value=None)
    @patch("urllib.request.build_opener")
    def test_non_transient_error_does_not_retry(self, mock_build_opener, mock_sleep):
        dest = Path(self.temp_dir) / "no_retry.safetensors"
        mock_resp = self._create_mock_response(self.content)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        with self.assertRaises(ValueError):
            download_file(
                url="https://huggingface.co/test/no_retry.safetensors",
                destination=dest,
                expected_hash="0" * 64,
                max_retries=3,
                progress=False,
            )

        self.assertEqual(mock_opener.open.call_count, 1)
        mock_sleep.assert_not_called()
        self.assertFalse(dest.exists())

    @patch("urllib.request.build_opener")
    def test_checksum_mismatch_cleans_up_and_fails(self, mock_build_opener):
        mock_resp = self._create_mock_response(self.content)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "corrupt.safetensors"
        bad_hash = "0" * 64

        with self.assertRaises(ValueError) as ctx:
            download_file(
                url="https://huggingface.co/test/corrupt.safetensors",
                destination=dest,
                expected_hash=bad_hash,
                progress=False,
            )

        self.assertIn("integrity check failed", str(ctx.exception).lower())
        self.assertFalse(dest.exists())

    @patch("urllib.request.build_opener")
    def test_incomplete_download_content_length_fails(self, mock_build_opener):
        short_data = b"short" * 20
        buffer = io.BytesIO(short_data)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": "10000"}
        mock_resp.read.side_effect = lambda amt: buffer.read(amt)
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "incomplete.bin"
        with self.assertRaises(RuntimeError) as ctx:
            download_file(
                url="https://huggingface.co/test/incomplete.bin",
                destination=dest,
                max_retries=0,
                progress=False,
            )

        self.assertIn("incomplete download", str(ctx.exception).lower())
        self.assertFalse(dest.exists())

    @patch("urllib.request.build_opener")
    def test_empty_download_fails(self, mock_build_opener):
        mock_resp = self._create_mock_response(b"")
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        dest = Path(self.temp_dir) / "empty.bin"
        with self.assertRaises(RuntimeError) as ctx:
            download_file(
                url="https://huggingface.co/test/empty.bin",
                destination=dest,
                max_retries=0,
                progress=False,
            )

        self.assertIn("empty", str(ctx.exception).lower())
        self.assertFalse(dest.exists())


class TestIntegrationCompatibility(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.payload = b"Call site integration payload test"
        self.payload_sha256 = hashlib.sha256(self.payload).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_import_model_loader_does_not_require_torch(self):
        import modules.model_loader
        self.assertNotIn("torch", sys.modules)

    def test_launch_can_import_model_loader_before_torch(self):
        from launch import load_file_from_url as launch_loader
        from modules.model_loader import load_file_from_url as direct_loader
        self.assertIs(launch_loader, direct_loader)

    @patch("modules.model_loader.download_file")
    def test_all_fooocus_call_signatures(self, mock_download):
        mock_download.return_value = "/mock/path"

        # 1. launch.py and modules.config style (kwargs url, model_dir, file_name)
        load_file_from_url(
            url="https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            model_dir=self.temp_dir,
            file_name="xlvaeapp.pth",
        )
        mock_download.assert_called_with(
            url="https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            destination=Path(self.temp_dir) / "xlvaeapp.pth",
            progress=True,
            expected_hash=None,
            hash_algorithm="sha256",
            timeout=None,
            allowed_hosts=None,
            allowed_domains=None,
            max_retries=None,
            retry_backoff=None,
            max_size=None,
            max_duration=None,
        )

        # 2. extras/interrogate.py style (positional url, kwargs model_dir, file_name)
        load_file_from_url(
            "https://huggingface.co/lllyasviel/misc/resolve/main/fooocus_expansion.bin",
            model_dir=self.temp_dir,
            file_name="pytorch_model.bin",
        )
        mock_download.assert_called_with(
            url="https://huggingface.co/lllyasviel/misc/resolve/main/fooocus_expansion.bin",
            destination=Path(self.temp_dir) / "pytorch_model.bin",
            progress=True,
            expected_hash=None,
            hash_algorithm="sha256",
            timeout=None,
            allowed_hosts=None,
            allowed_domains=None,
            max_retries=None,
            retry_backoff=None,
            max_size=None,
            max_duration=None,
        )

        # 3. extras/facexlib/utils/misc.py style (download_url_to_file)
        target_path = str(Path(self.temp_dir) / "facex.pth")
        download_url_to_file(
            url="https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            dst=target_path,
            hash_prefix="6c8db5",
            progress=False,
        )
        mock_download.assert_called_with(
            url="https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth",
            destination=Path(target_path).resolve(),
            progress=False,
            expected_hash="6c8db5",
            hash_algorithm="sha256",
        )


class TestRealHTTPSIntegration(unittest.TestCase):
    """
    Live HTTPS integration test against Hugging Face using the small (208 KB)
    xlvaeapp.pth auxiliary model defined in launch.py.
    """

    KNOWN_URL = "https://huggingface.co/lllyasviel/misc/resolve/main/xlvaeapp.pth"
    KNOWN_SHA256 = "6c8db511f910184436a613807ce06a729f4cf96bbf7977c7c6c40d5b3e4a8333"
    KNOWN_SIZE = 213777

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_live_https_download_with_redirect_and_checksum(self):
        dest = Path(self.temp_dir) / "xlvaeapp.pth"

        downloaded_path = download_file(
            url=self.KNOWN_URL,
            destination=dest,
            expected_hash=self.KNOWN_SHA256,
            progress=False,
        )

        self.assertEqual(downloaded_path, str(dest))
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.stat().st_size, self.KNOWN_SIZE)

        # Verify hash matches perfectly
        actual_hash = calculate_file_hash(dest, "sha256")
        self.assertEqual(actual_hash, self.KNOWN_SHA256)

        # Ensure no leftover temporary download files exist in directory (.lock file may be present)
        remaining_files = [f for f in Path(self.temp_dir).iterdir() if not f.name.endswith(".lock")]
        self.assertEqual(remaining_files, [dest])

        # Test cache hit on second invocation (should not re-download)
        with patch("urllib.request.build_opener") as mock_opener:
            reused_path = download_file(
                url=self.KNOWN_URL,
                destination=dest,
                expected_hash=self.KNOWN_SHA256,
                progress=False,
            )
            self.assertEqual(reused_path, str(dest))
            mock_opener.assert_not_called()


class TestDNSRebindingProductionPathRegression(unittest.TestCase):
    """
    Regression coverage for the confirmed DNS-rebinding/SSRF bypass: an allowlisted
    hostname must never make a private DNS answer acceptable, even when the exact
    production allowlist (`allowed_hosts=DEFAULT_ALLOWED_HOSTS`) is supplied.
    """

    ALLOWED_HOSTS = set(DEFAULT_ALLOWED_HOSTS)
    ALLOWED_DOMAINS = set(DEFAULT_ALLOWED_DOMAINS)

    def _assert_blocked(self, host, resolved_ip, allowed=None, expect="rebinding"):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved_ip, 443))
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses(host, 443, allowed_hosts=allowed)
        self.assertIn("private/local address", str(ctx.exception).lower())
        if expect:
            self.assertIn(expect, str(ctx.exception).lower())
        return mock_gai

    def test_allowlisted_hostname_resolving_to_loopback_blocked(self):
        self._assert_blocked("huggingface.co", "127.0.0.1", self.ALLOWED_HOSTS)

    def test_allowlisted_hostname_resolving_to_cloud_metadata_blocked(self):
        self._assert_blocked("huggingface.co", "169.254.169.254", self.ALLOWED_HOSTS)

    def test_allowlisted_hostname_resolving_to_cgnat_blocked(self):
        # 100.64.0.0/10 is neither loopback nor RFC1918; older Python versions
        # report it as global, so it needs explicit handling.
        self._assert_blocked("hf.co", "100.64.0.7", self.ALLOWED_HOSTS)

    def test_allowlisted_hostname_resolving_to_ipv6_unique_local_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 443, 0, 0))
            ]
            with self.assertRaises(ValueError) as ctx:
                _resolve_and_validate_addresses(
                    "cdn-lfs.huggingface.co", 443, allowed_hosts=self.ALLOWED_HOSTS
                )
        self.assertIn("private/local address", str(ctx.exception).lower())

    def test_literal_private_ip_not_covered_by_hostname_allowlist(self):
        with self.assertRaises(ValueError) as ctx:
            _resolve_and_validate_addresses(
                "169.254.169.254", 443, allowed_hosts=self.ALLOWED_HOSTS
            )
        self.assertIn("refusing connection to private/local address", str(ctx.exception).lower())

    def test_explicit_literal_ip_opt_in_still_supported(self):
        # Operators may deliberately allow an internal mirror by IP.
        resolved = _resolve_and_validate_addresses(
            "10.20.30.40", 443, allowed_hosts={"10.20.30.40"}
        )
        self.assertEqual(resolved, ("10.20.30.40", 443))

    def test_connection_refuses_before_opening_a_socket(self):
        conn = SafeHTTPSConnection(
            "huggingface.co",
            port=443,
            allowed_hosts=self.ALLOWED_HOSTS,
            allowed_domains=self.ALLOWED_DOMAINS,
        )
        conn._context = MagicMock()

        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
            ]
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("private/local address", str(ctx.exception).lower())
        mock_create_conn.assert_not_called()
        conn._context.wrap_socket.assert_not_called()

    def test_connection_refuses_host_not_on_allowlist(self):
        conn = SafeHTTPSConnection(
            "evil-hacker.com",
            port=443,
            allowed_hosts=self.ALLOWED_HOSTS,
            allowed_domains=self.ALLOWED_DOMAINS,
        )
        conn._context = MagicMock()

        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("untrusted host", str(ctx.exception).lower())
        mock_gai.assert_not_called()
        mock_create_conn.assert_not_called()


class TestProxyTunnelDestinationValidationRegression(unittest.TestCase):
    """
    Regression coverage for the confirmed proxy/tunnel validation gap: opening a
    CONNECT tunnel used to validate only the proxy, never the destination.
    """

    ALLOWED_HOSTS = set(DEFAULT_ALLOWED_HOSTS)
    ALLOWED_DOMAINS = set(DEFAULT_ALLOWED_DOMAINS)
    PUBLIC_PROXY = "93.184.216.34"  # example.com, public literal

    def _connection(self, proxy, target="huggingface.co", target_port=443):
        conn = SafeHTTPSConnection(
            proxy,
            allowed_hosts=self.ALLOWED_HOSTS,
            allowed_domains=self.ALLOWED_DOMAINS,
        )
        conn.set_tunnel(target, target_port)
        conn._context = MagicMock()
        return conn

    def test_tunnel_destination_resolving_to_loopback_blocked(self):
        conn = self._connection(f"{self.PUBLIC_PROXY}:8443")
        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
            ]
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("private/local address", str(ctx.exception).lower())
        self.assertIn("huggingface.co", str(ctx.exception))
        mock_create_conn.assert_not_called()

    def test_tunnel_destination_host_not_allowlisted_blocked_before_dns(self):
        conn = self._connection(
            f"{self.PUBLIC_PROXY}:8443", target="evil-hacker.com"
        )
        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("untrusted host", str(ctx.exception).lower())
        mock_gai.assert_not_called()
        mock_create_conn.assert_not_called()

    def test_tunnel_destination_dns_failure_fails_closed(self):
        conn = self._connection(f"{self.PUBLIC_PROXY}:8443")
        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            mock_gai.side_effect = socket.gaierror("no such host")
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("dns resolution failed", str(ctx.exception).lower())
        mock_create_conn.assert_not_called()

    def test_proxy_hostname_resolving_to_private_ip_blocked(self):
        conn = self._connection("proxy.example.org:3128")
        with patch("socket.getaddrinfo") as mock_gai, \
             patch("socket.create_connection") as mock_create_conn:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 3128))
            ]
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn("proxy.example.org", str(ctx.exception))
        self.assertIn("private/local address", str(ctx.exception).lower())
        mock_create_conn.assert_not_called()

    def test_ipv6_link_local_proxy_blocked(self):
        # `self.host.split(":")[0]` used to turn "fe80::1" into "fe80", which is
        # not a valid IP and therefore slipped through the private check.
        conn = self._connection("[fe80::1]:3128")
        with patch("socket.create_connection") as mock_create_conn:
            with self.assertRaises(ValueError) as ctx:
                conn.connect()

        self.assertIn(
            "refusing proxy connection to local or private address",
            str(ctx.exception).lower(),
        )
        self.assertIn("fe80::1", str(ctx.exception))
        mock_create_conn.assert_not_called()

    def test_ipv6_loopback_proxy_blocked(self):
        conn = self._connection("[::1]:3128")
        with self.assertRaises(ValueError) as ctx:
            conn.connect()
        self.assertIn(
            "refusing proxy connection to local or private address",
            str(ctx.exception).lower(),
        )

    def test_ipv4_link_local_proxy_blocked(self):
        conn = self._connection("169.254.169.254:8080")
        with self.assertRaises(ValueError) as ctx:
            conn.connect()
        self.assertIn(
            "refusing proxy connection to local or private address",
            str(ctx.exception).lower(),
        )

    def test_public_ipv6_proxy_passes_validation(self):
        conn = self._connection("[2600:1f18:1234::1]:3128")
        self.assertEqual(conn.host, "2600:1f18:1234::1")
        self.assertEqual(conn.port, 3128)

        with patch("socket.getaddrinfo") as mock_gai, \
             patch("http.client.HTTPSConnection.connect") as mock_super_connect:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            conn.connect()

        # Proxy DNS answer validated, then the tunnel was opened.
        self.assertTrue(mock_gai.called)
        mock_super_connect.assert_called_once()


class TestTemporaryFileAndLockHygiene(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("urllib.request.build_opener")
    def test_invalid_hash_algorithm_creates_no_temp_file(self, mock_build_opener):
        # `hashlib.new()` now runs before `mkstemp()`, so a bad algorithm cannot
        # leak a file descriptor or a temporary file.
        mock_build_opener.return_value = MagicMock()

        dest = Path(self.temp_dir) / "bad_alg.bin"
        with self.assertRaises(ValueError):
            download_file(
                "https://huggingface.co/test/bad_alg.bin",
                destination=dest,
                expected_hash="0" * 64,
                hash_algorithm="not-a-hash-algorithm",
                progress=False,
            )

        self.assertEqual(_residual_files(self.temp_dir), [])
        self.assertFalse(dest.exists())

    def test_lock_registry_is_not_leaked(self):
        from modules import model_loader

        before = len(model_loader._THREAD_LOCKS)
        for index in range(10):
            with DestinationLock(Path(self.temp_dir) / f".model{index}.lock"):
                pass
        self.assertEqual(len(model_loader._THREAD_LOCKS), before)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_symlinked_lock_file_rejected(self):
        target = Path(self.temp_dir) / "real.txt"
        target.write_text("owned by someone else")
        link = Path(self.temp_dir) / ".model.bin.lock"
        link.symlink_to(target)

        with self.assertRaises(ValueError) as ctx:
            with DestinationLock(link):
                pass
        self.assertIn("symlinked lock file", str(ctx.exception).lower())
        self.assertEqual(target.read_text(), "owned by someone else")

    def test_lock_file_is_persistent_by_design(self):
        lock = Path(self.temp_dir) / ".model.bin.lock"
        with DestinationLock(lock):
            self.assertTrue(lock.exists())
        # Removing it on release would reopen a check-to-use race; it persists.
        self.assertTrue(lock.exists())


class TestTLSVerificationNeverDisabled(unittest.TestCase):
    """
    Stage 3 regression protection: TLS certificate validation must stay enabled
    everywhere in this repository (launch.py historically disabled it globally).
    """

    SCAN_SUFFIXES = (".py", ".ipynb", ".sh", ".txt", ".cfg", ".toml", ".yml",
                     ".yaml", ".ps1", ".bat")
    SCAN_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
    FORBIDDEN_PATTERNS = (
        "_create_unverified_context",
        "CERT_NONE",
        "check_hostname = False",
        "check_hostname=False",
        "ssl.wrap_socket(",
        "verify=False",
        "verify = False",
        "PYTHONHTTPSVERIFY",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "--trusted-host",
        "_create_default_https_context =",
    )

    def _iter_source_files(self):
        own_file = Path(__file__).resolve()
        for path in REPO_ROOT.rglob("*"):
            if path.suffix not in self.SCAN_SUFFIXES or not path.is_file():
                continue
            if path.resolve() == own_file:
                continue
            if any(part in self.SCAN_SKIP_DIRS for part in path.parts):
                continue
            yield path

    def test_no_tls_bypass_patterns_in_repository(self):
        offenders = []
        for path in self._iter_source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pattern in self.FORBIDDEN_PATTERNS:
                if pattern in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern}")

        self.assertEqual(
            offenders,
            [],
            f"TLS verification bypass patterns found: {offenders}",
        )

    def test_default_ssl_context_requires_certificates_and_hostname(self):
        context = ssl.create_default_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_model_loader_builds_a_verifying_context(self):
        source = inspect.getsource(importlib.import_module("modules.model_loader"))
        self.assertIn("ssl.create_default_context()", source)
        self.assertNotIn("_create_unverified_context", source)
        self.assertNotIn("CERT_NONE", source)

    def test_launch_py_contains_no_tls_bypass(self):
        text = (REPO_ROOT / "launch.py").read_text(encoding="utf-8")
        self.assertNotIn("_create_unverified_context", text)
        self.assertNotIn("CERT_NONE", text)

    def test_live_handshake_accepts_valid_certificate(self):
        context = ssl.create_default_context()
        with socket.create_connection(("huggingface.co", 443), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname="huggingface.co") as tls:
                cert = tls.getpeercert()
                self.assertTrue(cert)
                self.assertIn("huggingface.co", str(cert.get("subject", "")) + str(cert.get("subjectAltName", "")))

    def test_live_handshake_rejects_wrong_hostname(self):
        context = ssl.create_default_context()
        with socket.create_connection(("huggingface.co", 443), timeout=15) as raw:
            with self.assertRaises((ssl.SSLError, ssl.CertificateError)):
                context.wrap_socket(raw, server_hostname="evil-hacker.com")


if __name__ == "__main__":
    unittest.main()
