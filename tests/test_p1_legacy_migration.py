"""
Stage 7 P1-A regression tests: legacy downloader migration.

Covers (offline; mocks and temporary directories only — no model weights):
  - facexlib download routing through the hardened downloader + manifest
  - existing-file behavior (no network touch)
  - production and fallback cache directories (legacy semantics preserved)
  - approved GitHub destinations and rejected destinations/redirects
  - unresolved-artifact warnings (allow_unverified opt-in)
  - download failures and temporary-file cleanup
  - checkpoint-loading behavior unchanged (static source assertions)
  - k-diffusion raw-urlopen helper removal and sampler utility availability
"""

import ast
import contextlib
import importlib.util
import io
import os
import shutil
import sys
import tempfile
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.model_loader import _validate_url, download_file
from modules import model_manifest
from modules.model_manifest import ManifestError, get_artifact

REPO_ROOT = Path(__file__).resolve().parent.parent

GITHUB_DOMAINS = ["github.com", "release-assets.githubusercontent.com"]
RESNET50_URL = (
    "https://github.com/xinntao/facexlib/releases/download/"
    "v0.1.0/detection_Resnet50_Final.pth"
)
PARSENET_URL = (
    "https://github.com/xinntao/facexlib/releases/download/"
    "v0.2.2/parsing_parsenet.pth"
)
MOBILENET_URL = (
    "https://github.com/xinntao/facexlib/releases/download/"
    "v0.1.0/detection_mobilenet0.25_Final.pth"
)
FACEXLIB_IDS = (
    "facexlib-detection-resnet50",
    "facexlib-detection-mobilenet",
    "facexlib-parsing-bisenet",
    "facexlib-parsing-parsenet",
)


def _load_facexlib_misc():
    """Load extras/facexlib/utils/misc.py standalone (no package __init__
    side effects, which would require numpy/torch/cv2).

    Any inert torch/cv2 stubs installed for the load are removed from
    sys.modules immediately afterwards, so P0's
    ``test_import_model_loader_does_not_require_torch`` invariant is not
    disturbed regardless of test ordering.
    """
    created = []
    for name in ("torch", "cv2"):
        try:
            __import__(name)
        except Exception:
            sys.modules[name] = types.ModuleType(name)
            created.append(name)
    try:
        path = REPO_ROOT / "extras" / "facexlib" / "utils" / "misc.py"
        spec = importlib.util.spec_from_file_location(
            "p1_facexlib_misc_under_test", str(path)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name in created:
            sys.modules.pop(name, None)


_FACEXLIB_MISC = None


def _misc():
    """Lazy, cached handle on the standalone-loaded facexlib wrapper."""
    global _FACEXLIB_MISC
    if _FACEXLIB_MISC is None:
        _FACEXLIB_MISC = _load_facexlib_misc()
    return _FACEXLIB_MISC


class P1TestCase(unittest.TestCase):
    """Temp directory + manifest-gate state isolation (real manifest kept)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._original_warned = set(model_manifest._unverified_warned)
        model_manifest._unverified_warned = set()

    def tearDown(self):
        model_manifest._unverified_warned = self._original_warned
        shutil.rmtree(self.temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Manifest recording (Task 1)
# ---------------------------------------------------------------------------


class TestFacexlibManifestRecording(P1TestCase):
    def test_four_release_assets_recorded_as_unresolved(self):
        for artifact_id in FACEXLIB_IDS:
            entry = get_artifact(artifact_id)
            with self.subTest(artifact_id=artifact_id):
                self.assertEqual(entry["status"], "unresolved")
                self.assertIsNone(entry["sha256"])
                self.assertFalse(entry["url_mutable"])
                self.assertTrue(entry["source"]["url"].startswith("https://github.com/"))
                self.assertIn("/releases/download/", entry["source"]["url"])
                self.assertGreater(entry["size_bytes"], 0)
                self.assertTrue(entry["evidence"])

    def test_unverified_downloads_require_and_carry_explicit_justification(self):
        for artifact_id in FACEXLIB_IDS:
            entry = get_artifact(artifact_id)
            with self.subTest(artifact_id=artifact_id):
                self.assertIs(entry["allow_unverified"], True)
                justification = entry["unverified_justification"]
                self.assertIsInstance(justification, str)
                self.assertIn("digest: null", justification)
                self.assertIn("SHA-256", justification)

    def test_per_artifact_github_domain_authorization(self):
        for artifact_id in FACEXLIB_IDS:
            entry = get_artifact(artifact_id)
            with self.subTest(artifact_id=artifact_id):
                self.assertEqual(entry["allowed_domains"], GITHUB_DOMAINS)

    def test_no_invented_hashes_for_unverified_artifacts(self):
        # The full-hash tier is approval-gated; nothing here may self-certify.
        for artifact_id in FACEXLIB_IDS:
            self.assertIsNone(get_artifact(artifact_id)["sha256"])


# ---------------------------------------------------------------------------
# Routing through the hardened downloader (Task 1 / Task 3)
# ---------------------------------------------------------------------------


class TestFacexlibRouting(P1TestCase):
    @patch("modules.model_manifest.load_file_from_url")
    def test_routes_through_hardened_loader_with_manifest_policy(self, mock_loader):
        mock_loader.return_value = "/mock/resnet50.pth"
        result = _misc().load_file_from_url(
            RESNET50_URL, save_dir=self.temp_dir, progress=False
        )
        self.assertEqual(result, "/mock/resnet50.pth")
        mock_loader.assert_called_once()
        kwargs = mock_loader.call_args.kwargs
        self.assertEqual(kwargs["url"], RESNET50_URL)
        self.assertEqual(kwargs["model_dir"], self.temp_dir)
        self.assertEqual(kwargs["file_name"], "detection_Resnet50_Final.pth")
        self.assertIsNone(kwargs["expected_hash"])
        self.assertEqual(kwargs["cached_hash_mismatch"], "redownload")
        self.assertEqual(kwargs["allowed_domains"], GITHUB_DOMAINS)
        self.assertIs(kwargs["progress"], False)

    @patch("modules.model_manifest.load_file_from_url")
    def test_manifest_records_url_used_by_call_sites(self, mock_loader):
        mock_loader.return_value = "/mock/parsenet.pth"
        result = _misc().load_file_from_url(PARSENET_URL, save_dir=self.temp_dir)
        self.assertEqual(result, "/mock/parsenet.pth")
        self.assertEqual(mock_loader.call_args.kwargs["file_name"], "parsing_parsenet.pth")

    @patch("modules.model_manifest.load_file_from_url")
    def test_unknown_url_is_refused_fail_closed(self, mock_loader):
        with self.assertRaises(ManifestError) as ctx:
            _misc().load_file_from_url(
                "https://evil.example.com/model.pth", save_dir=self.temp_dir
            )
        self.assertIn("not recorded in the model integrity manifest", str(ctx.exception))
        mock_loader.assert_not_called()

    @patch("modules.model_manifest.load_file_from_url")
    def test_file_name_override_is_honored(self, mock_loader):
        mock_loader.return_value = "/mock/custom.pth"
        _misc().load_file_from_url(
            RESNET50_URL, save_dir=self.temp_dir, file_name="custom.pth"
        )
        self.assertEqual(mock_loader.call_args.kwargs["file_name"], "custom.pth")

    def test_legacy_torch_hub_import_removed(self):
        source = (REPO_ROOT / "extras" / "facexlib" / "utils" / "misc.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("from torch.hub import", source)
        self.assertNotIn("import torch.hub", source)
        self.assertNotIn("download_url_to_file", source)
        self.assertIn("match_url", source)
        self.assertIn("manifest_download", source)


# ---------------------------------------------------------------------------
# Production and fallback cache directories (Task 3)
# ---------------------------------------------------------------------------


class TestFacexlibCacheDirectories(P1TestCase):
    @patch("modules.model_manifest.load_file_from_url")
    def test_production_save_dir_is_the_destination(self, mock_loader):
        mock_loader.return_value = "/mock/x.pth"
        production = os.path.join(self.temp_dir, "controlnet")
        _misc().load_file_from_url(RESNET50_URL, save_dir=production)
        self.assertEqual(mock_loader.call_args.kwargs["model_dir"], production)
        self.assertTrue(os.path.isdir(production))

    @patch("modules.model_manifest.load_file_from_url")
    def test_fallback_lands_under_root_dir_facexlib_weights(self, mock_loader):
        mock_loader.return_value = "/mock/x.pth"
        with patch.object(_misc(), "ROOT_DIR", self.temp_dir):
            _misc().load_file_from_url(
                RESNET50_URL, model_dir="facexlib/weights"
            )
        expected = os.path.join(self.temp_dir, "facexlib", "weights")
        self.assertEqual(mock_loader.call_args.kwargs["model_dir"], expected)
        self.assertTrue(os.path.isdir(expected))

    @patch("modules.model_manifest.load_file_from_url")
    def test_torch_hub_checkpoint_fallback_when_model_dir_none(self, mock_loader):
        mock_loader.return_value = "/mock/x.pth"
        torch_home = os.path.join(self.temp_dir, "torch-home")
        with patch.dict(os.environ, {"TORCH_HOME": torch_home}):
            _misc().load_file_from_url(RESNET50_URL, model_dir=None,
                                             save_dir=None)
        expected = os.path.join(torch_home, "hub", "checkpoints")
        self.assertEqual(mock_loader.call_args.kwargs["model_dir"], expected)
        self.assertTrue(os.path.isdir(expected))


# ---------------------------------------------------------------------------
# Existing-file behavior (Task 3)
# ---------------------------------------------------------------------------


class TestExistingFileBehavior(P1TestCase):
    @patch("urllib.request.build_opener")
    def test_existing_nonempty_file_returned_without_network(self, mock_build):
        payload = b"pre-existing facexlib weights"
        cached = Path(self.temp_dir) / "detection_Resnet50_Final.pth"
        cached.write_bytes(payload)

        def _network_touched(*args, **kwargs):
            raise AssertionError("network must not be touched for a cached file")

        mock_build.side_effect = _network_touched
        result = _misc().load_file_from_url(
            RESNET50_URL, save_dir=self.temp_dir
        )
        self.assertEqual(Path(result).resolve(), cached.resolve())
        self.assertEqual(cached.read_bytes(), payload)
        mock_build.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_existing_empty_file_triggers_redownload_path(self, mock_build):
        # Legacy trusted existence; the hardened loader requires size > 0.
        cached = Path(self.temp_dir) / "detection_Resnet50_Final.pth"
        cached.write_bytes(b"")
        mock_opener = MagicMock()
        mock_opener.open.side_effect = urllib.error.URLError("offline")
        mock_build.return_value = mock_opener

        with self.assertRaises(urllib.error.URLError):
            download_file(
                url=RESNET50_URL,
                destination=str(cached),
                allowed_domains=GITHUB_DOMAINS,
                max_retries=0,
                retry_backoff=0.0,
                progress=False,
            )
        mock_build.assert_called_once()


# ---------------------------------------------------------------------------
# Approved and rejected destinations (Task 3)
# ---------------------------------------------------------------------------


class TestDestinationPolicy(P1TestCase):
    def test_github_release_url_approved(self):
        _validate_url(RESNET50_URL, allowed_domains=GITHUB_DOMAINS)

    def test_release_assets_redirect_host_approved(self):
        _validate_url(
            "https://release-assets.githubusercontent.com/asset/1/x.pth",
            allowed_domains=GITHUB_DOMAINS,
        )

    def test_github_hosts_require_per_artifact_grant(self):
        # github.com is NOT in the built-in allowlist (huggingface/hf only):
        # GitHub access comes solely from the per-artifact allowed_domains.
        with self.assertRaises(ValueError):
            _validate_url(RESNET50_URL)
        _validate_url(RESNET50_URL, allowed_domains=GITHUB_DOMAINS)

    def test_other_hosts_rejected_under_github_plus_default_allowlist(self):
        for url in (
            "https://evil.example.com/x.pth",
            "http://github.com/xinntao/facexlib/releases/download/v0.1.0/x.pth",
            "https://127.0.0.1/x.pth",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _validate_url(url, allowed_domains=GITHUB_DOMAINS)

    def test_redirect_within_allowlist_allowed(self):
        from modules.model_loader import HardenedRedirectHandler

        handler = HardenedRedirectHandler(allowed_domains=GITHUB_DOMAINS)
        new_req = handler.redirect_request(
            req=urllib.request.Request(RESNET50_URL),
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://release-assets.githubusercontent.com/asset/1/x.pth",
        )
        self.assertIsNotNone(new_req)

    def test_redirect_to_untrusted_host_rejected(self):
        from modules.model_loader import HardenedRedirectHandler

        handler = HardenedRedirectHandler(allowed_domains=GITHUB_DOMAINS)
        with self.assertRaises(ValueError) as ctx:
            handler.redirect_request(
                req=urllib.request.Request(RESNET50_URL),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="https://evil.example.com/steal.pth",
            )
        self.assertIn("untrusted host", str(ctx.exception).lower())

    def test_redirect_to_insecure_http_rejected(self):
        from modules.model_loader import HardenedRedirectHandler

        handler = HardenedRedirectHandler(allowed_domains=GITHUB_DOMAINS)
        with self.assertRaises(ValueError):
            handler.redirect_request(
                req=urllib.request.Request(RESNET50_URL),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://github.com/x.pth",
            )


# ---------------------------------------------------------------------------
# Unresolved-artifact warnings (Task 3)
# ---------------------------------------------------------------------------


class TestUnresolvedArtifactWarnings(P1TestCase):
    @patch("modules.model_manifest.load_file_from_url")
    def test_first_unverified_download_warns_with_justification(self, mock_loader):
        mock_loader.return_value = "/mock/mobilenet.pth"
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            _misc().load_file_from_url(
                MOBILENET_URL, save_dir=self.temp_dir
            )
        output = captured.getvalue()
        self.assertIn("[Integrity] WARNING", output)
        self.assertIn("detection_mobilenet0.25_Final.pth", output)
        self.assertIn("digest: null", output)

    @patch("modules.model_manifest.load_file_from_url")
    def test_warning_emitted_once_per_artifact(self, mock_loader):
        mock_loader.return_value = "/mock/mobilenet.pth"
        first, second = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(first):
            _misc().load_file_from_url(
                MOBILENET_URL, save_dir=self.temp_dir
            )
        with contextlib.redirect_stdout(second):
            _misc().load_file_from_url(
                MOBILENET_URL, save_dir=self.temp_dir
            )
        self.assertIn("[Integrity] WARNING", first.getvalue())
        self.assertNotIn("[Integrity] WARNING", second.getvalue())


# ---------------------------------------------------------------------------
# Download failures and cleanup (Task 3)
# ---------------------------------------------------------------------------


class TestDownloadFailureAndCleanup(P1TestCase):
    @patch("modules.model_manifest.load_file_from_url")
    def test_wrapper_propagates_failure_and_leaves_no_file(self, mock_loader):
        mock_loader.side_effect = RuntimeError("transport failed")
        with self.assertRaises(RuntimeError):
            _misc().load_file_from_url(
                RESNET50_URL, save_dir=self.temp_dir
            )
        payload_files = [n for n in os.listdir(self.temp_dir) if n.endswith(".pth")]
        self.assertEqual(payload_files, [])

    @patch("urllib.request.build_opener")
    def test_hardened_failure_removes_temp_files(self, mock_build):
        mock_opener = MagicMock()
        mock_opener.open.side_effect = urllib.error.URLError("offline")
        mock_build.return_value = mock_opener
        destination = os.path.join(self.temp_dir, "detection_Resnet50_Final.pth")

        with self.assertRaises(urllib.error.URLError):
            download_file(
                url=RESNET50_URL,
                destination=destination,
                allowed_domains=GITHUB_DOMAINS,
                max_retries=0,
                retry_backoff=0.0,
                progress=False,
            )
        self.assertFalse(os.path.exists(destination))
        leftovers = [n for n in os.listdir(self.temp_dir) if n.endswith(".download")]
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# Checkpoint-loading behavior unchanged (Task 3)
# ---------------------------------------------------------------------------


class TestCheckpointLoadingUnchanged(P1TestCase):
    def test_detection_loading_still_safe_and_strict(self):
        source = (REPO_ROOT / "extras" / "facexlib" / "detection" / "__init__.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("weights_only=True", source)
        self.assertIn("load_state_dict(load_net, strict=True)", source)
        self.assertIn("k[7:]", source)
        self.assertIn(
            "https://github.com/xinntao/facexlib/releases/download/"
            "v0.1.0/detection_Resnet50_Final.pth",
            source,
        )
        self.assertIn(
            "https://github.com/xinntao/facexlib/releases/download/"
            "v0.1.0/detection_mobilenet0.25_Final.pth",
            source,
        )

    def test_parsing_loading_still_safe_and_strict(self):
        source = (REPO_ROOT / "extras" / "facexlib" / "parsing" / "__init__.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("weights_only=True", source)
        self.assertIn("load_state_dict(load_net, strict=True)", source)
        self.assertIn(
            "https://github.com/xinntao/facexlib/releases/download/"
            "v0.2.0/parsing_bisenet.pth",
            source,
        )
        self.assertIn(
            "https://github.com/xinntao/facexlib/releases/download/"
            "v0.2.2/parsing_parsenet.pth",
            source,
        )

    def test_loading_modules_do_not_import_hardened_transport(self):
        for rel in ("extras/facexlib/detection/__init__.py",
                    "extras/facexlib/parsing/__init__.py"):
            source = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("from extras.facexlib.utils import load_file_from_url", source)


# ---------------------------------------------------------------------------
# k-diffusion helper removal and sampler availability (Task 2)
# ---------------------------------------------------------------------------


class TestKDiffusionHelperRemoved(unittest.TestCase):
    def test_download_file_helper_removed_by_ast(self):
        path = REPO_ROOT / "ldm_patched" / "k_diffusion" / "utils.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function_names = {
            node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        self.assertNotIn("download_file", function_names)
        for required in ("append_dims", "n_params", "train_mode", "eval_mode",
                         "ema_update"):
            self.assertIn(required, function_names)

    def test_raw_urlopen_and_dead_imports_removed(self):
        source = (REPO_ROOT / "ldm_patched" / "k_diffusion" / "utils.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("urlopen", source)
        self.assertNotIn("hashlib", source)
        self.assertNotIn("shutil", source)
        self.assertNotIn("urllib", source)

    def test_sampling_module_still_imports_and_uses_utils(self):
        source = (REPO_ROOT / "ldm_patched" / "k_diffusion" / "sampling.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from . import utils", source)
        self.assertIn("utils.append_dims", source)

    def test_no_raw_urlopen_download_helper_anywhere_in_source(self):
        offenders = []
        for path in REPO_ROOT.rglob("*.py"):
            if ".git" in path.parts or "tests" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "urlopen" in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [], f"raw urlopen references found: {offenders}")

    def test_no_download_file_reintroduction_in_ldm_patched(self):
        offenders = []
        for path in (REPO_ROOT / "ldm_patched").rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "def download_file(" in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
