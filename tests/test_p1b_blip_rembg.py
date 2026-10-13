"""
Stage 7 P1-B regression tests: BLIP cleanup + rembg pre-seeding.

Covers (offline; mocks, fixtures, and temporary directories only — no model
weights are ever downloaded):
  - all seven audited rembg model mappings (flags <-> rembg_preseed <-> manifest)
  - manifest md5 schema validation and ambiguous-classification rejection
  - md5 mismatch rejection at download time and at cache-verification time
  - cache reuse (valid md5) and corruption (invalid md5, fail-closed)
  - symlinked-destination and path-traversal rejection
  - U2NET_HOME / XDG_DATA_HOME environment precedence (rembg semantics)
  - model-selection compatibility (flags coverage; call order preserved)
  - download failures and temporary-file cleanup
  - BLIP blip_pretrain.py removal with active captioning preserved
  - no checksum-disabling, no rembg/pooch monkey-patching (repo scan)
"""

import ast
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import model_manifest
from modules import rembg_preseed
from modules.model_loader import (
    CachedFileIntegrityError,
    _safe_destination,
    load_file_from_url,
)
from modules.model_manifest import (
    ManifestError,
    MissingManifestEntryError,
    download as manifest_download,
    load_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

CONTENT = b"p1b-rembg-preseed-test-payload"
CONTENT_MD5 = hashlib.md5(CONTENT).hexdigest()

REMBG_URL_PREFIX = (
    "https://github.com/danielgatis/rembg/releases/download/v0.0.0/"
)

# Publisher-attested md5 pins from the rembg 2.0.57 wheel source
# (rembg/sessions/*.py pooch checksums), cross-checked against the
# immutable GitHub release assets' metadata (names + byte sizes).
EXPECTED_REMBG = {
    "u2net": ("rembg-u2net", "u2net.onnx",
              "60024c5c889badc19c04ad937298a77b", 175997641),
    "u2netp": ("rembg-u2netp", "u2netp.onnx",
               "8e83ca70e441ab06c318d82300c84806", 4574861),
    "u2net_human_seg": ("rembg-u2net-human-seg", "u2net_human_seg.onnx",
                        "c09ddc2e0104f800e3e1bb4652583d1f", 175997641),
    "u2net_cloth_seg": ("rembg-u2net-cloth-seg", "u2net_cloth_seg.onnx",
                        "2434d1f3cb744e0e49386c906e5a08bb", 176194565),
    "silueta": ("rembg-silueta", "silueta.onnx",
                "55e59e0d8062d2f5d013f4725ee84782", 44173029),
    "isnet-general-use": ("rembg-isnet-general-use", "isnet-general-use.onnx",
                          "fc16ebd8b0c10d971d3513d564d01e29", 178648008),
    "isnet-anime": ("rembg-isnet-anime", "isnet-anime.onnx",
                    "6f184e756bb3bd901c8849220a83e38e", 176069933),
}


def _mock_response(data: bytes, status: int = 200):
    buffer = io.BytesIO(data)
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.headers = {"Content-Length": str(len(data))}
    mock_resp.read.side_effect = lambda amt: buffer.read(amt)
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None
    return mock_resp


def _install_opener(mock_build_opener, responses):
    mock_opener = MagicMock()
    mock_opener.open.side_effect = responses
    mock_build_opener.return_value = mock_opener
    return mock_opener


def _md5_entry(artifact_id="rembg-test", model="u2net", md5=CONTENT_MD5,
               sha256=None, **extra):
    file_name = f"{model}.onnx"
    url = f"{REMBG_URL_PREFIX}{file_name}"
    entry = {
        "id": artifact_id,
        "status": "unresolved",
        "file_name": file_name,
        "purpose": "test rembg model",
        "source": {
            "type": "github-release",
            "repo": "danielgatis/rembg",
            "path": file_name,
            "revision": "v0.0.0",
            "url": url,
            "mutable_url": None,
        },
        "url_mutable": False,
        "sha256": sha256,
        "md5": md5,
        "size_bytes": len(CONTENT),
        "evidence": ["https://example.invalid/evidence"],
        "allowed_domains": ["github.com", "release-assets.githubusercontent.com"],
        "mandatory": False,
        "user_substitutable": False,
        "allow_unverified": False,
        "call_sites": ["extras/inpaint_mask.py:64"],
    }
    entry.update(extra)
    return entry


class P1BManifestTestBase(unittest.TestCase):
    """Swaps in a synthetic manifest for isolation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._original_path = model_manifest._MANIFEST_PATH
        self._original_cache = model_manifest._manifest_cache
        self._original_warned = set(model_manifest._unverified_warned)
        model_manifest._unverified_warned = set()

    def tearDown(self):
        model_manifest._MANIFEST_PATH = self._original_path
        model_manifest._manifest_cache = self._original_cache
        model_manifest._unverified_warned = self._original_warned
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def install_manifest(self, artifacts, **top_level):
        manifest = {
            "schema_version": 1,
            "manifest_version": "p1b-test.1",
            "generated_from": {},
            "policy": {},
            "user_supplied_categories": [
                "checkpoint_downloads",
                "embeddings_downloads",
                "lora_downloads",
                "vae_downloads",
            ],
            "artifacts": artifacts,
        }
        manifest.update(top_level)
        path = os.path.join(self.temp_dir, "manifest.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        model_manifest._MANIFEST_PATH = path
        model_manifest._manifest_cache = None
        return load_manifest(refresh=True)


# ---------------------------------------------------------------------------
# 1. Seven rembg model mappings: flags <-> rembg_preseed <-> shipped manifest
# ---------------------------------------------------------------------------

class TestRembgModelMappings(unittest.TestCase):
    def test_preseed_mapping_matches_flags_minus_sam(self):
        from modules import flags
        expected = [m for m in flags.inpaint_mask_models if m != "sam"]
        self.assertEqual(
            sorted(rembg_preseed.REMBG_MODEL_ARTIFACTS), sorted(expected)
        )
        self.assertNotIn("sam", rembg_preseed.REMBG_MODEL_ARTIFACTS)

    def test_every_preseed_model_has_complete_manifest_entry(self):
        for model, (artifact_id, file_name, md5, size) in EXPECTED_REMBG.items():
            self.assertEqual(rembg_preseed.REMBG_MODEL_ARTIFACTS[model], artifact_id)
            entry = model_manifest.get_artifact(artifact_id)
            self.assertEqual(entry["file_name"], file_name)
            self.assertEqual(entry["md5"], md5)
            self.assertEqual(entry["size_bytes"], size)
            self.assertIsNone(entry["sha256"])
            self.assertEqual(entry["status"], "unresolved")
            self.assertEqual(entry["url_mutable"], False)
            self.assertEqual(entry["allow_unverified"], False)
            self.assertEqual(
                entry["source"]["url"], f"{REMBG_URL_PREFIX}{file_name}"
            )
            self.assertEqual(
                entry["allowed_domains"],
                ["github.com", "release-assets.githubusercontent.com"],
            )
            # pooch fname convention: f"{name}.onnx" — file name must match
            self.assertEqual(entry["file_name"], f"{model}.onnx")

    def test_no_manifest_entry_claimed_sha256_verified(self):
        manifest = model_manifest.load_manifest()
        for artifact_id, *_ in EXPECTED_REMBG.values():
            entry = model_manifest.get_artifact(artifact_id)
            self.assertNotEqual(entry["status"], "verified")
            self.assertIsNone(entry["sha256"])


# ---------------------------------------------------------------------------
# 2. Manifest md5 schema validation
# ---------------------------------------------------------------------------

class TestManifestMd5Schema(P1BManifestTestBase):
    def test_valid_md5_accepted(self):
        self.install_manifest([_md5_entry()])

    def test_md5_none_accepted(self):
        self.install_manifest([_md5_entry(md5=None)])

    def test_md5_wrong_length_rejected(self):
        for bad in ("a" * 31, "a" * 33, ""):
            with self.assertRaises(ManifestError):
                self.install_manifest([_md5_entry(md5=bad)])

    def test_md5_non_hex_rejected(self):
        with self.assertRaises(ManifestError):
            self.install_manifest([_md5_entry(md5="z" * 32)])

    def test_md5_non_string_rejected(self):
        with self.assertRaises(ManifestError):
            self.install_manifest([_md5_entry(md5=12345)])

    def test_md5_uppercase_accepted_like_sha256(self):
        self.install_manifest([_md5_entry(md5=CONTENT_MD5.upper())])

    def test_verified_entry_with_md5_rejected_as_ambiguous(self):
        entry = _md5_entry(
            status="verified",
            md5=CONTENT_MD5,
            sha256=hashlib.sha256(CONTENT).hexdigest(),
            url_mutable=False,
        )
        with self.assertRaises(ManifestError) as ctx:
            self.install_manifest([entry])
        self.assertIn("ambiguous", str(ctx.exception))

    def test_unresolved_with_both_sha256_and_md5_rejected(self):
        entry = _md5_entry(
            sha256=hashlib.sha256(CONTENT).hexdigest(),
        )
        with self.assertRaises(ManifestError) as ctx:
            self.install_manifest([entry])
        self.assertIn("ambiguous", str(ctx.exception))

    def test_md5_with_allow_unverified_rejected(self):
        entry = _md5_entry(allow_unverified=True)
        with self.assertRaises(ManifestError) as ctx:
            self.install_manifest([entry])
        self.assertIn("allow_unverified", str(ctx.exception))

    def test_unresolved_without_hash_and_without_optin_still_refused(self):
        self.install_manifest([_md5_entry(md5=None)])
        with self.assertRaises(ManifestError):
            manifest_download("rembg-test", model_dir=self.temp_dir)


# ---------------------------------------------------------------------------
# 3-4. MD5 download enforcement, mismatch rejection, cache reuse/corruption
# ---------------------------------------------------------------------------

class TestMd5DownloadEnforcement(P1BManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_md5_entry_downloads_with_md5_algorithm(self, mock_build_opener):
        self.install_manifest([_md5_entry()])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        with patch.object(
            model_manifest, "load_file_from_url",
            wraps=model_manifest.load_file_from_url,
        ) as spy:
            path = manifest_download("rembg-test", model_dir=self.temp_dir,
                                     progress=False)
            self.assertEqual(spy.call_args.kwargs["hash_algorithm"], "md5")
            self.assertEqual(spy.call_args.kwargs["expected_hash"], CONTENT_MD5)
            self.assertEqual(
                spy.call_args.kwargs["cached_hash_mismatch"], "fail"
            )
        self.assertEqual(Path(path).read_bytes(), CONTENT)

    @patch("urllib.request.build_opener")
    def test_md5_mismatch_fails_closed_without_file(self, mock_build_opener):
        self.install_manifest([_md5_entry(md5="0" * 32)])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        with self.assertRaises(ValueError) as ctx:
            manifest_download("rembg-test", model_dir=self.temp_dir,
                              progress=False)
        self.assertIn("integrity check failed", str(ctx.exception).lower())
        self.assertFalse((Path(self.temp_dir) / "u2net.onnx").exists())
        leftovers = [
            p for p in Path(self.temp_dir).iterdir()
            if p.name != "manifest.json"
            and not (p.name.startswith(".") and p.name.endswith(".lock"))
        ]
        self.assertEqual(leftovers, [])

    @patch("urllib.request.build_opener")
    def test_valid_md5_cache_reused_without_network(self, mock_build_opener):
        self.install_manifest([_md5_entry()])
        cached = Path(self.temp_dir) / "u2net.onnx"
        cached.write_bytes(CONTENT)

        path = manifest_download("rembg-test", model_dir=self.temp_dir,
                                 progress=False)
        self.assertEqual(path, str(cached.resolve()))
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_corrupted_cache_fails_closed_and_file_untouched(self,
                                                            mock_build_opener):
        self.install_manifest([_md5_entry()])
        cached = Path(self.temp_dir) / "u2net.onnx"
        cached.write_bytes(b"corrupted-not-the-payload")

        with self.assertRaises(CachedFileIntegrityError) as ctx:
            manifest_download("rembg-test", model_dir=self.temp_dir,
                              progress=False)
        self.assertIn("failed md5 verification", str(ctx.exception))
        self.assertEqual(cached.read_bytes(), b"corrupted-not-the-payload")
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_verified_sha256_path_unchanged(self, mock_build_opener):
        """P1-B must not alter sha256-verified behavior."""
        sha = hashlib.sha256(CONTENT).hexdigest()
        entry = {
            "id": "verified-test",
            "status": "verified",
            "file_name": "verified.bin",
            "purpose": "test",
            "source": {
                "type": "huggingface",
                "repo": "test/repo",
                "path": "verified.bin",
                "revision": "a" * 40,
                "url": "https://huggingface.co/test/repo/resolve/"
                       f"{'a' * 40}/verified.bin",
                "mutable_url": None,
            },
            "url_mutable": False,
            "sha256": sha,
            "size_bytes": len(CONTENT),
            "evidence": [],
            "mandatory": False,
            "user_substitutable": False,
        }
        self.install_manifest([entry])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        with patch.object(
            model_manifest, "load_file_from_url",
            wraps=model_manifest.load_file_from_url,
        ) as spy:
            manifest_download("verified-test", model_dir=self.temp_dir,
                              progress=False)
            self.assertEqual(spy.call_args.kwargs["hash_algorithm"], "sha256")
            self.assertEqual(spy.call_args.kwargs["expected_hash"], sha)
            self.assertEqual(
                spy.call_args.kwargs["cached_hash_mismatch"], "fail"
            )


# ---------------------------------------------------------------------------
# 5. Symlink and traversal rejection
# ---------------------------------------------------------------------------

class TestSymlinkAndTraversal(P1BManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_symlinked_destination_rejected(self, mock_build_opener):
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net")])
        home = Path(self.temp_dir) / "u2net_home"
        home.mkdir()
        outside = Path(self.temp_dir) / "outside.onnx"
        outside.write_bytes(CONTENT)
        link = home / "u2net.onnx"
        link.symlink_to(outside)

        with patch.dict(os.environ, {"U2NET_HOME": str(home)}):
            with self.assertRaises(ValueError) as ctx:
                rembg_preseed.ensure_rembg_model("u2net")
        self.assertIn("outside model directory", str(ctx.exception))
        mock_build_opener.assert_not_called()
        # outside target untouched
        self.assertEqual(outside.read_bytes(), CONTENT)
        self.assertTrue(link.is_symlink())

    def test_traversal_file_name_rejected_by_safe_destination(self):
        with self.assertRaises(ValueError) as ctx:
            _safe_destination(self.temp_dir, "../escape.onnx")
        self.assertIn("outside model directory", str(ctx.exception))

    @patch("urllib.request.build_opener")
    def test_traversal_via_loader_rejected_before_network(self,
                                                          mock_build_opener):
        with self.assertRaises(ValueError):
            load_file_from_url(
                url=f"{REMBG_URL_PREFIX}u2net.onnx",
                model_dir=self.temp_dir,
                file_name="../escape.onnx",
                progress=False,
            )
        mock_build_opener.assert_not_called()

    def test_traversal_manifest_file_name_rejected(self):
        entry = _md5_entry()
        entry["file_name"] = "../evil.onnx"
        with self.assertRaises(ManifestError):
            self.install_manifest([entry])


# ---------------------------------------------------------------------------
# 6. Environment-variable precedence (rembg u2net_home semantics)
# ---------------------------------------------------------------------------

class TestU2NetHomeEnvPrecedence(unittest.TestCase):
    def test_u2net_home_wins_over_xdg(self):
        with patch.dict(os.environ, {
            "U2NET_HOME": "/custom/u2net",
            "XDG_DATA_HOME": "/xdg/data",
        }):
            self.assertEqual(
                rembg_preseed.resolve_u2net_home(), "/custom/u2net"
            )

    def test_xdg_home_used_when_u2net_unset(self):
        env = {"XDG_DATA_HOME": "/xdg/data"}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("U2NET_HOME", None)
            self.assertEqual(
                rembg_preseed.resolve_u2net_home(),
                os.path.join("/xdg/data", ".u2net"),
            )

    def test_dot_u2net_fallback_when_both_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("U2NET_HOME", None)
            os.environ.pop("XDG_DATA_HOME", None)
            expected = os.path.expanduser(os.path.join("~", ".u2net"))
            self.assertEqual(rembg_preseed.resolve_u2net_home(), expected)

    def test_xdg_relative_component_expanded(self):
        with patch.dict(os.environ, {"XDG_DATA_HOME": "~/.local/share"},
                        clear=False):
            os.environ.pop("U2NET_HOME", None)
            self.assertEqual(
                rembg_preseed.resolve_u2net_home(),
                os.path.expanduser("~/.local/share/.u2net"),
            )


# ---------------------------------------------------------------------------
# 7. Model-selection compatibility
# ---------------------------------------------------------------------------

class TestModelSelectionCompatibility(unittest.TestCase):
    def test_inpaint_mask_source_calls_preseed_before_new_session(self):
        source = (REPO_ROOT / "extras" / "inpaint_mask.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("ensure_rembg_model(mask_model)", source)
        self.assertIn("new_session(mask_model, **extras)", source)
        self.assertLess(
            source.index("ensure_rembg_model(mask_model)"),
            source.index("new_session(mask_model, **extras)"),
        )
        self.assertIn(
            "from modules.rembg_preseed import ensure_rembg_model", source
        )

    def test_unrecognized_model_is_passthrough(self):
        """Non-flag names (e.g. rembg extras) are not pre-seeded or failed."""
        self.assertIsNone(rembg_preseed.ensure_rembg_model("u2net_custom"))
        self.assertIsNone(rembg_preseed.ensure_rembg_model("sam"))

    def test_manifest_selection_covers_every_flag_except_sam(self):
        from modules import flags
        for model in flags.inpaint_mask_models:
            if model == "sam":
                self.assertNotIn(
                    model, rembg_preseed.REMBG_MODEL_ARTIFACTS
                )
                continue
            artifact_id = rembg_preseed.REMBG_MODEL_ARTIFACTS[model]
            # get_artifact raises MissingManifestEntryError when absent
            model_manifest.get_artifact(artifact_id)


# ---------------------------------------------------------------------------
# 8. Pre-seed integration: download into rembg home, failures, cleanup
# ---------------------------------------------------------------------------

class TestPreseedIntegration(P1BManifestTestBase):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.temp_dir, "u2net_home")
        self._env_patcher = patch.dict(
            os.environ, {"U2NET_HOME": self.home}
        )
        self._env_patcher.start()

    def tearDown(self):
        self._env_patcher.stop()
        super().tearDown()

    @patch("urllib.request.build_opener")
    def test_preseed_writes_model_into_remgb_home(self, mock_build_opener):
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net")])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        path = rembg_preseed.ensure_rembg_model("u2net")
        self.assertEqual(path, str((Path(self.home) / "u2net.onnx").resolve()))
        self.assertEqual(
            (Path(self.home) / "u2net.onnx").read_bytes(), CONTENT
        )

    @patch("urllib.request.build_opener")
    def test_preseed_cache_reuse_no_network(self, mock_build_opener):
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net")])
        os.makedirs(self.home, exist_ok=True)
        (Path(self.home) / "u2net.onnx").write_bytes(CONTENT)

        path = rembg_preseed.ensure_rembg_model("u2net")
        self.assertEqual(
            Path(path).read_bytes(), CONTENT
        )
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_preseed_corrupted_cache_fails_closed(self, mock_build_opener):
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net")])
        os.makedirs(self.home, exist_ok=True)
        (Path(self.home) / "u2net.onnx").write_bytes(b"corrupted")

        with self.assertRaises(CachedFileIntegrityError):
            rembg_preseed.ensure_rembg_model("u2net")
        mock_build_opener.assert_not_called()

    @patch("modules.model_loader.time.sleep")
    @patch("urllib.request.build_opener")
    def test_preseed_download_failure_propagates_and_cleans_up(
        self, mock_build_opener, mock_sleep
    ):
        """Fail closed: HTTP error propagates; no model file or temp litter."""
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net")])
        _install_opener(mock_build_opener, [
            urllib.error.HTTPError(
                url=REMBG_URL_PREFIX + "u2net.onnx", code=404,
                msg="Not Found", hdrs=None, fp=None,
            ),
        ])

        with self.assertRaises(urllib.error.HTTPError):
            rembg_preseed.ensure_rembg_model("u2net")
        mock_sleep.assert_not_called()  # 404 is non-transient: no retry
        self.assertFalse(
            (Path(self.home) / "u2net.onnx").exists()
        )
        leftovers = [
            p for p in Path(self.home).iterdir()
            if not (p.name.startswith(".") and p.name.endswith(".lock"))
        ]
        self.assertEqual(leftovers, [])

    @patch("modules.model_loader.time.sleep")
    @patch("urllib.request.build_opener")
    def test_preseed_no_fallback_after_failure(self, mock_build_opener,
                                               mock_sleep):
        """A recognized model never falls back to rembg's downloader: the
        helper raises and never returns a path (callers must not catch and
        hand the name to new_session)."""
        self.install_manifest([_md5_entry(artifact_id="rembg-u2net",
                                          md5="0" * 32)])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        with self.assertRaises(ValueError):
            rembg_preseed.ensure_rembg_model("u2net")
        self.assertFalse((Path(self.home) / "u2net.onnx").exists())

    @patch("urllib.request.build_opener")
    def test_preseed_missing_manifest_entry_fails_closed(self, mock_build_opener):
        # manifest valid but lacks the rembg-u2net entry
        self.install_manifest([_md5_entry(artifact_id="other-artifact",
                                          model="other")])
        with self.assertRaises(MissingManifestEntryError):
            rembg_preseed.ensure_rembg_model("u2net")
        mock_build_opener.assert_not_called()


# ---------------------------------------------------------------------------
# 9. BLIP module removal + active captioning compatibility
# ---------------------------------------------------------------------------

class TestBlipCleanupAndCaptioning(unittest.TestCase):
    def test_blip_pretrain_removed(self):
        self.assertFalse(
            (REPO_ROOT / "extras" / "BLIP" / "models" / "blip_pretrain.py")
            .exists()
        )

    def test_no_blip_pretrain_references_in_code(self):
        hits = []
        for path in REPO_ROOT.rglob("*.py"):
            if ".git" in path.parts or "tests" in path.parts:
                continue
            if "blip_pretrain" in path.read_text(encoding="utf-8",
                                                  errors="ignore"):
                hits.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(hits, [])

    def test_active_blip_modules_present_with_expected_symbols(self):
        models = REPO_ROOT / "extras" / "BLIP" / "models"
        for name in ("blip.py", "vit.py", "med.py"):
            self.assertTrue((models / name).exists(), name)
        tree = ast.parse((models / "blip.py").read_text(encoding="utf-8"))
        top_level = {
            node.name for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn("blip_decoder", top_level)
        self.assertIn("blip_feature_extractor", top_level)

    def test_interrogate_still_wires_blip_captioning(self):
        source = (REPO_ROOT / "extras" / "interrogate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "from extras.BLIP.models.blip import blip_decoder", source
        )
        self.assertIn("blip-caption-base", source)

    def test_blip_caption_base_artifact_still_verified(self):
        entry = model_manifest.get_artifact("blip-caption-base")
        self.assertEqual(entry["status"], "verified")
        self.assertEqual(len(entry["sha256"]), 64)
        self.assertTrue(entry["sha256"])

    def test_deit_manifest_entry_retired(self):
        manifest = model_manifest.load_manifest()
        ids = {a["id"] for a in manifest["artifacts"]}
        self.assertNotIn("deit-base-patch16", ids)

    def test_no_torch_hub_download_in_extras(self):
        # The dead blip_pretrain path was the only extras module calling
        # torch.hub.load_state_dict_from_url; it is now gone. Latent
        # download_cached_file URL branches in blip.py/blip_nlvr.py remain
        # under separate approval (P1-B optional item 4) and are not
        # asserted here.
        for path in (REPO_ROOT / "extras").rglob("*.py"):
            source = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(
                "load_state_dict_from_url", source,
                f"unexpected load_state_dict_from_url in {path}",
            )


# ---------------------------------------------------------------------------
# 10. Guardrails: no checksum disabling, no monkey-patching
# ---------------------------------------------------------------------------

class TestGuardrails(unittest.TestCase):
    def test_model_checksum_disabled_never_referenced(self):
        for path in REPO_ROOT.rglob("*.py"):
            if ".git" in path.parts or "tests" in path.parts:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(
                "MODEL_CHECKSUM_DISABLED", source,
                f"checksum disabling referenced in {path}",
            )

    def test_inpaint_mask_does_not_patch_rembg_or_pooch(self):
        source = (REPO_ROOT / "extras" / "inpaint_mask.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(
                    func, "id", None
                )
                self.assertNotIn(name, {"setattr", "monkeypatch"},
                                 "no monkey-patching allowed")

    def test_preseed_module_imports_only_stdlib_and_manifest(self):
        tree = ast.parse(
            (REPO_ROOT / "modules" / "rembg_preseed.py").read_text(
                encoding="utf-8"
            )
        )
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(
            imported,
            {"os", "typing", "modules"},
            "pre-seed helper must stay free of rembg/pooch/network deps",
        )

    def test_shipped_manifest_matches_pinned_remgb_metadata(self):
        for model, (artifact_id, file_name, md5, size) in EXPECTED_REMBG.items():
            entry = model_manifest.get_artifact(artifact_id)
            self.assertEqual(entry["md5"], md5)
            self.assertEqual(entry["size_bytes"], size)
            self.assertEqual(entry["source"]["revision"], "v0.0.0")


if __name__ == "__main__":
    unittest.main()
