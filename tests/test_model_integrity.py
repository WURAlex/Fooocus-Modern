import hashlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.model_loader import (
    CachedFileIntegrityError,
    download_file,
    load_file_from_url,
)
from modules import model_manifest
from modules.model_manifest import (
    ManifestError,
    MissingManifestEntryError,
    download as manifest_download,
    download_user_supplied,
    get_artifact,
    load_manifest,
    match_file_name_url,
)


CONTENT = b"stage7-integrity-test-payload"
CONTENT_SHA256 = hashlib.sha256(CONTENT).hexdigest()
GITHUB_URL = (
    "https://github.com/IDEA-Research/GroundingDINO/releases/download/"
    "v0.1.0-alpha/groundingdino_swint_ogc.pth"
)


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


def _synthetic_entry(artifact_id="test-artifact", status="verified",
                     sha256=CONTENT_SHA256, file_name="test_artifact.bin",
                     url="https://huggingface.co/test/repo/resolve/"
                         "0123456789abcdef0123456789abcdef01234567/test_artifact.bin",
                     **extra):
    entry = {
        "id": artifact_id,
        "status": status,
        "file_name": file_name,
        "purpose": "test artifact",
        "source": {
            "type": "huggingface",
            "repo": "test/repo",
            "path": file_name,
            "revision": "0123456789abcdef0123456789abcdef01234567",
            "url": url,
            "mutable_url": url.replace(
                "/0123456789abcdef0123456789abcdef01234567/", "/main/"
            ),
        },
        "url_mutable": status == "unresolved",
        "sha256": sha256,
        "size_bytes": len(CONTENT),
        "evidence": ["https://example.invalid/evidence"],
        "mandatory": False,
        "user_substitutable": False,
    }
    if status == "unresolved":
        entry["allow_unverified"] = extra.pop("allow_unverified", False)
        if entry["allow_unverified"]:
            entry["unverified_justification"] = extra.pop(
                "unverified_justification", "test justification"
            )
    entry.update(extra)
    return entry


class ManifestTestBase(unittest.TestCase):
    """Base class that swaps in a synthetic manifest for isolation."""

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
            "manifest_version": "test.1",
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


class TestCorrectManifestHash(ManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_verified_artifact_downloads_with_expected_hash(self, mock_build_opener):
        self.install_manifest([_synthetic_entry()])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        result = manifest_download("test-artifact", model_dir=self.temp_dir)

        self.assertEqual(result, str(Path(self.temp_dir) / "test_artifact.bin"))
        self.assertEqual(Path(result).read_bytes(), CONTENT)
        mock_build_opener.assert_called_once()


class TestIncorrectManifestHash(ManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_hash_mismatch_fails_closed_without_file(self, mock_build_opener):
        wrong_sha = hashlib.sha256(b"different-content").hexdigest()
        self.install_manifest([_synthetic_entry(sha256=wrong_sha)])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        with self.assertRaises(ValueError) as ctx:
            manifest_download("test-artifact", model_dir=self.temp_dir)

        self.assertIn("integrity check failed", str(ctx.exception).lower())
        self.assertFalse((Path(self.temp_dir) / "test_artifact.bin").exists())
        leftovers = [
            p for p in Path(self.temp_dir).iterdir()
            if p.name != "manifest.json"
            and not (p.name.startswith(".") and p.name.endswith(".lock"))
        ]
        self.assertEqual(leftovers, [])


class TestCorruptedCachedArtifact(ManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_cached_mismatch_fails_closed_and_preserves_file(self, mock_build_opener):
        self.install_manifest([_synthetic_entry()])
        dest = Path(self.temp_dir) / "test_artifact.bin"
        corrupted = b"CORRUPTED-CACHE"
        dest.write_bytes(corrupted)

        with self.assertRaises(CachedFileIntegrityError) as ctx:
            manifest_download("test-artifact", model_dir=self.temp_dir)

        message = str(ctx.exception)
        self.assertIn("failed sha256 verification", message)
        self.assertIn("remove it explicitly", message)
        self.assertEqual(dest.read_bytes(), corrupted)
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_explicit_removal_allows_redownload(self, mock_build_opener):
        self.install_manifest([_synthetic_entry()])
        dest = Path(self.temp_dir) / "test_artifact.bin"
        dest.write_bytes(b"CORRUPTED-CACHE")

        with self.assertRaises(CachedFileIntegrityError):
            manifest_download("test-artifact", model_dir=self.temp_dir)

        dest.unlink()
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])
        result = manifest_download("test-artifact", model_dir=self.temp_dir)
        self.assertEqual(Path(result).read_bytes(), CONTENT)

    @patch("urllib.request.build_opener")
    def test_default_policy_still_redownloads(self, mock_build_opener):
        dest = Path(self.temp_dir) / "legacy.bin"
        dest.write_bytes(b"CORRUPTED-CACHE")
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        result = download_file(
            url="https://huggingface.co/test/repo/resolve/"
                "0123456789abcdef0123456789abcdef01234567/legacy.bin",
            destination=dest,
            expected_hash=CONTENT_SHA256,
            progress=False,
        )
        self.assertEqual(Path(result).read_bytes(), CONTENT)


class TestMissingManifestEntry(ManifestTestBase):
    def test_unknown_artifact_id_raises(self):
        self.install_manifest([_synthetic_entry()])
        with self.assertRaises(MissingManifestEntryError):
            manifest_download("no-such-artifact", model_dir=self.temp_dir)

    def test_get_artifact_unknown_id_raises(self):
        self.install_manifest([_synthetic_entry()])
        with self.assertRaises(MissingManifestEntryError):
            get_artifact("no-such-artifact")


class TestUnresolvedArtifact(ManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_unresolved_without_opt_in_is_refused(self, mock_build_opener):
        entry = _synthetic_entry(
            status="unresolved", sha256=None, allow_unverified=False
        )
        self.install_manifest([entry])

        with self.assertRaises(ManifestError) as ctx:
            manifest_download("test-artifact", model_dir=self.temp_dir)

        self.assertIn("unresolved", str(ctx.exception))
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_unresolved_with_opt_in_downloads_without_hash(self, mock_build_opener):
        entry = _synthetic_entry(
            status="unresolved",
            sha256=None,
            allow_unverified=True,
            unverified_justification="no published digest",
        )
        self.install_manifest([entry])
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        result = manifest_download("test-artifact", model_dir=self.temp_dir)

        self.assertEqual(Path(result).read_bytes(), CONTENT)
        mock_build_opener.assert_called_once()


class TestUserProvidedModel(ManifestTestBase):
    @patch("modules.model_loader.download_file")
    def test_unknown_pair_downloads_without_hash(self, mock_download):
        self.install_manifest([_synthetic_entry()])
        mock_download.return_value = "/mock/path"

        user_url = "https://huggingface.co/someone/else/resolve/main/custom.bin"
        result = download_user_supplied("custom.bin", user_url, self.temp_dir)

        self.assertEqual(result, "/mock/path")
        _, kwargs = mock_download.call_args
        self.assertIsNone(kwargs["expected_hash"])
        self.assertEqual(kwargs["url"], user_url)

    @patch("modules.model_loader.download_file")
    def test_verified_pair_is_enforced(self, mock_download):
        self.install_manifest([_synthetic_entry()])
        mock_download.return_value = "/mock/path"

        entry = get_artifact("test-artifact")
        pinned = entry["source"]["url"]
        result = download_user_supplied("test_artifact.bin", pinned, self.temp_dir)

        self.assertEqual(result, "/mock/path")
        _, kwargs = mock_download.call_args
        self.assertEqual(kwargs["expected_hash"], CONTENT_SHA256)
        self.assertEqual(kwargs["cached_hash_mismatch"], "fail")
        self.assertEqual(kwargs["url"], pinned)

    @patch("modules.model_loader.download_file")
    def test_mutable_alias_pair_is_enforced(self, mock_download):
        self.install_manifest([_synthetic_entry()])
        mock_download.return_value = "/mock/path"

        entry = get_artifact("test-artifact")
        mutable = entry["source"]["mutable_url"]
        download_user_supplied("test_artifact.bin", mutable, self.temp_dir)

        _, kwargs = mock_download.call_args
        self.assertEqual(kwargs["url"], entry["source"]["url"])
        self.assertEqual(kwargs["expected_hash"], CONTENT_SHA256)


class TestMutableVersusImmutableRevision(ManifestTestBase):
    def test_verified_entry_with_mutable_url_is_rejected(self):
        entry = _synthetic_entry(
            url="https://huggingface.co/test/repo/resolve/main/test_artifact.bin"
        )
        entry["url_mutable"] = True
        with self.assertRaises(ManifestError) as ctx:
            self.install_manifest([entry])
        self.assertIn("immutable", str(ctx.exception).lower())

    def test_pinned_revision_url_accepted_and_aliases_match(self):
        self.install_manifest([_synthetic_entry()])
        entry = get_artifact("test-artifact")
        self.assertFalse(entry["url_mutable"])
        self.assertIn(
            "/0123456789abcdef0123456789abcdef01234567/",
            entry["source"]["url"],
        )
        pinned = match_file_name_url("test_artifact.bin", entry["source"]["url"])
        alias = match_file_name_url("test_artifact.bin", entry["source"]["mutable_url"])
        self.assertIsNotNone(pinned)
        self.assertIsNotNone(alias)
        self.assertIs(pinned, alias)


class TestGroundingDinoAuthorization(ManifestTestBase):
    def test_manifest_entry_carries_narrow_github_allowlist(self):
        real = load_manifest(refresh=True)
        previous_cache = model_manifest._manifest_cache
        try:
            model_manifest._manifest_cache = real
            entry = get_artifact("groundingdino-swint-ogc")
            self.assertEqual(
                entry["allowed_domains"],
                ["github.com", "release-assets.githubusercontent.com"],
            )
            self.assertEqual(entry["source"]["url"], GITHUB_URL)
            self.assertEqual(entry["status"], "unresolved")
        finally:
            model_manifest._manifest_cache = previous_cache

    @patch("urllib.request.build_opener")
    def test_authorized_github_destination_succeeds(self, mock_build_opener):
        _install_opener(mock_build_opener, [_mock_response(CONTENT)])

        result = load_file_from_url(
            url=GITHUB_URL,
            model_dir=self.temp_dir,
            file_name="groundingdino_swint_ogc.pth",
            allowed_domains=["github.com", "release-assets.githubusercontent.com"],
            progress=False,
        )
        self.assertEqual(Path(result).read_bytes(), CONTENT)

    @patch("urllib.request.build_opener")
    def test_redirect_to_release_asset_host_is_accepted(self, mock_build_opener):
        from urllib.request import Request

        from modules.model_loader import HardenedRedirectHandler

        handler = HardenedRedirectHandler(
            allowed_domains=["github.com", "release-assets.githubusercontent.com"],
        )
        req = Request(GITHUB_URL, method="HEAD")
        release_asset_url = (
            "https://release-assets.githubusercontent.com/"
            "github-production-release-asset/1/abc?sig=x"
        )
        new_req = handler.redirect_request(
            req, None, 302, "Found", {"Location": release_asset_url},
            release_asset_url,
        )
        self.assertIsNotNone(new_req)
        self.assertEqual(new_req.full_url, release_asset_url)

        _install_opener(mock_build_opener, [_mock_response(CONTENT)])
        result = load_file_from_url(
            url=GITHUB_URL,
            model_dir=self.temp_dir,
            file_name="groundingdino_swint_ogc.pth",
            allowed_domains=["github.com", "release-assets.githubusercontent.com"],
            progress=False,
        )
        self.assertEqual(Path(result).read_bytes(), CONTENT)

    @patch("urllib.request.build_opener")
    def test_redirect_to_unauthorized_host_is_refused(self, mock_build_opener):
        from urllib.request import Request

        from modules.model_loader import HardenedRedirectHandler

        handler = HardenedRedirectHandler(
            allowed_domains=["github.com", "release-assets.githubusercontent.com"],
        )
        req = Request(GITHUB_URL, method="HEAD")
        with self.assertRaises(ValueError) as ctx:
            handler.redirect_request(
                req, None, 302, "Found",
                {"Location": "https://evil.example.com/steal"},
                "https://evil.example.com/steal",
            )
        self.assertIn("untrusted host", str(ctx.exception).lower())
        mock_build_opener.assert_not_called()


class TestUnauthorizedGitHubDestination(ManifestTestBase):
    @patch("urllib.request.build_opener")
    def test_github_without_allowlist_is_refused(self, mock_build_opener):
        with self.assertRaises(ValueError) as ctx:
            load_file_from_url(
                url=GITHUB_URL,
                model_dir=self.temp_dir,
                file_name="groundingdino_swint_ogc.pth",
                progress=False,
            )
        self.assertIn("untrusted host", str(ctx.exception).lower())
        mock_build_opener.assert_not_called()

    @patch("urllib.request.build_opener")
    def test_unlisted_github_host_is_refused(self, mock_build_opener):
        with self.assertRaises(ValueError):
            load_file_from_url(
                url="https://evil.example.com/groundingdino_swint_ogc.pth",
                model_dir=self.temp_dir,
                file_name="groundingdino_swint_ogc.pth",
                allowed_domains=["github.com", "release-assets.githubusercontent.com"],
                progress=False,
            )
        mock_build_opener.assert_not_called()


class TestInterruptedDownloadAndRetry(ManifestTestBase):
    @patch("time.sleep", return_value=None)
    @patch("urllib.request.build_opener")
    def test_transient_failure_retries_and_verifies(self, mock_build_opener, _sleep):
        self.install_manifest([_synthetic_entry()])

        failing = MagicMock()
        failing.status = 200
        failing.headers = {"Content-Length": str(len(CONTENT))}
        failing.read.side_effect = socket.timeout("connection dropped")
        failing.__enter__.return_value = failing
        failing.__exit__.return_value = None

        _install_opener(mock_build_opener, [failing, _mock_response(CONTENT)])

        result = manifest_download("test-artifact", model_dir=self.temp_dir)

        self.assertEqual(Path(result).read_bytes(), CONTENT)
        self.assertEqual(mock_build_opener.return_value.open.call_count, 2)


class TestManifestSchemaCorrections(ManifestTestBase):
    """Post-review corrections L1 (entry types), L2 (allowed_domains),
    and L3 (file_name) — malformed data must raise ManifestError."""

    def _entry(self, **overrides):
        entry = _synthetic_entry()
        entry.update(overrides)
        return entry

    # --- L1: non-dictionary artifact entries -------------------------------
    def test_l1_non_dict_entries_rejected_with_manifest_error(self):
        for bad in ("just-a-string", 42, None, ["id"], True):
            with self.subTest(entry=bad):
                with self.assertRaises(ManifestError):
                    self.install_manifest([bad])

    def test_l1_non_dict_entry_after_valid_one_still_manifest_error(self):
        with self.assertRaises(ManifestError):
            self.install_manifest([self._entry(), 42])

    # --- L2: allowed_domains validation ------------------------------------
    def test_l2_malformed_allowed_domains_rejected(self):
        bad_values = [
            "github.com",                 # bare string instead of list
            "",                           # empty string
            [],                           # empty list
            [123],                        # non-string element
            [None],
            [""],                         # empty element
            ["https://github.com"],       # scheme
            ["github.com:443"],           # port
            ["github.com/path"],          # path
            ["*.github.com"],             # wildcard
            ["bad_underscore.example"],   # underscore
            ["-bad.example"],             # leading hyphen
            ["bad-.example"],             # trailing hyphen hyphen
            ["exam ple.com"],             # whitespace
            ["github.com."],              # trailing dot
            {"host": "github.com"},       # dict instead of list
        ]
        for bad in bad_values:
            with self.subTest(allowed_domains=bad):
                with self.assertRaises(ManifestError):
                    self.install_manifest([self._entry(allowed_domains=bad)])

    def test_l2_valid_allowed_domains_accepted(self):
        manifest = self.install_manifest([
            self._entry(
                allowed_domains=["github.com", "release-assets.githubusercontent.com"],
            ),
        ])
        self.assertEqual(
            manifest["artifacts"][0]["allowed_domains"],
            ["github.com", "release-assets.githubusercontent.com"],
        )

    def test_l2_entries_without_allowed_domains_still_accepted(self):
        manifest = self.install_manifest([self._entry()])
        self.assertNotIn("allowed_domains", manifest["artifacts"][0])

    # --- L3: file_name validation ------------------------------------------
    def test_l3_invalid_file_names_rejected(self):
        bad_names = [
            "",                            # empty
            "   ",                         # whitespace only
            " padded.pth",                 # leading whitespace
            "padded.pth ",                 # trailing whitespace
            ".",                           # traversal component
            "..",                          # traversal component
            "../evil.pth",                 # traversal
            "..\\evil.pth",                # traversal (backslash)
            "a/b.pth",                     # path separator
            "a\\b.pth",                    # path separator
            "/abs.pth",                    # absolute path
            "sub/dir/model.pth",           # nested path
            "C:evil.pth",                  # windows drive
            "evil\x00.pth",                # NUL
            "evil\n.pth",                  # control code
            "evil\t.pth",                  # control code
            "<v>.pth",                     # windows-invalid
            "a|b.pth",                     # windows-invalid
            "q?.pth",                      # windows-invalid
            123,                           # non-string
            None,                          # non-string
        ]
        for bad in bad_names:
            with self.subTest(file_name=bad):
                with self.assertRaises(ManifestError):
                    self.install_manifest([self._entry(file_name=bad)])

    def test_l3_valid_file_names_accepted(self):
        good_names = [
            "model.pth",
            "inpaint.fooocus.patch",
            "sd_xl_offset_example-lora_1.0.safetensors",
            "xl-to-v1_interposer-v4.0.safetensors",
            "wd-v1-4-moat-tagger-v2.csv",
        ]
        for good in good_names:
            with self.subTest(file_name=good):
                manifest = self.install_manifest([self._entry(file_name=good)])
                self.assertEqual(manifest["artifacts"][0]["file_name"], good)

    def test_l3_real_manifest_file_names_still_valid(self):
        manifest = load_manifest(refresh=True)
        # 39 since P1-B retired the orphaned deit-base-patch16 entry
        # (its only call site, blip_pretrain.py, was deleted).
        self.assertEqual(len(manifest["artifacts"]), 39)


class TestRealManifestAndWiring(unittest.TestCase):
    """Offline checks against the real manifest and the wired call sites."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest(refresh=True)
        cls.repo_root = Path(__file__).resolve().parent.parent

    def test_manifest_entry_counts(self):
        artifacts = self.manifest["artifacts"]
        # 39 since P1-B retired the orphaned deit-base-patch16 entry
        # (its only call site, blip_pretrain.py, was deleted).
        self.assertEqual(len(artifacts), 39)
        verified = [a for a in artifacts if a["status"] == "verified"]
        unresolved = [a for a in artifacts if a["status"] == "unresolved"]
        self.assertEqual(len(verified), 26)
        self.assertEqual(len(unresolved), 13)
        self.assertEqual(
            self.manifest["user_supplied_categories"],
            [
                "checkpoint_downloads",
                "embeddings_downloads",
                "lora_downloads",
                "vae_downloads",
            ],
        )

    def test_verified_entries_have_trusted_hashes_and_pinned_urls(self):
        for entry in self.manifest["artifacts"]:
            if entry["status"] != "verified":
                continue
            sha = entry["sha256"]
            self.assertRegex(sha, r"^[0-9a-f]{64}$", entry["id"])
            self.assertFalse(entry["url_mutable"], entry["id"])
            url = entry["source"]["url"]
            self.assertTrue(url.startswith("https://"), entry["id"])
            self.assertNotIn("/resolve/main/", url, entry["id"])
            self.assertTrue(entry["evidence"], entry["id"])

    def test_unresolved_entries_are_not_promoted(self):
        for entry in self.manifest["artifacts"]:
            if entry["status"] != "unresolved":
                continue
            self.assertFalse(entry.get("allow_unverified") and entry.get("sha256"),
                             entry["id"])
            if entry.get("allow_unverified"):
                self.assertTrue(entry.get("unverified_justification"), entry["id"])

    def test_no_hardcoded_hf_resolve_urls_anywhere_in_python_tree(self):
        import re

        pattern = re.compile(r"https?://huggingface\.co/\S*/resolve/")
        for path in (self.repo_root).rglob("*.py"):
            rel = path.relative_to(self.repo_root)
            parts = rel.parts
            if ".git" in parts or "tests" in parts:
                continue
            if path.name == "model_manifest.py":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            match = pattern.search(text)
            self.assertIsNone(
                match,
                f"hardcoded HF resolve URL in {rel}: {match.group(0) if match else ''}",
            )

    def test_no_mutable_model_url_literals_in_wired_modules(self):
        for relative in (
            "modules/config.py",
            "launch.py",
            "extras/interrogate.py",
            "extras/GroundingDINO/util/inference.py",
        ):
            text = (self.repo_root / relative).read_text(encoding="utf-8")
            self.assertNotIn(
                "huggingface.co/lllyasviel",
                text.replace(" ", ""),
                f"mutable HF URL literal remains in {relative}",
            )
            self.assertNotIn(
                "huggingface.co/mashb1t",
                text.replace(" ", ""),
                f"mutable HF URL literal remains in {relative}",
            )

    def test_every_wired_artifact_id_exists_in_manifest(self):
        sources = {
            "modules/config.py": self._manifest_download_ids("modules/config.py"),
            "launch.py": self._manifest_download_ids("launch.py"),
            "extras/interrogate.py": self._manifest_download_ids(
                "extras/interrogate.py"
            ),
            "extras/wd14tagger.py": self._manifest_download_ids(
                "extras/wd14tagger.py"
            ),
            "extras/GroundingDINO/util/inference.py": self._manifest_download_ids(
                "extras/GroundingDINO/util/inference.py"
            ),
        }
        known = {a["id"] for a in self.manifest["artifacts"]}
        for relative, ids in sources.items():
            self.assertTrue(ids, f"no manifest downloads found in {relative}")
            for artifact_id in ids:
                self.assertIn(artifact_id, known, f"{relative}: {artifact_id}")

    def _manifest_download_ids(self, relative):
        import re

        text = (self.repo_root / relative).read_text(encoding="utf-8")
        return re.findall(r'manifest_download\(\s*"([^"]+)"', text)

    def test_launch_reexports_hardened_loader(self):
        sys.path.insert(0, str(self.repo_root))
        import launch

        self.assertIs(launch.load_file_from_url, load_file_from_url)


if __name__ == "__main__":
    unittest.main()
