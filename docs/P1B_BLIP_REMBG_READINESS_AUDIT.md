# Stage 7 P1-B Implementation-Readiness Audit (BLIP/DeiT + rembg)

**Status: AUDIT AND DESIGN ONLY — no implementation, awaiting approval.**
No application code, dependency pin, notebook, or model weight was changed or
downloaded (network use: GitHub **metadata** only for asset sizes; one rembg
**source wheel** inspected in a scratch dir outside the repo).

| Field | Value |
|---|---|
| Repository | WURAlex/Fooocus-Modern |
| Approved integration baseline | `182a863006a967ab0bdc5a202279c0397d085788` (`origin/modern-platform`, post-P1-A merge) |
| Branch / worktree | `feature/stage7-blip-rembg` in `/home/alex/Fooocus-Modern-stage7-p1b` (changes uncommitted) |
| Date | 2026-10-12 |
| Scope | Tasks 2–4 of the P1-B brief: BLIP/DeiT dependency analysis, rembg integration analysis, security design |
| Prior art | `docs/LEGACY_DOWNLOADER_MIGRATION_AUDIT.md` (P1 audit + P1-A record §9), `docs/MODEL_INTEGRITY_AUDIT.md` (P0), `models/manifest.json` |

Pinned environment facts: `rembg==2.0.57` (`requirements_versions.txt:21`),
`onnxruntime==1.18.1` (`:16`), `torch==2.1.0` (`launch.py:61`), `pooch`
unpinned (transitive via rembg). rembg source facts below were verified
against the published `rembg-2.0.57-py3-none-any.whl` (scratch inspection).

---

## 0. Summary

| Component | Live? | Download mechanism today | P1-B recommendation |
|---|---|---|---|
| `extras/BLIP/models/blip_pretrain.py` | **Dead — zero importers** | `torch.hub.load_state_dict_from_url` (DeiT, prefix-only `check_hash`) at `:41-43`, full-pickle load | **Delete the module** (lowest risk); retire its `deit-base-patch16` manifest entry |
| `extras/BLIP/models/blip.py` (+ `vit.py`, `med.py`, tokenizer) | **Live** via `extras/interrogate.py:10` (`blip_decoder`) | None at runtime: verified manifest download `blip-caption-base` (SHA-256 pinned) then **local** `torch.load(weights_only=True)` | Keep; optional follow-up: remove dead URL branch in `load_checkpoint` (separate approval) |
| rembg (7 selectable models) | **Live** via `extras/inpaint_mask.py:8,64` | Internal `pooch.retrieve(url, "md5:<hash>")` into `$U2NET_HOME`/`~/.u2net`, md5 re-verified on every `new_session` | **Pre-seed via the hardened downloader**, preserving pooch's md5 verification; no third-party modification; no checksum disabling |

---

## 1. Task 2 — BLIP/DeiT dependency analysis

### 1.1 The dead module

`extras/BLIP/models/blip_pretrain.py` defines `BLIP_Pretrain` /
`blip_pretrain()`. Inside `__init__` (vit='base' branch, `:41-43`):

```python
checkpoint = torch.hub.load_state_dict_from_url(
    url="https://dl.fbaipublicfiles.com/deit/deit_base_patch16_224-b5f2ef4d.pth",
    map_location="cpu", check_hash=True)
state_dict = checkpoint["model"]
msg = self.visual_encoder.load_state_dict(state_dict, strict=False)
```

Direct imports: `extras.BLIP.models.med` (BertConfig/BertModel/BertLMHeadModel),
`extras.BLIP.models.blip` (`create_vit`, `init_tokenizer`, `load_checkpoint`),
`transformers`, `torch`. The `vit='large'` branch additionally imports
`timm.models.helpers.load_custom_pretrained` (also dead).

### 1.2 Reference scan — zero consumers

| Search surface | Result |
|---|---|
| Python importers of `blip_pretrain` / `BLIP_Pretrain` (app, tests, scripts) | **ZERO** (static grep; no dynamic `importlib`/`__import__` references either) |
| Notebooks (`.ipynb`), shell scripts | **ZERO** |
| Documentation | `docs/MODERNIZATION_ROADMAP.md` + `docs/LEGACY_DOWNLOADER_MIGRATION_AUDIT.md` (status text only); `update_log.md:198` historical note about a *tokenizer* fix, unrelated |
| Manifest `call_sites` | `models/manifest.json:736` — `extras/BLIP/models/blip_pretrain.py:41` (the dead DeiT entry only) |

`extras/BLIP/` has **no `__init__.py`** (namespace package) — deleting one
module cannot break imports of its siblings.

### 1.3 What is actually live in the BLIP package

`extras/interrogate.py` (used by `webui.py:1069-1070` "describe" flow):

- `:10` `from extras.BLIP.models.blip import blip_decoder`
- `:28-34` downloads **`blip-caption-base` through the hardened manifest
  path** (`modules.model_manifest.download`, status **verified**, sha256
  `96ac8749…174086`, 896,081,425 bytes), then `blip_decoder(pretrained=<local
  file>, …)` → `blip.py:216-230 load_checkpoint`:

  - `is_url()` false for a local path → **no `timm.download_cached_file`
    call**; `torch.load(..., weights_only=True)` on the local file only.
  - The URL branch (`blip.py:217-218`, `download_cached_file(check_hash=False)`)
    is **dead in the live flow** but remains a latent bypass if any future
    caller passed a URL.

Reachability from `blip.py`: `vit.py` (VisionTransformer; timm imports, no
network at import), `med.py` (transformers modeling, no network at import),
local `BertTokenizer.from_pretrained(<repo tokenizer dir>)` — no download
(pre-fixed per `update_log.md:198`). Dead siblings with zero importers:
`blip_nlvr.py`, `blip_retrieval.py`, `blip_itm.py`, `blip_vqa.py`,
`nlvr_encoder.py` (out of P1-B scope; deletion optional later).

### 1.4 Security implications of the current state

- DeiT fetch: HTTPS to `dl.fbaipublicfiles.com`, `check_hash=True` verifies
  only the **8-hex-char sha256 prefix** embedded in the filename
  (`b5f2ef4d`), at download time only; cached file never re-checked; result
  loaded into the model without `weights_only` at that site (raw
  `load_state_dict_from_url` returns a dict via `torch.load(weights_only=False)`
  semantics on torch 2.1.0). **Currently unexploitable: zero callers.**
- Live BLIP captioning is already hardened (verified SHA-256 via P0).

### 1.5 Options compared

| | Option A — **remove** `blip_pretrain.py` | Option B — retain + migrate |
|---|---|---|
| Code delta | 1 file deleted (+ manifest entry retirement) | Rewrite download to manifest routing; add DeiT full-hash tier (needs one-time ~340 MB approval-gated digest); `weights_only`/deserialization review; tests for a class nothing uses |
| Risk | Effectively zero (zero importers; namespace package) | Non-zero ongoing surface for unused functionality |
| Functional impact | None (no supported feature references it) | None either — but retains a second ViT-initialization path nobody calls |
| Precedent | Matches P1-A k-diffusion dead-helper removal | No precedent; P0/P1-A removed rather than migrated dead code |

### 1.6 Recommendation (lowest risk)

**Option A: delete `extras/BLIP/models/blip_pretrain.py`** and retire the
orphaned `deit-base-patch16` manifest entry (remove the entry — it exists only
to describe that dead call site, has `sha256: null`, `allow_unverified:
false`, and becomes unreachable; alternatively retain with
`call_sites: []` + note — deletion is cleaner and is the recommendation).
Optionally (separate approval, can be deferred): harden
`blip.py:load_checkpoint` to refuse URLs (`is_url` → `raise`), removing the
latent `download_cached_file(check_hash=False)` path and the `timm.models.hub`
import from the live module.

---

## 2. Task 3 — rembg integration analysis

### 2.1 Pin and mechanism (source-backed, wheel 2.0.57)

- `requirements_versions.txt:21` `rembg==2.0.57`; `pooch` is an **unpinned**
  transitive dependency.
- App call chain: `webui.py:302/319` and `modules/async_worker.py:3/1372` →
  `extras/inpaint_mask.py:64 new_session(mask_model, **extras)` →
  `rembg/session_factory.py` (name lookup; default `U2netSession`) →
  `rembg/sessions/base.py` `BaseSession.__init__` →
  `ort.InferenceSession(str(cls.download_models()), …)` → per-model
  `pooch.retrieve(<url>, "md5:<hash>", fname, path=cls.u2net_home())`.
- `pooch.retrieve` semantics: file absent → download + md5 verify; file
  present + md5 match → **no network, return path**; file present + md5
  mismatch → **raises** (fail-closed). `MODEL_CHECKSUM_DISABLED` set → hash
  `None` → existing file accepted blindly (`base.py checksum_disabled`).

### 2.2 Supported cache override — verified

`rembg/sessions/base.py`:

```python
os.path.expanduser(os.getenv("U2NET_HOME",
    os.path.join(os.getenv("XDG_DATA_HOME", "~"), ".u2net")))
```

`U2NET_HOME` is honored verbatim; default `~/.u2net` (via `XDG_DATA_HOME`
default `"~"`). Pre-seeding must replicate this exact computation.

### 2.3 The seven model artifacts (flags ↔ rembg ↔ manifest)

`modules/flags.py:87` selects 8 masks; `sam` is routed to
GroundingDINO+segment-anything (`inpaint_mask.py:66+`), leaving **7 rembg
models**. All URLs are immutable `v0.0.0` GitHub release assets; md5 values
are pinned in the rembg wheel source (publisher-attested):

| `flags` name | File in `$U2NET_HOME` | URL (immutable tag) | md5 (wheel-pinned) | Size (release API metadata) | Manifest entry |
|---|---|---|---|---|---|
| `u2net` | `u2net.onnx` | `…/v0.0.0/u2net.onnx` | `60024c5c889badc19c04ad937298a77b` | 176.0 MB | `rembg-u2net` |
| `u2netp` | `u2netp.onnx` | `…/v0.0.0/u2netp.onnx` | `8e83ca70e441ab06c318d82300c84806` | 4.6 MB | `rembg-u2netp` |
| `u2net_human_seg` | `u2net_human_seg.onnx` | `…/v0.0.0/u2net_human_seg.onnx` | `c09ddc2e0104f800e3e1bb4652583d1f` | 176.0 MB | `rembg-u2net-human-seg` |
| `u2net_cloth_seg` | `u2net_cloth_seg.onnx` | `…/v0.0.0/u2net_cloth_seg.onnx` | `2434d1f3cb744e0e49386c906e5a08bb` | 176.2 MB | `rembg-u2net-cloth-seg` |
| `silueta` | `silueta.onnx` | `…/v0.0.0/silueta.onnx` | `55e59e0d8062d2f5d013f4725ee84782` | 44.2 MB | `rembg-silueta` |
| `isnet-general-use` | `isnet-general-use.onnx` | `…/v0.0.0/isnet-general-use.onnx` | `fc16ebd8b0c10d971d3513d564d01e29` | 178.6 MB | `rembg-isnet-general-use` |
| `isnet-anime` | `isnet-anime.onnx` | `…/v0.0.0/isnet-anime.onnx` | `6f184e756bb3bd901c8849220a83e38e` | 176.1 MB | `rembg-isnet-anime` |

Base URL prefix: `https://github.com/danielgatis/rembg/releases/download/v0.0.0/`.
Total ≈ **932 MB** (Tier B sha256 upgrade would re-download all seven;
metadata sizes only today). All 7 manifest entries currently
`status: unresolved`, `sha256/size_bytes: null`, **`source.url: null`**
(placeholder — "URL and hash to be filled from the pinned rembg wheel",
`models/manifest.json` rembg notes).

Edge case (out of the 7): `inpaint_mask.py:61` `sam_options` defaults to the
**class** `SAMOptions` (truthy), so `mask_model='sam'` normally bypasses
rembg; only an explicit `sam_options=None` would hit rembg's own `SamSession`
(multi-file pooch downloads). Not used by `webui.py`/`async_worker.py`
callers; documented for completeness. rembg also ships `u2net_custom`
(no URL; unused).

### 2.4 Session creation and model selection

- `new_session(name)` linear-scans `sessions_class` for `sc.name() == name`
  (`session_factory.py`); unknown names fall back to `U2netSession` (**note**:
  a typo would download u2net, not error — flag values are closed lists, so
  low risk).
- Every `new_session` re-runs `download_models` → `pooch.retrieve` →
  **md5 re-verification of the cached file on every use** (this property must
  be preserved).
- `remove(image, session=…)` (`extras/inpaint_mask.py:63-67`) is the only
  production consumer; cloth category passed as `cc` kwarg.

### 2.5 Pre-seeding design (offline-testable, third-party untouched)

**Design D1 — app-side pre-seed, pooch kept as the verifier:**

1. **Manifest completion (schema extension, approval-gated):** fill
   `source.url` for the 7 entries with the immutable `v0.0.0` URLs above;
   add an optional `md5` field mirroring the wheel-pinned values
   (`sha256` stays `null`, `status` stays `unresolved`,
   `size_bytes` filled from release-API metadata). Extend
   `modules/model_manifest.download` so that when `sha256` is absent and
   `md5` is present it calls the hardened loader with
   `expected_hash=<md5>, hash_algorithm="md5"`. The loader already supports
   `hash_algorithm` — no downloader change required.
2. **Pre-seed helper** (e.g. `extras/inpaint_mask.py::ensure_rembg_model` or
   a small `modules/rembg_preseed.py`): resolve the target directory with the
   **exact** `u2net_home()` semantics above (honor `U2NET_HOME`, never set
   it), then `model_manifest.download(rembg-<slug>, model_dir=<home>,
   file_name="<name>.onnx")`. Hardened loader provides: allowlist (GitHub
   hosts via per-artifact `allowed_domains`, same pattern as P1-A), TLS/SSRF/
   DNS pinning, redirect re-validation, atomic temp+replace, `_safe_destination`
   symlink/traversal guards, and md5 verification of any existing cached file
   (`cached_hash_mismatch="fail"` — a substituted cache fails closed and
   pooch would refuse it anyway).
3. **Interception point:** call the helper immediately before
   `new_session(mask_model, …)` in `generate_mask_from_image`
   (`extras/inpaint_mask.py:61-67`), wrapped so that a hardened-path failure
   falls back to today's behavior (pooch performs the download itself) —
   availability-preserving; a strict fail-closed variant is an optional
   follow-up decision.
4. **Verification is never weakened:** rembg/pooch still md5-checks the file
   at every `new_session`; `MODEL_CHECKSUM_DISABLED` is never set (scan test
   bans it); no monkey-patching of `pooch`, `rembg`, or `urllib`; no
   dependency code modified or upgraded.

Offline-testability: all tests use a tmp `U2NET_HOME`, synthetic files, and
`patch("urllib.request.build_opener")` exactly like
`tests/test_p1_legacy_migration.py`; md5 values are recomputed locally from
synthetic content when a hash-path test needs a "valid" file; real weights
never downloaded.

---

## 3. Task 4 — Security design evaluation

| Dimension | Assessment |
|---|---|
| **Trusted model provenance** | rembg assets: immutable GitHub release tag `v0.0.0` + md5 pinned inside the publisher's version-pinned wheel source (two independent, version-locked attestations). Same trust tier as P1-A facexlib Tier 2, but **with** a checksum (md5) instead of none. BLIP caption model: already SHA-256 verified (P0). DeiT: dies with `blip_pretrain.py`. |
| **Cache integrity & symlinks** | Hardened loader: `_safe_destination` refuses paths/symlinks escaping the model dir (`model_loader.py:692-714`); existing cache reused only after md5 verification (now supplied); pooch re-verifies md5 independently at session time. Residual: a same-dir symlink to attacker content inside `$U2NET_HOME` is content-checked by md5 (must match or fail). |
| **Atomic downloads & failure recovery** | Hardened loader: `.download` temp in same dir + `os.replace`, retries, deadline, lock files; failure leaves no partial destination (P0/P1-A tested). pooch has its own download protocol (unchanged fallback). |
| **SHA-256 availability** | Not available metadata-only today (GitHub release assets publish no digest). Tier B: one-time download of ≈932 MB (approval-gated, forbidden under current restrictions) to record per-file sha256; then entries can become `verified` and md5 demoted to defense-in-depth. |
| **MD5 limitations** | Collision-prone; not identity-grade. Accepted here as a **publisher-attested floor + pinned URL + hardened transport**, with documented upgrade path. Must be described honestly in manifest notes (no "SHA-256 verified" language). |
| **Environment variables** | `U2NET_HOME`: honored, replicated exactly, never set by the app. `XDG_DATA_HOME`: same. `MODEL_CHECKSUM_DISABLED`: **banned** by proposed scan test. `FOOOCUS_ALLOWED_DOWNLOAD_HOSTS` / proxy envs: unchanged P0 semantics. |
| **Google Colab** | Default `~/.u2net` is writable on Colab; pre-seed uses the same path; no notebook edits; `U2NET_HOME` pre-seeding by users continues to work. |
| **Offline testing** | Mirror P1-A harness (stubbed torch/cv2 where needed, patched opener, tmp dirs, synthetic files). CI-safe: `packaging` only; pooch/rembg/onnxruntime are **not** imported by tests (static/source checks instead). |

### 3.1 Behavioral changes requiring separate approval

1. **Delete** `extras/BLIP/models/blip_pretrain.py` and the
   `deit-base-patch16` manifest entry (dead-code removal; zero functional
   impact).
2. **Manifest schema extension:** optional `md5` field + `hash_algorithm`
   support in `modules/model_manifest.download`; fill the 7 rembg entries'
   `source.url`/`md5`/`size_bytes`.
3. **Pre-seed interception** in `generate_mask_from_image` (first-use network
   path moves from pooch to the hardened downloader; fallback to pooch on
   hardened failure keeps availability).
4. Optional hardening: `blip.py load_checkpoint` local-only (refuse URLs).
5. Explicitly **not** proposed: overriding `U2NET_HOME` to a repo-local
   directory (changes user-visible cache location); disabling/monkey-patching
   pooch; upgrading rembg/pooch/onnxruntime.

---

## 4. Recommended implementation order (upon approval)

1. **BLIP deletion slice:** delete `blip_pretrain.py`, remove
   `deit-base-patch16` entry, add repo-scan tests (no
   `load_state_dict_from_url` outside `modules/model_loader.py` docs; no
   `blip_pretrain` references). Smallest review unit.
2. **Manifest rembg completion + md5 schema:** fill 7 entries, add optional
   `md5`, extend `model_manifest.download`, unit tests with synthetic md5s.
3. **Pre-seed helper + interception + scan tests**
   (`MODEL_CHECKSUM_DISABLED` ban, flag↔manifest coverage: every
   `flags.inpaint_mask_models` entry except `sam` has a complete `rembg-*`
   entry).
4. **(Approval-gated, later) Tier B sha256** rehash of the 7 files.
5. Optional: `blip.py` local-only `load_checkpoint`.

## 5. Test requirements

- `tests/test_p1b_blip_rembg.py` (new), CI-safe (no rembg/pooch/onnxruntime
  imports):
  - static: `blip_pretrain.py` absent; zero references; `load_state_dict_from_url`
    absent from app code; `MODEL_CHECKSUM_DISABLED` absent from repo source;
    `inpaint_mask.py` still imports `new_session`/`remove` (compat).
  - manifest: 7 rembg entries have immutable `source.url`, 32-hex `md5`,
    `size_bytes > 0`, `sha256: null`, `status: unresolved`; flag coverage
    mapping incl. `sam` exemption.
  - behavior (patched `build_opener`, tmp `U2NET_HOME`): pre-seed writes
    `<name>.onnx` into the resolved home; `U2NET_HOME`/`XDG_DATA_HOME`
    honored; missing → download attempted; valid md5 cache → no network;
    wrong-md5 cache → fail closed; symlink escape refused.
  - P1-A/P0 suites must remain green unchanged (202 tests baseline).

## 6. Security acceptance criteria

1. No third-party file modified; no dependency upgraded; no checksum
   verification disabled (`MODEL_CHECKSUM_DISABLED` banned by test).
2. All 7 rembg models fetched (when fetched) through the hardened downloader:
   HTTPS-only, allowlisted GitHub hosts per-artifact, redirect re-validation,
   DNS/IP pinning, atomic replace, md5 verified at download **and** at every
   `new_session` (pooch, unchanged).
3. `sha256: null` artifacts are never described as SHA-256-verified in
   runtime output or docs; md5 tier documented honestly.
4. Dead BLIP/DeiT path removed with zero references; live BLIP captioning
   (`blip-caption-base`, verified) unaffected.
5. Full offline suite green on Python 3.10/3.12/3.14; actionlint clean; no
   notebooks touched; Colab default paths unchanged.

## 7. Restrictions honored

Audit and design only — the only file changes are this document and a
roadmap status note (both uncommitted, in the new
`/home/alex/Fooocus-Modern-stage7-p1b` worktree). No application code,
dependencies, or notebooks modified; no model weights downloaded (GitHub
release **metadata** and one rembg **source wheel** only, scratch dirs
outside the repo); no commit/push/merge/tag; existing worktrees and
`origin/main` untouched.

## 8. Stop point

Stopping here per the task brief. **Implementation of §4 items 1–3 (and
approval-gated item 4/5) requires explicit approval.**

---

## 9. Implementation record (approved items 1–3, 2026-10-13)

Implemented on `feature/stage7-blip-rembg` (worktree
`/home/alex/Fooocus-Modern-stage7-p1b`, baseline `182a863`) under explicit
approval for items 1–3. Uncommitted by design; full diff listed in the
handover report.

### 9.1 What changed

| File | Change |
|---|---|
| `extras/BLIP/models/blip_pretrain.py` | **Deleted** (zero importers; DeiT `torch.hub` prefix-only path removed from the tree) |
| `models/manifest.json` | `deit-base-patch16` entry removed (provenance retained in `docs/MODEL_INTEGRITY_AUDIT.md:103,183` and §1 above); 7 `rembg-*` entries completed: immutable `source.url` (`v0.0.0` release assets), `md5` pins, exact `size_bytes`, `allowed_domains` (`github.com`, `release-assets.githubusercontent.com`), `url_mutable: false`; `manifest_version` → `2026.10.13.1`; policy text documents the md5 tier |
| `modules/model_manifest.py` | Optional `md5` schema field (32-hex); ambiguity rules (verified+md5 rejected; sha256+md5 rejected; md5+`allow_unverified` rejected); `download()` uses `hash_algorithm="md5"` and `cached_hash_mismatch="fail"` for md5-pinned entries |
| `modules/rembg_preseed.py` | **New**: `REMBG_MODEL_ARTIFACTS` map, `resolve_u2net_home()` (exact rembg semantics), `ensure_rembg_model()` pre-seed helper (stdlib-only) |
| `extras/inpaint_mask.py` | `ensure_rembg_model(mask_model)` called immediately before `new_session()` on the rembg path; SAM/GroundingDINO path untouched |
| `tests/test_p1b_blip_rembg.py` | **New**: 46 offline regression tests (§9.5) |
| `tests/test_model_integrity.py` | Artifact-count assertions updated 40→39, unresolved 14→13 (deit retirement) |
| `.github/workflows/security-ci.yml` | Suite line adds `tests.test_p1b_blip_rembg` |
| `docs/MODERNIZATION_ROADMAP.md` | P1-B status updated |

Not touched: `modules/model_loader.py` (downloader protections byte-identical),
all other dependencies, notebooks, `blip.py`/`vit.py`/`med.py`/
`interrogate.py` (active captioning), rembg/pooch third-party code.

### 9.2 Supported models

The seven rembg models in `flags.inpaint_mask_models` minus `sam`:
`u2net`, `u2netp`, `u2net_human_seg`, `u2net_cloth_seg`, `silueta`,
`isnet-general-use`, `isnet-anime`. Each maps 1:1 to a manifest
`rembg-*` entry whose `file_name` is exactly pooch's `f"{name}.onnx"`
convention, so the pre-seeded file is the file `new_session()` verifies.
`sam` (rembg SamSession / GroundingDINO+SAM UI path) is **not**
pre-seeded: it has no manifest entry and keeps its existing behavior.
Any other rembg-internal name (`u2net_custom`, …) is a passthrough
(`ensure_rembg_model` returns `None`) — not pre-seeded, not failed.

### 9.3 How cache pre-seeding works

1. `generate_mask_from_image` calls `ensure_rembg_model(mask_model)`
   before `new_session()` (rembg path only).
2. For a recognized model, the helper resolves rembg's cache directory
   with `BaseSession.u2net_home()` semantics (`U2NET_HOME` →
   `XDG_DATA_HOME/.u2net` → `~/.u2net`, `expanduser` applied), creates
   it if missing, and calls `model_manifest.download(artifact_id,
   model_dir=home)`.
3. The hardened downloader fetches over HTTPS with per-artifact GitHub
   domain allowlist, redirect re-validation, DNS/IP pinning, size/deadline
   limits, temporary file + atomic replace, and **md5 verification**
   (`hash_algorithm="md5"` from the manifest pin). Cached files are
   re-verified against the same md5; mismatch fails closed
   (`cached_hash_mismatch="fail"` — the corrupt file is left in place for
   forensic removal, never silently replaced).
4. `new_session()` then runs unchanged: pooch re-verifies the same md5
   before handing the session its weights. Integrity is enforced twice;
   nothing in rembg/pooch is patched, skipped, or disabled
   (`MODEL_CHECKSUM_DISABLED` is banned by repo-scan test).

### 9.4 Failure, recovery, and MD5 limitations

- **Fail closed:** any download, hash-verification, DNS, or filesystem
  error for a recognized model propagates out of `ensure_rembg_model`;
  `generate_mask_from_image` surfaces it to the worker/UI. There is **no**
  fallback that hands a recognized model to rembg's internal downloader.
- **Recovery:** a corrupted cache file raises `CachedFileIntegrityError`
  with the path; the operator deletes the named file and retries. A
  refused symlink/traversal destination likewise leaves everything intact.
- **MD5 limitations (be honest):** md5 is a *weak* hash — collision
  attacks are practical. The pins here are publisher-attested (baked into
  the rembg 2.0.57 wheel source, which is itself version-pinned in
  `requirements_versions.txt`), so they guard against accidental
  corruption and non-targeted tampering of the pinned release assets, but
  they are **not** a substitute for SHA-256 provenance. md5-pinned
  entries stay `status: unresolved` and are never reported as
  SHA-256-verified. The loader's dual check (hardened downloader + pooch)
  raises the cost of a targeted swap but does not make md5
  collision-resistant.
- **Remaining SHA-256 provenance (Tier B, approval-gated, not done):**
  re-download/re-hash all 7 files (~932 MB) with an independent SHA-256
  computation and upgrade the manifest entries to `status: verified`
  (then the md5 field must be dropped — mixed tiers are rejected by
  schema). Deferred per restriction.
- **Compatibility limitations:** users who pre-populated `$U2NET_HOME`
  with files whose bytes differ from the pinned release assets (e.g.
  self-converted ONNX) will now get a fail-closed integrity error instead
  of silent acceptance — intentional. `MODEL_CHECKSUM_DISABLED` (a rembg
  env escape hatch) remains usable by rembg's own pooch path if a user
  sets it, but our downloader never honors it and the pre-seed md5 check
  is independent of it. Colab default paths (`~/.u2net`) are unchanged.

### 9.5 Test results

`tests/test_p1b_blip_rembg.py`: **46 tests**, offline (mocked opener,
synthetic manifests, temp dirs — zero network, zero weight bytes).

| Area | Tests |
|---|---|
| 7 model mappings (flags ↔ preseed ↔ manifest) | 3 |
| Manifest md5 schema + ambiguity rules | 10 |
| MD5 download enforcement / mismatch / cache reuse / corruption / sha256-unchanged | 5 |
| Symlink + traversal rejection | 4 |
| `U2NET_HOME`/`XDG_DATA_HOME` precedence | 4 |
| Model-selection compatibility | 3 |
| Pre-seed integration (download, reuse, corruption, failure cleanup, no-fallback, missing-entry) | 6 |
| BLIP removal + active captioning preserved | 7 |
| Guardrails (no checksum-disabling, no monkey-patching, import hygiene, pinned metadata) | 4 |

Full suite: **248/248 OK** on Python 3.10, 3.12, and 3.14 (202 baseline +
46 new; the two count assertions in `test_model_integrity.py` were updated
40→39 for the deit retirement). `actionlint` clean; `git diff --check`
clean; `modules/model_loader.py` untouched (downloader protections
unchanged).
