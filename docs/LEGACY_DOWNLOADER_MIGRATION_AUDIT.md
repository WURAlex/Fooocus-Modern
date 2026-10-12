# Legacy Downloader Migration Audit (Stage 7 P1)

**Status: AUDIT + DESIGN DONE; P1-A IMPLEMENTED (uncommitted, awaiting
review) — BLIP/DeiT and rembg migrations NOT started.**

P1-A (this session, 2026-10-12): facexlib routed through the hardened
downloader (§9), the dead k-diffusion `download_file` helper deleted,
`tests/test_p1_legacy_migration.py` added (33 tests), Security CI extended.
No dependency was upgraded, no notebook was touched, no BLIP/DeiT or rembg
code was modified, and no model weight was downloaded (network probes were
metadata-only). The earlier audit-only claim below is retained in §7/§8
history form; current restrictions are listed in §9.4.

| Field | Value |
|---|---|
| Repository | WURAlex/Fooocus-Modern |
| Approved integration baseline | `9df2d33e2fea2e74e9cbea9d3d08afbe699d6ccf` (`origin/modern-platform`) |
| Branch / worktree | `feature/stage7-legacy-downloaders` in `/home/alex/Fooocus-Modern-stage7-p1` (changes uncommitted) |
| Date | 2026-10-12 |
| Scope | Tasks 2–5 of the P1 audit brief: facexlib, BLIP/DeiT, rembg, dead raw-`urlopen` helper; migration plan in §6 |
| Prior art | `docs/MODEL_INTEGRITY_AUDIT.md` (P0), `models/manifest.json` (40 entries) |

Pinned environment facts used throughout: `torch==2.1.0` (default
`TORCH_COMMAND`, `launch.py:61`), `rembg==2.0.57` (`requirements_versions.txt:21`),
`pooch` is an **unpinned** transitive dependency of rembg.

---

## 0. Summary

| # | Component | Live download sites | Mechanism | Hash verification today | Migration possible without downloading weights? |
|---|---|---|---|---|---|
| 1 | facexlib | 4 URL literals (`extras/facexlib/{detection,parsing}/__init__.py`), funnelled through `extras/facexlib/utils/misc.py:59` | `torch.hub.download_url_to_file`, `hash_prefix=None` hardcoded at `misc.py:77` | **None** (existence check only) | **Yes** for routing (provenance pinning in two tiers, see §1.7/§6); **full SHA-256 pinning requires one-time digest work** — GitHub publishes no digest (`digest: null` verified 2026-10-12) |
| 2 | BLIP/DeiT | 1 site (`extras/BLIP/models/blip_pretrain.py:41`) — **dead code, zero callers** | `torch.hub.load_state_dict_from_url(check_hash=True)` | Partial: filename-embedded sha256 **prefix** `b5f2ef4d` at download time only; cached file never re-checked; `torch.load(weights_only=False)` full pickle | **Yes** — prefix pin already exists in the manifest (`sha256_prefix`); full hash optional later (one-time ~340 MB download) |
| 3 | rembg | 7 selectable models, internal to the installed wheel | `pooch.retrieve(url, "md5:<hash>")` into `$U2NET_HOME`/`~/.u2net` | pooch **md5** (pinned in the published wheel) verified on every `new_session` | **Yes** — pre-seed the pooch cache via the hardened downloader; sha256 rehash of the family is a separate, download-requiring follow-up |
| 4 | k_diffusion helper | 0 (dead function) | raw `urllib.request.urlopen` (`ldm_patched/k_diffusion/utils.py:37-48`) | Optional `digest` parameter, never used (no callers) | **Yes** — pure dead-code deletion; the module itself must stay (§5) |

---

## 1. Task 2 — facexlib audit

### 1.1 Download call and caller chain

Every facexlib download funnels through one function:

```
modules/async_worker.py:435            # IP-Adapter face preprocessor (flags.cn_ip_face)
  └─ extras/face_crop.py:28-33          # crop_image(), builds helper once
      └─ FaceRestoreHelper(model_rootpath=modules.config.path_controlnet, device='cpu')
          extras/facexlib/utils/face_restoration_helper.py:99
          └─ init_detection_model('retinaface_resnet50', ..., model_rootpath=...)
              extras/facexlib/detection/__init__.py:18
          face_restoration_helper.py:103
          └─ init_parsing_model('parsenet', ..., model_rootpath=...)
              extras/facexlib/parsing/__init__.py:18
              └─ load_file_from_url(...)          # extras/facexlib/utils/misc.py:59
                  └─ torch.hub.download_url_to_file(url, cached_file,
                        hash_prefix=None, ...)    # misc.py:77  ← THE BYPASS
```

Secondary references (not production runtime):

- `extras/facexlib/utils/face_utils.py:214-222` — inside an
  `if __name__ == '__main__':` dev block; calls
  `init_detection_model('retinaface_resnet50', half=False)` **without**
  `model_rootpath` (falls back to the default cache, §1.3).
- `experiments_face.py:2` — `import extras.face_crop as cropper` (experiment
  script reusing the same chain).
- The `retinaface_mobile0.25` and `bisenet` branches are reachable only via
  direct calls to `init_detection_model` / `init_parsing_model`; no in-repo
  caller passes those names today, but the URL literals ship in code.

The only `torch.hub` import in facexlib is `misc.py:5`
(`download_url_to_file`, `get_dir`); no other `torch.hub` call exists under
`extras/facexlib/` (repo-wide scan, this audit).

### 1.2 Exact model URLs and filenames

All four are recorded in `models/manifest.json` as `status: "unresolved"`,
`allow_unverified: false` (i.e. `modules.model_manifest.download()` refuses
them by default today).

| Manifest id | URL (immutable release path) | Release | `size_bytes` | Call site |
|---|---|---|---|---|
| `facexlib-detection-resnet50` | `https://github.com/xinntao/facexlib/releases/download/v0.1.0/detection_Resnet50_Final.pth` | v0.1.0 | 109,497,761 | `detection/__init__.py:11` |
| `facexlib-detection-mobilenet` | `https://github.com/xinntao/facexlib/releases/download/v0.1.0/detection_mobilenet0.25_Final.pth` | v0.1.0 | 1,789,735 | `detection/__init__.py:14` |
| `facexlib-parsing-bisenet` | `https://github.com/xinntao/facexlib/releases/download/v0.2.0/parsing_bisenet.pth` | v0.2.0 | 53,289,463 | `parsing/__init__.py:11` |
| `facexlib-parsing-parsenet` | `https://github.com/xinntao/facexlib/releases/download/v0.2.2/parsing_parsenet.pth` | v0.2.2 | 85,331,193 | `parsing/__init__.py:14` |

Provenance probe (metadata only, 2026-10-12): the GitHub Releases API
returns `digest: null` for **all four** assets — GitHub does not publish a
SHA-256 for these assets, so (unlike the 26 HF LFS entries) no
metadata-only full-hash source exists today. The manifest `evidence` URLs
(the release-tag API pages) remain valid for size/tag attestation.

### 1.3 Expected cache locations

`misc.load_file_from_url(url, model_dir='facexlib/weights', file_name=None,
save_dir=model_rootpath)`:

- **Production path** (`save_dir` given): `os.path.abspath(os.path.join(save_dir, filename))`
  → `modules.config.path_controlnet` (`config.py:198`, default
  `../models/controlnet/`) + the file name, e.g.
  `…/models/controlnet/detection_Resnet50_Final.pth`. Note the legacy quirk:
  `model_dir='facexlib/weights'` is **ignored** whenever `save_dir` is set.
- **Fallback path** (`save_dir=None`, dev blocks): `ROOT_DIR/facexlib/weights`
  where `ROOT_DIR` = the `extras/` directory → `extras/facexlib/weights/`.
- The `model_dir is None` branch would use `torch.hub.get_dir()/checkpoints`
  (`~/.cache/torch/hub/checkpoints/`); no in-repo caller reaches it (both
  callers pass `model_dir`).

A migration must keep these destinations byte-for-byte identical so existing
cached files keep being reused.

### 1.4 Checkpoint loading behavior

- `detection/__init__.py:22` — `torch.load(path, map_location=…, weights_only=True)`
  then strips a `module.` key prefix (`:24-27`) and `load_state_dict(strict=True)`.
- `parsing/__init__.py:20` — `torch.load(…, weights_only=True)` then
  `load_state_dict(strict=True)`.
- Deserialization is already safe (`weights_only=True`); the weakness is
  purely transport/integrity (what bytes are fetched and what cached bytes
  are trusted).

### 1.5 Existing hash verification

**None.** `hash_prefix=None` is hardcoded (`misc.py:77`), and an existing
cached file short-circuits the download entirely (`misc.py:75`) with no
verification of any kind — a corrupted or tampered file in
`path_controlnet` is loaded as-is. No size cap, no deadline, no host
allowlist, environment HTTPS proxies honored implicitly by torch.hub.

### 1.6 Required API compatibility

Callers rely on exactly this contract:

```python
load_file_from_url(url, model_dir=..., progress=True, file_name=..., save_dir=...) -> str  # absolute path
init_detection_model(model_name, half=False, device='cuda', model_rootpath=None) -> nn.Module
init_parsing_model(model_name='bisenet', half=False, device='cuda', model_rootpath=None) -> nn.Module
```

Constraints the migration must preserve: return an absolute path string;
destination = `save_dir`/`model_rootpath` when supplied (else
`extras/facexlib/weights`); `weights_only=True` loading; `strict=True` loads;
the `module.`-prefix strip for detection.

### 1.7 Migration design (implemented as P1-A, 2026-10-12 — see §9)

1. Rewrite the **body** of `extras/facexlib/utils/misc.py::load_file_from_url`
   to delegate to the hardened `modules.model_loader.load_file_from_url`
   (signature: keyword-only after `url`, requires `model_dir=`,
   supports `expected_hash`, `allowed_domains`, `max_size`, `max_duration`,
   `cached_hash_mismatch`), passing:
   - `model_dir=<resolved save_dir>` (keeps today's destinations),
   - `file_name` mirroring the legacy override logic,
   - `expected_hash` from a manifest lookup by URL/file name when a hash is
     established, else `None` during the interim tier (below),
   - `allowed_domains=("github.com", "release-assets.githubusercontent.com")`
     — the same per-artifact pattern proven for GroundingDINO in P0.
   Drop `from torch.hub import …` entirely (`misc.py:5`).
2. Hash provenance tiers (this is the "required model provenance" answer):
   - **Tier 1 (preferred, metadata-only):** locate an authoritative
     Hugging Face mirror of the same files with matching `size_bytes` and
     pin the HF LFS OID — the exact method that produced 26/26 verified
     hashes in P0. No weight download needed; requires proof the HF repo is
     the same publisher (facexlib authors).
   - **Tier 2 (interim, as implemented):** mark the four entries
     `allow_unverified: true` with a documented justification (pinned
     release tag + hardened transport) and log the integrity warning —
     the wd14/groundingdino P0 precedent. The original design also
     proposed enforcing the manifest `size_bytes`; **that was not
     implemented — `size_bytes` is recorded metadata only and no code
     path in `modules/` reads or enforces it.** Honest limitation: GitHub
     release assets are re-placeable by the repo owner, so Tier 2
     provides transport integrity plus a pinned immutable release URL,
     not cryptographic identity and not size verification.
   - **Tier 3 (one-time, needs approval):** download each asset once and
     record its SHA-256 (~250 MB total; forbidden under the present
     "no large model downloads" restriction).
3. `manifest_download`/`model_manifest.download` remains the entry point of
   record once hashes exist (entries become `verified`, call sites recorded).

---

## 2. Task 3 — BLIP/DeiT audit

### 2.1 The call

`extras/BLIP/models/blip_pretrain.py:41-45` (inside
`BLIP_Pretrain.__init__`, `vit='base'` branch):

```python
checkpoint = torch.hub.load_state_dict_from_url(
    url="https://dl.fbaipublicfiles.com/deit/deit_base_patch16_224-b5f2ef4d.pth",
    map_location="cpu", check_hash=True)
state_dict = checkpoint["model"]
msg = self.visual_encoder.load_state_dict(state_dict, strict=False)
```

### 2.2 Caller analysis — the module is dead code

Static and dynamic scans (this audit) found **zero callers**:

- No `blip_pretrain` / `BLIP_Pretrain` reference anywhere (`.py` and
  `.ipynb`), other than the module itself and documentation.
- `extras/interrogate.py:10` imports `blip_decoder` from
  `extras/BLIP/models/blip.py` — a different class; its checkpoint
  (`blip-caption-base`) was already converted to the hardened loader in P0.
- No `importlib` / `__import__` / string-path references.

The DeiT download therefore never executes in this application today; it is
live only if the vendored module is imported by future code.

### 2.3 Exact runtime behavior (torch 2.1.0, verified against upstream
`torch/hub.py` at tag v2.1.0)

- Cache: `torch.hub.get_dir()/checkpoints/` → `~/.cache/torch/hub/checkpoints/deit_base_patch16_224-b5f2ef4d.pth`
  (`$TORCH_HOME` respected).
- `check_hash=True` → filename regex extracts prefix `b5f2ef4d`; the prefix
  is checked **only inside `download_url_to_file` during a fresh download**.
  If the cached file exists, torch.hub performs **no hash check at all** and
  loads it directly (`hub.py` `if not os.path.exists(cached_file): …`).
- Deserialization: `torch.load(cached_file, map_location=…, weights_only=False)`
  — **full pickle** (torch 2.1.0 default). For a mutable-CDN file whose only
  identity signal is an 8-hex-char prefix checked at download time, this is
  the weakest spot of any live-or-dead path in the app.
- Format: a pickle `dict`; the code consumes `checkpoint["model"]`
  (a plain state dict) and loads it with `strict=False` into the ViT-B/16
  visual encoder. No custom classes are required to unpickle the tensors
  under `weights_only=True` expectations, but that must be confirmed by test
  at implementation time (see §6, compat risk) — not changed blind.

### 2.4 Required API compatibility

Nothing outside the module depends on it (dead code). Within the module:
`checkpoint["model"]` extraction and `load_state_dict(strict=False)` must be
preserved so the file stays a small, reviewable diff against vendored BLIP
upstream. The `vit='large'` branch (timm) does not download.

### 2.5 Migration design (proposal — not implemented)

Preferred: keep `blip_pretrain.py` structurally identical but replace lines
41-45 with (a) a hardened pre-download of the DeiT file into **the same
torch.hub cache path** (so users' existing caches remain valid) using
`modules.model_loader.load_file_from_url(..., expected_hash=<prefix> or full
hash, allowed_domains=("dl.fbaipublicfiles.com",))`, followed by (b)
`torch.load(local_path, map_location="cpu", weights_only=True)` with a
documented fallback to `weights_only=False` only if the pinned
checkpoint fails allowlisted loading (this is the "avoid unsafe
deserialization changes" balance: never weaken below today's behavior,
prefer strengthening, prove compatibility by test first).

Alternative (to be chosen at approval): delete the dead `BLIP_Pretrain`
module outright — strongest fix, but diverges further from vendored BLIP
upstream; would also drop the manifest entry or mark it retired.

Provenance: manifest already records `sha256_prefix: "b5f2ef4d"` (unresolved,
`allow_unverified: false`). Tier options: prefix-pin now via the hardened
loader's prefix matching (`modules/model_loader.py:973-976` explicitly
supports torch.hub-style prefixes); full SHA-256 later by one-time download
(~340 MB, needs approval) or if facebook ever publishes digests.

---

## 3. Task 4 — rembg audit

### 3.1 Dependency and mechanism

- **Pinned version:** `rembg==2.0.57` (`requirements_versions.txt:21`);
  `onnxruntime==1.18.1` beside it. `pooch` is `Requires-Dist: pooch`
  (unversioned) in the wheel — transitive, **not pinned** in this repo.
- Source inspected from the published wheel
  (`rembg-2.0.57-py3-none-any.whl`, downloaded to a scratch dir; repo
  untouched):

| Aspect | Finding |
|---|---|
| Entry points used by this repo | `extras/inpaint_mask.py:8` → `from rembg import remove, new_session`; `:64` → `new_session(mask_model, **extras)` |
| Download engine | `pooch.retrieve(url, "md5:<hash>", fname, path)` in each session's `download_models()` classmethod (e.g. `sessions/u2net.py:62-74`) |
| URLs | `https://github.com/danielgatis/rembg/releases/download/v0.0.0/<model>.onnx` (all 7 selectable models; plus SAM asset URLs in `sessions/sam.py`, unused by this repo's SAM path) |
| Cache location | `BaseSession.u2net_home()` = `$U2NET_HOME` if set, else `$XDG_DATA_HOME`/`~/.u2net` (`sessions/base.py`) |
| Hash verification | pooch **md5** pinned per model in the published wheel; pooch re-checks the cached file against the md5 on each retrieve and re-downloads on mismatch |
| Disable switch | `MODEL_CHECKSUM_DISABLED` env var disables the md5 check (`base.py::checksum_disabled`) — **must never be set by this app** |
| Selection | `modules/flags.py:87`: `['u2net','u2netp','u2net_human_seg','u2net_cloth_seg','silueta','isnet-general-use','isnet-anime','sam']`; config default `isnet-general-use` (`config.py:681-684`); `sam` is handled by segment-anything in `inpaint_mask.py:61` and never reaches rembg |

### 3.2 Can downloads be disabled, intercepted, or redirected through
supported APIs?

Assessment against supported surface only:

- **Redirect: YES (supported).** `U2NET_HOME` is a documented, supported
  environment knob. Pre-seeding `$U2NET_HOME/<model>.onnx` with
  hash-correct bytes makes pooch verify + reuse the file with **no
  network fetch** — this is the sanctioned interception point.
- **Disable: NO official "offline" switch.** Unsetting the network just
  fails. `MODEL_CHECKSUM_DISABLED` exists but *removes* verification —
  setting it would be a security regression and is explicitly out of scope.
- **Intercept: no hook.** rembg calls `pooch.retrieve(...)` directly with
  fixed arguments; pooch exposes no global downloader registry. Redirecting
  the *URL* would require monkey-patching `pooch.retrieve`, `requests`, or
  `urllib` — i.e. patching security-sensitive network functions. Per the
  task constraint, this is **not recommended**: the justification would be
  "pin a SHA-256 the upstream does not publish", but the same outcome is
  achieved without patches by pre-seeding the cache through the hardened
  loader (which is exactly what P0's `download_file` does). Monkey-patching
  remains a last-resort option only with separate written justification.

### 3.3 Compatibility and Colab

- Cache path semantics are unchanged by the pre-seed design (same
  `~/.u2net`, same `U2NET_HOME` override), so Colab behavior is identical:
  ephemeral home → first-run download (as today) or pre-baked image.
- Frequency note (existing behavior, not a defect introduced here):
  `new_session` is called per mask operation, so pooch md5-hashes the cached
  file every call (u2net ≈ 176 MB class file → noticeable CPU cost);
  migration does not worsen this and may improve it if rembg's session
  caching is later addressed (out of scope).
- Model identity: the seven selectable names map 1:1 to manifest entries
  `rembg-u2net` … `rembg-isnet-anime` (all `unresolved`,
  `allow_unverified: false`, `sha256: null`, `size_bytes: null`).

### 3.4 Migration design (proposal — not implemented)

1. Add a small `extras/rembg_preseed.py`-style helper (name TBD at
   implementation) that, for a given model name, resolves the **same URL**
   (single source of truth: keep the URL list in the manifest, mirroring the
   wheel), calls the hardened downloader to place bytes at
   `$U2NET_HOME/<name>.onnx` with `expected_hash` when established, and
   never touches pooch internals. Call it lazily before `new_session(...)`
   in `extras/inpaint_mask.py`.
2. Provenance tiers: (a) record SHA-256 by hashing the pooch-verified file
   after its normal first download (trust-on-first-use **guarded by pooch's
   pinned md5** — weaker than HF-LFS evidence; documented as such);
   (b) one-time direct download+hash of all seven models (~hundreds of MB,
   needs approval); (c) meanwhile, rely on pooch's existing md5 while the
   hardened loader provides the *pre-seed* path for environments that
   pre-bake models.
3. Guardrails: repo-scan test that the app never sets
   `MODEL_CHECKSUM_DISABLED`; keep `U2NET_HOME` support; document that
   sha256 pinning of the rembg family is the last unresolved piece (7 of
   the 14 `unresolved` manifest entries).

---

## 4. Task 5 — unused downloader helper audit

**Target:** `ldm_patched/k_diffusion/utils.py:37-48` —
`def download_file(path, url, digest=None)`, raw `urllib.request.urlopen`
copy with optional post-hoc SHA-256 (reads the whole file into memory).

Verification performed (this audit):

1. **Direct callers:** repo-wide grep for `download_file` — the only hit in
   `ldm_patched` is the definition itself. (All other `download_file` hits
   are `modules.model_loader.download_file` — a different, hardened
   function — and its tests.)
2. **Module imports:** `ldm_patched/k_diffusion/sampling.py:9`
   (`from . import utils`) means the *module* is live, and `sampling.py:47`
   uses `utils.append_dims` — so the module must **not** be deleted. No
   other file imports `k_diffusion.utils` or `from ldm_patched.k_diffusion import utils`.
3. **Dynamic/indirect references:** `getattr(utils, …)`, `importlib`,
   `__import__` scans across `ldm_patched/`, `modules/`, `extras/` → none
   referencing `download_file` or `utils` dynamically; `.ipynb` scan →
   none; string-path scan (`models.blip_pretrain`, `k_diffusion.utils`) →
   only documentation matches.
4. `k_diffusion` consumers elsewhere import only `.sampling`
   (`external_custom_sampler.py`, `ldm_patched/modules/samplers.py`,
   `modules/sample_hijack.py`, `modules/patch.py`,
   `modules/patch_clip.py`).

**Conclusion:** `download_file` has zero callers (dead function inside a
live module). Recommended replacement: **delete the function only**, keep
`utils.py` (it provides `append_dims` etc. to `sampling.py`), and add a
source-scan regression test that no raw-`urlopen` download helper reappears
(§6). This matches the P0 finding in `docs/MODEL_INTEGRITY_AUDIT.md:29`.

---

## 5. Cross-cutting compatibility risks

1. **Fail-closed cached verification** (facexlib, once hashes exist): a
   corrupted cached official file will raise `CachedFileIntegrityError`
   (`cached_hash_mismatch="fail"`) instead of silently loading — same
   intentional M2-style behavior accepted for P0. Interim tier (no hash yet)
   keeps today's "load what's there" behavior for these files.
2. **Destination lock semantics:** the hardened loader takes destination
   locks in `model_dir`; legacy callers did not. Concurrent first-time use
   from both paths during transition is safe (hardened wins), but tests must
   cover the mixed directory (`path_controlnet` shared with controlnets).
3. **`weights_only=True` on the DeiT pickle** must be proven with a test
   fixture before adoption; if the real checkpoint carries non-tensor
   metadata that the allowlist rejects, keep `weights_only=False` (status
   quo) and note it — never regress below current behavior silently.
4. **Import weight:** `extras/facexlib` would import `modules.model_loader`
   (torch-free by design); `extras` already imports `torch` itself, so no
   new constraint for production. CI security suites must remain
   torch-free (they install only `packaging`) — all new tests are mock-based.
5. **Pooch pinning gap:** `pooch` is unpinned transitively; version drift
   could change download/verify behavior inside rembg. Out of scope to pin
   (dependency change forbidden in P1 audit), recorded for Stage 4.

---

## 6. Migration plan (per component)

### 6.1 facexlib (4 sites → 1 wrapper) — **IMPLEMENTED (P1-A, §9)**

| Field | Plan |
|---|---|
| Existing behavior | `torch.hub.download_url_to_file`, no hash/size/allowlist; cached file trusted by existence; dest = `path_controlnet` (prod) or `extras/facexlib/weights` (fallback) |
| Security weakness | Transport-only integrity (TLS), zero content verification, no caps/deadline, env-proxy hijack possible |
| Proposed replacement | Rewrite body of `misc.py::load_file_from_url` to delegate to `modules.model_loader.load_file_from_url` with `allowed_domains=(github.com, release-assets.githubusercontent.com)`, `expected_hash` when available, `cached_hash_mismatch="fail"` when pinned; drop `torch.hub` import. **As implemented (§9): the manifest `size_bytes` is NOT passed as `max_size` and is not enforced anywhere — `size_bytes` is metadata only (the original `max_size`-from-manifest proposal above was not carried out)** |
| Required provenance | Tier 1 HF-mirror LFS OID (metadata-only), Tier 2 interim `allow_unverified` + size/tag justification, Tier 3 one-time digest (~250 MB, needs approval). GitHub `digest` confirmed `null` |
| Compatibility risks | §5.1–5.2; path/`save_dir` semantics must be byte-identical; dev `__main__` block keeps working |
| Regression tests | (a) delegation test (mock hardened loader, assert args incl. hash & domains); (b) repo-scan: no `torch.hub` import under `extras/facexlib/`; (c) pre-seeded-cache reuse without network (tmp dir, mocked); (d) corrupt cached pinned file → `CachedFileIntegrityError`; (e) destination-equality test vs legacy path computation |
| Without downloading weights? | **Yes** for the routing itself; full hash pinning = Tier 3 (deferred, approval required) |

### 6.2 BLIP/DeiT (1 site, dead)

| Field | Plan |
|---|---|
| Existing behavior | torch.hub download with download-time prefix check; cache trusted thereafter; full-pickle load (`weights_only=False`) |
| Security weakness | Mutable CDN, 8-char prefix only, no cache re-check, unsafe-deserialization default; module is dead code |
| Proposed replacement | Hardened pre-download to the same torch.hub cache path (`allowed_domains=("dl.fbaipublicfiles.com",)`, prefix/full hash) + explicit `torch.load(…, weights_only=True)` after fixture proof; **or** delete the dead module (decision at approval) |
| Required provenance | `sha256_prefix: b5f2ef4d` already in manifest; full SHA-256 = one-time ~340 MB download (approval) or future publisher digest |
| Compatibility risks | §5.3; `checkpoint["model"]` + `strict=False` must behave identically; vendor-diff size differs between replace-vs-delete options |
| Regression tests | (a) repo-scan: no `load_state_dict_from_url` outside `modules/model_loader.py` docs; (b) synthetic pickle fixture → replacement returns `["model"]` and survives `weights_only=True` (or records the documented fallback); (c) prefix verification via `_matches_hash` |
| Without downloading weights? | **Yes** (prefix tier); full pin deferred |

### 6.3 rembg (7 internal sites)

| Field | Plan |
|---|---|
| Existing behavior | pooch md5-verified download into `~/.u2net`/`$U2NET_HOME` on every `new_session`; URL fixed in wheel |
| Security weakness | md5 (collision-weak), unpinned pooch, no app-level size/deadline/allowlist, `MODEL_CHECKSUM_DISABLED` footgun, 7 unresolved manifest entries with `sha256/size_bytes: null` |
| Proposed replacement | **No monkey-patching.** Pre-seed `$U2NET_HOME` via hardened loader before `new_session` (supported `U2NET_HOME` redirect); manifest becomes URL+hash source of truth; scan test bans `MODEL_CHECKSUM_DISABLED` |
| Required provenance | Tier A: hash the pooch-verified file post-first-use (TOFU under pinned md5 — documented weaker tier); Tier B: one-time download+sha256 of 7 models (approval); keep pooch md5 as working floor meanwhile |
| Compatibility risks | §5.5; Colab unchanged; per-call pooch re-hash cost unchanged; session behavior untouched |
| Regression tests | (a) pre-seed helper writes to correct `U2NET_HOME` path & calls hardened loader (mock); (b) repo-scan: no `MODEL_CHECKSUM_DISABLED`, no patching of `pooch`/`requests`/`urlopen` in app code; (c) flag↔manifest coverage: every name in `flags.inpaint_mask_models` (except `sam`) has a manifest entry |
| Without downloading weights? | **Yes** for pre-seeding design; Tier B needs download (deferred) |

### 6.4 Dead raw-`urlopen` helper — **IMPLEMENTED (P1-A, §9: deleted)**

| Field | Plan |
|---|---|
| Existing behavior | Dead function; module live (`utils.append_dims` for `sampling.py:47`) |
| Security weakness | None live; re-introduction risk only |
| Proposed replacement | Delete `download_file` (lines 37-48); keep module |
| Required provenance | None (no artifact) |
| Compatibility risks | None — zero callers proven incl. dynamic scan |
| Regression tests | Source scan: `def download_file(path, url` absent from `ldm_patched/`; `urllib.request.urlopen` absent outside `modules/model_loader.py` |
| Without downloading weights? | **Yes** |

### 6.5 Shared test/CI notes

- All new tests must run under Security CI's minimal environment
  (`packaging` only, no torch/onnxruntime) → mocks/fixtures only.
- Extend the existing repo-scan harness pattern from
  `tests/test_model_loader.py::TestTLSVerificationNeverDisabled::test_no_tls_bypass_patterns_in_repository`
  (`_iter_source_files`) rather than inventing a new scanner.
- ~~No CI workflow changes are required to run them.~~ **Done differently in
  P1-A:** `.github/workflows/security-ci.yml` run line now includes
  `tests.test_p1_legacy_migration` (actionlint clean) so the new module runs
  on the 3.10/3.12/3.14 matrix.

---

## 7. Restrictions honored

- Audit and design only — **no application code modified** (this document
  and the roadmap status note are the only file changes; both uncommitted).
- No dependency upgrades (`rembg==2.0.57`, `torch==2.1.0`, unpinned `pooch`
  all left untouched — recorded as findings only).
- No notebook changes.
- No model weights downloaded (network use: GitHub/PyPI/HF **metadata** and
  one 33 KB wheel for source inspection, in a scratch dir outside the repo).
- No commit, push, merge, or tag; existing branches/worktrees preserved;
  `main` untouched.

## 8. Stop point (superseded by §9 for the P1-A items)

~~Stopping here per the task brief.~~ **P1-A was subsequently approved and
implemented the same day:** facexlib routing + dead-helper deletion + tests
(§9). The remaining §6 items — BLIP/DeiT replacement or deletion, rembg
pre-seeding, and the hash-tier downloads (Tier 1/3 for facexlib, rembg Tier B,
BLIP full hash) — still **require explicit approval** before any
implementation.

---

## 9. P1-A implementation record (2026-10-12, uncommitted)

### 9.1 What changed

| File | Change |
|---|---|
| `extras/facexlib/utils/misc.py` | `from torch.hub import …` removed; `_torch_hub_checkpoints_dir()` replicates legacy `TORCH_HOME`/`XDG_CACHE_HOME` semantics; `load_file_from_url` keeps its exact signature and destination computation, raises `ManifestError` for URLs with no manifest entry, and delegates to `modules.model_manifest.download(..., model_dir=save_dir, file_name=filename, progress=progress)` |
| `modules/model_manifest.py` | added `match_url(url)` resolver; `download()` gained `progress: bool = True` passed through to the hardened loader |
| `models/manifest.json` | the 4 facexlib entries: `allow_unverified: true` + `unverified_justification` (Tier 2, cites `digest: null` / SHA-256 follow-up) + per-artifact `allowed_domains: ["github.com", "release-assets.githubusercontent.com"]` + note. **Still `status: "unresolved"`, `sha256: null` — no hash was invented** |
| `ldm_patched/k_diffusion/utils.py` | dead `download_file` (raw `urlopen`) deleted with its now-unused `hashlib`/`shutil`/`urllib` imports; module kept for `utils.append_dims` |
| `tests/test_p1_legacy_migration.py` | **new**, 33 tests: manifest recording/`match_url`, delegation with legacy-compatible args, cache-dir semantics (prod `path_controlnet` vs fallback, `TORCH_HOME`), existing-file reuse, destination/redirect/allowlist rejection, unverified warning, failure cleanup, static checks (no `torch.hub`/`download_url_to_file` in `extras/facexlib/`, no `def download_file(path, url` in `ldm_patched/`) |
| `.github/workflows/security-ci.yml` | run line adds `tests.test_p1_legacy_migration` (actionlint clean) |

Tests load `misc.py` standalone via `spec_from_file_location` with inert
`torch`/`cv2` stubs that are **removed from `sys.modules` immediately after
load**, so P0's `test_import_model_loader_does_not_require_torch` invariant
holds under any test ordering.

### 9.2 Verification

- Full suite **201 tests (loader 132 + integrity 36 + p1 33) green ×3** on
  Python 3.10 / 3.12 / 3.14 (Security CI environment: `packaging` only).
- New module also green standalone on all three interpreters.
- `actionlint` clean on the edited workflow; `git diff` touches **no**
  dependency file (no new/removed imports outside stdlib + existing modules).

### 9.3 Compatibility limitations (honest record)

1. **Allowlist is additive, not restrictive:** per-artifact
   `allowed_domains` *grants* GitHub hosts on top of
   `DEFAULT_ALLOWED_HOSTS` (huggingface/hf). huggingface.co therefore
   remains reachable from facexlib URLs as before — unchanged from P0, and
   GitHub access still requires the per-artifact grant (test:
   `test_github_hosts_require_per_artifact_grant`).
2. **Cached-file semantics differ from legacy torch.hub:** legacy trusted
   *existence*; the hardened loader reuses a cached file only when
   `st_size > 0` (`modules/model_loader.py:1307`) and re-downloads a
   zero-byte cache. **Unresolved cached models are accepted on that
   existence check alone — with `expected_hash=None` there is no SHA-256
   verification and no manifest-`size_bytes` comparison**
   (`modules/model_loader.py:1306-1308`). A hash mismatch fails closed
   only for `verified` entries (`cached_hash_mismatch="fail"`); the
   manifest `size_bytes` is metadata only and is never checked against
   the cache or the download.
3. **Unknown URL = refuse:** `misc.py` raises `ManifestError` for any URL
   not present in the manifest (legacy downloaded anything). Future new
   facexlib URLs must be added to `models/manifest.json` first.
4. **Provenance is Tier 2 (transport + pinned immutable release URL/tag),
   not cryptographic identity and not size verification** for the 4 GitHub
   release assets (`digest: null` verified 2026-10-12; manifest
   `size_bytes` recorded but unenforced — see 9.3.2). Tier 1 (HF mirror
   LFS OID) or Tier 3 (one-time ~250 MB SHA-256, approval-gated)
   upgrades remain open.

### 9.4 Restrictions honored (P1-A)

- facexlib + dead k-diffusion helper + tests/docs/CI only; **no BLIP/DeiT or
  rembg code changed**, no checksum disabled, no dependency upgraded, no
  notebook edited, no model weight downloaded.
- No commit/push/merge/tag; baseline `9df2d33` untouched; other worktrees
  untouched.
