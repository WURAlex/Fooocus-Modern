# Fooocus-Modern — Stage 7: Model URL and Cryptographic Integrity Audit

- **Repository:** WURAlex/Fooocus-Modern
- **Integration branch:** `modern-platform`
- **Audited baseline:** `c4e898685c8e2408f82789337caabf997bc94cfa`
- **Audit branch:** `stage7-model-integrity-audit` (worktree `/home/alex/Fooocus-Modern-stage7`)
- **Audit date:** 2026-10-12
- **Scope:** audit and design only. No download behavior was changed, no dependencies were upgraded, no notebooks were modified, no model files were downloaded (metadata APIs only), nothing was committed or pushed.

---

## 1. Executive summary

| Metric | Value |
|---|---|
| In-repo download call sites | **32** (previous roadmap estimate: 30) |
| Download implementations in tree | **5** + 1 dependency-internal (rembg) |
| Fixed artifact identities tracked | **34** (27 Hugging Face, 5 GitHub release, 1 fbaipublicfiles, 1 rembg family of 7 model files) |
| Call sites that pass `expected_hash` today | **0 of 32** |
| Artifacts with an independently supported SHA-256 | **26 of 34** (all Hugging Face LFS files) |
| Artifacts with no independent SHA-256 | **8** (1 HF non-LFS CSV, 5 GitHub release assets, 1 DeiT partial-prefix-only, 7 rembg-internal model files tracked as 1 unresolved family) |
| User-supplied download categories | **4** (`checkpoint_downloads`, `embeddings_downloads`, `lora_downloads`, `vae_downloads`) |
| New defect found during audit | **1 functional** (GitHub-hosted artifact unreachable via hardened downloader) + **1 dead-code bypass** (confirmed) |

Three findings dominate this audit:

1. **No cryptographic identity is enforced at download time.** Every hardened call site passes `expected_hash=None`; existing files are accepted on size > 0 alone (`modules/model_loader.py:1279-1287`).
2. **The hardened allowlist excludes `github.com`** (`modules/model_loader.py:28-40`), so the only hardened caller that targets a GitHub release — `extras/GroundingDINO/util/inference.py:32` — **fails closed on a fresh install**. It works today only if the file is pre-placed.
3. **Two legacy downloaders bypass all Stage 2/3 hardening** (`extras/facexlib/utils/misc.py:59` via `torch.hub.download_url_to_file`, and `torch.hub.load_state_dict_from_url` in `extras/BLIP/models/blip_pretrain.py:41`), and one dead-code raw-`urlopen` downloader remains (`ldm_patched/k_diffusion/utils.py:37`, zero callers).

---

## 2. Download implementations found in the tree

| # | Implementation | Location | Hardening (Stage 2/3) | Hash support | In-repo call sites |
|---|---|---|---|---|---|
| 1 | `load_file_from_url` (hardened) | `modules/model_loader.py:1487` | Yes: HTTPS-only, host/domain allowlist, IP pinning, redirect scrub, size caps, deadline, retries, atomic replace, destination locks | `expected_hash` (sha256 exact/prefix) | 28 |
| 2 | `download_url_to_file` (hardened torch.hub drop-in) | `modules/model_loader.py:1535` | Same as above | `hash_prefix` → sha256 prefix | **0 production callers** (tests only) |
| 3 | facexlib `load_file_from_url` (legacy) | `extras/facexlib/utils/misc.py:59` → `torch.hub.download_url_to_file` | **None** (plain HTTPS, env proxies honored, no allowlist, no size cap, no deadline, no IP pinning) | `hash_prefix=None` hardcoded (`:77`) | 2 |
| 4 | `torch.hub.load_state_dict_from_url` | `extras/BLIP/models/blip_pretrain.py:41` | **None** (torch.hub cache, env proxies) | `check_hash=True` (parses sha256 **prefix** from filename) | 1 |
| 5 | raw `urllib.request.urlopen` helper | `ldm_patched/k_diffusion/utils.py:37` | **None** (no TLS pinning, env proxies, no size cap) | optional `digest=` sha256 — **never passed; zero callers (dead code)** | 1 (definition, 0 callers) |
| 6 | rembg internal downloader | `rembg.new_session` invoked at `extras/inpaint_mask.py:64` | **None** (third-party code; downloads to user cache) | none known | 1 (dependency-internal; 7 model names) |

Note: implementation #2 exists precisely to be the hardened replacement for #3/#4 and currently has no production consumer.

---

## 3. Call-site inventory (32 in-repo + 1 dependency-internal)

Integrity controls "today" column: **none** = `expected_hash=None` and existing files trusted on size alone; **partial** = torch.hub `check_hash` prefix; **n/a** = dead code.

### 3.1 `modules/config.py` — 18 sites (all hardened loader)

| Line | Function | URL construction | Destination | Today |
|---|---|---|---|---|
| 826 | `downloading_inpaint_models` | fixed `…/fooocus_inpaint/resolve/main/fooocus_inpaint_head.pth` | `path_inpaint` | none |
| 835 | same, engine `v1` | fixed `inpaint.fooocus.patch` | `path_inpaint` | none |
| 843 | same, engine `v2.5` | fixed `inpaint_v25.fooocus.patch` | `path_inpaint` | none |
| 851 | same, engine `v2.6` | fixed `inpaint_v26.fooocus.patch` | `path_inpaint` | none |
| 862 | `downloading_sdxl_lcm_lora` | fixed `lllyasviel/misc/…/sdxl_lcm_lora.safetensors` | `paths_loras[0]`, name from `PerformanceLoRA.EXTREME_SPEED` | none |
| 871 | `downloading_sdxl_lightning_lora` | fixed `mashb1t/misc/…/sdxl_lightning_4step_lora.safetensors` | `paths_loras[0]` | none |
| 880 | `downloading_sdxl_hyper_sd_lora` | fixed `mashb1t/misc/…/sdxl_hyper_sd_4step_lora.safetensors` | `paths_loras[0]` | none |
| 889 | `downloading_controlnet_canny` | fixed `lllyasviel/misc/…/control-lora-canny-rank128.safetensors` | `path_controlnet` | none |
| 898 | `downloading_controlnet_cpds` | fixed `lllyasviel/misc/…/fooocus_xl_cpds_128.safetensors` | `path_controlnet` | none |
| 911 | `downloading_ip_adapters` | fixed `clip_vision_vit_h.safetensors` | `path_clip_vision` | none |
| 918 | same | fixed `fooocus_ip_negative.safetensors` | `path_controlnet` | none |
| 926 | same, `v='ip'` | fixed `ip-adapter-plus_sdxl_vit-h.bin` | `path_controlnet` | none |
| 934 | same, `v='face'` | fixed `ip-adapter-plus-face_sdxl_vit-h.bin` | `path_controlnet` | none |
| 945 | `downloading_upscale_model` | fixed `fooocus_upscaler_s409985e5.bin` | `path_upscale_models` | none |
| 953 | `downloading_safety_checker_model` | fixed `mashb1t/misc/…/stable-diffusion-safety-checker.bin` | `path_safety_checker` | none |
| 974 | `downloading_sam_vit_b` | fixed `sam_vit_b_01ec64.pth` | `path_sam` | none |
| 983 | `downloading_sam_vit_l` | fixed `sam_vit_l_0b3195.pth` | `path_sam` | none |
| 992 | `downloading_sam_vit_h` | fixed `sam_vit_h_4b8939.pth` | `path_sam` | none |

Trigger context: invoked from `modules/async_worker.py` (performance LoRAs :797/:817/:837, upscale :896/:951, inpaint :899/:998, controlnet :921/:923, IP-Adapter :925/:927), `modules/upscaler.py:19`, `extras/inpaint_mask.py:83` (SAM), `extras/censor.py:26` (safety checker), `webui.py` preset preparation.

### 3.2 `launch.py` — 6 sites (all hardened loader)

| Line | Function | URL construction | Destination | Today |
|---|---|---|---|---|
| 168 | `download_models` (VAE approx loop, 3 entries) | fixed table `vae_approx_filenames` (:40-54) | `path_vae_approx` | none |
| 178 | `download_models` | fixed `lllyasviel/misc/…/fooocus_expansion.bin`, saved as `pytorch_model.bin` | `path_fooocus_expansion` | none |
| 245 | `download_models` (checkpoint loop) | **user-supplied** `checkpoint_downloads` (config/preset) | resolved subdirectory of `paths_checkpoints` | none |
| 256 | `download_models` (embeddings loop) | **user-supplied** `embeddings_downloads` | `path_embeddings` | none |
| 274 | `download_models` (LoRA loop) | **user-supplied** `lora_downloads` | resolved subdirectory of `paths_loras` | none |
| 285 | `download_models` (VAE loop) | **user-supplied** `vae_downloads` | `path_vae` | none |

### 3.3 `extras/` — 4 hardened-loader sites

| Line | Function | URL construction | Destination | Today |
|---|---|---|---|---|
| `extras/GroundingDINO/util/inference.py:32` | `GroundingDinoModel.predict_with_caption` (lazy init) | fixed `github.com/IDEA-Research/GroundingDINO/releases/download/v0.1.0-alpha/groundingdino_swint_ogc.pth` | `path_inpaint` | none — **plus functional defect: `github.com` not allowlisted → fails closed** |
| `extras/interrogate.py:28` | `Interrogator.interrogate` (lazy init) | fixed `lllyasviel/misc/…/model_base_caption_capfilt_large.pth` | `path_clip_vision` | none |
| `extras/wd14tagger.py:32` | `default_interrogator` | templated `…/{model_name}.onnx`, `model_name` hardcoded `wd-v1-4-moat-tagger-v2` | `path_clip_vision` | none |
| `extras/wd14tagger.py:38` | same | templated `…/{model_name}.csv` | `path_clip_vision` | none |

### 3.4 Legacy / bypass sites — 5

| Line | Function | URL construction | Destination | Today |
|---|---|---|---|---|
| `extras/facexlib/detection/__init__.py:18` | `init_detection_model` | fixed GitHub release URLs (`retinaface_resnet50` / `retinaface_mobile0.25`) | `save_dir=model_rootpath` (from `extras/face_crop.py:32` → `path_controlnet`); `model_dir='facexlib/weights'` ignored when `save_dir` given | none (`hash_prefix=None`); **bypasses hardened downloader** |
| `extras/facexlib/parsing/__init__.py:18` | `init_parsing_model` | fixed GitHub release URLs (`bisenet` v0.2.0 / `parsenet` v0.2.2) | same | none; **bypass** |
| `extras/BLIP/models/blip_pretrain.py:41` | `blip_pretrain.__init__` (`vit='base'`) | fixed `https://dl.fbaipublicfiles.com/deit/deit_base_patch16_224-b5f2ef4d.pth` | torch.hub cache (`~/.cache/torch/hub/checkpoints/`) | partial: `check_hash=True` verifies filename-embedded sha256 prefix `b5f2ef4d`; **bypass** |
| `ldm_patched/k_diffusion/utils.py:37` | `download_file(path, url, digest=None)` | caller-supplied | caller-supplied | n/a — **dead code, zero callers** (verified by grep) |
| `extras/inpaint_mask.py:64` | `generate_mask_from_image` → `rembg.new_session(mask_model)` | dependency-internal (rembg ≥2 downloads `{model}.onnx` from its own release URLs) | rembg user cache (typically `~/.u2net/`) | none; dependency-internal bypass; model names from `modules/flags.py:87`: `u2net`, `u2netp`, `u2net_human_seg`, `u2net_cloth_seg`, `silueta`, `isnet-general-use`, `isnet-anime` |

`modules/hash_cache.py` / `modules/util.py:178` compute SHA-256 of **local** files for UI metadata only — not download verification.

---

## 4. Trusted model identities

Method: identity data was collected from **independent upstream metadata APIs**, not by downloading model bytes and not by hashing local copies:

- Hugging Face: `https://huggingface.co/api/models/{repo}` (main revision SHA, last-modified) and `https://huggingface.co/api/models/{repo}/tree/main?recursive=true` (per-file **LFS OID = SHA-256 of file content**, size). HF exposes the LFS object ID precisely so clients can verify without trusting the CDN response body.
- GitHub Releases: `https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}` (asset name, size, `updated_at`). The API returned `digest: null` for all five assets audited — **no independently published SHA-256 exists**, so none is claimed below.
- fbaipublicfiles.com: no metadata API. The only identity signal is the sha256 **prefix** embedded in the filename (`-b5f2ef4d`), which torch.hub verifies when `check_hash=True`.

No hash in this section was invented; where no independent hash exists the cell reads `none published`.

Status legend: **verified** = independently published SHA-256 available (HF LFS OID); **unresolved** = no independent SHA-256; **user-provided** = artifact identity chosen by the user at runtime.

### 4.1 Hugging Face artifacts (27; 26 verified, 1 unresolved)

HF main revisions captured at audit time (URLs in code use `/resolve/main/`, which is mutable; pinned form is `/resolve/{revision}/`):

| Repo | Main revision (immutable) | Last modified |
|---|---|---|
| `lllyasviel/misc` | `71f7a66a7affe631c64af469fe647217d422cac0` | 2023-12-13 |
| `mashb1t/misc` | `f93e6891b34e7acd732c52e3274c0c2a2ec836d4` | 2024-06-16 |
| `lllyasviel/fooocus_inpaint` | `74bbcc070e55219adb9b6c3b0d035b34e3697d1d` | 2023-11-11 |
| `lllyasviel/fav_models` | `9ed0826762ff6a535ad09c8ead37b63170768b61` | 2024-01-28 |
| `stabilityai/stable-diffusion-xl-base-1.0` | `462165984030d82259a11f4367a4eed129e94a7b` | 2023-10-30 |

| # | Artifact (local file name) | Purpose | Repo / path | SHA-256 (HF LFS OID) | Size (bytes) | URL mutable (`/resolve/main`)? | Mandatory / optional | User-substitutable | Call site |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `xlvaeapp.pth` | SDXL latent VAE approx | lllyasviel/misc | `6c8db511f910184436a613807ce06a729f4cf96bbf7977c7c6c40d5b3e4a8333` | 213,777 | yes | mandatory (every startup) | no | launch.py:42 |
| 2 | `vaeapp_sd15.pth` (from `vaeapp_sd15.pt`) | SD1.5 latent VAE approx | lllyasviel/misc | `4f88c9078bb2238cdd0d8864671dd33e3f42e091e41f08903f3c15e4a54a9b39` | 213,777 | yes | mandatory | no | launch.py:47 |
| 3 | `xl-to-v1_interposer-v4.0.safetensors` | XL→v1 latent interposer | mashb1t/misc | `da4c2d772c621134ba1a2d961a439cbc4b4c85c43aae1197ab3c024e2a3efa57` | 5,667,280 | yes | mandatory | no | launch.py:50 |
| 4 | `pytorch_model.bin` (from `fooocus_expansion.bin`) | Fooocus prompt expansion GPT-2 | lllyasviel/misc | `dd54cc90d95d2c72b97830e4b38f44a6521847284d5b9dbcfd16ba82779cdeb3` | 351,283,802 | yes | mandatory | no | launch.py:178 |
| 5 | `juggernautXL_v8Rundiffusion.safetensors` | default base checkpoint | lllyasviel/fav_models `fav/…` | `aeb7e9e6897a1e58b10494bd989d001e3d4bc9b634633cd7b559838f612c2867` | 7,105,348,592 | yes | first-run default (skippable / fallback) | **yes** (user checkpoints) | presets/default.json → launch.py:245 |
| 6 | `sd_xl_offset_example-lora_1.0.safetensors` | default offset LoRA | stabilityai/stable-diffusion-xl-base-1.0 | `4852686128f953d0277d0793e2f0335352f96a919c9c16a09787d77f55cbdf6f` | 49,553,604 | yes | first-run default | **yes** (user LoRAs) | presets/default.json → launch.py:274 |
| 7 | `fooocus_inpaint_head.pth` | Fooocus inpaint head | lllyasviel/fooocus_inpaint | `32f7f838e0c6d8f13437ba8411e77a4688d77a2e34df8857e4ef4d51f6b97692` | 52,602 | yes | optional (first inpaint task) | no | config.py:826 |
| 8 | `inpaint.fooocus.patch` | inpaint patch v1 | lllyasviel/fooocus_inpaint | `ba2a82dec0151105cb593ba7254f58548ec6810aeb9e081c4533fb227d654476` | 1,317,090,025 | yes | optional (engine v1) | no | config.py:835 |
| 9 | `inpaint_v25.fooocus.patch` | inpaint patch v2.5 | lllyasviel/fooocus_inpaint | `640e480158e8a8e0aa673c77d19f8b4095a562ac72e2f2a146b445f78ed0febc` | 2,580,722,369 | yes | optional (engine v2.5) | no | config.py:843 |
| 10 | `inpaint_v26.fooocus.patch` | inpaint patch v2.6 (default engine) | lllyasviel/fooocus_inpaint | `f8657a025104e22d70f9c060635d8e8c2196f433871a2f68dc40abd2171f0d59` | 1,323,362,033 | yes | optional (first inpaint task; default engine v2.6) | no | config.py:851 |
| 11 | `sdxl_lcm_lora.safetensors` | Extreme Speed performance LoRA | lllyasviel/misc | `c3dbf7eb26dd00ae6b6b95da69be9f1cb95a3b2c5bcf9be82323227a19b91329` | 393,854,624 | yes | optional (performance select) | no | config.py:862 |
| 12 | `sdxl_lightning_4step_lora.safetensors` | Lightning performance LoRA | mashb1t/misc | `bf56cf2657efb15e465d81402ed481d1e11c4677e4bcce1bc11fe71ad8506b79` | 393,854,592 | yes | optional | no | config.py:871 |
| 13 | `sdxl_hyper_sd_4step_lora.safetensors` | Hyper-SD performance LoRA | mashb1t/misc | `12f81a27d00a751a40d68fd15597091896c5a90f3bd632fb6c475607cbdad76e` | 787,359,648 | yes | optional | no | config.py:880 |
| 14 | `control-lora-canny-rank128.safetensors` | ControlNet canny | lllyasviel/misc | `56389dbb245ca44de91d662529bd4298abc55ce2318f60bc19454fb72ff68247` | 395,733,680 | yes | optional | no | config.py:889 |
| 15 | `fooocus_xl_cpds_128.safetensors` | ControlNet CPDS | lllyasviel/misc | `eec3fd8209a65b41341ea9f415de66909c97b30fb4d20965b3304e8e5251c2f1` | 395,706,528 | yes | optional | no | config.py:898 |
| 16 | `clip_vision_vit_h.safetensors` | CLIP vision (IP-Adapter) | lllyasviel/misc | `9a11c14945fb98c7ac9a54fab5e498885731a0780260dad7adf41f6f59655ee5` | 1,972,298,538 | yes | optional | no | config.py:911 |
| 17 | `fooocus_ip_negative.safetensors` | IP-Adapter negative | lllyasviel/misc | `d7caedfb46780825895718c7c8e9ee077e675c935ddfcf272f1c01a4fc8ea72d` | 65,616 | yes | optional | no | config.py:918 |
| 18 | `ip-adapter-plus_sdxl_vit-h.bin` | IP-Adapter plus | lllyasviel/misc | `ec70edb7cc8e769c9388d94eeaea3e4526352c9fae793a608782d1d8951fde90` | 1,013,454,427 | yes | optional | no | config.py:926 |
| 19 | `ip-adapter-plus-face_sdxl_vit-h.bin` | face IP-Adapter | lllyasviel/misc | `50e886d82940b3c5873d80c2b06d8a4b0d0fccec70bc44fd53f16ac3cfd7fc36` | 1,013,454,761 | yes | optional | no | config.py:934 |
| 20 | `fooocus_upscaler_s409985e5.bin` | Fooocus upscaler | lllyasviel/misc | `b2a66d21d2e44d2b59c53414419279763a423a61f05bc43d7c24e0489aeca5a3` | 33,636,613 | yes | optional | no | config.py:945 |
| 21 | `stable-diffusion-safety-checker.bin` | safety checker / censor | mashb1t/misc | `64b8393f1afd5a0c1ed2aa5f341fa7c08286839a48f3743162a76a2835c808bd` | 1,216,067,303 | yes | optional | no | config.py:953 |
| 22 | `sam_vit_b_01ec64.pth` | SAM ViT-B | mashb1t/misc | `ec2df62732614e57411cdcf32a23ffdf28910380d03139ee0f4fcbe91eb8c912` | 375,042,383 | yes | optional | no | config.py:974 |
| 23 | `sam_vit_l_0b3195.pth` | SAM ViT-L | mashb1t/misc | `3adcc4315b642a4d2101128f611684e8734c41232a17c648ed1693702a49a622` | 1,249,524,607 | yes | optional | no | config.py:983 |
| 24 | `sam_vit_h_4b8939.pth` | SAM ViT-H | mashb1t/misc | `a7bf3b02f3ebf1267aba913ff637d9a2d5c33d3173bb679e46d9f338c26f262e` | 2,564,550,879 | yes | optional | no | config.py:992 |
| 25 | `model_base_caption_capfilt_large.pth` | BLIP caption (interrogate) | lllyasviel/misc | `96ac8749bd0a568c274ebe302b3a3748ab9be614c737f3d8c529697139174086` | 896,081,425 | yes | optional | no | extras/interrogate.py:28 |
| 26 | `wd-v1-4-moat-tagger-v2.onnx` | WD14 anime tagger | lllyasviel/misc | `b8cef913be4c9e8d93f9f903e74271416502ce0b4b04df0ff1e2f00df488aa03` | 326,197,340 | yes | optional | no | extras/wd14tagger.py:32 |
| 27 | `wd-v1-4-moat-tagger-v2.csv` | WD14 tag list | lllyasviel/misc | **none published** (not LFS; git blob OID only) | 253,906 | yes | optional | no | extras/wd14tagger.py:38 |

Evidence: `https://huggingface.co/api/models/{repo}` and `https://huggingface.co/api/models/{repo}/tree/main?recursive=true` (accessed 2026-10-12). Pinned URL form: `https://huggingface.co/{repo}/resolve/{revision}/{path}`.

### 4.2 GitHub release artifacts (5; all unresolved)

| # | Artifact | Purpose | Release (immutable tag) | SHA-256 | Size (bytes) | Mutable? | Mandatory / optional | Call site |
|---|---|---|---|---|---|---|---|---|
| 28 | `groundingdino_swint_ogc.pth` | GroundingDINO detector | IDEA-Research/GroundingDINO `v0.1.0-alpha` | none published (`digest: null`) | 693,997,677 | tag-pinned asset (immutable in practice; admin-replaceable) | optional | extras/GroundingDINO/util/inference.py:32 |
| 29 | `detection_Resnet50_Final.pth` | facexlib face detection | xinntao/facexlib `v0.1.0` | none published | 109,497,761 | same | optional | extras/facexlib/detection/__init__.py:11 |
| 30 | `detection_mobilenet0.25_Final.pth` | facexlib face detection (light) | xinntao/facexlib `v0.1.0` | none published | 1,789,735 | same | optional | extras/facexlib/detection/__init__.py:14 |
| 31 | `parsing_bisenet.pth` | facexlib face parsing | xinntao/facexlib `v0.2.0` | none published | 53,289,463 | same | optional | extras/facexlib/parsing/__init__.py:11 |
| 32 | `parsing_parsenet.pth` | facexlib face parsing | xinntao/facexlib `v0.2.2` | none published | 85,331,193 | same | optional | extras/facexlib/parsing/__init__.py:14 |

Evidence: `https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}` (accessed 2026-10-12; all assets returned `digest: null`).

### 4.3 Other artifacts (2 tracked identities)

| # | Artifact | Purpose | Source | SHA-256 | Status | Mutable? | Call site |
|---|---|---|---|---|---|---|---|
| 33 | `deit_base_patch16_224-b5f2ef4d.pth` | ViT-B/16 init for BLIP visual encoder | `https://dl.fbaipublicfiles.com/deit/deit_base_patch16_224-b5f2ef4d.pth` (facebookresearch DeiT) | partial only: prefix `b5f2ef4d` (verified at download by torch.hub `check_hash=True`) | **unresolved** (full SHA-256 not independently published; no metadata API) | yes (mutable CDN) | extras/BLIP/models/blip_pretrain.py:41 |
| 34 | rembg model family (`u2net`, `u2netp`, `u2net_human_seg`, `u2net_cloth_seg`, `silueta`, `isnet-general-use`, `isnet-anime`) | rembg background removal | dependency-internal URLs (rembg package) | none published | **unresolved** | yes | extras/inpaint_mask.py:64 (via `rembg.new_session`) |

### 4.4 User-provided download categories (4)

| Category | Config key | Destination | Status |
|---|---|---|---|
| Checkpoints | `checkpoint_downloads` | `paths_checkpoints` subdirectory | **user-provided** |
| Embeddings | `embeddings_downloads` | `path_embeddings` | **user-provided** |
| LoRAs | `lora_downloads` | `paths_loras` subdirectory | **user-provided** |
| VAEs | `vae_downloads` | `path_vae` | **user-provided** |

Users may additionally place arbitrary `.pth/.ckpt/.bin/.safetensors/.fooocus.patch` files in any model directory (`modules/config.py:800-810`); these are never hash-checked (Stage 7 will not change that — user substitution is a product feature).

---

## 5. Integrity manifest design (implemented as `models/manifest.json`)

### 5.1 Location and format

`models/manifest.json` (repo-root `models/` directory already exists for runtime weights; the manifest is a **source-controlled data file**, excluded from `.gitignore`d weight paths by living at `models/manifest.json` with weights still ignored — implementation detail to confirm, fallback `docs/models_manifest.json`). JSON is chosen over YAML because the runtime already parses JSON configs and PyYAML is pinned but unnecessary here.

```json
{
  "schema_version": 1,
  "manifest_version": "2026.10.12.1",
  "generated_from": {
    "baseline_commit": "c4e898685c8e2408f82789337caabf997bc94cfa",
    "audit_doc": "docs/MODEL_INTEGRITY_AUDIT.md"
  },
  "artifacts": [
    {
      "id": "sdxl-lcm-lora",
      "status": "verified",
      "file_name": "sdxl_lcm_lora.safetensors",
      "purpose": "Extreme Speed performance LoRA",
      "source": {
        "type": "huggingface",
        "repo": "lllyasviel/misc",
        "path": "sdxl_lcm_lora.safetensors",
        "revision": "71f7a66a7affe631c64af469fe647217d422cac0",
        "url": "https://huggingface.co/lllyasviel/misc/resolve/71f7a66a7affe631c64af469fe647217d422cac0/sdxl_lcm_lora.safetensors"
      },
      "url_mutable": false,
      "sha256": "c3dbf7eb26dd00ae6b6b95da69be9f1cb95a3b2c5bcf9be82323227a19b91329",
      "size_bytes": 393854624,
      "evidence": [
        "https://huggingface.co/api/models/lllyasviel/misc/tree/main"
      ],
      "mandatory": false,
      "user_substitutable": false,
      "call_sites": ["modules/config.py:862"]
    }
  ],
  "user_supplied_categories": ["checkpoint_downloads", "embeddings_downloads", "lora_downloads", "vae_downloads"]
}
```

### 5.2 Status values (explicit, closed set)

| Status | Meaning | Enforcement expectation |
|---|---|---|
| `verified` | Independently published SHA-256 recorded (HF LFS OID, or maintainer-computed hash cross-signed per §5.3 for otherwise-unresolved artifacts after explicit approval) | Download must pass `expected_hash`; mismatch → fail closed, no file left behind (loader already does this) |
| `unresolved` | No independent SHA-256 currently available | Download permitted **only** with explicit per-artifact opt-in flag in the manifest (`allow_unverified: true` + justification string); warning printed; CI flags drift |
| `user-provided` | Identity chosen by the user at runtime | No hash expected; existing Stage 2/3 transport controls still apply; never auto-pinned |

### 5.3 Review and authentication of manifest updates

1. **CODEOWNERS**: `models/manifest.json` and `docs/MODEL_INTEGRITY_AUDIT.md` owned by the maintainer; any change requires a pull request.
2. **Provenance in the PR**: every new/changed `sha256` must cite the evidence URL used (HF tree API, GitHub release API, or a documented maintainer-computed hash with method, tool version, and the exact upstream revision). Reviewers verify the evidence URL resolves to the claimed value.
3. **CI cross-check (network job, scheduled + on manifest change)**: re-fetch HF tree API for every `verified` artifact and fail if upstream LFS OID for the pinned revision differs from the manifest (upstream tamper or repository rewrite detector).
4. **Unit test (offline, PR-blocking)**: every fixed URL/call-site in the tree must resolve to exactly one manifest entry (grep-driven coverage test, §8 P0 acceptance test T7).
5. **Authentication**: commit signing via GitHub-verified (GPG/SSH) commits for manifest changes; optional future step — Sigstore `cosign sign-blob` over the manifest with the attestation stored in the repo or in Rekor. Until signing keys exist, PR review + CI cross-check is the trust anchor.
6. **Revision pinning policy**: manifest URLs must use `/resolve/{commit-sha}/` (HF) or tag-pinned release assets (GitHub); `/resolve/main/` URLs are rejected by review and by the offline unit test.

---

## 6. Security and compatibility analysis

### 6.1 Model replacement and supply-chain attacks

- **Today:** an attacker who can write to a model directory, or who controls a mutable upstream URL, can substitute a model and it will be accepted (size > 0). Backdoored SDXL checkpoints/LoRAs execute arbitrary code through `torch.load` paths in `ldm_patched` unless weights-only loading is guaranteed — LoRA/checkpoint loading is a known arbitrary-code surface in the PyTorch ecosystem.
- **After Stage 7 (P0):** transport is already hardened (Stage 2/3); adding `expected_hash` closes the substitution window at rest and in transit. Manifest revision pinning closes the `/resolve/main` swap window.

### 6.2 Mutable upstream URLs

- All 27 HF URLs use `/resolve/main/` — mutable by repo owner at any time. Mitigated today only by the fact that all five audited repos have been static since 2023–2024 (last-modified dates in §4.1), which is **not** a guarantee.
- GitHub tag-pinned release assets are immutable in practice but not cryptographically authenticated (no published digest for the five audited assets).
- `dl.fbaipublicfiles.com` is a fully mutable CDN path with only a 32-bit prefix check.

### 6.3 Checksum mismatches

- Hardened loader already fails closed: mismatch on a fresh download deletes the partial file and raises (`modules/model_loader.py:1440-1445`); mismatch on an existing cached file re-downloads (`:1272-1280`). Prefix vs full-hash matching is supported (`_matches_hash`), so DeiT-style prefix pins can migrate to full hashes later.
- Risk to manage in implementation: users who already have a *legitimately different* file (e.g., a re-uploaded same-named model from an old Fooocus install) will see a hard failure once hashes are enforced. Mitigation: clear error text naming the artifact, expected/actual hash, and the override path (user-provided category or documented `FOOOCUS_ALLOW_UNVERIFIED_MODELS=1` escape hatch — decision needed).

### 6.4 Interrupted downloads

- Already handled by the hardened downloader: streamed to temp file, atomic `os.replace`, size caps for both `Content-Length` and lying/absent headers, global deadline, destination locks (Stage 2/3). Facexlib's legacy torch.hub path inherits torch.hub's temp-file behavior but none of the Stage 2/3 caps — another reason to migrate it (P1).
- No `fsync` before `os.replace` remains a documented gap (roadmap §7.3 #10) — power-loss durability, not integrity against an attacker.

### 6.5 Hugging Face redirects and CDN behavior

- `/resolve/main/` and `/resolve/{sha}/` both 302 to `cdn-lfs.huggingface.co` (in `DEFAULT_ALLOWED_HOSTS`) or `cdn-lfs*.hf.co` variants — covered by the Stage 2 redirect scrubbing (sensitive headers stripped case-insensitively, redirect destination re-validated, CONNECT-tunnel destination validated, destination IP pinned). Private/CGNAT/metadata destinations blocked.
- Residual: HF can add new CDN hostnames at any time; a new hostname fails closed until added to the allowlist. Per-artifact `allowed_domains` from the manifest (P0 design) makes this an explicit, reviewable data change instead of a code change.

### 6.6 User-supplied models and LoRAs

- The 4 user-supplied download categories (§4.4) and free placement of model files are product features. Stage 7 must **not** hash-pin them. Transport hardening (HTTPS-only, SSRF/rebinding protection, size caps, deadline) already applies to their download URLs — verified by the Stage 2/3 test suite (132 tests).
- Metadata hashing (`modules/hash_cache.py`) remains display-only; do not repurpose it as an integrity gate for user files.

### 6.7 Google Colab storage and runtime constraints

- `fooocus_colab.ipynb` clones the repo and relies on runtime persistence; models download on first use into the mounted drive. Hash verification adds one full-file read (~GB-scale) on **every** launch for cached files unless results are cached.
- Design requirement: hash-verify cached files **once per (file, manifest revision)** and record the verification in a sidecar cache (`<model>.sha256.ok` containing manifest hash), keyed by the manifest hash, so repeated Colab sessions do not re-hash 7 GB every boot. Sidecar must be invalidated whenever manifest hash or file mtime/size changes.
- Colab notebook itself is Stage 6 scope; Stage 7 must not modify it (restriction honored).

### 6.8 Legacy downloader bypasses

| Bypass | Exposure | Disposition |
|---|---|---|
| facexlib `torch.hub.download_url_to_file` (`extras/facexlib/utils/misc.py:77`) | GitHub-hosted detection/parsing weights; no allowlist, no caps, env proxies honored | P1: route through `modules.model_loader.download_url_to_file` |
| `torch.hub.load_state_dict_from_url` (DeiT, `blip_pretrain.py:41`) | mutable CDN; prefix-only hash; torch.hub cache dir | P1: pre-download via hardened loader with pinned hash, load from local path |
| `ldm_patched/k_diffusion/utils.py:37` raw `urlopen` | dead code (0 callers) — latent risk if resurrected | P1: delete (Stage 7 cleanup, approved separately) |
| rembg internal downloader | 7 mask models downloaded to user cache with no integrity controls | P1: pre-download via hardened loader into app-managed dir using manifest entries, or gate/document |
| **Functional defect:** `github.com` missing from hardened allowlist | `groundingdino_swint_ogc.pth` download fails closed on fresh installs | P0: add per-artifact `allowed_domains: ["github.com", "objects.githubusercontent.com"]` via manifest (explicit, reviewable) rather than widening the global default |

### 6.9 Residual risks accepted (for the record)

1. HF LFS OID is self-asserted by the upstream repository owner; it protects against CDN/network substitution and accidental upstream rewrite, not against a malicious upstream publisher. Publisher trust is the same trust already placed in `lllyasviel`/`mashb1t`/`stabilityai`.
2. GitHub release assets without published digests remain unverifiable without maintainer-computed hashes (option in §5.3 step 2).
3. `DEFAULT_MAX_DURATION=1800 s` may abort legitimate 6–10 GB downloads on slow links (roadmap §7.2 #3) — interacts with integrity because a deadline-aborted download leaves no file (safe) but users may then disable verification to work around timeouts (unsafe behavior drift to watch).

---

## 7. Classification summary

| Integrity status (identity) | Artifacts | Call sites |
|---|---|---|
| **verified** (independent SHA-256 available) | 26 | 24 fixed-artifact hardened call sites (config.py ×18, launch.py ×2, extras ×4) + 2 verified defaults (juggernaut checkpoint, offset LoRA) reached through the 4 user-URL loops |
| **unresolved** (no independent SHA-256) | 8 audit categories (1 HF CSV, 5 GitHub assets, 1 DeiT prefix-only, 1 rembg family) = **14 manifest entries** (rembg listed per-file) | 5 legacy/bypass sites + wd14 CSV site + GroundingDINO site (GitHub allowlist defect) |
| **user-provided** | 4 categories | 4 launch.py loops (which also carry the 2 verified defaults above) |
| **Enforcement (audit time)** | 0 of 32 call sites pass `expected_hash`; existing files trusted on size > 0 | **After P0:** 24 fixed sites + verified user-URL pairs enforced (§10) |

Exact discovered download paths: **32 in-repo call sites** (28 hardened-loader, 2 legacy-facexlib, 1 torch.hub, 1 dead raw-urlopen) **+ 1 dependency-internal** (rembg), covering **34 fixed artifact identities** plus **4 user-supplied categories**. Previous roadmap estimate of 30 `load_file_from_url` call sites was close but understated the true total: 28 hardened call sites plus 4 non-`load_file_from_url` download mechanisms.

---

## 8. Implementation plan (P0 implemented 2026-10-12, uncommitted; P1–P3 await approval)

### P0 — Enforce identity for verified artifacts (highest priority)

1. Land `models/manifest.json` (schema §5.1) with all 26 `verified` entries; `unresolved` entries carry `allow_unverified: true` + justification (initially: GitHub assets, DeiT, rembg family, wd14 CSV).
2. Change the 24 fixed-artifact hardened call sites to build URLs from the manifest (pinned `/resolve/{revision}/` for HF; keep GitHub URLs with per-artifact `allowed_domains`), and revision-pin the 2 verified preset defaults carried by the user-URL loops.
3. Enforce existing-file verification: with `expected_hash` set, the loader already re-verifies cached files; add sidecar verification cache for Colab (§6.7).
4. Add `github.com`/`objects.githubusercontent.com` per-artifact allowlist entries (fixes the GroundingDINO fail-closed defect without widening the global default).

**Acceptance tests (P0):**
- T1: `python -m unittest tests.test_model_loader` remains green (132+).
- T2: new tests: manifest-driven download with correct hash succeeds; wrong hash fails closed and leaves no file; cached file with wrong hash is re-downloaded; `/resolve/main` URL in manifest fails the offline unit test.
- T3: GroundingDINO download succeeds with per-artifact allowlist and fails for a non-allowlisted GitHub path.
- T4: live (network, CI-optional) verification of one small artifact (`xlvaeapp.pth`, 209 KiB) against manifest hash.
- T5: `requirements_versions.txt` sha256 unchanged; no new dependencies.

### P1 — Eliminate legacy bypasses

1. Route facexlib downloads through `modules.model_loader.download_url_to_file` (drop `torch.hub` import).
2. Pre-download DeiT via hardened loader with full SHA-256 (maintainer computes once from upstream file, evidence recorded per §5.3); load BLIP from local path.
3. Delete dead `ldm_patched/k_diffusion/utils.py:37` `download_file`.
4. rembg: pre-download the 7 model files via hardened loader using manifest entries (hashes to be established the same way as GitHub assets), or ship `unresolved` status with explicit runtime warning.

**Acceptance tests (P1):**
- T6: repo-wide scan test (already patterned in `tests/test_model_loader.py:1445-1501`) extended to assert no `torch.hub.download_url_to_file`, no `load_state_dict_from_url`, no raw `urlopen` download helpers remain outside `modules/model_loader.py`.

### P2 — CI and drift detection

1. Offline PR-blocking test: every fixed URL/call-site maps to exactly one manifest entry (coverage, prevents "new download without identity").
2. Scheduled network job: re-verify HF LFS OIDs for pinned revisions; open an issue on mismatch.
3. Extend Security CI matrix to run the new manifest tests (workflow already exists: `.github/workflows/security-ci.yml`).

**Acceptance tests (P2):**
- T7: deleting any manifest entry breaks CI (coverage test); adding a hardcoded HF URL in a `.py` file breaks CI.
- T8: scheduled job dry-run completes against the five HF repos with zero drift.

### P3 — Deferred / needs product decision

1. Maintainer-computed SHA-256 for the 5 GitHub assets + DeiT full hash (requires downloading ~1.0 GB total — approval + bandwidth needed; can be computed by upstream maintainers' published values if any appear later).
2. Colab-specific verification caching UX (Stage 6 overlap).
3. `DEFAULT_MAX_DURATION` vs multi-GB downloads (roadmap §7.2 #3, product decision).

**Explicitly out of scope for Stage 7 implementation:** changing user-supplied model/LoRA policy, dependency upgrades (Stage 4), notebook changes (Stage 6), GPU tests (Stages 9/10).

---

## 9. Audit limitations

- Identity data reflects upstream state on 2026-10-12; HF `main` revisions can change (the manifest pins them, the scheduled job detects drift).
- GitHub release digests were `null` in the API for all five assets; no hashes were fabricated to fill the gap.
- No model bytes were downloaded during this audit (restriction honored); size and hash values are upstream-asserted metadata.
- The GroundingDINO fail-closed finding is derived from allowlist code review plus the absence of any `github.com` entry or per-call `allowed_hosts` override at that call site; it was not reproduced with a live download (large file, restriction).
- rembg's internal download URLs were not asserted from the dependency source in this audit (package not installed in the inspection environment); marked unresolved for verification at implementation time.

---

## 10. P0 implementation record (2026-10-12, uncommitted — awaiting approval)

Implemented on branch `stage7-model-integrity-audit` in the Stage 7 worktree,
baseline `c4e8986`. No dependency, notebook, or configuration-default changes;
`requirements_versions.txt` sha256 unchanged (`2b4972930f47541ab1f59634d7fd255914b5e292529e4a350652bfc9e8b71310`).

**What landed**

| Piece | File(s) | Summary |
|---|---|---|
| Manifest | `models/manifest.json` | `manifest_version 2026.10.12.1`; **40 entries = 26 verified + 14 unresolved**; 4 `user_supplied_categories`; GroundingDINO entry carries `allowed_domains: ["github.com", "release-assets.githubusercontent.com"]` (redirect chain verified with HEAD: `github.com` 302 → `release-assets.githubusercontent.com`). |
| Manifest API | `modules/model_manifest.py` (new) | `load_manifest()` validation (unique ids; verified ⇒ 64-hex sha + non-mutable `https` URL + no `/resolve/main/`), `get_artifact`, `download`, `download_user_supplied`, `ManifestError` / `MissingManifestEntryError`. |
| Loader | `modules/model_loader.py` | `CachedFileIntegrityError` + `cached_hash_mismatch` param on `download_file`/`load_file_from_url` (`"redownload"` default preserves legacy behavior; `"fail"` raises with removal remediation). |
| Fixed call sites ×24 | `modules/config.py` ×18, `launch.py` ×2, `extras/interrogate.py`, `extras/wd14tagger.py` ×2, `extras/GroundingDINO/util/inference.py` | All URL literals replaced by manifest ids; return paths byte-identical to before. |
| User-URL loops ×4 | `launch.py` | `download_user_supplied(file_name, url, …)` — hash enforced only when the pair matches a verified entry (pinned or `mutable_url` alias), so user substitution keeps working. |
| Tests | `tests/test_model_integrity.py` (new, 27 tests) | See acceptance results below. |
| CI | `.github/workflows/security-ci.yml` | Run line now `tests.test_model_loader tests.test_model_integrity` (actionlint clean). |

**Acceptance results (§8)**

- **T1 ✅** `tests.test_model_loader` green: **160/160 combined suite** on Python 3.10, 3.12, 3.14 (132 pre-existing loader tests + 27 integrity tests + 1 signature-test update for the new kwarg).
- **T2 ✅** correct-hash download succeeds; wrong hash fails closed with no artifact file left (lock file excluded by design, §7.3 #9); **deviation:** the plan said "cached file with wrong hash is re-downloaded" — manifest-driven downloads now **fail closed** (`CachedFileIntegrityError`, explicit removal required) per the approved fail-closed requirement; the legacy default remains `redownload` (both paths covered by tests).
- **T3 ✅** GroundingDINO: per-artifact allowlist accepted (`github.com` → `release-assets.githubusercontent.com`), non-allowlisted host and missing allowlist both refused before any network call; redirect handler refusal covered directly.
- **T4 ⏭ skipped (by restriction)** — live network verification of `xlvaeapp.pth` not run; no model bytes downloaded.
- **T5 ✅** no dependency changes; `requirements_versions.txt` untouched.
- **T7 ✅ (offline, PR-blocking)** — coverage test: every `manifest_download` id in `config.py`/`launch.py`/extras must exist in the manifest (deleting an entry breaks CI); repo-wide scan: no `huggingface.co/.../resolve/` URL literal exists in any tracked `.py` outside `tests/` (adding one breaks CI).
- T6/T8 remain P1/P2 scope.

**Residual (unchanged, P1+):** 4 facexlib GitHub URL literals (`extras/facexlib/**/__init__.py`) use the legacy prefix-only path; BLIP/DeiT torch.hub downloads; rembg internal downloader (7 files, `unresolved`); dead `ldm_patched` raw-`urlopen` helper; sidecar verification cache for Colab (§6.7) not implemented. Of the 14 `unresolved` entries, only the 2 wired ones (wd14 CSV, GroundingDINO) download through the manifest — both with `allow_unverified: true` + justification, i.e. **without hash verification but with a logged integrity warning**; the other 12 (4 facexlib, DeiT, rembg ×7) are not wired yet and keep their legacy prefix-only paths until P1, and `manifest_download` refuses them by default until hashes are established.

**Explicit non-goals honored:** no hash-mismatch override flag, no widened allowlist defaults, no TLS/SSRF/redirect/proxy weakening, no Colab notebook edits, no commit/push.

---

## 11. Post-review corrections — L1, L2, L3, L5 (2026-10-12)

P0 passed security acceptance review conditionally; the four mandated
corrections below were applied. All counts in this section **supersede** the
test counts in §10. The reviewer explicitly approved the fail-closed
cached-hash-mismatch behavior (M2) and required M1 to remain a documented
residual risk.

### L1 — Manifest entry types (`modules/model_manifest.py:96-102`)

`_validate_entry` now rejects non-dictionary artifact entries with a
`ManifestError` (`"artifacts[N] must be a JSON object, got <type>"`) before any
attribute access, replacing the previously observed uncaught `AttributeError`.
Applies to any position in the artifacts list, including after valid entries.

### L2 — `allowed_domains` validation (`modules/model_manifest.py:64-86`)

The optional `allowed_domains` field is validated at manifest load: it must be
a **non-empty list** of non-empty strings, each a canonical DNS domain matching
`^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`
(case-insensitive). Rejected: bare strings, empty lists, non-string/empty
elements, schemes (`https://…`), ports (`:443`), paths (`/…`), wildcards
(`*.`), underscores, leading/trailing hyphens, trailing dots, whitespace, and
non-list JSON types. The sole production value
(`groundingdino-swint-ogc → ["github.com", "release-assets.githubusercontent.com"]`)
passes unchanged.

### L3 — `file_name` validation (`modules/model_manifest.py:49-62`)

Every entry's `file_name` is validated at manifest load: must be a string,
non-empty, untrimmed-whitespace-free, not `.`/`..`, and free of path separators
(`/`, `\`), drive prefixes (`:`), Windows-reserved characters (`<>:"|?*`),
control codes/NUL (`0x00-0x1F`, `0x7F`), and lengths >255. The downloader's
`_safe_destination` (`modules/model_loader.py:692-716`) is untouched and
remains as defence in depth — manifest validation adds an earlier, explicit
rejection layer only.

### L5 — `call_sites` metadata (`models/manifest.json`)

25 stale line references corrected to the current post-P0 source lines:
`launch.py` (vae-approx loop → `:160` ×3, expansion → `:169`, juggernaut preset
loop → `:232`, offset-LoRA loop → `:253`), `modules/config.py` (23 entries:
`:831,835,839,846,851,856,861,866,875,878,882,886,893,897,914,919,924` — the
already-correct `fooocus-inpaint-head :826` was left as-is), and
`extras/wd14tagger.py` (`:30`, `:35`). All 40 entries' `call_sites` were
re-verified programmatically: each reference resolves to a source line
containing the expected call (`manifest_download` / `download_user_supplied` /
legacy P1 symbols). Legacy P1 references (facexlib ×4, BLIP/DeiT `:41`, rembg
`:64`) were already accurate and unchanged.

### Regression tests

8 new tests in `tests/test_model_integrity.py`
(`TestManifestSchemaCorrections`): L1 non-dict entries (str/int/None/list/bool,
alone and after a valid entry) → `ManifestError`; L2 16 malformed
`allowed_domains` variants rejected + valid list accepted + absent field
accepted; L3 21 invalid `file_name` variants rejected + 5 valid names accepted
+ real 40-entry manifest still validates.

### Final test results (supersede §10)

| Suite | 3.10.19 | 3.12.12 | 3.14.4 |
|---|---|---|---|
| `tests.test_model_loader` (132) + `tests.test_model_integrity` (36) + `tests.test_extra_utils` (1) = **169** | OK | OK | OK |

### Confirmations after corrections

1. **26 verified SHA-256 values unchanged** — sorted `(id, sha256)` digest
   `8b821bc7c501cd270d96104dec2a63bb262bb319f1c7e50119b2cba84bc1efe8`
   identical before/after; still 26/26 vs live HF API LFS OIDs (§10).
2. **24 converted sites remain wired** — 26 manifest ids resolve
   (config ×18, launch loop+expansion ×4 ids, extras ×4); wiring tests green.
3. **No transport protections weakened** — `modules/model_loader.py` and the
   Security CI workflow are byte-identical to the accepted state (diff
   checksums `4d782964…` and `78b86279…` unchanged this round); TLS, SSRF,
   DNS/IP validation, proxy policy, and redirect validation untouched; full
   security suite green on all three interpreters.
4. **GroundingDINO remains scoped** — `allowed_domains` exists on exactly one
   entry, `["github.com", "release-assets.githubusercontent.com"]`.
5. **Cached SHA-256 mismatches still fail closed** — `TestCorruptedCachedArtifact`
   (3 tests) green; `CachedFileIntegrityError` with explicit-removal
   remediation unchanged.
6. **No dependencies or notebooks modified** — `requirements_versions.txt`
   sha256 `2b4972930f47541ab1f59634d7fd255914b5e292529e4a350652bfc9e8b71310`
   unchanged; no `.ipynb` in the change set; `model_manifest.py` remains
   stdlib-only.

### Preserved risks (unchanged by this round)

- **M1 (Medium, residual):** manifest tampering is not mechanically detectable
  — no signature, and CI validates structure/wiring but not sha↔upstream
  (P2 drift job unimplemented, out of scope for P0). **`models/manifest.json`
  must be reviewed line-by-line before merging.**
- **M2 (Medium, approved):** startup hard-fails on a cached official file whose
  sha256 mismatches (`launch.py:357` → `CachedFileIntegrityError`, no silent
  redownload) — approved fail-closed behavior, remediation printed.
- Low-severity leftovers deferred (not in scope): L4 (`size_bytes` not passed
  as `max_size`), L6/L7/L8 (allowlist suffix semantics, load-time TOCTOU,
  warning-set thread-safety).
