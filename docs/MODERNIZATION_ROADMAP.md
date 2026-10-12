# Fooocus-Modern — Modernization Roadmap

Repository: https://github.com/WURAlex/Fooocus-Modern.git
Development branch: `modern-platform`
Document created: 2026-10-12 (independent inspection, read-only)
Last updated: 2026-10-12 — Stage 2 repair session + Stage 3 validation tests (approved)

This document records the original 14-stage modernization plan, the acceptance
criteria for each stage, **independently verified** progress, unresolved issues,
and the prioritized next steps.

---

## 1. How completion status is reported

Every stage carries exactly one of these labels:

| Label | Meaning |
|---|---|
| **VERIFIED COMPLETE** | Inspected/executed during the 2026-10-12 review; evidence cited in this document. |
| **VERIFIED PARTIAL** | Some criteria verified as met, at least one verified as unmet. |
| **REPORTED, NOT VERIFIED** | A previous tool session claimed completion; no independent evidence exists. |
| **NOT STARTED** | No implementation found. |
| **VERIFIED BROKEN** | Inspected and confirmed non-functional. |

Historical claims made by Codex/Antigravity are reproduced verbatim in
"Previous claim" columns and are **not** treated as facts.

GPU-dependent claims are never marked verified unless a run actually occurred
on a GPU. **No GPU test has been run as of this document's creation.**

---

## 2. Repository state (verified 2026-10-12)

| Item | Verified value |
|---|---|
| Primary checkout | `/home/alex/Fooocus-Modern` |
| Current branch | `feature/harden-model-downloader` (note: not `modern-platform`) |
| HEAD | `4fae360 Harden launcher and model downloads` |
| Primary working tree | ` M modules/model_loader.py`, `?? tests/test_model_loader.py`, `?? docs/MODERNIZATION_ROADMAP.md` — **nothing committed** |
| `modern-platform`, `origin/modern-platform` | both `4fae360` (identical to HEAD) |
| Stashes | none |
| Second worktree | `/home/alex/.gemini/antigravity/worktrees/Fooocus-Modern/harden_model_downloader`, branch `harden_model_downloader`, HEAD `4fae360`, **2 uncommitted artifacts** (see §3) — untouched by the repair session, still ` M ` + `??` |
| Commit history | `ae05379` (upstream baseline) → `3c8b447 docs: establish Fooocus Modern baseline` → `4fae360 Harden launcher and model downloads` |
| Tags | upstream only (`v2.4.1` … `v2.5.5`); no modernization tag |
| CI | `.github/workflows/build_container.yml` (Docker build only). **No test/CI workflow exists.** |
| Test environment | Python 3.14.4, `torch` not installed, `numpy` not installed; no dependencies installed during inspection |
| Test results (2026-10-12, post-repair) | `python3 -m unittest tests.test_model_loader` → **Ran 85 — OK** (3 consecutive runs); `discover -s tests` → Ran 87 — 1 error (`tests/test_utils` needs `numpy`) |

---

## 3. Existing modernization changes (verified)

### 3.1 Committed (reachable from `modern-platform`)

`3c8b447` added `docs/BASELINE.md` (upstream baseline `ae05379`, project
objectives).

`4fae360` changed 5 files:

| File | Change |
|---|---|
| `entry_with_update.py` | Git self-update removed (see Stage 1) |
| `launch.py` | TLS verification bypass removed (see Stage 3), self-update/config hooks removed, hardened VAE/auxiliary download block |
| `modules/model_loader.py` | First hardening pass: HTTPS-only allowlist, `HF_MIRROR` validation, path-traversal guard, temp file + atomic `os.replace` |
| `fooocus_colab.ipynb` | updated (still broken, see Stage 6) |
| `requirements_versions.txt` | `pygit2==1.15.1` removed |

### 3.2 Uncommitted Stage 2 artifacts (worktree + primary checkout)

Original copies (untouched, must be preserved):

```
/home/alex/.gemini/antigravity/.../harden_model_downloader/
 M modules/model_loader.py     943 insertions(+), 64 deletions(-)   155 → 1034 lines
 ?? tests/test_model_loader.py  new file, 973 lines, 54 tests
```

This is the substantive Stage 2 work: a pure-standard-library downloader with
redirect hardening, DNS pinning, size caps, deadlines, retries, locking, and
streaming SHA-256 verification, plus its test suite.

**Transfer of 2026-10-12 (approved, safe):**

| Check | Result |
|---|---|
| Locations searched | `find /home/alex -name model_loader.py` → only the two copies below |
| Primary checkout before transfer | `modules/model_loader.py` = committed 155-line file, `f724a72d…`, fully recoverable via `git show HEAD:modules/model_loader.py`; `tests/test_model_loader.py` **did not exist** |
| Worktree copies (source) | `14c6a84d…` (loader, 2026-10-12 00:24), `571669fb…` (tests, 2026-10-12 00:26) — newest anywhere |
| Backups taken before overwrite | `/tmp/opencode/stage2_backup/{worktree_model_loader.py,worktree_test_model_loader.py,committed_model_loader.py,HEAD_model_loader.py}` |
| Post-transfer identity | `diff -q` identical for both files; sha256 matches the worktree originals |
| Worktree afterwards | still ` M ` + `??` — **no file in the worktree was modified** |

---

## 4. The 14-stage plan (verbatim)

1. Remove Git self-update.
2. Harden model downloader.
3. Remove TLS verification bypass completely.
4. Modernize the Python/PyTorch/CUDA dependency stack.
5. Modernize Gradio and related packages.
6. Fix and update the Google Colab notebook.
7. Review model URLs and model integrity.
8. Review subprocess, network, and update behavior.
9. Review VRAM/GPU detection and Colab compatibility.
10. Test generation: SDXL → LoRA → image prompt → inpainting.
11. Add startup and security validation.
12. Create the final Fooocus-Modern Colab launcher.
13. Test from a clean Google Colab runtime.
14. Commit and tag the modernized fork.

Sequence must be preserved. Stages may be *prepared* out of order (analysis,
tests, docs), but no stage is declared complete out of order.

---

## 5. Stage-by-stage status

### Stage 1 — Remove Git self-update — **VERIFIED COMPLETE**

Evidence (commit `4fae360`):

- `entry_with_update.py` rewritten to a 13-line trampoline (`from launch.main`);
  the previous `pygit2` import, `remote.fetch()`, `merge_analysis`,
  `repo.reset(..., GIT_RESET_HARD)` logic is gone.
- `pygit2==1.15.1` removed from `requirements_versions.txt`.
- Repository-wide search over tracked `.py`/`.txt`/`.ipynb` for
  `pygit2`, `git pull`, `git fetch`, `import git`, `repo.git` → **0 hits**.
- `modules/config.py:813 update_files()` re-inspected: it only rescans the local
  model/preset folders (no network, no git). Benign.

Acceptance criteria: self-update absent, `pygit2` absent, no reintroduction — **met**.
Residual: **no regression test guards against reintroduction** (recommended in §8).

### Stage 2 — Harden model downloader — **VERIFIED PARTIAL (not accepted)**

Historical claim (Antigravity): "*43 downloader tests passed, including a small
live HTTPS download with SHA-256 verification*"; a follow-up run reported
"*43 tests … FAILED (failures=1, errors=2)*".

Verified findings:

**a) Test inventory — the claimed 43 tests do not exist as stated.**
`tests/test_model_loader.py` exists **only in the worktree** and contains
**54** test methods in 13 classes (43 + 11 new: DNS-rebinding 5, proxy 2,
size 2, deadline 1, concurrency 1). The historical report also cites class
names that no longer exist (`TestDownloadFileStreamingAndIntegrity`,
`TestWrappers`) and its per-class counts do not sum to 43.

**b) Current results (executed 2026-10-12, no dependencies installed):**

| Command | Result |
|---|---|
| `python3 -m unittest tests.test_model_loader` (worktree) | **Ran 54 — FAILED (failures=2, errors=2)** → 50 green / 4 red |
| `python3 -m unittest discover tests` (worktree) | Ran 56 — FAILED (failures=2, errors=3) (+ `test_utils` numpy import error) |
| `python3 -m unittest discover tests` (primary checkout) | Ran 2 — FAILED (errors=1) — **no downloader tests at all** |
| same suite with the concurrency test excluded | Ran 53 → **50 pass / 3 red** |
| `TestRealHTTPSIntegration` in isolation | **PASS** — 213 777 bytes, sha256 `6c8db511f910184436a613807ce06a729f4cf96bbf7977c7c6c40d5b3e4a8333`, independently confirmed against a `curl` download |

**c) The 4 red tests and their root causes (all diagnosed):**

| # | Test | Failure | Root cause |
|---|---|---|---|
| 1 | `test_max_size_enforced_with_content_length` | ERROR | mock missing `mock_resp.__enter__.return_value = mock_resp` → `resp.status` is a `MagicMock` → `RuntimeError: HTTP request failed with status <MagicMock…>` |
| 2 | `test_max_size_enforced_without_content_length` | FAIL | asserts the temp dir is empty, but `download_file` leaves the persistent `.<name>.lock` file |
| 3 | `test_total_download_deadline_enforced` | FAIL | same leftover `.lock` file |
| 4 | `test_live_https_download_with_redirect_and_checksum` | ERROR | `test_concurrent_downloads_thread_safety` enters/exits `patch("urllib.request.build_opener")` concurrently from 4 threads; `mock.patch` is not thread-safe, so `urllib.request.build_opener` stays replaced by a `MagicMock` for the rest of the process. Proven: the live test's "downloaded" bytes hash to `cabb71b1712c19d2ea9d329244503ac3685cd0531205666da491e44749ccd2c3` = sha256 of the concurrency test's canned payload |

**d) Required security controls (your Stage 2 verification list):**

| Control | Verdict | Evidence |
|---|---|---|
| DNS rebinding protection | **FAIL in the production path** | `_resolve_and_validate_addresses` (`modules/model_loader.py:253-260`) short-circuits when `host in allowed_hosts`. `SafeHTTPSConnection` is *always* built with `allowed_hosts=eff_hosts`, which contains the requested host, so a mocked `getaddrinfo → 127.0.0.1` yields `('127.0.0.1', 443)` instead of raising. The 5 rebinding tests call it with `allowed_hosts=None`, so they pass while the deployed code is unprotected. |
| Proxy cannot bypass destination validation | **FAIL (partial)** | Tunnel branch (`:406-415`) validates only the *proxy* host; `_resolve_and_validate_addresses` is never called for the target, so `HTTPS_PROXY` silently disables DNS pinning. Also `self.host.split(":")[0]` mangles IPv6 proxies (`fe80::1` → `fe80` → `blocked=False`). Proxy tests only exercise hostname allowlisting, not the DNS layer. |
| Maximum download size | **PASS** | pre-read `Content-Length` check (`:857-865`) and per-chunk check before `write` (`:901-911`); default cap 50 GiB; both size tests green modulo the defects above. |
| Total download deadline | **PARTIAL** | deadline checked per chunk (`:876-883`) but `download_start_time` resets **inside the retry loop** (`:837`) and deadline expiry raises `TimeoutError`, classified transient (`:653`) → observed retries 1s/2s/4s after expiry. Not a *total* deadline. |
| Concurrent-download safety | **PASS (implementation)** / test defective | `DestinationLock` (`:56-99`) = per-path thread lock + `flock(LOCK_EX)` acquired before the cache check (`:777`); unique `mkstemp` temps; atomic `os.replace`; 4-thread test green. Weaknesses: lock file persists forever, `os.open` lacks `O_NOFOLLOW`, `_THREAD_LOCKS` grows unboundedly. |

**e) Other Stage 2 acceptance criteria:**

| Criterion | Verdict |
|---|---|
| Import downloader without PyTorch | **PASS in worktree**, **FAIL in committed tree** (primary checkout still has `from torch.hub import download_url_to_file`, `modules/model_loader.py:7` → `ModuleNotFoundError` without torch) |
| Every Fooocus call site still compatible | **PASS** (30 call sites inspected: `launch.py` 6, `modules/config.py` 18, `extras/` 6) |
| Redirect security (HTTPS-only, allowlist, loops, hops) | **PASS** for scheme/host/loop/hop; **PARTIAL** for headers: `Proxy-Authorization` survives cross-origin redirects because `Request` normalizes keys via `str.capitalize()` while the stripper deletes `"Proxy-Authorization"` (`:506-512`). Proven: post-redirect headers = `{'Proxy-authorization': 'Basic x'}`. The test asserts the wrong key case → **false PASS**. |
| Existing valid files preserved on failed replacement | **PASS** (test green) |
| Dependency stack untouched | **PASS** (`requirements_versions.txt` unchanged by the worktree work) |
| No unauthorized git operations | **PASS** (nothing committed/pushed) |

**Stage 2 verdict at inspection time: NOT ACCEPTED.** The code is largely
sound, but two HIGH vulnerabilities were open, the suite was not green, and the
primary checkout did not contain the work. *(The tables above record the
pre-repair state; see the continued Stage 2 section below for the approved
repair session and its results.)*

### Stage 2 (continued) — approved repair session (2026-10-12)

Authorized by the maintainer: repair Stage 2 on the existing feature branch,
follow this document, no commits/push/merges/tags, no dependency changes, no
notebook edits, no Stage 4.

**a) Work preserved and transferred safely** — see §3.2.

**b) Security findings fixed (verified before → after with
`/tmp/opencode/verify_before_after.py`, which runs the same checks against the
pre-repair file and the repaired file):**

| # | Severity | Finding | Pre-repair | Post-repair | Fix |
|---|---|---|---|---|---|
| 1 | HIGH | DNS rebinding: `host in allowed_hosts` short-circuit let an allowlisted hostname resolve to a private IP | **VULNERABLE** (127.0.0.1 accepted) | **BLOCKED** | `_resolve_and_validate_addresses`: only a *literal IP that is itself allowlisted* may be private; the literal-IP branch was also un-swallowing (its `raise` sat inside `except ValueError: pass`) |
| 2 | HIGH | CONNECT tunnel validated only the proxy, never the destination → `HTTPS_PROXY` disabled DNS pinning | **VULNERABLE** (tunnel opened unvalidated) | **BLOCKED** | tunnel branch now runs `_validate_target_host` + `_resolve_and_validate_addresses` for the target; on any doubt it fails closed |
| 3 | MED | IPv6 proxy parse `self.host.split(":")[0]` turned `fe80::1` into `fe80` → not an IP → check skipped | **VULNERABLE** (link-local proxy accepted) | **BLOCKED** | new `_hostname_without_port()`; `http.client` already splits host/port, so the raw host is used |
| 4 | MED | Proxy *name* resolving to a private address was never resolved/checked | not tested | **BLOCKED** (fail closed) | proxy answer resolved and validated with the same rules; explicit allowlist opt-in still possible |
| 5 | MED | `Proxy-Authorization` leaked cross-origin (`capitalize()` vs `Proxy-Authorization`) | **VULNERABLE** (`Proxy-authorization` survived) | **BLOCKED** | case-insensitive strip over `headers` **and** `unredirected_hdrs`; test now asserts lowercase keys |
| 6 | MED | Deadline reset per attempt and expiry was retried (observed 1 s/2 s/4 s sleeps after expiry) | **VULNERABLE** (deadline retried) | **BLOCKED** — deadline terminal, read timeouts still retryable | single `download_deadline_start` before the retry loop, new `DownloadDeadlineExceeded(TimeoutError)`, non-transient, checked before each attempt, before each read, and before each backoff sleep (sleep clamped to the remaining budget) |
| 7 | MED | `100.64.0.0/10` (CGNAT) and other special-use ranges not blocked | **VULNERABLE** | **BLOCKED** | explicit `_NON_PUBLIC_NETWORKS` list + `not ip.is_global` + NAT64/6to4 embedded-IPv4 checks (only blocks when the *embedded* IPv4 is non-public, so DNS64 for public targets still works) |
| — | control | Size cap with and without `Content-Length` | already enforced | still enforced | added a third test for a server whose `Content-Length` *understates* the stream |
| — | control | Concurrency/atomicity/cleanup | sound | hardened | `O_NOFOLLOW` on the lock file (symlink → `ValueError`, fail closed), refcounted `_THREAD_LOCKS` (no unbounded growth), `hashlib.new()` before `mkstemp()` + fd hand-off guard (no fd/temp leak), `__enter__` failure releases the thread lock (a failed `__enter__` never reaches `__exit__`) |

**c) Test repairs (root causes from the 4 red tests; no security assertion was
weakened):**

| Test | Defect | Repair |
|---|---|---|
| `test_max_size_enforced_with_content_length` | mock missing `__enter__` | `mock_resp.__enter__.return_value = mock_resp` |
| `test_max_size_enforced_without_content_length`, `test_total_download_deadline_enforced` | asserted an *empty* temp dir while `DestinationLock` persists `.<name>.lock` by design | shared `_residual_files()` helper ignores `*.lock` only (temp/download files still must be gone); new `test_lock_file_is_persistent_by_design` documents why the lock must not be deleted |
| `test_concurrent_downloads_thread_safety` | `patch()` entered/exited from 4 threads → leaked a `MagicMock` into `urllib.request.build_opener` | one patch scope around the whole run; asserts `build_opener` was restored, `call_count == 1` (proves `DestinationLock` serialises) and `open.call_count == 1` |
| `test_cross_origin_sensitive_headers_stripped` | asserted `"Proxy-Authorization"` but `Request` stores `Proxy-authorization` → **false PASS** | case-insensitive assertions over both header dicts + new `test_sensitive_headers_stripped_regardless_of_storage_case` |

**d) New regression tests added (26):** `TestDNSRebindingProductionPathRegression`
(8, all run with the *production* `allowed_hosts=DEFAULT_ALLOWED_HOSTS`),
`TestProxyTunnelDestinationValidationRegression` (8: untrusted tunnel target
rejected before DNS, private destination rejected, DNS failure fails closed,
private proxy-by-name rejected, IPv6 link-local/loopback/IPv4 link-local proxies
rejected, public IPv6 proxy still allowed),
`TestTemporaryFileAndLockHygiene` (4: bad hash algorithm leaves no temp file or
fd, lock registry not leaked, symlinked lock rejected, lock persistence),
`TestTLSVerificationNeverDisabled` (6, see the continued Stage 3 section), plus
`test_max_size_enforced_when_content_length_understates`,
`test_deadline_spans_retries_and_backoff`,
`TestDeadlineErrorIsNotRetried` (2).

**e) Test results (executed 2026-10-12, no dependencies installed):**

| Command | Result |
|---|---|
| `python3 -m unittest tests.test_model_loader` | **Ran 85 — OK** (8.9 s → 2.6 s after removing the illegal deadline retries) |
| same, 3 consecutive runs | **85 — OK, 85 — OK, 85 — OK** (no flakiness) |
| `python3 -m unittest discover -s tests` | Ran 87 — FAILED (errors=1): `tests/test_utils` import needs `numpy` (**pre-existing**, dependency install forbidden) |
| `python3 -m unittest tests.test_extra_utils` | Ran 1 — OK |
| Pre-repair baseline (same day, before any edit) | Ran 54 — FAILED (failures=2, errors=2) → 50 green / 4 red |

**f) Acceptance assessment — Stage 2:** every item on the approved task list is
implemented and covered by tests. Two HIGH and four MEDIUM findings are fixed
and proven against the pre-repair code. **Recommended status: VERIFIED COMPLETE
(pending your sign-off).** Remaining risks are recorded in §7 (deferred), none
of them opened by this work.

### Stage 3 — Remove TLS verification bypass completely — **VERIFIED COMPLETE (code); test missing**

Historical status said "not yet completed"; inspection contradicts that:

- Upstream baseline `ae05379:launch.py:16` contained
  `ssl._create_default_https_context = ssl._create_unverified_context`.
- That line was **removed in `4fae360`**.
- Current repository-wide search for `unverified_context`, `CERT_NONE`,
  `check_hostname = False`, `verify = False`, `verify=False`,
  `_create_unverified`, `trusted-host`, `PYTHONHTTPSVERIFY`, `CURL_CA_BUNDLE`,
  `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` → **0 hits**.
- The hardened downloader uses `ssl.create_default_context()` (`:821`).

Residual work at inspection time: add an automated test that fails if any of
those patterns reappear, and remove the now-unused `import ssl` at
`launch.py:3`.

### Stage 3 (continued) — validation tests (2026-10-12, approved task 4)

Automated regression tests added in `tests/test_model_loader.py`
(`TestTLSVerificationNeverDisabled`, 6 tests):

| Test | What it proves |
|---|---|
| `test_no_tls_bypass_patterns_in_repository` | Scans every `.py/.ipynb/.sh/.txt/.cfg/.toml/.yml/.yaml/.ps1/.bat` file in the repo (excluding `.git`, `__pycache__`, venvs and the test file itself) for 14 bypass patterns: `_create_unverified_context`, `CERT_NONE`, `check_hostname = False`, `ssl.wrap_socket(`, `verify=False`, `PYTHONHTTPSVERIFY`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `--trusted-host`, `_create_default_https_context =`, … → fails if any reappears |
| `test_default_ssl_context_requires_certificates_and_hostname` | `ssl.create_default_context()` → `verify_mode == CERT_REQUIRED`, `check_hostname is True` |
| `test_model_loader_builds_a_verifying_context` | the downloader source contains `ssl.create_default_context()` and no bypass |
| `test_launch_py_contains_no_tls_bypass` | `launch.py` (the file that historically disabled verification) is clean |
| `test_live_handshake_accepts_valid_certificate` | a real TLS handshake to `huggingface.co` succeeds and the peer certificate names `huggingface.co` |
| `test_live_handshake_rejects_wrong_hostname` | the same context **rejects** a handshake for `evil-hacker.com` → `SSLCertVerificationError` — hostname verification is genuinely active, not just configured |

**Dependency check:** `requirements_versions.txt` sha256 before/after the session
identical (`2b4972930f47541ab1f59634d7fd255914b5e292529e4a350652bfc9e8b71310`);
`git diff --name-only` shows **only** `modules/model_loader.py`. No dependency
was added, removed, or upgraded.

**Acceptance assessment — Stage 3:** **VERIFIED COMPLETE** (code + automated
regression coverage + live verification). Remaining: the unused `import ssl` at
`launch.py:3` (cosmetic, deferred).

### Stage 4 — Modernize Python/PyTorch/CUDA stack — **NOT STARTED**

Current pins: `torch==2.1.0` / `torchvision==0.16.0` with
`--extra-index-url …/whl/cu121` (`launch.py:67-72`), `python=3.10`
(`environment.yaml`), Python 3.10 in `Dockerfile`, requirements frozen at 2024
releases (`transformers==4.42.4`, `pytorch_lightning==2.3.3`, `numpy==1.26.4`,
…). **Do not start before Stage 2/3 sign-off.**

### Stage 5 — Modernize Gradio — **NOT STARTED**

`gradio==3.41.2` pinned. Touch points already located: `webui.py:1121-1125`
(`share`, `auth`, `server_name`, `inbrowser`), `modules/auth.py`,
`modules/gradio_hijack.py`.

### Stage 6 — Fix and update the Google Colab notebook — **VERIFIED BROKEN**

`fooocus_colab.ipynb` cell 0:
`%cd /content/Fooocus-Modern/Fooocus` — the repository has **no `Fooocus/`
subdirectory**, so the notebook fails at `%cd` before `launch.py` runs. It also
performs no dependency pre-check, no GPU check, and no persistent-storage
handling.

### Stage 7 — Review model URLs and model integrity — **NOT STARTED**

- **0 of 30** `load_file_from_url(...)` call sites pass `expected_hash`
  (`launch.py`, `modules/config.py`, `extras/`), so every model downloads with
  `expected_hash=None` and is accepted on size/HTTPS alone.
- The only `hash_prefix` usage is `extras/facexlib/utils/misc.py:77` →
  `hash_prefix=None` (and it still calls `torch.hub.download_url_to_file`,
  bypassing the hardened downloader entirely).
- `modules/hash_cache.py` computes SHA-256 of *local* files for UI metadata —
  not download verification.

### Stage 8 — Review subprocess, network, and update behavior — **NOT STARTED**

`subprocess` appears only in `modules/launch_util.py` (pip execution). Network
call sites are the downloader plus Gradio/`httpx`. Audit still required.

### Stage 9 — VRAM/GPU detection and Colab compatibility — **NOT STARTED (no GPU run)**

Existing flags located (`args_manager.py`, `--disable-offload-from-vram`,
`--always-high-vram` used by the notebook). No verification performed; **no GPU
test has been executed**.

### Stage 10 — Generation tests (SDXL → LoRA → image prompt → inpainting) — **NOT STARTED**

No generation has been run in this repository state. Requires a GPU runtime.

### Stage 11 — Startup and security validation — **NOT STARTED**

No startup validation module, no environment preflight, no security assertions
beyond the downloader.

### Stage 12 — Final Fooocus-Modern Colab launcher — **NOT STARTED**

### Stage 13 — Test from a clean Google Colab runtime — **NOT STARTED**

### Stage 14 — Commit and tag the modernized fork — **NOT STARTED**

Only upstream tags exist; no modernization commits have been pushed; nothing
will be committed or tagged without explicit approval.

---

## 6. Verified progress summary

| # | Stage | Status |
|---|---|---|
| 1 | Remove Git self-update | **VERIFIED COMPLETE** |
| 2 | Harden model downloader | **VERIFIED COMPLETE — pending sign-off** (2026-10-12 repair): 2 HIGH + 4 MEDIUM findings fixed and proven against the pre-repair code; **85/85 tests green ×3**; original worktree artifacts preserved |
| 3 | Remove TLS verification bypass | **VERIFIED COMPLETE** — bypass-free source scan + runtime context assertions + live handshake accept/reject tests; no dependency changed |
| 4 | Modernize Python/PyTorch/CUDA | NOT STARTED (blocked: Stages 2/3 sign-off) |
| 5 | Modernize Gradio | NOT STARTED |
| 6 | Fix Colab notebook | **VERIFIED BROKEN** |
| 7 | Model URLs & integrity | NOT STARTED (0/30 call sites hashed) |
| 8 | Subprocess/network/update review | NOT STARTED |
| 9 | VRAM/GPU & Colab compatibility | NOT STARTED (**no GPU run**) |
| 10 | SDXL → LoRA → image prompt → inpainting | NOT STARTED (**no GPU run**) |
| 11 | Startup & security validation | NOT STARTED |
| 12 | Final Colab launcher | NOT STARTED |
| 13 | Clean-Colab-runtime test | NOT STARTED (**no GPU run**) |
| 14 | Commit & tag | NOT STARTED |

**Verified vs reported:** Stages 1, 2 and 3 now carry independently executed
evidence in this document. Stage 2's previous "43 tests passed" claim remains
**not reproducible** as stated (the suite was 54 tests / 4 red before the
approved repair; it is now 85 tests / 0 red). No other stage has any evidence
behind it.

---

## 7. Unresolved issues (prioritized)

### 7.1 Fixed in the approved repair session (2026-10-12) — for the record

| # | Was | Now |
|---|---|---|
| 1 | HIGH: DNS-rebinding bypass for allowlisted hosts (`host in allowed_hosts`) | **fixed** + 8 production-path regression tests |
| 2 | HIGH: tunnel path never validated the destination | **fixed** (fail closed) + 8 proxy/tunnel tests |
| 3 | MED: IPv6 proxy parse fails open (`fe80::1` → `fe80`) | **fixed** (`_hostname_without_port`) + tests |
| 4 | MED: `Proxy-Authorization` leaked cross-origin; test asserted the wrong case | **fixed** (case-insensitive, both header dicts) + test corrected and strengthened |
| 5 | MED: deadline per attempt, expiry retried | **fixed** (single global budget, `DownloadDeadlineExceeded` terminal, sleep clamped) + 3 tests |
| 6 | MED: `100.64.0.0/10` and other special-use ranges unblocked | **fixed** (`_NON_PUBLIC_NETWORKS`, `not is_global`, NAT64/6to4 embedded-IPv4) |
| 7 | Test defects: thread-unsafe `patch`, missing `__enter__`, `.lock` assertions | **fixed** (no security assertion weakened) |
| 8 | Work not present in the primary checkout | **transferred safely**, worktree originals preserved |

### 7.2 Remaining risks (open, reviewed and accepted for now)

1. **Proxy TOCTOU (documented limitation).** With `HTTPS_PROXY` set, our process
   validates the destination *before* opening the tunnel, but the proxy performs
   its own resolution afterwards. A proxy you do not control can re-point the
   connection. Fail-closed behaviour is implemented (target must validate, proxy
   must validate, DNS failure aborts); the residual risk cannot be removed
   client-side. **Only use proxies you control.** Documented in the
   `SafeHTTPSConnection` docstring.
2. **Private proxies by hostname are refused** unless explicitly listed in
   `allowed_hosts` (e.g. `FOOOCUS_ALLOWED_DOWNLOAD_HOSTS`). Intentional fail-closed
   behaviour; an operator behind a corporate proxy must opt in.
3. **`DEFAULT_MAX_DURATION=1800 s` may abort a legitimate slow 6–10 GB download**
   — product decision needed before Stage 4/7. The deadline is now genuinely
   total, so this is more visible than before.
4. **No `fsync` before `os.replace`** — a power loss can leave a truncated model
   file that still passes the *hash* check only if `expected_hash` was supplied
   (today: 0/30 call sites, see Stage 7). Fix belongs with Stage 7 integrity work.
5. **`extras/facexlib/utils/misc.py` still calls `torch.hub.download_url_to_file`**
   → bypasses the hardened downloader and hashes nothing (`hash_prefix=None`).
6. **`tests/test_utils.py` needs `numpy`** → `discover -s tests` can never be
   fully green in a clean environment (dependency installs are forbidden until
   Stage 4 is authorized).
7. **No CI test workflow** — the 85 tests only run when someone runs them.

### 7.3 Deferred improvements (not defects of this session)

8. Unused `import ssl` at `launch.py:3`.
9. Persistent `.<name>.lock` files in model directories (intentional; removing
   them on release reintroduces a check-to-use race — documented in
   `test_lock_file_is_persistent_by_design`).
10. `download_file` calls `fsync` on neither temp file nor directory.
11. Stage 6 notebook, Stage 7 hashing of the 30 call sites, Stage 4 dependency
    modernization — all untouched, as instructed.

---

## 8. Next development tasks (prioritized)

**P0 — completed in the approved session (2026-10-12), awaiting sign-off**

1. ✅ Transfer the two worktree artifacts into the primary checkout unchanged
   (verified byte-identical; originals backed up and left untouched in the
   worktree). Not staged, not committed.
2. ✅ Make the downloader suite green: **85/85, three consecutive runs**.
3. ✅ Fix HIGH #1 (DNS rebinding) + regression tests exercising the production
   configuration (`allowed_hosts=DEFAULT_ALLOWED_HOSTS`).
4. ✅ Fix HIGH #2 (tunnel destination) and MEDIUM #3 (IPv6 proxy parse), plus
   proxy *name* resolution; proxy regression tests added; fail-closed behaviour
   documented where it cannot be guaranteed (§7.2 #1).
5. ✅ Fix header leakage (case-insensitive, both header dicts) and correct the
   false-PASS assertion.
6. ✅ Fix the deadline (single global budget, terminal, retry-aware).
7. ✅ Enforce size caps including missing/lying `Content-Length` (test added).
8. ✅ Review locking, temp-file cleanup, resource exhaustion
   (`O_NOFOLLOW`, refcounted lock registry, fd/temp leak guards, `__enter__`
   failure path).
9. ✅ Stage 3: TLS regression tests + live certificate acceptance **and**
   rejection checks; no dependency upgraded.
10. ✅ This document updated with verified results (§5 Stage 2/Stage 3
    continuations, §6, §7).

**P0 — your decision required next**

11. Review §5 Stage 2 (continued), §5 Stage 3 (continued), §7.2 and sign off
    Stage 2/Stage 3, or name the items to rework.
12. Approve staging/committing the three files
    (`modules/model_loader.py`, `tests/test_model_loader.py`,
    `docs/MODERNIZATION_ROADMAP.md`) onto `feature/harden-model-downloader` and
    the merge into `modern-platform`. Nothing has been staged or committed yet.
13. Decide on §7.2 #3 (30-minute deadline vs. multi-GB downloads).

**P1 — after Stage 2 sign-off**

14. Stage 7 groundwork: build a model manifest with SHA-256 for every download
    URL (30 call sites) and start passing `expected_hash`; route
    `extras/facexlib/utils/misc.py` through the hardened downloader; add
    `fsync` before `os.replace`.
15. Stage 8: audit `modules/launch_util.py` subprocess execution, network call
    sites, and any residual update behavior.
16. Add a CI workflow running `python3 -m unittest discover -s tests` (after
    deciding how `tests/test_utils.py` gets `numpy`).

**P2 — after Stages 3/7/8**

17. Stage 4 (Python/PyTorch/CUDA), Stage 5 (Gradio), Stage 6 (notebook),
    Stage 9 (VRAM/GPU/Colab), Stage 10 (generation tests on a GPU),
    Stages 11–13 (validation, launcher, clean runtime), Stage 14 (commit/tag —
    with approval).

---

## 9. Standing constraints

- Preserve all completed work; never rewrite history or overwrite the worktree
  artifacts without approval.
- Never reintroduce Git self-update or `pygit2`.
- Never disable TLS certificate verification.
- Prefer cryptographically verified model downloads.
- Avoid unnecessary dependencies; do not upgrade the dependency stack before
  Stage 3 is formally closed.
- Maintain Google Colab compatibility.
- Add automated tests for security-sensitive changes.
- Never claim GPU tests passed unless they ran on a GPU.
- Do not commit, push, merge, or tag without explicit approval.
- Keep this document updated at the end of every stage; record new evidence and
  never overwrite historical claims without labeling them.
