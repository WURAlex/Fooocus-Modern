# Fooocus-Modern — Modernization Roadmap

Repository: https://github.com/WURAlex/Fooocus-Modern.git
Development branch: `modern-platform`
Document created: 2026-10-12 (independent inspection, read-only)
Last updated: 2026-10-12 — Stage 2 repair session + Stage 3 validation tests (approved, committed as `90869ce`); fail-closed HTTPS proxy policy (approved follow-up, uncommitted)

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
| HEAD | `90869ce security: harden model downloader and add TLS regression tests` (parent `4fae360`, approved commit) |
| Primary working tree | ` M modules/model_loader.py`, ` M tests/test_model_loader.py`, ` M docs/MODERNIZATION_ROADMAP.md` — the approved fail-closed HTTPS proxy policy plus its final integration verification, **not committed** (awaiting approval) |
| `modern-platform`, `origin/modern-platform` | both `4fae360`; the local branch is 1 ahead — **not pushed** |
| Stashes | none |
| Second worktree | `/home/alex/.gemini/antigravity/worktrees/Fooocus-Modern/harden_model_downloader`, branch `harden_model_downloader`, HEAD `4fae360`, **2 uncommitted artifacts** (see §3) — untouched by the repair session, still ` M ` + `??` |
| Commit history | `ae05379` (upstream baseline) → `3c8b447 docs: establish Fooocus Modern baseline` → `4fae360 Harden launcher and model downloads` → `90869ce security: harden model downloader and add TLS regression tests` |
| Tags | upstream only (`v2.4.1` … `v2.5.5`); no modernization tag |
| CI | `.github/workflows/build_container.yml` (Docker build only). **No test/CI workflow exists.** |
| Test environment | Python 3.14.4, `torch` not installed, `numpy` not installed; no dependencies installed during inspection |
| Test results (2026-10-12, post-repair + proxy policy + final verification) | `python3 -m unittest tests.test_model_loader` → **Ran 132 — OK** (3 consecutive runs); `discover -s tests` → Ran 134 — 1 error (`tests/test_utils` needs `numpy`) |

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

### Stage 2 (continued 2) — fail-closed HTTPS proxy policy (2026-10-12, approved follow-up)

Authorized by the maintainer after the Stage 2/3 commit: reject proxy use by
default, detect proxies with urllib's own selection rules, authorize via
`FOOOCUS_ALLOWED_HTTPS_PROXIES` (separate from the destination allowlist),
validate approved endpoints and their resolved IPs, add regression tests, run
all downloader security tests, update this document; no commit/push/merge/tag,
no Stage 4.

**a) Detection mirrors urllib (verified empirically against
`urllib.request`, Python 3.14).** `_configured_https_proxy()` makes the same
API calls `ProxyHandler` makes — `getproxies()` + `proxy_bypass(host)`:

| Environment | urllib behaviour for `https://` requests (probed) | Gate |
|---|---|---|
| `HTTPS_PROXY` / `https_proxy` | dials the **proxy** and issues `CONNECT` (`_tunnel_host` set) | **requires approval** |
| `HTTP_PROXY` only | dials the destination directly (the `http` key is never consulted for https) | not gated (cannot cause a tunnel) |
| `ALL_PROXY` / `FTP_PROXY` | dials the destination directly (same reason) | not gated |
| `NO_PROXY` covering the destination | bypass → direct | not gated (mirrors urllib) |
| `REQUEST_METHOD` (CGI) present | does **not** drop the `https` key (only `http`) | unchanged |

Port inference matches urllib exactly: an explicit port wins, otherwise the
connection defaults to **443** (probed: `HTTPS_PROXY=http://proxy.example` and
schemeless `proxy.example` both dial port 443).

**b) Two-phase enforcement:**

- **Phase A — pre-flight in `download_file`** (`_enforce_proxy_policy`,
  runs immediately after `_validate_url`, before any lock, temp file or
  destination DNS): approval check → private/local check → public-IP
  resolution of the proxy. Unparseable proxy URLs and malformed approval
  entries both fail closed; proxy credentials are redacted from every error
  message.
- **Phase B — defense in depth at `CONNECT` time**
  (`SafeHTTPSConnection.connect`, new `allowed_proxies` plumbed through
  `SafeHTTPSHandler`): the tunnel branch re-checks approval first, then the
  private check, then DNS validation, then the destination checks from the
  Stage 2 repair. This catches any detection gap (e.g. the environment
  changing after Phase A). The proxy socket is now **pinned to the validated
  IP** (`_create_connection` override), closing the validate-then-re-resolve
  TOCTOU on the proxy name itself; TLS still validates against
  `_tunnel_host` (the destination), so certificate checks are unaffected.

**c) Authorization rules:**

- `FOOOCUS_ALLOWED_HTTPS_PROXIES` = comma-separated entries: `host`,
  `host:port`, `scheme://host:port` (credentials allowed, ignored for
  matching — host:port is the authorization unit because urllib issues the
  same CONNECT regardless of scheme, probed). An entry without a port matches
  any port on that host; with a port it must match exactly. Empty/unset →
  nothing is approved.
- Approval is **independent of the destination allowlist**: a destination
  host authorized via `FOOOCUS_ALLOWED_DOWNLOAD_HOSTS` gains no proxy rights
  (`test_destination_allowlist_does_not_authorize_proxy`).
- **Private/local proxy endpoints are rejected even when approved** and even
  when their address is destination-allowlisted (the previous
  `allowed_hosts` escape hatch for private proxies was removed — it
  contradicted requirement 4). Corporate proxies on private networks are
  intentionally unsupported; tunnel through an endpoint you can authorize.

**d) Tests (35 new in this round; suite 120 at this point — final totals in g):** `TestFailClosedProxyPolicy` (14: unapproved
blocked before any network, destination-allowlist independence, approved path
green, portless/port-mismatch matching, credential redaction, approved-private
blocked, approved-DNS-private blocked with only the proxy resolved,
unparseable proxy, malformed approval entry, `NO_PROXY` bypass, `HTTP_PROXY`/
`ALL_PROXY` inertness), `TestProxyDetectionMirrorsUrllib` (8, selection-rule
table above), `TestProxyEndpointParsing` (7: parse + approval matching rules),
`TestTunnelProxyApproval` (5: Phase B fail-closed without/wrong approval,
portless approval, destination-allowlist private proxy still rejected,
validated-IP pinning). The 9 pre-existing proxy tests were *upgraded* (pass
`allowed_proxies` explicitly) so their address-validation assertions still
execute past the new approval gate — no assertion weakened.

**e) Results of the proxy-policy round (executed 2026-10-12; superseded for
current counts by g below):**

| Check | Result |
|---|---|
| `python3 -m unittest tests.test_model_loader` | **Ran 120 — OK** (×3 consecutive) |
| `discover -s tests` | Ran 122 — 1 error (`tests/test_utils` needs `numpy`, pre-existing) |
| security subset (proxy + rebinding + TLS classes, 64 tests) | **64 — OK** |
| `/tmp/opencode/verify_before_after.py` | pre-repair: **7 VULNERABLE**/2 blocked; current: **9/9 BLOCKED, 0 VULNERABLE** (new check #9: unapproved env `HTTPS_PROXY` blocks the download) |
| live env (real `HTTPS_PROXY=http://93.184.216.34:8443`, no mocks) | `BLOCKED: Refusing to use unapproved HTTPS proxy … FOOOCUS_ALLOWED_HTTPS_PROXIES …`; no temp file created; `HTTP_PROXY` alone → detection returns `None` |
| dependencies / TLS / git-self-update scans | unchanged (no dependency edits; no TLS bypass; no self-update code) |

**f) Acceptance assessment:** every approved requirement implemented, tested
and demonstrated live. Remaining proxy risks are recorded in §7.2 (#1 trust
boundary, #2 private-proxy constraint).

**g) Final integration verification (2026-10-12, approved review round).**
All nine verification points re-checked against the finished implementation;
three defects were found, fixed, and covered by regression tests:

| # | Point | Verdict |
|---|---|---|
| 1 | Detection parity with urllib | **PROVEN** — external probe (`/tmp/opencode/probe_parity_final.py`) compares the gate against urllib's *actual dial decision* (sentinel `socket.create_connection`, per-case opener rebuild): **22/22 cases agree, 0 mismatches**; plus in-suite oracle matrix (fresh `ProxyHandler` per case, 20 subtests) |
| 2 | Python-version consistency | **PROVEN** — no declared `python_requires`/`requires-python` anywhere, no `sys.version_info` guards; CPython 3.10 vs 3.14 sources compared: `http/client.py` (instance-level `_create_connection`, `server_hostname = self._tunnel_host` when tunnelled) and `urllib/request.py` (two-pass `getproxies_environment`, CGI `REQUEST_METHOD` pops only `http`, `proxy_bypass_environment`, `_parse_proxy` schemeless-authority branch, `set_proxy`/`_tunnel_host`) are semantically identical → no version-dependent behavior. The raw-`urlopen` `download_file` in `ldm_patched/k_diffusion/utils.py` has **zero callers** (dead code, recorded in §7.2 #5) |
| 3 | `NO_PROXY` safety | **PROVEN** — bypass cases in probe + matrix (exact, dot-suffix, `*`, port-qualified, portless-vs-port); see D3 below |
| 4 | Redirect cannot bypass the gate | **PROVEN** — 7 existing `TestHardenedRedirectHandler` cases (https-only, trusted-host, SSRF, loops) + new composition test: a Phase A that bypassed via `NO_PROXY` grants **no** approval for a later tunnel, refused at CONNECT before any DNS/socket |
| 5 | Credentials never leak | **DEFECT D1/D2 found and fixed** — approval-entry errors now redacted (`_redact_proxy_display`), and redaction uses `rsplit("@")` so a password containing `@` cannot leak its tail; covered by e2e + unit tests |
| 6 | TLS inside the tunnel | **PROVEN + new tests** — new test asserts `wrap_socket(server_hostname="huggingface.co")` (destination, never the proxy) and that the default `SafeHTTPSConnection` context stays `CERT_REQUIRED` + `check_hostname` |
| 7 | Direct-path pinning | **PROVEN** — existing named tests `test_safe_https_connection_direct_connects_to_validated_ip` (dials the pre-validated IP, `server_hostname` = destination) and `test_tunnel_dials_the_validated_proxy_address` (proxy dial pinned) |
| 8 | Environment change after Phase A | **PROVEN + new test** — a proxy appearing after Phase A is refused at CONNECT using the approval state captured at Phase A (no DNS, no socket) |
| 9 | No dependency/TLS/self-update regressions | **PROVEN** — `git diff` touches only the 3 approved files; no dependency files changed; TLS-bypass source scan green in-suite; repo grep shows no `pygit2`/`git pull`/self-update code; harness **9/9 BLOCKED, 0 VULNERABLE**; live unmocked `HTTPS_PROXY=http://93.184.216.34:8443` blocked with no residual file |

**Defects found in this round (all fixed):**

- **D1** — `_parse_approved_proxy_entries` echoed the raw approval entry
  (`{entry!r}`) in its error; an approval entry may itself carry credentials
  (`scheme://user:pass@host:port`), which would land in logs/consoles. Fixed:
  message now passes the entry through `_redact_proxy_display`.
- **D2** — `_redact_proxy_display` used `split("@", 1)`, so a password
  containing `@` leaked its tail (`***@ss@host`). Fixed: `rsplit("@", 1)`
  (everything up to the last `@` is userinfo).
- **D3** — Phase A passed `urlparse(url).hostname` (**port stripped**) to
  `proxy_bypass`, while urllib compares `NO_PROXY` against `Request.host`,
  which keeps an explicit URL port. With `HTTPS_PROXY` set,
  `NO_PROXY=huggingface.co:443` and URL `https://huggingface.co:443/…` urllib
  goes direct but the old gate refused (false-positive block; fail-closed
  direction, but not the claimed parity). Fixed: the gate now receives
  `urlparse(url).netloc` (userinfo is impossible there — `_validate_url`
  rejected it earlier), exactly as `Request.host` carries it. Proof:
  `proxy_bypass("huggingface.co")` → `False` vs
  `proxy_bypass("huggingface.co:443")` → `True` for that env, and the probe's
  `URL:443 NO_PROXY:443` / `URL:8443 NO_PROXY:8443` cases now agree.

**Final counts (executed 2026-10-12):**

| Check | Result |
|---|---|
| `python3 -m unittest tests.test_model_loader` | **Ran 132 — OK** (3 consecutive; +12 tests over the policy round) |
| `discover -s tests` | Ran 134 — 1 error (`tests/test_utils` needs `numpy`, pre-existing) |
| security subset (12 URL/redirect/rebinding/TLS/proxy classes, 101 tests) | **101 — OK** |
| `tests.test_extra_utils` | 1 — OK |
| parity probe (external, real urllib dial oracle) | **22/22 agree, 0 mismatches** |
| `/tmp/opencode/verify_before_after.py` | **9/9 BLOCKED, 0 VULNERABLE** |
| live unapproved `HTTPS_PROXY` (no mocks) | `BLOCKED … FOOOCUS_ALLOWED_HTTPS_PROXIES …`, no residual file |
| `py_compile` | OK |

New regression tests: `test_gate_agrees_with_urllib_on_every_selection_case`
(20 subtests incl. all port-qualified `NO_PROXY` forms), D3 e2e pair
(`test_no_proxy_entry_with_port_matches_url_with_port`,
`test_no_proxy_entry_for_unlisted_port_does_not_bypass`),
`test_approval_entry_credentials_never_leak_into_errors` + 4 redaction/
approval-parsing units, `test_phase_a_bypass_grants_no_authorization_for_a_later_tunnel`,
`test_proxy_appearing_after_phase_a_is_refused_at_connect`,
`test_tunnel_tls_is_validated_against_the_destination`,
`test_safe_https_connection_context_requires_verification`.

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
| 2 | Harden model downloader | **VERIFIED COMPLETE — pending sign-off** (2026-10-12 repair, committed as `90869ce`): 2 HIGH + 4 MEDIUM findings fixed and proven against the pre-repair code; **plus approved follow-up: fail-closed HTTPS proxy policy** (uncommitted): proxy use rejected by default, urllib-mirrored detection, `FOOOCUS_ALLOWED_HTTPS_PROXIES` authorization separate from the destination allowlist, two-phase enforcement with IP pinning, **plus final integration verification** (9/9 points, 3 defects fixed, probe 22/22); **132/132 tests green ×3**; original worktree artifacts preserved |
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
approved repair; it is now 132 tests / 0 red after the repair, the
fail-closed proxy policy, and the final integration verification). No other
stage has any evidence behind it.

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
| 9 | Proxy policy follow-up: ambient `HTTPS_PROXY` silently proxied downloads; private proxies could be unlocked via the destination `allowed_hosts`; proxy name validated then re-resolved at dial time | **fixed** (fail-closed two-phase approval via `FOOOCUS_ALLOWED_HTTPS_PROXIES`, private proxies always rejected, dial pinned to the validated IP) + 35 tests |
| 10 | Final-review defects: approval-entry credentials echoed in errors; `rsplit`-style redaction split at the *first* `@`; Phase A passed a port-stripped hostname to `proxy_bypass` (diverged from `Request.host` for port-qualified `NO_PROXY`) | **fixed** + 12 regression tests (parity matrix, D3 e2e pair, redaction units, Phase B compositions) |

### 7.2 Remaining risks (open, reviewed and accepted for now)

1. **Proxy trust boundary (documented limitation, narrowed by the proxy
   policy).** Proxy use now requires explicit approval via
   `FOOOCUS_ALLOWED_HTTPS_PROXIES` (fail closed) and both the proxy and the
   destination are validated before the tunnel opens; the proxy's own socket
   is pinned to the validated IP (no client-side re-resolution). What remains:
   `CONNECT` sends the destination *hostname*, so an **approved** proxy
   performs its own resolution afterwards and can re-point the connection —
   this cannot be removed client-side. TLS still validates the destination
   certificate, so an untrusted proxy cannot forge the session, only
   observe/refuse/route it. **Only approve proxies you control** (proxy
   approval delegates destination resolution to them). Documented in the
   `SafeHTTPSConnection` docstring.
2. **Private/local proxy endpoints are refused unconditionally** — even when
   approved via `FOOOCUS_ALLOWED_HTTPS_PROXIES` and even when the address
   appears in the destination allowlist (the old `allowed_hosts` escape hatch
   was removed in the proxy-policy follow-up because it mixed proxy and
   destination authorization). An operator whose proxy lives on a private
   network has no opt-in; route through a public endpoint instead. Intentional
   fail-closed behaviour; tests assert it on both enforcement phases.
3. **`DEFAULT_MAX_DURATION=1800 s` may abort a legitimate slow 6–10 GB download**
   — product decision needed before Stage 4/7. The deadline is now genuinely
   total, so this is more visible than before.
4. **No `fsync` before `os.replace`** — a power loss can leave a truncated model
   file that still passes the *hash* check only if `expected_hash` was supplied
   (today: 0/30 call sites, see Stage 7). Fix belongs with Stage 7 integrity work.
5. **Alternate download paths bypass the hardened downloader.**
   `extras/facexlib/utils/misc.py` still calls
   `torch.hub.download_url_to_file` → hashes nothing (`hash_prefix=None`).
   Likewise `ldm_patched/k_diffusion/utils.py::download_file` uses raw
   `urllib.request.urlopen` (env-proxy aware, no SSRF/approval hardening) —
   verified in the final review to have **zero callers** anywhere in the repo
   (dead code): no live exposure, remove it during Stage 7 cleanup.
6. **`tests/test_utils.py` needs `numpy`** → `discover -s tests` can never be
   fully green in a clean environment (dependency installs are forbidden until
   Stage 4 is authorized).
7. **No CI test workflow** — the 132 tests only run when someone runs them.

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
11. ✅ Fail-closed HTTPS proxy policy (approved follow-up): urllib-mirrored
    detection, `FOOOCUS_ALLOWED_HTTPS_PROXIES` authorization kept
    separate from the destination allowlist (§5 Stage 2 continued 2), two-phase
    enforcement with validated-IP pinning, live unapproved-proxy proof,
    before/after harness 9/9 blocked — **plus the approved final integration
    verification** (all 9 points; 3 defects D1–D3 found/fixed; parity probe
    22/22; **47 new tests total, suite 132/132 ×3**). Changes to
    `modules/model_loader.py`, `tests/test_model_loader.py` and this document
    are **staged (`git add`), not committed — awaiting approval**.

**P0 — your decision required next**

12. Review §5 Stage 2 (continued), §5 Stage 2 (continued 2), §5 Stage 3
    (continued), §7.2 and sign off Stages 2/3 (including the proxy policy), or
    name the items to rework.
13. Approve committing the proxy-policy + final-verification changes to
    `modules/model_loader.py`, `tests/test_model_loader.py` and
    `docs/MODERNIZATION_ROADMAP.md` on `feature/harden-model-downloader`
    (the Stage 2/3 work is already committed as `90869ce`; the three approved
    files are **staged, not committed**, and no push/merge/tag has been
    performed).
14. Decide on §7.2 #3 (30-minute deadline vs. multi-GB downloads).

**P1 — after Stage 2 sign-off**

15. Stage 7 groundwork: build a model manifest with SHA-256 for every download
    URL (30 call sites) and start passing `expected_hash`; route
    `extras/facexlib/utils/misc.py` through the hardened downloader; add
    `fsync` before `os.replace`.
16. Stage 8: audit `modules/launch_util.py` subprocess execution, network call
    sites, and any residual update behavior.
17. Add a CI workflow running `python3 -m unittest discover -s tests` (after
    deciding how `tests/test_utils.py` gets `numpy`).

**P2 — after Stages 3/7/8**

18. Stage 4 (Python/PyTorch/CUDA), Stage 5 (Gradio), Stage 6 (notebook),
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
