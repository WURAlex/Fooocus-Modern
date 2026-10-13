"""
rembg U2NET model pre-seeding through the hardened downloader (Stage 7 P1-B).

rembg's new_session() downloads its ONNX models internally via pooch into
u2net_home() and re-verifies publisher-attested md5 pins on every session
creation. That path has no transport hardening (no host allowlist, no DNS
pinning, no size/deadline limits) and its integrity gate is a weak md5.

This module prepares the seven audited rembg models through the Stage 7
hardened downloader (modules.model_manifest) *before* new_session() runs:
the same cache directory rembg resolves (u2net_home() semantics preserved
exactly: U2NET_HOME > XDG_DATA_HOME/.u2net > ~/.u2net), the same file
names pooch uses (<model>.onnx), and the same md5 pins the rembg 2.0.57
wheel attests. After pre-seeding, rembg's own pooch md5 check still runs
at session creation and is never disabled, skipped, or monkey-patched:
integrity is enforced twice (hardened downloader at fetch time, pooch at
session time).

Fail-closed policy: for a recognized model, any pre-seed or verification
error propagates to the caller. There is no fallback that hands a
recognized model to rembg's internal downloader.

Stdlib-only (plus the stdlib-only model_manifest module) so the offline
test suite can exercise this without rembg/onnxruntime installed.
"""

import os
from typing import Optional

from modules import model_manifest

# flags.inpaint_mask_models entries handled by rembg sessions, mapped to
# their Stage 7 manifest artifact ids. 'sam' is intentionally absent: it
# is rembg's SamSession (multi-file, separately tracked) and the UI's
# GroundingDINO+SAM path does not use rembg's downloader at all.
REMBG_MODEL_ARTIFACTS = {
    "u2net": "rembg-u2net",
    "u2netp": "rembg-u2netp",
    "u2net_human_seg": "rembg-u2net-human-seg",
    "u2net_cloth_seg": "rembg-u2net-cloth-seg",
    "silueta": "rembg-silueta",
    "isnet-general-use": "rembg-isnet-general-use",
    "isnet-anime": "rembg-isnet-anime",
}


def resolve_u2net_home() -> str:
    """
    Resolve rembg's model cache directory with BaseSession.u2net_home()
    semantics from the pinned rembg 2.0.57 wheel:

        os.path.expanduser(
            os.getenv("U2NET_HOME", os.path.join(os.getenv("XDG_DATA_HOME", "~"), ".u2net"))
        )

    U2NET_HOME wins over XDG_DATA_HOME; both unset falls back to ~/.u2net.
    """
    xdg = os.getenv("XDG_DATA_HOME", "~")
    return os.path.expanduser(os.getenv("U2NET_HOME", os.path.join(xdg, ".u2net")))


def ensure_rembg_model(mask_model: str) -> Optional[str]:
    """
    Pre-seed a recognized rembg model into the rembg cache directory through
    the hardened downloader (md5-pinned manifest entry, fail-closed on
    mismatch or network failure).

    Returns the local model path for recognized models; returns None for
    unrecognized names (they were never pre-seeded and keep whatever rembg
    itself does — this helper neither pre-seeds nor fails them).

    Raises on any download, verification, or filesystem error for a
    recognized model: the caller must not fall back to rembg's internal
    downloader for models we claim to manage.
    """
    artifact_id = REMBG_MODEL_ARTIFACTS.get(mask_model)
    if artifact_id is None:
        return None

    home = resolve_u2net_home()
    os.makedirs(home, exist_ok=True)
    # md5 enforced here (hash_algorithm="md5" via the manifest entry);
    # cached-file mismatches fail closed; pooch re-verifies afterwards.
    return model_manifest.download(artifact_id, model_dir=home, progress=False)
