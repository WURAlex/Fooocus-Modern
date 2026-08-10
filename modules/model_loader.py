import os
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from torch.hub import download_url_to_file


DEFAULT_ALLOWED_HOSTS = {
    "huggingface.co",
    "cdn-lfs.huggingface.co",
}


def _resolve_huggingface_mirror(url: str) -> str:
    mirror = os.environ.get("HF_MIRROR")

    if not mirror:
        return url

    mirror = mirror.rstrip("/")

    parsed_mirror = urlparse(mirror)

    if parsed_mirror.scheme != "https":
        raise ValueError("HF_MIRROR must use HTTPS.")

    if parsed_mirror.username or parsed_mirror.password:
        raise ValueError("HF_MIRROR must not contain credentials.")

    if parsed_mirror.query or parsed_mirror.fragment:
        raise ValueError("HF_MIRROR must not contain query or fragment data.")

    if not parsed_mirror.hostname:
        raise ValueError("HF_MIRROR must contain a valid hostname.")

    return url.replace(
        "https://huggingface.co",
        mirror,
        1,
    )


def _validate_url(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(
            f"Refusing insecure model URL: {url!r}. "
            "Model downloads must use HTTPS."
        )

    hostname = (parsed.hostname or "").lower()

    if hostname in DEFAULT_ALLOWED_HOSTS:
        return

    mirror = os.environ.get("HF_MIRROR")
    if mirror:
        mirror_hostname = (urlparse(mirror).hostname or "").lower()

        if hostname == mirror_hostname:
            return

    raise ValueError(
        f"Refusing download from untrusted host: {hostname!r}"
    )


def _safe_destination(model_dir: str, file_name: str) -> Path:
    root = Path(model_dir).resolve()
    destination = (root / file_name).resolve()

    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Refusing model path outside model directory: {file_name!r}"
        ) from exc

    return destination


def load_file_from_url(
    url: str,
    *,
    model_dir: str,
    progress: bool = True,
    file_name: Optional[str] = None,
) -> str:
    """
    Download a model file securely and return its local path.

    Existing files are reused. New files are downloaded to a temporary
    file and atomically moved into the model directory.
    """

    url = _resolve_huggingface_mirror(url)
    _validate_url(url)

    parsed = urlparse(url)

    if not file_name:
        file_name = os.path.basename(parsed.path)

    if not file_name:
        raise ValueError(f"Could not determine filename from URL: {url!r}")

    destination = _safe_destination(model_dir, file_name)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.is_file():
        return str(destination)

    print(f'Downloading: "{url}"')
    print(f"Destination: {destination}")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".download",
        dir=str(destination.parent),
    )

    os.close(fd)

    try:
        download_url_to_file(
            url,
            temporary_name,
            progress=progress,
        )

        temporary_path = Path(temporary_name)

        if not temporary_path.is_file():
            raise RuntimeError(
                f"Download completed without creating file: {url!r}"
            )

        if temporary_path.stat().st_size == 0:
            raise RuntimeError(
                f"Downloaded file is empty: {url!r}"
            )

        os.replace(temporary_path, destination)

    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    return str(destination)