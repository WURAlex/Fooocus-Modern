import cv2
import os
import os.path as osp
import torch
from urllib.parse import urlparse

from modules.model_manifest import (
    ManifestError,
    download as manifest_download,
    match_url,
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _torch_hub_checkpoints_dir():
    """Replicates torch.hub.get_dir()/checkpoints without importing torch.hub.

    torch 2.1 semantics: $TORCH_HOME/hub/checkpoints, where $TORCH_HOME
    defaults to $XDG_CACHE_HOME/torch and $XDG_CACHE_HOME defaults to ~/.cache.
    """
    torch_home = os.path.expanduser(
        os.getenv(
            "TORCH_HOME",
            os.path.join(os.getenv("XDG_CACHE_HOME", "~/.cache"), "torch"),
        )
    )
    return os.path.join(torch_home, "hub", "checkpoints")


def imwrite(img, file_path, params=None, auto_mkdir=True):
    """Write image to file.

    Args:
        img (ndarray): Image array to be written.
        file_path (str): Image file path.
        params (None or list): Same as opencv's :func:`imwrite` interface.
        auto_mkdir (bool): If the parent folder of `file_path` does not exist,
            whether to create it automatically.

    Returns:
        bool: Successful or not.
    """
    if auto_mkdir:
        dir_name = os.path.abspath(os.path.dirname(file_path))
        os.makedirs(dir_name, exist_ok=True)
    return cv2.imwrite(file_path, img, params)


def img2tensor(imgs, bgr2rgb=True, float32=True):
    """Numpy array to tensor.

    Args:
        imgs (list[ndarray] | ndarray): Input images.
        bgr2rgb (bool): Whether to change bgr to rgb.
        float32 (bool): Whether to change to float32.

    Returns:
        list[tensor] | tensor: Tensor images. If returned results only have
            one element, just return tensor.
    """

    def _totensor(img, bgr2rgb, float32):
        if img.shape[2] == 3 and bgr2rgb:
            if img.dtype == 'float64':
                img = img.astype('float32')
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img = torch.from_numpy(img.transpose(2, 0, 1))
        if float32:
            img = img.float()
        return img

    if isinstance(imgs, list):
        return [_totensor(img, bgr2rgb, float32) for img in imgs]
    else:
        return _totensor(imgs, bgr2rgb, float32)


def load_file_from_url(url, model_dir=None, progress=True, file_name=None, save_dir=None):
    """Ref:https://github.com/1adrianb/face-alignment/blob/master/face_alignment/utils.py

    P1-A: routes through the hardened downloader via the model-integrity
    manifest (modules.model_manifest). Signature, cache-directory semantics,
    and return value (absolute path) match the legacy implementation; the
    legacy torch.hub transport is gone. URLs not recorded in the manifest are
    refused (fail-closed).
    """
    if model_dir is None:
        model_dir = _torch_hub_checkpoints_dir()

    if save_dir is None:
        save_dir = os.path.join(ROOT_DIR, model_dir)
    os.makedirs(save_dir, exist_ok=True)

    parts = urlparse(url)
    filename = os.path.basename(parts.path)
    if file_name is not None:
        filename = file_name

    entry = match_url(url)
    if entry is None:
        raise ManifestError(
            f"Refusing download of a URL that is not recorded in the model "
            f"integrity manifest: {url!r}"
        )

    return manifest_download(
        entry["id"],
        model_dir=save_dir,
        file_name=filename,
        progress=progress,
    )


def scandir(dir_path, suffix=None, recursive=False, full_path=False):
    """Scan a directory to find the interested files.
    Args:
        dir_path (str): Path of the directory.
        suffix (str | tuple(str), optional): File suffix that we are
            interested in. Default: None.
        recursive (bool, optional): If set to True, recursively scan the
            directory. Default: False.
        full_path (bool, optional): If set to True, include the dir_path.
            Default: False.
    Returns:
        A generator for all the interested files with relative paths.
    """

    if (suffix is not None) and not isinstance(suffix, (str, tuple)):
        raise TypeError('"suffix" must be a string or tuple of strings')

    root = dir_path

    def _scandir(dir_path, suffix, recursive):
        for entry in os.scandir(dir_path):
            if not entry.name.startswith('.') and entry.is_file():
                if full_path:
                    return_path = entry.path
                else:
                    return_path = osp.relpath(entry.path, root)

                if suffix is None:
                    yield return_path
                elif return_path.endswith(suffix):
                    yield return_path
            else:
                if recursive:
                    yield from _scandir(entry.path, suffix=suffix, recursive=recursive)
                else:
                    continue

    return _scandir(dir_path, suffix=suffix, recursive=recursive)
