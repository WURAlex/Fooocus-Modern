import os
import platform
import ssl
import sys

print('[System ARGV] ' + str(sys.argv))

root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
os.chdir(root)

os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.0"

if "GRADIO_SERVER_PORT" not in os.environ:
    os.environ["GRADIO_SERVER_PORT"] = "7865"

import fooocus_version

from build_launcher import build_launcher
from modules.launch_util import (
    is_installed,
    run,
    python,
    run_pip,
    requirements_met,
    delete_folder_content,
)
from modules.model_loader import load_file_from_url
from modules.model_manifest import download as manifest_download
from modules.model_manifest import download_user_supplied


REINSTALL_ALL = False
TRY_INSTALL_XFORMERS = False


# ---------------------------------------------------------
# VAE / auxiliary model downloads
# ---------------------------------------------------------

vae_approx_artifacts = [
    'vae-approx-xl',
    'vae-approx-sd15',
    'xl-v1-interposer',
]


# ---------------------------------------------------------
# Environment preparation
# ---------------------------------------------------------

def prepare_environment():
    torch_index_url = os.environ.get(
        "TORCH_INDEX_URL",
        "https://download.pytorch.org/whl/cu121",
    )

    torch_command = os.environ.get(
        "TORCH_COMMAND",
        f"pip install torch==2.1.0 torchvision==0.16.0 "
        f"--extra-index-url {torch_index_url}",
    )

    requirements_file = os.environ.get(
        "REQS_FILE",
        "requirements_versions.txt",
    )

    print(f"Python {sys.version}")
    print(f"Fooocus version: {fooocus_version.version}")

    # -----------------------------------------------------
    # PyTorch
    # -----------------------------------------------------

    if (
        REINSTALL_ALL
        or not is_installed("torch")
        or not is_installed("torchvision")
    ):
        run(
            f'"{python}" -m {torch_command}',
            "Installing torch and torchvision",
            "Couldn't install torch",
            live=True,
        )

    # -----------------------------------------------------
    # xformers
    # -----------------------------------------------------

    if TRY_INSTALL_XFORMERS:
        if REINSTALL_ALL or not is_installed("xformers"):
            xformers_package = os.environ.get(
                "XFORMERS_PACKAGE",
                "xformers==0.0.23",
            )

            if platform.system() == "Windows":
                if platform.python_version().startswith("3.10"):
                    run_pip(
                        f"install -U -I --no-deps {xformers_package}",
                        "xformers",
                        live=True,
                    )
                else:
                    print(
                        "Installation of xformers is not supported "
                        "in this version of Python."
                    )

            elif platform.system() == "Linux":
                run_pip(
                    f"install -U -I --no-deps {xformers_package}",
                    "xformers",
                )

    # -----------------------------------------------------
    # Fooocus requirements
    # -----------------------------------------------------

    if REINSTALL_ALL or not requirements_met(requirements_file):
        run_pip(
            f'install -r "{requirements_file}"',
            "requirements",
        )


# ---------------------------------------------------------
# Argument initialization
# ---------------------------------------------------------

def ini_args():
    from args_manager import args
    return args


# ---------------------------------------------------------
# Model downloading
# ---------------------------------------------------------

def download_models(
    default_model,
    previous_default_models,
    checkpoint_downloads,
    embeddings_downloads,
    lora_downloads,
    vae_downloads,
    config,
    args,
):
    from modules.util import get_file_from_folder_list

    # -----------------------------------------------------
    # Approximate VAE files
    # -----------------------------------------------------

    for artifact_id in vae_approx_artifacts:
        manifest_download(
            artifact_id,
            model_dir=config.path_vae_approx,
        )

    # -----------------------------------------------------
    # Fooocus expansion model
    # -----------------------------------------------------

    manifest_download(
        "fooocus-expansion",
        model_dir=config.path_fooocus_expansion,
    )

    # -----------------------------------------------------
    # Optional preset download disabling
    # -----------------------------------------------------

    if args.disable_preset_download:
        print("Skipped model download.")
        return default_model, checkpoint_downloads

    # -----------------------------------------------------
    # Check whether an older default model can be reused
    # -----------------------------------------------------

    if not args.always_download_new_model:
        default_model_path = get_file_from_folder_list(
            default_model,
            config.paths_checkpoints,
        )

        if not os.path.isfile(default_model_path):
            for alternative_model_name in previous_default_models:
                alternative_model_path = get_file_from_folder_list(
                    alternative_model_name,
                    config.paths_checkpoints,
                )

                if os.path.isfile(alternative_model_path):
                    print(
                        f"You do not have [{default_model}] "
                        f"but you have [{alternative_model_name}]."
                    )

                    print(
                        f"Fooocus will use [{alternative_model_name}] "
                        f"to avoid downloading new models, "
                        f"but you are not using the latest models."
                    )

                    print(
                        "Use --always-download-new-model "
                        "to avoid fallback and always get new models."
                    )

                    checkpoint_downloads = {}
                    default_model = alternative_model_name
                    break

    # -----------------------------------------------------
    # Checkpoints
    # -----------------------------------------------------

    for file_name, url in checkpoint_downloads.items():
        model_dir = os.path.dirname(
            get_file_from_folder_list(
                file_name,
                config.paths_checkpoints,
            )
        )

        download_user_supplied(file_name, url, model_dir)

    # -----------------------------------------------------
    # Embeddings
    # -----------------------------------------------------

    for file_name, url in embeddings_downloads.items():
        download_user_supplied(file_name, url, config.path_embeddings)

    # -----------------------------------------------------
    # LoRAs
    # -----------------------------------------------------

    for file_name, url in lora_downloads.items():
        model_dir = os.path.dirname(
            get_file_from_folder_list(
                file_name,
                config.paths_loras,
            )
        )

        download_user_supplied(file_name, url, model_dir)

    # -----------------------------------------------------
    # VAE
    # -----------------------------------------------------

    for file_name, url in vae_downloads.items():
        download_user_supplied(file_name, url, config.path_vae)

    return default_model, checkpoint_downloads


# ---------------------------------------------------------
# Main application startup
# ---------------------------------------------------------

def main():
    # -----------------------------------------------------
    # 1. Prepare environment
    # -----------------------------------------------------

    prepare_environment()

    # -----------------------------------------------------
    # 2. Build launcher
    # -----------------------------------------------------

    build_launcher()

    # -----------------------------------------------------
    # 3. Parse arguments
    # -----------------------------------------------------

    args = ini_args()

    # -----------------------------------------------------
    # 4. GPU selection
    # -----------------------------------------------------

    if args.gpu_device_id is not None:
        os.environ["CUDA_VISIBLE_DEVICES"] = str(
            args.gpu_device_id
        )

        print(
            "Set device to:",
            args.gpu_device_id,
        )

    # -----------------------------------------------------
    # 5. Optional Hugging Face mirror
    # -----------------------------------------------------

    if args.hf_mirror is not None:
        os.environ["HF_MIRROR"] = str(
            args.hf_mirror
        )

        print(
            "Set hf_mirror to:",
            args.hf_mirror,
        )

    # -----------------------------------------------------
    # 6. Import runtime configuration
    # -----------------------------------------------------

    from modules import config
    from modules.hash_cache import init_cache

    # -----------------------------------------------------
    # 7. Configure runtime directories
    # -----------------------------------------------------

    os.environ["U2NET_HOME"] = config.path_inpaint
    os.environ["GRADIO_TEMP_DIR"] = config.temp_path

    # -----------------------------------------------------
    # 8. Clean temporary directory
    # -----------------------------------------------------

    if config.temp_path_cleanup_on_launch:
        print(
            f"[Cleanup] Attempting to delete content of "
            f"temp dir {config.temp_path}"
        )

        result = delete_folder_content(
            config.temp_path,
            "[Cleanup] ",
        )

        if result:
            print("[Cleanup] Cleanup successful")
        else:
            print("[Cleanup] Failed to clean temp directory.")

    # -----------------------------------------------------
    # 9. Download / locate models
    # -----------------------------------------------------

    (
        config.default_base_model_name,
        config.checkpoint_downloads,
    ) = download_models(
        config.default_base_model_name,
        config.previous_default_models,
        config.checkpoint_downloads,
        config.embeddings_downloads,
        config.lora_downloads,
        config.vae_downloads,
        config,
        args,
    )

    # -----------------------------------------------------
    # 10. Update model file lists
    # -----------------------------------------------------

    config.update_files()

    # -----------------------------------------------------
    # 11. Initialize model / LoRA hash cache
    # -----------------------------------------------------

    init_cache(
        config.model_filenames,
        config.paths_checkpoints,
        config.lora_filenames,
        config.paths_loras,
    )

    # -----------------------------------------------------
    # 12. Start WebUI
    # -----------------------------------------------------

    import webui


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    main()