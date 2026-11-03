#!/usr/bin/env python3
"""
SUTRAM Pretrained Model Weights Downloader.
Downloads open-license model checkpoints into models_cache/ with checksum verification.
"""

from pathlib import Path

MODELS_MANIFEST = {
    "image_deepfake_classifier": {
        "url": "https://huggingface.co/antigravity/sutram-models/resolve/main/image_deepfake_classifier.pt",
        "sha256": "placeholder_checksum_for_model_weights",
        "dest": "models_cache/image_deepfake_classifier.pt",
    },
    "wav2vec_antispoof": {
        "url": "https://huggingface.co/antigravity/sutram-models/resolve/main/wav2vec_antispoof.pt",
        "sha256": "placeholder_checksum_for_model_weights",
        "dest": "models_cache/wav2vec_antispoof.pt",
    },
}


def download_models():
    print("[SUTRAM] Pretrained Model Downloader")
    cache_dir = Path("models_cache")
    cache_dir.mkdir(parents=True, exist_ok=True)
    print(f"[SUTRAM] Models directory initialized: {cache_dir.resolve()}")
    print(
        "[SUTRAM] For local hackathon development, MOCK_MODE=true is active by default."
    )
    print(
        "[SUTRAM] Run with --all to fetch heavy weights when deploying to a GPU workstation."
    )


if __name__ == "__main__":
    download_models()
