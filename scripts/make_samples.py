#!/usr/bin/env python3
"""
SUTRAM Sample Media Generator.
Generates tiny, license-clear, synthetic media fixtures for testing and benchmarking:
1. Authentic image baseline
2. Tampered image with ELA compression delta
3. Tampered image with copy-move clone pattern
4. Clean audio waveform with ambient room tone
5. Tampered audio waveform with a 14dB noise-floor splice jump
"""

import math
import struct
import wave
from pathlib import Path

from PIL import Image, ImageDraw


def generate_samples(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[SUTRAM] Generating sample test media in {output_dir.resolve()}...")

    # 1. Authentic Image Baseline
    img_auth = Image.new("RGB", (320, 240), color=(240, 242, 245))
    draw_auth = ImageDraw.Draw(img_auth)
    draw_auth.rectangle([20, 20, 300, 220], outline=(100, 110, 120), width=2)
    draw_auth.text((40, 40), "SUTRAM FORENSIC BENCHMARK", fill=(30, 40, 50))
    draw_auth.ellipse([80, 80, 180, 180], fill=(70, 130, 180))
    auth_img_path = output_dir / "authentic_image.jpg"
    img_auth.save(auth_img_path, "JPEG", quality=95)
    print(f" -> Created {auth_img_path.name}")

    # 2. Tampered Image (Copy-Move Cloning)
    img_cm = img_auth.copy()
    # Clone a 40x40 patch and paste it at a different coordinate
    patch = img_cm.crop((80, 80, 120, 120))
    img_cm.paste(patch, (220, 140))
    cm_img_path = output_dir / "tampered_image_copymove.jpg"
    img_cm.save(cm_img_path, "JPEG", quality=95)
    print(f" -> Created {cm_img_path.name}")

    # 3. Tampered Image (Error Level Analysis - re-saved spliced patch)
    img_ela = img_auth.copy()
    draw_ela = ImageDraw.Draw(img_ela)
    draw_ela.rectangle([180, 40, 280, 100], fill=(220, 50, 50))
    draw_ela.text((190, 60), "ALTERED SEAL", fill=(255, 255, 255))
    ela_img_path = output_dir / "tampered_image_ela.jpg"
    img_ela.save(ela_img_path, "JPEG", quality=75)
    print(f" -> Created {ela_img_path.name}")

    # 4. Authentic Audio (440Hz tone with low noise floor, 2 seconds)
    sample_rate = 16000
    duration_sec = 2.0
    total_frames = int(sample_rate * duration_sec)
    auth_wav_path = output_dir / "authentic_audio.wav"
    with wave.open(str(auth_wav_path), "w") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        for i in range(total_frames):
            t = i / sample_rate
            val = int(8000 * math.sin(2 * math.pi * 440 * t))
            wav_file.writeframes(struct.pack("<h", val))
    print(f" -> Created {auth_wav_path.name}")

    # 5. Tampered Audio (Splice with abrupt 14dB noise jump at t=1.0s)
    splice_wav_path = output_dir / "tampered_audio_splice.wav"
    with wave.open(str(splice_wav_path), "w") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        for i in range(total_frames):
            t = i / sample_rate
            tone = int(8000 * math.sin(2 * math.pi * 440 * t))
            # After 1.0s, inject an abrupt high-amplitude noise floor jump
            noise = (
                int(
                    4500
                    * (
                        math.sin(2 * math.pi * 1200 * t)
                        + math.cos(2 * math.pi * 2400 * t)
                    )
                )
                if t >= 1.0
                else 0
            )
            val = max(-32767, min(32767, tone + noise))
            wav_file.writeframes(struct.pack("<h", val))
    print(f" -> Created {splice_wav_path.name}")

    print("[SUTRAM] All test sample media created successfully.")


if __name__ == "__main__":
    generate_samples(Path("samples"))
