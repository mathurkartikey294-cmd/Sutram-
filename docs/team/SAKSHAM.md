# SUTRAM Task Specification: Saksham (Audio Forensics & Voice Clone Detection Lead)

> **Agent Directive**: If you are an AI coding agent (Antigravity, Claude, Cursor, Copilot) assisting **Saksham**, your scope is defined by this document. Adhere strictly to the forensic integrity principles in `AGENTS.md` and `docs/FORENSIC_STANDARDS.md`. Every finding must be explainable, generate visual audio artifacts (spectrograms with flagged time intervals), express results via the calibrated verbal scale, and explicitly flag low-bitrate compression limitations.

---

## 1. Role Overview & System Responsibilities
- **Name**: Saksham
- **Title**: Lead Audio Forensics Engineer
- **Primary Domain**: Voice cloning detection, synthetic speech recognition (TTS / voice conversion), audio tampering (splices, noise-floor jumps, edit discontinuities), prosodic/pitch unnaturalness, and spectral/codec artifact analysis.
- **Core Interface**:
  - Subclasses `BaseDetector` from `app.detectors.base`.
  - Self-registers in `app.detectors.registry`.
  - Generates `DetectorResult` payloads with time-stamped region evidence, waveform/spectrogram artifacts, and verbal-scale verdicts.

---

## 2. Directory & File Ownership
You have primary ownership and authority over:
```
backend/app/detectors/audio/
├── __init__.py
├── wav2vec_classifier.py    # Pretrained wav2vec 2.0 anti-spoofing classifier
├── prosody_pauses.py        # Pitch contour (F0), pause duration distribution, jitter/shimmer
├── spectral.py             # Mel-spectrogram generation, high-frequency cutoff, phase consistency
├── codec.py                # Re-encoding traces, lossy compression artifacts, telephony limits
└── splice_discontinuity.py  # Abrupt noise floor jumps, silence edits, zero-crossing violations

backend/tests/
├── test_audio_detectors.py # Comprehensive unit tests for all audio modules
└── test_audio_splicing.py  # Tests on synthetic spliced audio samples
```

---

## 3. Detailed Task Breakdown & Implementation Guide

### Task A1: Base Plugin Contract Compliance
All audio detectors must implement:
```python
from app.detectors.base import BaseDetector, DetectorResult, EvidenceItem, CalibratedScale

class ExampleAudioDetector(BaseDetector):
    name = "example_audio_detector"
    version = "1.0.0"
    category = "synthetic_detection" # synthetic_detection | tampering | provenance | quality
    supported_media_types = ["audio/wav", "audio/mpeg", "audio/aac", "audio/ogg", "audio/flac"]

    def analyze(self, media_path: Path, context: dict) -> DetectorResult:
        # Load audio using scipy.io.wavfile or librosa/soundfile safely
        ...
```
- Audio Processing Rules:
  - Do not shell out to external commands with unsanitized paths. If calling `ffmpeg` to transcode, use `core.security.safe_subprocess`.
  - Always check sample rate and duration. If duration $< 1.0$ second, return `status="skipped"` with explanation: "Audio duration insufficient for reliable forensic evaluation".

---

### Task A2: Synthetic Voice & Anti-Spoofing Classifier (`wav2vec_classifier.py`)
- **Forensic Principle**: Self-supervised speech representations (like wav2vec 2.0 / XLS-R) trained on vast human speech capture subtle phoneme transitions and glottal flow features that generative voice clones (ElevenLabs, Tortoise, VITS) fail to reproduce accurately.
- **Architecture**:
  - Pretrained `facebook/wav2vec2-base` or ASVspoof-finetuned linear classification head.
  - Input: Raw 16kHz mono audio waveform.
  - Output: Probabilistic score for `Synthetic` vs `Authentic`.
- **Explainability**:
  - Divide audio into 1-second sliding windows (50% overlap).
  - Score each window independently to produce a temporal suspiciousness curve.
  - Highlight the most artificial segment in the report artifact.
- **Fallback**: When model weights are absent or `MOCK_MODE=True`, return deterministic mock results clearly marked `[MOCK]`, or `status="not_implemented"`. Never return random numbers.

---

### Task A3: Splice & Edit Discontinuity Detection (`splice_discontinuity.py`)
- **Forensic Principle**: When audio is cut and spliced (e.g. deleting words or inserting phrases), microscopic acoustic boundaries are created:
  1. Abrupt changes in background ambient noise floor (room acoustics change).
  2. Non-zero-crossing splices creating high-frequency impulse clicks.
  3. Unnatural digital silence (exact 0.0 values) inserted between words.
- **Algorithm**:
  1. Windowing: Frame audio into 50ms frames with 25ms step.
  2. Noise Floor Tracking: Calculate Root-Mean-Square (RMS) energy in unvoiced/silent segments. Compute first-order difference: $\Delta \text{RMS} = |\text{RMS}_{t} - \text{RMS}_{t-1}|$.
  3. Flag statistical outliers where background noise jumps > 12 dB across consecutive frames without vocal onset.
  4. Spectral Flux: Compute spectral distance between adjacent frames:
     $$\text{Flux}_t = \sum_k (|S(t, k)| - |S(t-1, k)|)^2$$
     An abnormal spike occurring outside phonetic boundaries indicates an edit point.
  5. Save artifact: Waveform visualization with vertical red markers indicating splice candidate timestamps.
- **Output Evidence**:
  - List of detected edit candidates: `[{"time_start": 3.42, "time_end": 3.45, "delta_db": 14.2, "confidence": 0.82}]`.

---

### Task A4: Prosodic & Pitch (F0) Analysis (`prosody_pauses.py`)
- **Forensic Principle**: Synthetic speech generators frequently exhibit prosodic defects:
  - Robotic, over-regularized speech rate.
  - Lack of micro-tremor in fundamental frequency ($F_0$) during sustained vowels.
  - Unnatural pause distributions (too brief, mathematically regular intervals, or breathing absent before long utterances).
- **Algorithm**:
  1. Extract fundamental frequency ($F_0$) trajectory using autocorrelation or Yin algorithm (`scipy.signal` / `librosa`).
  2. Compute pitch dynamics: jitter (cycle-to-cycle frequency variation) and shimmer (cycle-to-cycle amplitude variation). Real human vocal folds have natural non-zero jitter (0.5% - 1.0%). Zero or near-zero jitter indicates algorithmic synthesis.
  3. Detect pauses: Silence threshold at -40 dBFS. Compute histogram of pause durations. Compare with human conversational pause models.
  4. Plot F0 contour and pause histogram as an artifact PNG.

---

### Task A5: Spectral & High-Frequency Artifacts (`spectral.py`)
- **Forensic Principle**: Many neural vocoders (HiFi-GAN, MelGAN, WaveGlow) exhibit severe spectral rolloff or checkerboard artifacts above 4kHz or 8kHz, and show unnatural phase cancellation across harmonic overtones.
- **Algorithm**:
  1. Compute Short-Time Fourier Transform (STFT) with Hann window (n_fft=2048, hop_length=512).
  2. Generate a standard Mel-spectrogram (80 or 128 mel bins).
  3. High-Frequency Rolloff Test: Compare energy in the 8kHz–16kHz band vs 0kHz–8kHz band. Abrupt flat-line dropoffs indicate vocoder bandwidth limitation.
  4. Phase Derivative Check: Detect phase inconsistencies along harmonic tracks.
  5. Save the Mel-spectrogram artifact with high-contrast colormap (`spectrogram.png`).

---

### Task A6: Codec & Compression Quality Guard (`codec.py`)
- **Forensic Principle**: Cellular voice calls (AMR-NB at 4.75-12.2 kbps) or WhatsApp voice notes (Opus at low bitrate) destroy high frequencies and introduce heavy quantization noise that renders synthetic voice detectors unreliable.
- **Checks**:
  1. Container & Codec Inspection: Detect bitrate, sample rate, channels, bit depth.
  2. Identify telephony bandwidth restriction (narrowband 300Hz - 3400Hz).
  3. Quality Suitability Rule: If sample rate $< 16000$ Hz or bitrate $< 24$ kbps, emit a prominent **`QUALITY WARNING`**:
     *"Audio exhibits aggressive compression or narrowband telephony characteristics. AI synthetic voice detection confidence is severely degraded."*

---

## 4. Definition of Done for Saksham
- [ ] All 5 audio detectors implemented in `backend/app/detectors/audio/` with registry auto-registration.
- [ ] Splice detector pinpoints artificial noise floor shifts and abrupt cuts with timestamps.
- [ ] Pitch and pause analyzer computes $F_0$ trajectory and flags unnatural robotic stability.
- [ ] Spectral analyzer exports high-resolution Mel-spectrogram artifacts.
- [ ] Codec analyzer issues clear forensic suitability warnings on degraded audio.
- [ ] `uv run pytest backend/tests/test_audio_detectors.py` passes.
- [ ] Clean linting and strict type checking (`ruff` and `mypy`).
