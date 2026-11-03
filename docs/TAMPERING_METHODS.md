# Forensic Mechanics of Multimedia Tampering Methods (TAMPERING_METHODS.md)

This document details the physical, mathematical, and algorithmic mechanics behind digital tampering techniques and how SUTRAM detects them.

---

## 1. Copy-Move Forgery
- **Mechanics**: An investigator or adversary copies a region of an image (e.g., foliage, text, or a vehicle) and pastes it elsewhere within the same image to conceal an object or duplicate evidence.
- **Forensic Footprint**: The duplicated regions share identical sensor noise, lighting vectors, and feature descriptors. Even if the adversary rotates or scales the copied patch, scale-invariant feature transform (SIFT) or ORB keypoint descriptors detect affine geometric correspondences that naturally occurring textures do not produce.
- **SUTRAM Defense**: `CopyMoveDetector` extracts keypoints, matches them using Lowe's ratio test, filters out local spatial proximity to ignore natural uniform textures, and applies DBSCAN spatial clustering to verify multi-point geometric congruence.

---

## 2. Image Splicing & Compositing
- **Mechanics**: Elements from two or more distinct donor images are combined into a composite image.
- **Forensic Footprint**:
  1. **Noise Inconsistency**: Different cameras, ISO settings, and post-processing pipelines generate distinct sensor noise levels.
  2. **Boundary Discontinuities**: The border where the spliced object meets the host background exhibits unnatural gradients in sharpness or chromatic aberration.
  3. **Illumination Inconsistency**: Shadows cast by the spliced element often conflict with the primary light source direction of the scene.
- **SUTRAM Defense**:
  - `ErrorLevelAnalysisDetector`: Flags regions with differential JPEG compression error.
  - `SplicingDetector`: Computes local noise variance maps across $32\times32$ patches using wavelet decomposition.
  - `FaceBlendDetector`: Analyzes sharpness and noise transitions along facial boundary masks.

---

## 3. Double JPEG Compression
- **Mechanics**: When a JPEG image is modified and re-saved, the image undergoes Discrete Cosine Transform (DCT) quantization twice.
- **Forensic Footprint**: If the primary compression used quantization matrix $Q_1$ and the secondary compression used $Q_2$, the resulting histogram of DCT coefficients exhibits periodic gaps or peaks caused by the non-linear rounding operations:
  $$\text{round}\left(\frac{\text{round}(x / Q_1) \cdot Q_1}{Q_2}\right)$$
- **SUTRAM Defense**: `DoubleJPEGDetector` performs Benford's law analysis and periodic histogram peak detection across primary DCT AC coefficients.

---

## 4. Deepfake Face-Swapping & Full-Head Synthesis
- **Mechanics**: Using autoencoders (DeepFaceLab, SimSwap) or latent diffusion models to superimpose a target identity onto a donor body.
- **Forensic Footprint**:
  1. **Spatial Blending Artifacts**: Blur, color bleeding, or unnatural pixel jitter along facial margins.
  2. **Frequency Checkerboards**: Transposed convolutions in generative decoders leave distinct grid patterns in the 2D Fourier power spectrum.
  3. **Physiological Absence**: Synthetic faces do not reproduce biological micro-circulation (cardiovascular pulse signals in the green channel).
- **SUTRAM Defense**:
  - `FaceBlendDetector`: Boundary transition variance.
  - `NoiseFrequencyDetector`: 2D FFT radial power distribution.
  - `RPPGDetector`: Cardiovascular skin blood volume pulse extraction.

---

## 5. Voice Cloning & Neural Speech Synthesis
- **Mechanics**: Deep neural voice cloning models (VITS, FastSpeech, ElevenLabs) synthesize speech from text or convert an existing speaker's voice using neural vocoders (HiFi-GAN, WaveGlow).
- **Forensic Footprint**:
  1. **Neural Vocoder Spectral Cutoff**: HiFi-GAN and similar vocoders often introduce sharp high-frequency rolloff above 8kHz or 12kHz, leaving unnatural dead zones in the upper spectrum.
  2. **Robotic Pitch Stability**: Natural human vocal cords exhibit micro-instability (jitter/shimmer). Synthesized speech displays abnormally flat fundamental frequency ($F_0$) tracks.
  3. **Unnatural Pauses**: Synthetic speech generators rarely model spontaneous conversational pauses or inhalation sounds.
- **SUTRAM Defense**:
  - `Wav2VecClassifier`: Deep self-supervised feature extraction trained on voice clone benchmarks.
  - `AudioSpectralDetector`: High-frequency rolloff and Mel-spectrogram anomaly inspection.
  - `ProsodyPausesDetector`: Pitch jitter, shimmer, and pause histogram profiling.

---

## 6. Video Frame Tampering & Re-Encoding
- **Mechanics**: Cutting frames from a video or inserting frames to alter context (e.g. removing a weapon or altering the timing of an incident).
- **Forensic Footprint**:
  1. **GOP Interruption**: Video codecs rely on Group of Pictures structures. Splicing a clip introduces unexpected I-frame keyframes out of sequence.
  2. **Timestamp PTS Jitter**: Spliced segments often create Presentation Timestamp (PTS) non-monotonic jumps or duplicated timebase values.
  3. **Frame Duplication**: Frame rate conversion or time-stretching introduces identical adjacent frames.
- **SUTRAM Defense**:
  - `GOPReencodeDetector`: Maps I/P/B frame cadences and detects spliced keyframe anomalies.
  - `TimestampPTSDetector`: Verifies monotonic progression of presentation timestamps.
  - `FrameDupDropDetector`: Identifies repetitive frozen frame sequences using perceptual hashes.
