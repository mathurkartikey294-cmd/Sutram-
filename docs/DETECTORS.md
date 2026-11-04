# SUTRAM Forensic Detector Taxonomy (DETECTORS.md)

This catalog details all forensic detection modules available in SUTRAM, categorized by media modality and forensic category.

---

## 1. Image & Document Modality Detectors

| Detector Name | Category | Module Path | Lead Owner | Underlying Principle | Primary Artifact / Output |
|:---|:---|:---|:---|:---|:---|
| **Error Level Analysis (ELA)** | Tampering | `detectors/image/ela.py` | Shivendra | JPEG compression error differential at fixed resave quality | False-color error heatmap PNG |
| **Copy-Move Forgery** | Tampering | `detectors/image/copy_move.py` | Shivendra | ORB/AKAZE keypoint matching with spatial distance clustering | Matched keypoint line plot PNG |
| **Document Image Tampering** | Tampering | `detectors/image/document_tampering.py` | Shivendra | Paper stroke binarization, altered digits noise halo, cloned stamps/signatures | Document tamper bounding box PNG |
| **Metadata Inconsistency** | Provenance | `detectors/image/metadata.py` | Shivendra | EXIF/XMP editing software tags & thumbnail hash comparison | Metadata divergence table |
| **2D FFT Frequency Analysis** | Synthetic | `detectors/image/noise_frequency.py` | Shivendra | Radial Fourier power spectrum anomalies from diffusion/GAN upsamplers | 2D Fourier power spectrum PNG |
| **Face Boundary Blending** | Tampering | `detectors/image/face_blend.py` | Shivendra | Landmark convex hull sharpness & noise gradient discontinuity | Facial transition mask PNG |
| **Deep Synthetic Classifier** | Synthetic | `detectors/image/cnn_classifier.py` | Shivendra | Deep neural network (EfficientNet/ResNet) + Grad-CAM activation | Grad-CAM attribution heatmap PNG |
| **Double JPEG Quantization** | Tampering | `detectors/image/double_jpeg.py` | Shivendra | DCT coefficient histogram periodicity from secondary compression | DCT coefficient periodicity plot |
| **Local Noise Splicing** | Tampering | `detectors/image/splicing.py` | Shivendra | Patch-level wavelet median absolute deviation noise variance | Local noise variance map PNG |
| **PRNU Fingerprinting** | Provenance | `detectors/image/prnu_experimental.py` | Shivendra | Photo-Response Non-Uniformity sensor noise cross-correlation | Sensor noise correlation score |
| **3D Corneal Lighting** | Tampering | `detectors/image/lighting_experimental.py` | Shivendra | Corneal iris highlight position consistency (Hu et al. 2021) & YCbCr chroma/shading vectors | Highlight reflection alignment vector |

---

## 2. Audio Modality Detectors

| Detector Name | Category | Module Path | Lead Owner | Underlying Principle | Primary Artifact / Output |
|:---|:---|:---|:---|:---|:---|
| **wav2vec Anti-Spoofing** | Synthetic | `detectors/audio/wav2vec_classifier.py` | Saksham | Self-supervised speech representation & ONNX windowed probe | Temporal suspiciousness curve |
| **Splice & Cut Discontinuity** | Tampering | `detectors/audio/splice_discontinuity.py` | Saksham | Abrupt ambient noise-floor jumps (>12dB) & spectral flux clicks | Flagged splice timestamps & waveform plot |
| **ENF 50Hz Phase Tracking** | Tampering | `detectors/audio/spectral.py` | Saksham | 50 Hz/60 Hz power grid hum phase continuity (Hilbert transform) | ENF phase jump timeline |
| **Prosody & Pitch Dynamics** | Synthetic | `detectors/audio/prosody_pauses.py` | Saksham | Vocal fold pitch ($F_0$) jitter/shimmer & conversational pause histogram | Pitch contour & pause distribution plot |
| **Spectral Artifact Analysis** | Synthetic | `detectors/audio/spectral.py` | Saksham | Neural vocoder high-frequency cutoff (>8kHz) & phase mismatch | High-resolution Mel-spectrogram PNG |
| **Codec & Compression Guard** | Quality | `detectors/audio/codec.py` | Saksham | Bitrate, sampling rate, and narrowband telephony quality assessment | Suitability warning flags |

---

## 3. Video Modality Detectors

| Detector Name | Category | Module Path | Lead Owner | Underlying Principle | Primary Artifact / Output |
|:---|:---|:---|:---|:---|:---|
| **Frame Sampler & Demuxer** | Quality | `detectors/video/frame_sampler.py` | Saarika | Multi-tier sampling (sparse 1-2 fps vs dense windows) & audio extraction | Extracted frames & audio stream |
| **POS rPPG Pulse & Coherence** | Synthetic | `detectors/video/rppg.py` | Saarika | Plane-Orthogonal-to-Skin (POS) pulse extraction & spatial cheek/forehead coherence | Pulse waveform & coherence plot |
| **Lip-Sync Desynchronization** | Tampering | `detectors/video/lipsync.py` | Saarika | Inner-lip aperture vs audio log-RMS envelope cross-correlation lag ($[-400\text{ms}, +400\text{ms}]$) | Lag vs correlation curve PNG |
| **Temporal Jitter & Flicker** | Synthetic | `detectors/video/temporal.py` | Saarika | Facial landmark inter-frame acceleration & dense optical flow variance | Temporal jitter index plot |
| **Container & Atom Analysis** | Provenance | `detectors/video/container.py` | Saarika | MP4 box hierarchy, Lavf/FFmpeg encoder tags, header conflicts | Container structure breakdown |
| **GOP Cadence & Re-encoding** | Tampering | `detectors/video/gop_reencode.py` | Saarika | I/P/B frame sequencing irregularities and spliced keyframe points | GOP cadence chart |
| **Frame Duplication & Drops** | Tampering | `detectors/video/frame_dup_drop.py` | Saarika | Consecutive frame perceptual hash difference & frozen frame runs | Repeated frame timeline |
| **Timestamp PTS Jitter** | Tampering | `detectors/video/timestamp_pts.py` | Saarika | Presentation timestamp (PTS/DTS) non-monotonic jumps | Timestamp delta plot |

---

## 4. Document & Electronic Record Provenance Detectors

| Detector Name | Category | Module Path | Lead Owner | Underlying Principle | Primary Artifact / Output |
|:---|:---|:---|:---|:---|:---|
| **Native PDF Structure Forensics** | Tampering | `provenance/pdf_document.py` | Kartikey | Incremental update revision extraction, font stream mismatches & hidden OCR layer diffs | Multi-revision diff report |
| **C2PA Manifest Verifier** | Provenance | `provenance/c2pa.py` | Kartikey | Cryptographic assertion verification on Coalition for Content Provenance manifests | Provenance assertion tree |
| **RFC 8785 Audit Hash Chain** | Integrity | `core/signing.py` | Kartikey | Canonical JSON hashing (JCS) with SHA-256 append-only ledger | Audit chain verification certificate |
| **Confidence Fusion Engine** | Fusion | `pipeline/fusion.py` | Kartikey | Confidence-weighted aggregator with conflict-to-`INCONCLUSIVE` resolution | Composite verdict & radar weights |
| **4-Axis Assessment** | Assessment | `pipeline/evidentiary_assessment.py` | Kartikey | Independent evaluation of Integrity, Authenticity, Provenance, Suitability | 4-Axis court summary card |
