# SUTRAM Task Specification: Saarika (Video Forensics & Synthetic Video Detection Lead)

> **Agent Directive**: If you are an AI coding agent (Antigravity, OpenCode, Claude Code, Cursor, Copilot, Gemini) assisting **Saarika**, your scope is defined by this document. Adhere strictly to the forensic integrity principles in `AGENTS.md` and `docs/FORENSIC_STANDARDS.md`. Ensure CPU-friendly video processing, extract audio cleanly for the audio pipeline, generate synchronized timeline artifacts, express findings on the calibrated verbal scale, and clearly document all limitations.

---

## 1. Role Overview & System Responsibilities
- **Name**: Saarika
- **Title**: Lead Video Forensics Engineer
- **Primary Domain**: Video manipulation detection (deepfake face-swaps, synthetic video, frame tampering, re-encoding), biological physiological consistency (Plane-Orthogonal-to-Skin / POS rPPG pulse & FakeCatcher spatial coherence), audiovisual synchronization (lip-sync offset correlation), and container/GOP stream forensics.
- **Core Interface**:
  - Subclasses `BaseDetector` from `app.detectors.base`.
  - Self-registers in `app.detectors.registry`.
  - Emits `DetectorResult` objects equipped with timeline arrays (flagging start/end timestamps of suspicious segments) and visual plot artifacts (rPPG waveforms, lip-sync cross-correlation curves).

---

## 2. Directory & File Ownership
You have primary ownership and authority over:
```
backend/app/detectors/video/
├── __init__.py
├── frame_sampler.py        # Frame sampling (1-2 fps sparse vs dense windows), audio extraction
├── face_track.py           # Face detection, landmark tracking, bounding box stabilization
├── rppg.py                 # POS (Plane-Orthogonal-to-Skin) rPPG pulse & spatial cheek/forehead coherence
├── lipsync.py              # Pure-NumPy mouth aperture vs audio log-RMS envelope lag correlation
├── temporal.py             # Temporal flicker, optical flow discontinuity, landmark jitter
├── frame_classifier.py     # Frame-level deepfake aggregator across sampled frames
├── container.py            # MP4/MKV atom/box inspection, tool tags, metadata conflicts
├── gop_reencode.py         # GOP (Group of Pictures) structure, re-encoding traces, I/P/B frames
├── frame_dup_drop.py       # Frame duplication & drop detection (pHash diffs, motion vectors)
└── timestamp_pts.py        # PTS/DTS presentation timestamp jitter & non-monotonic jumps

backend/tests/
├── test_video_detectors.py # Comprehensive unit tests for all video modules
├── test_pos_rppg.py        # Numerical verification of POS pulse extraction
└── test_temporal_gop.py    # Tests on video stream tampering fixtures
```

---

## 3. Detailed Task Breakdown & Implementation Guide

### Task V1: Frame Sampler & Audio Extractor (`frame_sampler.py`)
- **Forensic Principle**: Videos are data-heavy. Evaluating every frame of a 1080p 60fps video on CPU causes unacceptable latency. We need multi-tier sampling:
  1. **Sparse Tier**: 1 to 2 frames per second for spatial deepfake classification and image detector passes (cap total sampled frames to max 60).
  2. **Dense Tier**: 2 to 3 dense windows of 2-3 seconds at native fps (e.g. 30 fps) for physiological rPPG pulse analysis and temporal jitter.
  3. **Audio Demux**: Extract the primary audio stream losslessly to a temporary WAV file (`16kHz mono`) using `ffmpeg` and trigger **Saksham's** audio pipeline.
- Implement robust subprocess handling without shell injection (`app.core.security.safe_subprocess`).

---

### Task V2: Remote Photoplethysmography (POS rPPG Pulse & Coherence) (`rppg.py`)
- **Forensic Principle**: Real human facial skin fluctuates in color with cardiac blood volume changes. The **Plane-Orthogonal-to-Skin (POS, Wang et al. 2017)** algorithm projects normalized RGB skin traces onto an orthogonal chrominance plane to extract the pulse signal while eliminating lighting and specular motion artifacts.
- **Algorithm**:
  1. Extract separate skin patches: Forehead, Left Cheek, and Right Cheek.
  2. Compute POS Projection on each patch:
     $$S_1 = G - B, \quad S_2 = -2R + G + B$$
     $$P = S_1 + \left(\frac{\sigma(S_1)}{\sigma(S_2)}\right) S_2$$
  3. Zero-phase FFT bandpass filter across physiological human heart rates $[0.7\text{ Hz}, 3.5\text{ Hz}]$ (42 to 210 BPM).
  4. Spatial Coherence (FakeCatcher logic): Measure Pearson correlation between forehead, left cheek, and right cheek pulse traces. Real humans display synchronized cardiac cycles ($\text{coherence} > 0.65$); synthetic face generators obliterate spatial pulse coherence.
  5. Compute Signal-to-Noise Ratio (SNR). If $\text{SNR} < 1.5\text{ dB}$, return `status="inconclusive"` with explanation *"Illumination or head movement prevents reliable cardiac pulse extraction"*.
  6. Save artifact: Time-domain pulse waveform plot and frequency power spectrum (`rppg_plot.png`).

---

### Task V3: Audiovisual Lip-Sync Consistency (`lipsync.py`)
- **Forensic Principle**: Lip-synced deepfakes and audio dubbing create noticeable timing offsets between vocal phoneme acoustic energy and visual mouth opening/closing kinematics.
- **Algorithm (Pure-NumPy)**:
  1. Extract mouth vertical aperture: $A(t) = \text{inner\_lip\_gap} / \text{mouth\_width}$ from facial landmarks.
  2. Compute first-differenced log-RMS audio envelope $E(t)$ around each frame timestamp ($t \pm 40\text{ms}$).
  3. Speech Mask: Filter frames where audio envelope is $\ge 6\text{ dB}$ above noise floor to evaluate only voiced intervals.
  4. Cross-Correlation: Compute normalized cross-correlation across temporal lags $\tau \in [-400\text{ms}, +400\text{ms}]$.
  5. Measure optimal lag $\tau^* = \arg\max \rho(\tau)$ and peak correlation coefficient. If $|\tau^*| > 60\text{ms}$ or $\rho < 0.20$, flag audiovisual desynchronization.
  6. Save artifact: Lag vs cross-correlation curve (`lipsync_lag.png`).

---

### Task V4: Temporal Inconsistency & Landmark Jitter (`temporal.py`)
- **Forensic Principle**: Generative face swaps struggle with inter-frame temporal coherence. Faces exhibit micro-flicker in skin texture, landmark coordinate jitter, or warping along boundaries between frames.
- **Algorithm**:
  1. Track 68 facial landmarks across adjacent frames.
  2. Normalize face coordinates against rigid head motion (affine alignment using outer eye corners).
  3. Calculate residual landmark acceleration (second derivative): $\mathbf{a}_i(t) = \mathbf{p}_i(t+1) - 2\mathbf{p}_i(t) + \mathbf{p}_i(t-1)$.
  4. Compute High-Frequency Temporal Energy (HFTE). Real faces have smooth kinematics; deepfakes show abnormal high-frequency jitter.
  5. Optical Flow: Compute Farneback dense optical flow inside face bounding box vs outside. Boundary discontinuity confirms warping.

---

### Task V5: Container & Metadata Forensics (`container.py`)
- **Forensic Principle**: Original camera video recordings embed vendor-specific container atoms (e.g. Apple QuickTime atoms `keys`, `moov`, `udta`, camera serial numbers, lens info). Videos processed through editing software or online generators have standard generic FFmpeg/Lavf headers or missing proprietary atoms.
- **Checks**:
  1. Parse container structure using `ffprobe` JSON output.
  2. Inspect encoder tags: Search for `Lavf`, `HandBrake`, `Adobe`, or missing camera manufacturer metadata.
  3. Container / Stream Inconsistencies: Compare container declared duration vs actual stream packet duration. Discrepancies point to truncation or editing.

---

### Task V6: GOP Structure & Re-Encoding Traces (`gop_reencode.py`)
- **Forensic Principle**: Video codecs group frames into I-frames (intra), P-frames (predicted), and B-frames (bi-directional).
  - Editing a video and re-exporting it resets or alters the Group of Pictures (GOP) cadence.
  - Splicing scenes together often forces an unexpected keyframe (I-frame) out of sequence.
- **Algorithm**:
  1. Extract frame types (`I`, `P`, `B`) and packet sizes using `ffprobe -show_frames`.
  2. Plot GOP sequence. Check if GOP length is fixed or irregular.
  3. Detect spliced keyframes: An isolated I-frame with mismatched quantization parameter ($QP$) or sudden scene change metric without natural dissolve indicates a cut/splice point.

---

### Task V7: Frame Duplication, Drops & Timestamp PTS Jitter (`frame_dup_drop.py`, `timestamp_pts.py`)
- **Frame Duplication / Drop**:
  - Compute perceptual hash difference (`pHash`) and Mean Squared Error between consecutive frames.
  - Detect repetitive frozen frame patterns.
- **PTS/DTS Irregularities**:
  - Inspect Presentation Timestamps (PTS). Check for non-monotonic timestamp progressions, negative deltas, or erratic timebase jumps.
  - Construct a synchronized **Timeline of Suspicious Segments** for the frontend workbench.

---

## 4. Definition of Done for Saarika
- [ ] All video forensic modules implemented in `backend/app/detectors/video/` with self-registration.
- [ ] Frame sampler cleanly demuxes audio to temporary WAV and caps frame count for fast CPU execution.
- [ ] POS rPPG accurately extracts pulse, calculates spatial cheek/forehead coherence, and returns `inconclusive` on low-SNR video.
- [ ] Lip-sync analyzer computes aperture vs envelope correlation and produces lag plot artifact.
- [ ] Container and GOP analyzers detect re-encoding signatures and unexpected keyframe cuts.
- [ ] Timestamp PTS inspector flags timebase jitter and outputs a suspicious segment timeline.
- [ ] Unit tests pass cleanly (`pytest backend/tests`).
