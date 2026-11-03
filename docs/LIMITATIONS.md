# Forensic Limitations & Quality Boundaries (LIMITATIONS.md)

Scientific integrity requires transparent disclosure of the boundary conditions where digital forensics tools lose reliability. SUTRAM is designed to provide calibrated decision support to forensic examiners, **not** to serve as an infallible automated judge.

---

## 1. Modality-Specific Limitations

### 1.1 Image Forensics Limitations
1. **Aggressive Social Media Re-Compression**:
   - Platforms such as WhatsApp, Facebook, and Instagram strip metadata, resize dimensions (often to $\le 1080\text{p}$), and recompress images using low-quality JPEG or WebP tables.
   - *Impact*: Error Level Analysis (ELA) and Double JPEG detectors lose calibration because the social media compression layer completely overwrites subtle historical compression footprints.
2. **Generative Inpainting & Small Spliced Regions**:
   - High-resolution diffusion inpainting on very small regions ($< 3\%$ of total image area) may not leave sufficient frequency anomalies to trigger whole-image Fourier detectors.
3. **Sensor Fingerprinting (PRNU) Constraints**:
   - PRNU extraction requires either uncompressed RAW media or at least 20–50 reference images captured by the identical physical sensor. It cannot establish attribution from a single lossy JPEG.

### 1.2 Video Forensics Limitations
1. **Remote Photoplethysmography (rPPG) Sensitivity**:
   - Face motion ($> 15^\circ$ head rotation), rapid lighting changes, heavy makeup, or camera motion blur destroy subtle green-channel skin color fluctuations.
   - *System Guard*: When the signal-to-noise ratio (SNR) is $< 1.5\text{ dB}$, `rppg.py` reports `status="inconclusive"` and does not penalize authenticity.
2. **Low-Frame-Rate & Heavy Motion Blur**:
   - Videos captured below 15 fps or with extreme shutter blur prevent accurate landmark acceleration tracking and optical flow boundary segmentation.
3. **Audiovisual Lip-Sync Drift**:
   - Bluetooth recording devices, network streaming jitter, or hardware latency frequently introduce genuine $50-100\text{ ms}$ desynchronization in real camera footage, which must not be mistaken for deepfake dubbing.

### 1.3 Audio Forensics Limitations
1. **Narrowband Telephony (8kHz AMR/G.711)**:
   - Traditional cellular telephone calls truncate all frequencies above $3.4\text{ kHz}$.
   - *Impact*: Eliminates upper spectral overtones where neural vocoder artifacts typically appear.
   - *System Guard*: Emits a mandatory `QUALITY WARNING` reducing detector confidence.
2. **Acoustic Environment Variations**:
   - Splicing two authentic recordings captured in identical studio environments with identical microphone setups may not yield detectable ambient noise floor jumps.

---

## 2. General Machine Learning Boundaries
1. **Zero-Day Generative Models**:
   - Detectors trained on existing generative architectures (GANs, standard Latent Diffusion) may exhibit reduced sensitivity against novel architectures until new fine-tuned checkpoints are deployed.
2. **Adversarial Perturbations**:
   - Deliberately added adversarial noise specifically optimized to deceive neural classifiers can lower detection probabilities without visibly degrading media quality.

---

## 3. Evidentiary & Legal Disclaimer
SUTRAM provides objective empirical metrics, visual heatmaps, and calibrated verbal scale assessments to assist qualified forensic examiners. **It does not issue legal conclusions of guilt, liability, or evidentiary admissibility.** Findings must be interpreted in conjunction with corroborating investigative evidence, chain of custody logs, and qualified human expert testimony.
