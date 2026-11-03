# SUTRAM Task Specification: Shivendra (Image Forensics & Synthetic Detection Lead)

> **Agent Directive**: If you are an AI coding agent (Antigravity, Claude, Cursor, Copilot) assisting **Shivendra**, your scope is defined by this document. Adhere strictly to the forensic integrity principles in `AGENTS.md` and `docs/FORENSIC_STANDARDS.md`. Every finding must be explainable, generate reproducible artifacts (heatmaps, masks), map to the calibrated verbal scale, and clearly document limitations.

---

## 1. Role Overview & System Responsibilities
- **Name**: Shivendra
- **Title**: Lead Image Forensics Engineer
- **Primary Domain**: Still image analysis, tampering localization (Error Level Analysis, Copy-Move, Splicing, Double JPEG, Face Boundary Blending), metadata inconsistency detection, and synthetic media identification (FFT/frequency anomalies, deep classifier with Grad-CAM).
- **Core Interface**:
  - Subclasses `BaseDetector` from `app.detectors.base`.
  - Self-registers in `app.detectors.registry`.
  - Delivers structured `DetectorResult` objects containing visual artifacts (saved to disk, referenced by path), scores, confidence, and plain-English forensic findings.

---

## 2. Directory & File Ownership
You have primary ownership and authority over:
```
backend/app/detectors/image/
├── __init__.py
├── metadata.py             # EXIF/XMP analysis, software signatures, thumbnail mismatch
├── ela.py                  # Error Level Analysis with JPEG re-save delta
├── copy_move.py            # Keypoint (ORB/AKAZE) matching & cluster verification
├── noise_frequency.py      # 2D FFT / DCT high-frequency synthetic artifacts
├── face_blend.py           # Face boundary blending, landmark contour discontinuity
├── splicing.py             # Local noise variance inconsistency mapping
├── double_jpeg.py          # Quantization table analysis, histogram periodicity
├── cnn_classifier.py       # Pretrained deep synthetic classifier + Grad-CAM heatmap
├── prnu_experimental.py    # Sensor pattern noise correlation (experimental)
└── lighting_experimental.py# Shadow & specular highlight vector consistency (experimental)

backend/tests/
├── test_image_detectors.py # Comprehensive unit tests for all image modules
└── test_ela_copymove.py    # Algorithmic accuracy tests on synthetic fixtures
```

---

## 3. Detailed Task Breakdown & Implementation Guide

### Task S1: Base Plugin Contract Compliance
All your detectors must inherit from `BaseDetector`:
```python
from app.detectors.base import BaseDetector, DetectorResult, EvidenceItem, CalibratedScale

class ExampleImageDetector(BaseDetector):
    name = "example_detector"
    version = "1.0.0"
    category = "tampering" # synthetic_detection | tampering | provenance | quality
    supported_media_types = ["image/jpeg", "image/png", "image/webp"]

    def analyze(self, media_path: Path, context: dict) -> DetectorResult:
        # Implementation
        ...
```
- When `MOCK_MODE=True` or weights/binaries are not installed:
  - If a deep model is pending: return `status="not_implemented"` with a clear `TODO` and owner name, OR if mock mode is requested, return deterministic labeled fixture data marked `[MOCK]`.
  - **NEVER return `random.random()` or ungrounded mock scores**.

---

### Task S2: Error Level Analysis (ELA) (`ela.py`)
- **Forensic Principle**: Re-saving a JPEG at a known quality (e.g. 90-95%) creates compression error. Unmodified regions reach an error equilibrium, while spliced or edited regions (saved a different number of times or from foreign sources) exhibit higher error levels.
- **Algorithm**:
  1. Open image with Pillow, save to an in-memory buffer at `quality=92`.
  2. Compute the absolute difference between the original pixel array and the re-saved array: `delta = |original - resaved|`.
  3. Scale the difference for visibility (e.g. `scale_factor = 255.0 / max(delta.max(), 1)`).
  4. Convert to a false-color heatmap (e.g., using OpenCV `COLORMAP_JET` or `COLORMAP_MAGMA`).
  5. Calculate statistical variance and peak error ratio to determine if localized regions deviate significantly (> 3 standard deviations from median background error).
  6. Save the heatmap artifact as a PNG in `evidence_store/artifacts/{analysis_id}_ela.png`.
- **Output Evidence**:
  - Metric: `peak_error_ratio`, `mean_background_error`, `anomaly_percentage`.
  - Artifact: Heatmap image showing bright high-error clusters.

---

### Task S3: Copy-Move Forgery Detection (`copy_move.py`)
- **Forensic Principle**: Copy-move involves cloning an image region to cover an object or duplicate elements. Cloned regions share identical or near-identical keypoint descriptors under affine transformations.
- **Algorithm**:
  1. Convert image to grayscale. Extract feature keypoints and descriptors using ORB or AKAZE (CPU-efficient, patent-free).
  2. Match descriptors with `cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)`.
  3. Apply Lowe's ratio test (keep matches where `d1 < 0.75 * d2`).
  4. Spatial Distance Filter: Discard matches where spatial Euclidean distance between keypoints is `< min_distance` (e.g. 30 pixels) to avoid natural texture self-matching.
  5. Geometric Clustering: Group remaining match vectors into spatial clusters. If a cluster contains $\ge 5$ consistent vector matches, flag copy-move cloning.
  6. Render an artifact image drawing colored connection lines between duplicated regions.
- **Output Evidence**:
  - Metric: `matched_pairs_count`, `dominant_cluster_size`.
  - Artifact: `copymove_matches.png` highlighting connected cloned areas.

---

### Task S4: Metadata & Software Traces Detector (`metadata.py`)
- **Forensic Principle**: Editing tools (Photoshop, GIMP, Lightroom, Canva) embed unmistakable metadata artifacts: software tags, history records, Adobe XMP packets, or thumbnail mismatches.
- **Checks**:
  1. Parse EXIF tags using Pillow / `piexif` or `exiftool`.
  2. Software Signatures: Search for known editing tools in `Software`, `ProcessingSoftware`, `HistorySoftwareAgent`.
  3. Timestamp Consistency: Compare `DateTimeOriginal`, `DateTimeDigitized`, and filesystem modification timestamps. If `DateTimeOriginal` > `DateTime`, flag chronological impossibility.
  4. Embedded Thumbnail Check: Extract the EXIF thumbnail if present. Compare its perceptual hash (`dHash`) with the full-resolution image. Significant divergence indicates the full image was edited without re-generating the thumbnail.

---

### Task S5: Noise & Frequency Domain Analysis (`noise_frequency.py`)
- **Forensic Principle**: Diffusion models (Midjourney, Stable Diffusion, DALL-E) and GANs leave distinct frequency fingerprints due to upsampling architectures (transposed convolutions) and checkerboard artifacts visible in the 2D Fourier power spectrum.
- **Algorithm**:
  1. Convert image to single-channel luminance, compute 2D Fast Fourier Transform (`np.fft.fft2`), and shift zero-frequency to the center (`fftshift`).
  2. Compute the log-magnitude power spectrum: `spectrum = log(1 + |shifted_fft|)`.
  3. Radial Profile: Compute radially averaged power spectral density from center to Nyquist frequency.
  4. Detect unnatural periodic peaks or high-frequency fall-off anomalies typical of AI upsamplers.
  5. Save the 2D power spectrum visualization as `fft_spectrum.png`.

---

### Task S6: Face Boundary & Blending Forensics (`face_blend.py`)
- **Forensic Principle**: Face swaps and deepfake image splices paste a generated face onto a donor background. Even with blending, boundaries show micro-discontinuities in blur, color gradient, or noise floor.
- **Algorithm**:
  1. Detect face and 68 landmark coordinates using MediaPipe or OpenCV Haar/Dlib.
  2. Generate a tight convex hull mask around the outer facial boundary (jawline to brow).
  3. Dilate the boundary mask by 5 pixels outward and erode by 5 pixels inward to create a 10-pixel transition ring.
  4. Compare Laplacian sharpness and gradient variance inside the face vs immediately outside the boundary ring.
  5. High discontinuity in sharpness or local noise variance supports boundary manipulation.

---

### Task S7: Deep Classifier & Grad-CAM Visualization (`cnn_classifier.py`)
- **Model Backbone**: Pretrained EfficientNet or ResNet binary classifier (Synthetic vs Authentic).
- **Grad-CAM**:
  - Extract gradient activations from the final convolutional layer with respect to the "Synthetic" class.
  - Project activation heatmap back onto the original image dimensions.
  - Generates `gradcam_heatmap.png` showing the exact visual features (eyes, hair borders, background warping) triggering the classification.
- **Fallback**: When model weights (`models_cache/image_deepfake_detector.pt`) are not present, return deterministic mock results clearly marked `[MOCK]` if `MOCK_MODE=True`, or return `status="not_implemented"`.

---

### Task S8: Double JPEG & Local Noise Splicing (`double_jpeg.py`, `splicing.py`)
- Double JPEG: Analyze Discrete Cosine Transform (DCT) coefficient histograms for periodic peaks caused by repeated quantization with different quantization matrices.
- Splicing: Split image into $32 \times 32$ non-overlapping tiles. Estimate noise variance per tile using median absolute deviation of high-frequency wavelets. Produce a noise variance map artifact highlighting foreign spliced patches.

---

## 4. Definition of Done for Shivendra
- [ ] All 10 image detectors implemented in `backend/app/detectors/image/` with self-registration.
- [ ] ELA generates high-contrast heatmap artifacts and properly flags re-compressed slices.
- [ ] Copy-Move successfully identifies cloned regions without false-matching uniform textures.
- [ ] Metadata analyzer identifies editing tags, timestamp paradoxes, and thumbnail deviations.
- [ ] Every detector produces clean, valid `DetectorResult` structures adhering to the verbal scale.
- [ ] `uv run pytest backend/tests/test_image_detectors.py` passes.
- [ ] Code is formatted with `ruff` and strictly typed (`mypy`).
