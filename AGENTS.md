# SUTRAM: AI Coding Agents Master Guide (AGENTS.md)

> **SINGLE SOURCE OF TRUTH**: This document governs all autonomous AI coding agents (Antigravity, Claude, Cursor, Copilot) working in the SUTRAM codebase. Every agent must read and comply with the directives, architecture boundaries, and forensic principles outlined below before generating or editing code.

---

## 1. Project Purpose & System Mission
**SUTRAM** is an AI-powered Multimedia Forensics Platform engineered specifically for forensic examiners, cyber-crime investigators, lab reviewers, and prosecutors. The platform authenticates digital evidence, localizes tampering, detects generative AI/deepfakes across image, video, and audio modalities, and assesses the legal and evidentiary value of digital media.

### The Five Core Deliverables
1. **Deepfake and Synthetic Media Detection Engine** (Images, Videos, Audio).
2. **Multimedia Authentication and Tampering Detection Framework** (ELA, Copy-Move, Splices, Container).
3. **Multimedia Provenance and Source Attribution Tool** (C2PA, EXIF/XMP, Hashes, Lineage).
4. **Explainable AI-Based Forensic Analysis Dashboard** (Dark-themed workbench, heatmaps, timelines, 4-axis assessment).
5. **Automated Forensic Reporting System** (Signed PDF, JSON, and Bharatiya Sakshya Adhiniyam 2023 Section 63 certificate template).

---

## 2. Team Structure & Role Specifications
To prevent merge conflicts and ensure modular development, the codebase is partitioned into four primary role assignments. Detailed individual task specifications are documented in `docs/team/`:

| Team Member | Primary Domain | Task Specification Document |
|:---|:---|:---|
| **Kartikey** | Backend Core, Storage, Tamper-Evident Audit Chain, Evidentiary Fusion, API, Reporting & Integration | [`docs/team/KARTIKEY.md`](file:///docs/team/KARTIKEY.md) |
| **Shivendra** | Image Forensics, ELA, Copy-Move, Metadata, Frequency Anomalies, Deep Synthetic Classifier | [`docs/team/SHIVENDRA.md`](file:///docs/team/SHIVENDRA.md) |
| **Saksham** | Audio Forensics, Voice Clone Detection, wav2vec 2.0, Splice Cuts, Prosody & Codec Warnings | [`docs/team/SAKSHAM.md`](file:///docs/team/SAKSHAM.md) |
| **Saarika** | Video Forensics, Frame Sampler, rPPG Pulse, Lip-Sync Lag, Temporal Jitter, GOP & PTS Analysis | [`docs/team/SAARIKA.md`](file:///docs/team/SAARIKA.md) |

---

## 3. Mandatory Forensic Principles (Non-Negotiable)

1. **Evidence is Never Modified (ISO/IEC 27037)**:
   - Original evidence files are ingested into `evidence_store/originals/` with read-only filesystem permissions.
   - Dual cryptographic hashes (`SHA-256` and `SHA-512`) are computed immediately upon receipt.
   - Analysis pipelines operate **exclusively** on ephemeral working copies in `evidence_store/working/`.
   - Never write, open for write, or overwrite any file in `originals/`.

2. **Never Fake Results or Scores**:
   - Random or arbitrary numbers (`random.random()`, hardcoded arbitrary floats) are **strictly prohibited**.
   - If a heavy machine learning model is not yet installed or in training, return `status="not_implemented"` with an explicit `TODO` and assigned owner.
   - If `MOCK_MODE=true` is enabled in configuration, return deterministic benchmark fixtures and **prominently label every finding and UI card with `[MOCK]`**.

3. **Calibrated Verbal Scale over Raw Probabilities**:
   - Forensic examiners and courts do not accept raw model logits as certainty.
   - Every numerical score (0.0 to 1.0) must map to the standardized 5-tier verbal scale:
     - `0.00 - 0.20`: **Strongly supports authenticity**
     - `0.21 - 0.40`: **Supports authenticity**
     - `0.41 - 0.59`: **Inconclusive**
     - `0.60 - 0.79`: **Supports manipulation**
     - `0.80 - 1.00`: **Strongly supports manipulation**
   - Raw scores are kept in `parameters_used` or details views for examiners, but primary verdicts use the verbal scale.

4. **Explainability & Reproducibility**:
   - Every finding must cite: detection method name, algorithm version, input parameters used, and known limitations.
   - Visual detectors must output verifiable visual artifacts (e.g., ELA heatmap PNG, copy-move match vector PNG, spectrogram PNG).

5. **Local / Air-Gapped Operation by Default**:
   - All evidence remains on the local host.
   - Never initiate external network requests with evidence files, extracted frames, or audio bytes.

6. **Honest Quality Limits & Suitability Warnings**:
   - If media is heavily compressed (e.g., WhatsApp video, 8kHz telephony audio, resolution < 256x256), the system must emit an explicit **Quality Warning** stating that detector reliability is degraded.

---

## 4. Detector Plugin Interface (`detectors/base.py`)

Every detector module across image, video, and audio modalities must inherit from `BaseDetector` and register itself in `detectors/registry.py`:

```python
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class EvidenceItem(BaseModel):
    item_type: str  # "metric" | "text" | "region_bbox" | "time_range" | "mask"
    description: str
    value: Any
    confidence: float = Field(ge=0.0, le=1.0)

class DetectorResult(BaseModel):
    detector_name: str
    detector_version: str
    category: str  # "synthetic_detection" | "tampering" | "provenance" | "quality"
    status: str    # "ok" | "not_implemented" | "error" | "skipped"
    score: float = Field(ge=0.0, le=1.0, description="0.0=authentic, 1.0=manipulated")
    confidence: float = Field(ge=0.0, le=1.0)
    verbal_verdict: str # 5-tier calibrated verbal scale
    summary: str   # Plain-English explanation for non-technical examiners
    evidence: List[EvidenceItem] = []
    artifacts: List[str] = [] # Relative paths to generated PNG heatmaps / plots
    parameters_used: Dict[str, Any] = {}
    limitations: List[str] = []

class BaseDetector:
    name: str = "base"
    version: str = "1.0.0"
    category: str = "tampering"
    supported_media_types: List[str] = []

    def analyze(self, media_path: Path, context: Dict[str, Any]) -> DetectorResult:
        raise NotImplementedError("Subclasses must implement analyze()")
```

### Self-Registration Pattern
In each detector file, register with the global registry:
```python
from app.detectors.registry import detector_registry

detector_registry.register(MyCustomDetector())
```

---

## 5. Coding Conventions & Quality Standards

- **Language & Runtime**: Python 3.12 (managed via `uv`), FastAPI, Pydantic v2.
- **Type Annotations**: Mandatory type hints on all function signatures (`mypy --strict` compliant).
- **Style & Linting**: Ruff for linting and formatting (`line-length = 100`).
- **Docstrings**: Explain the **forensic WHY**, not merely the what. Reference the physical, mathematical, or codec basis of each algorithm.
- **Subprocess Execution**:
  - Never use `shell=True`.
  - Always use `subprocess.run(args_list, check=True, timeout=30, capture_output=True)`.
  - Check exit codes and handle exceptions gracefully without crashing the server.
- **Imports**: Group imports logically: standard library, third-party libraries, local application modules.

---

## 6. Development & Verification Commands

All agents and contributors must test their changes using the project automation:
```bash
# Setup dependencies
make setup

# Run backend unit and integration tests
make test
# Or directly via uv:
uv run pytest backend/tests -v

# Run code linters & type checks
make lint
# Or directly:
uv run ruff check backend
uv run mypy backend/app

# Format code
make format

# Generate sample media
make samples

# Run detector evaluation suite
make eval
```

---

## 7. Definition of Done (DoD)
Before any task or pull request is considered complete:
1. All new detector classes conform to `BaseDetector` and register in `registry.py`.
2. Unit tests are added in `backend/tests/` covering both positive and negative cases.
3. No fake/arbitrary numbers are introduced; all mock modes are explicitly flagged `[MOCK]`.
4. Original evidence read-only integrity is verified.
5. `ruff check backend`, `mypy backend/app`, and `pytest backend/tests` all pass cleanly with zero errors.
