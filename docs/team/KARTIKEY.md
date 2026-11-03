# SUTRAM Task Specification: Kartikey (Backend Core, Provenance, Reporting & Integration Lead)

> **Agent Directive**: If you are an AI coding agent (Antigravity, Claude, Cursor, Copilot) assisting **Kartikey**, your scope is defined by this document. Adhere strictly to the forensic integrity principles in `AGENTS.md` and `docs/FORENSIC_STANDARDS.md`. Never modify original evidence files, never generate invented scores, and ensure all audit entries are hash-chained.

---

## 1. Role Overview & System Responsibilities
- **Name**: Kartikey
- **Title**: Lead Backend Architect & Forensic Core Engineer
- **Primary Domain**: Backend infrastructure, evidence lifecycle & read-only storage, tamper-evident audit chaining, evidentiary assessment & fusion engine, provenance tracking (C2PA/hashing), forensic reporting (signed PDF + JSON + BSA 63 certificate), and FastAPI REST routing.
- **Collaborator Interfaces**:
  - Receives detectors from **Shivendra** (`detectors/image/`), **Saksham** (`detectors/audio/`), and **Saarika** (`detectors/video/`) via `detectors/registry.py`.
  - Supplies normalized data contracts and API endpoints to the **Frontend Workbench**.

---

## 2. Directory & File Ownership
You have primary ownership and authority over:
```
backend/
├── pyproject.toml
├── app/
│   ├── main.py
│   ├── core/              # Config, storage isolation, security, cryptographic signing
│   │   ├── config.py
│   │   ├── storage.py     # Read-only originals, ephemeral working copies
│   │   ├── security.py    # Hostile upload validation, magic bytes, path safety
│   │   └── signing.py     # HMAC-SHA256 / Ed25519 report signing
│   ├── db/                # Database engine & SQLAlchemy models
│   │   ├── session.py
│   │   └── models.py      # Case, EvidenceItem, Analysis, Finding, AuditEntry, User
│   ├── schemas/           # Pydantic v2 validation contracts
│   │   ├── case.py
│   │   ├── evidence.py
│   │   ├── analysis.py
│   │   ├── audit.py
│   │   └── report.py
│   ├── pipeline/          # Orchestration, fusion & evidentiary evaluation
│   │   ├── router.py      # Media-type router
│   │   ├── jobs.py        # In-process background analysis queue
│   │   ├── fusion.py      # Weighted confidence fusion engine
│   │   └── evidentiary_assessment.py # 4-axis assessment engine
│   ├── provenance/        # Provenance, attribution & chain of custody
│   │   ├── hashing.py     # SHA-256, SHA-512, perceptual hashes (pHash/dHash)
│   │   ├── c2pa.py        # C2PA manifest reader & signature verifier
│   │   ├── metadata_xmp_exif.py
│   │   ├── near_duplicate.py
│   │   └── chain_of_custody.py
│   ├── reporting/         # Automated court-ready report generation
│   │   ├── builder.py
│   │   ├── pdf.py         # ReportLab pure-python PDF generator
│   │   ├── certificate_bsa63.py # Section 63 BSA 2023 legal template
│   │   └── templates/
│   └── api/               # Versioned REST API routers
│       ├── cases.py
│       ├── evidence.py
│       ├── analyses.py    # Includes SSE live progress stream
│       ├── reports.py
│       ├── artifacts.py
│       ├── audit.py       # Includes audit chain verification
│       ├── auth.py
│       └── health.py
└── tests/
    ├── test_audit_chain.py
    ├── test_storage_integrity.py
    ├── test_fusion.py
    ├── test_evidentiary_assessment.py
    └── test_api_happy_path.py
```

---

## 3. Detailed Task Breakdown & Implementation Guide

### Task K1: Secure Storage Engine & Read-Only Evidence Ingest (`app/core/storage.py`, `app/core/security.py`)
- **Objective**: Implement strict evidence intake following ISO/IEC 27037 standards.
- **Requirements**:
  1. Validate incoming files using magic bytes (`magic` or byte header signatures). Reject disallowed MIME types immediately.
  2. Enforce file size caps (`MAX_UPLOAD_SIZE_MB`, default 500MB). Guard against decompression bombs (`Image.MAX_IMAGE_PIXELS`).
  3. Write uploaded evidence to the `originals/` directory. Compute dual hashes (`SHA-256` and `SHA-512`) during the stream write.
  4. Apply read-only filesystem attributes (e.g. `chmod 0444` on POSIX, read-only flag on Windows) to the original.
  5. Provide `create_working_copy(evidence_id) -> Path`: Creates an ephemeral working copy in `working/` for detector pipelines to analyze.
  6. Provide `verify_original_integrity(evidence_id) -> bool`: Re-reads the stored original file, recomputes SHA-256 and SHA-512, and compares with the initial ingest database record.

### Task K2: Tamper-Evident Hash-Chained Audit Log (`app/db/models.py`, `app/api/audit.py`)
- **Objective**: Ensure absolute auditability where any database manipulation is immediately caught.
- **Model**:
  ```python
  class AuditEntry(Base):
      __tablename__ = "audit_entries"
      id = Column(Integer, primary_key=True)
      case_id = Column(String, ForeignKey("cases.id"), nullable=True)
      timestamp_utc = Column(DateTime, default=datetime.utcnow, nullable=False)
      actor = Column(String, nullable=False) # e.g. "examiner:kartikey"
      action = Column(String, nullable=False) # "ingest", "verify_hash", "analysis_start", "report_export"
      target_type = Column(String, nullable=False) # "evidence", "analysis", "case"
      target_id = Column(String, nullable=False)
      details = Column(JSON, nullable=False)
      prev_hash = Column(String, nullable=False) # SHA-256 of the previous entry's canonical string representation
      current_hash = Column(String, nullable=False) # SHA-256 of (id + timestamp + actor + action + target + details + prev_hash)
  ```
- **Chain Verification**: Implement `verify_case_audit_chain(case_id) -> VerificationResult`. If any row's `current_hash` or `prev_hash` does not match, return `valid=False` and identify the exact tampered entry.

### Task K3: Evidentiary Fusion Engine (`app/pipeline/fusion.py`)
- **Objective**: Combine individual detector outputs from image, audio, and video pipelines into a single calibrated synthesis.
- **Rules**:
  1. Weighted average based on each detector's self-reported `confidence` (0.0 to 1.0) and system weight config.
  2. **Contradiction Resolution**: If detector A scores > 0.85 (manipulated) with high confidence, but detector B scores < 0.15 (authentic) with high confidence on the same region/modality, score must resolve to **`INCONCLUSIVE`** with an explicit rationale noting conflicting evidence.
  3. Map composite score to calibrated verbal scale:
     - `0.00 - 0.20`: *Strongly supports authenticity*
     - `0.21 - 0.40`: *Supports authenticity*
     - `0.41 - 0.59`: *Inconclusive / Neutral*
     - `0.60 - 0.79`: *Supports manipulation*
     - `0.80 - 1.00`: *Strongly supports manipulation*

### Task K4: 4-Axis Evidentiary Assessment (`app/pipeline/evidentiary_assessment.py`)
- **Objective**: Construct four independent forensic dimensions (NEVER collapse into a single grade):
  1. **Integrity Axis**: Was the file modified post-acquisition? Container consistency, re-encoding indicators, hash verification.
  2. **Authenticity Axis**: Evidence of generative AI synthesis, face swapping, splicing, copy-move, or voice cloning.
  3. **Provenance Axis**: Traceability of origin. Verified C2PA manifest vs claimed metadata (EXIF/XMP) vs unknown/stripped.
  4. **Suitability Axis**: Resolution, bitrate, compression, duration. Warns examiner if evidence quality is too degraded for reliable analysis.
- **Narratives**:
  - `what_this_means_for_the_case`: Plain-language explanation for prosecutors and non-technical judges.
  - `what_could_not_be_determined`: Explicit statement of limits (e.g. "Generator family could not be established due to aggressive social media recompression").

### Task K5: Provenance & C2PA Tooling (`app/provenance/`)
- Multi-hash calculation: `SHA-256`, `SHA-512`, `dHash`, `pHash`.
- C2PA manifest extraction: Use `c2pa-python` or invoke `c2patool` safely without shell interpolation. If C2PA tool is missing, report `manifest_found=False`, status `ok` with clear note.
- Metadata parser: Extract EXIF, XMP, IPTC, and tag mismatches (e.g. software tag says "Adobe Photoshop" but device model claims "iPhone 15 Pro").

### Task K6: Forensic Reporting Engine & Section 63 BSA Certificate (`app/reporting/`)
- Pure Python PDF builder (`ReportLab`) generating a formal forensic lab report:
  - Header: Agency name, Case Number, Examiner name, Date/Time (UTC).
  - Chain of Custody & Evidence Ingest Hashes.
  - Methodology & Tool Versions (reproducibility guarantee).
  - Findings breakdown with embedded heatmap artifacts.
  - 4-Axis Evidentiary Assessment table.
  - Mandatory Limitations section.
  - Cryptographic signature block: HMAC-SHA256 or Ed25519 signature over the canonical report JSON.
- **Section 63 BSA 2023 Certificate**:
  - Electronic record certificate under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (formerly Section 65B of Indian Evidence Act).
  - Clear header: `[TEMPLATE ONLY - FOR LEGAL REVIEW BY INVESTIGATING OFFICER / PUBLIC PROSECUTOR]`.

### Task K7: REST API & In-Process Job Queue (`app/api/`, `app/pipeline/jobs.py`)
- Endpoints:
  - `POST /api/v1/cases` & `GET /api/v1/cases`
  - `POST /api/v1/cases/{id}/evidence`: Upload with progress and instant hash calculation.
  - `POST /api/v1/evidence/{id}/verify`: Integrity verification check.
  - `POST /api/v1/evidence/{id}/analyses`: Launch background analysis.
  - `GET /api/v1/analyses/{id}`: Poll status & get results.
  - `GET /api/v1/analyses/{id}/events`: Server-Sent Events (SSE) progress updates.
  - `GET /api/v1/analyses/{id}/artifacts/{name}`: Serve heatmap PNGs and waveform plots.
  - `GET /api/v1/cases/{id}/audit`: Retrieve log.
  - `GET /api/v1/cases/{id}/audit/verify`: Audit chain validation check.
  - `GET /api/v1/analyses/{id}/report.pdf`: Download signed court-ready PDF.
  - `GET /api/v1/analyses/{id}/report.json` & `.sig`.
  - `GET /api/v1/health`: Return server status and mock mode flags.

---

## 4. Definition of Done for Kartikey
- [ ] All database models created and SQLite database migrations initialize seamlessly.
- [ ] Ingesting an evidence file computes SHA-256 and SHA-512, locks the file, and logs an audit entry.
- [ ] Corrupting a single audit entry causes `verify_case_audit_chain` to return `valid=False`.
- [ ] Fusion engine correctly marks contradictory high-confidence results as `INCONCLUSIVE`.
- [ ] Evidentiary assessment outputs all 4 axes with plain-language explanations.
- [ ] ReportLab generates a valid, styled PDF with embedded evidence visuals and digital signature.
- [ ] `uv run pytest backend/tests/test_audit_chain.py` and other core tests pass 100%.
- [ ] `uv run ruff check backend` and `uv run mypy backend/app` pass without errors.
