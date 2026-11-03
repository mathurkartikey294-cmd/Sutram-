# SUTRAM REST API Specification (v1)

Base URL: `http://localhost:8000/api/v1`  
Interactive Swagger Docs: `http://localhost:8000/docs`  
OpenAPI Specification JSON: `http://localhost:8000/openapi.json`

---

## 1. Authentication & Security
- Standard Bearer token authentication: `Authorization: Bearer <jwt_token>`.
- Roles: `examiner`, `reviewer` (read-only + annotations), `admin`.
- For early hackathon development/mock mode, basic local auth is preconfigured with default credentials.

---

## 2. Cases Endpoints

### `POST /api/v1/cases`
Create a new forensic investigation case.
- **Request Body**:
  ```json
  {
    "case_number": "CFSL-2026-DEL-089",
    "title": "State vs. Unknown (Deepfake Extortion)",
    "investigating_agency": "Cyber Crime Police Station, North District",
    "investigating_officer": "Inspector R. Sharma",
    "description": "Alleged manipulated video circulated on social messaging platforms."
  }
  ```
- **Response `201 Created`**:
  ```json
  {
    "id": "case_9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "case_number": "CFSL-2026-DEL-089",
    "title": "State vs. Unknown (Deepfake Extortion)",
    "status": "active",
    "created_at": "2026-11-03T23:00:00Z",
    "evidence_count": 0
  }
  ```

### `GET /api/v1/cases`
List all cases with summary counts.

### `GET /api/v1/cases/{id}`
Retrieve a specific case, including its attached evidence items and current status.

---

## 3. Evidence Ingest & Integrity Endpoints

### `POST /api/v1/cases/{id}/evidence`
Upload and ingest an evidence file.
- **Headers**: `Content-Type: multipart/form-data`
- **Form Fields**:
  - `file`: Raw binary media file.
  - `source_description`: "Seized Samsung Galaxy S23 Ultra internal storage".
  - `acquisition_method`: "Cellebrite UFED physical extraction image".
  - `submitted_by`: "Sub-Inspector V. Kumar".
  - `device_make_model`: "Samsung SM-S918B".
- **Ingest Behavior**:
  1. Validates magic bytes (rejects disallowed MIME).
  2. Saves directly to `evidence_store/originals/` with read-only file permissions.
  3. Computes `SHA-256`, `SHA-512`, and perceptual hash.
  4. Appends record to hash-chained audit log.
- **Response `201 Created`**:
  ```json
  {
    "id": "ev_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "case_id": "case_9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "original_filename": "suspect_video_msg.mp4",
    "mime_type": "video/mp4",
    "file_size_bytes": 14205882,
    "sha256": "3a7acb4f9e8a7d6c5b4a3210fedcba9876543210abcdef0123456789abcdef01",
    "sha512": "9f8e7d6c5b4a3210fedcba9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
    "read_only_locked": true,
    "ingested_at": "2026-11-03T23:02:15Z"
  }
  ```

### `POST /api/v1/evidence/{id}/verify`
Re-verifies the integrity of stored evidence. Re-reads the file from disk, recalculates SHA-256 and SHA-512, and compares with database values.
- **Response `200 OK`**:
  ```json
  {
    "evidence_id": "ev_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "integrity_status": "INTACT",
    "sha256_match": true,
    "sha512_match": true,
    "checked_at": "2026-11-03T23:05:00Z"
  }
  ```

---

## 4. Forensic Analysis & Progress Streaming

### `POST /api/v1/evidence/{id}/analyses`
Dispatch analysis jobs on the working copy of the evidence.
- **Request Body**:
  ```json
  {
    "enable_deep_classifiers": true,
    "enable_tampering_detectors": true,
    "enable_provenance": true,
    "custom_parameters": {
      "ela_quality": 92,
      "video_sample_fps": 1.5
    }
  }
  ```
- **Response `202 Accepted`**:
  ```json
  {
    "analysis_id": "an_7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e",
    "evidence_id": "ev_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "status": "queued",
    "message": "Analysis dispatched. Follow progress via SSE endpoint."
  }
  ```

### `GET /api/v1/analyses/{id}/events`
Server-Sent Events (SSE) streaming live progress updates as each detector completes.
- **Event stream format**:
  ```
  event: progress
  data: {"stage": "ela", "progress_pct": 25, "detector": "ErrorLevelAnalysisDetector", "verdict": "Supports manipulation"}

  event: progress
  data: {"stage": "copy_move", "progress_pct": 50, "detector": "CopyMoveDetector", "verdict": "Supports manipulation"}

  event: complete
  data: {"analysis_id": "an_7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e", "status": "completed"}
  ```

### `GET /api/v1/analyses/{id}`
Retrieve full analysis results, including individual detector findings, composite fusion score, and the 4-axis evidentiary assessment.

---

## 5. Artifacts & Evidence Inspection

### `GET /api/v1/analyses/{id}/artifacts/{artifact_filename}`
Serve generated visual artifacts: ELA heatmaps, copy-move match connection plots, Grad-CAM overlays, rPPG pulse graphs, or Mel-spectrogram images.
- **Response**: Binary image stream (`image/png`).

---

## 6. Audit Trail & Cryptographic Verification

### `GET /api/v1/cases/{id}/audit`
Retrieve the ordered audit log for a case.

### `POST /api/v1/cases/{id}/audit/verify`
Recalculates the SHA-256 hash chain across all audit entries for the specified case.
- **Response `200 OK` (Valid)**:
  ```json
  {
    "case_id": "case_9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "chain_valid": true,
    "entries_verified": 14,
    "tampered_entry_id": null,
    "message": "Audit log hash chain is intact. No alteration detected."
  }
  ```
- **Response `200 OK` (Tampering Detected)**:
  ```json
  {
    "case_id": "case_9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "chain_valid": false,
    "entries_verified": 6,
    "tampered_entry_id": 7,
    "message": "CRITICAL: Hash chain broken at entry ID 7. Unauthorized record modification or deletion detected."
  }
  ```

---

## 7. Reports & Legal Attestation

### `GET /api/v1/analyses/{id}/report.pdf`
Download a court-ready forensic report PDF including case info, tool versions, methodology, visual heatmap artifacts, 4-axis assessment, and digital signature.

### `GET /api/v1/analyses/{id}/report.json`
Machine-readable canonical JSON report.

### `GET /api/v1/analyses/{id}/report.sig`
Cryptographic digital signature (`HMAC-SHA256` or `Ed25519`) calculated over the canonical JSON report hash.

---

## 8. Health & System Status

### `GET /api/v1/health`
- **Response `200 OK`**:
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "mock_mode": true,
    "device": "cpu",
    "detectors_registered": 27,
    "storage_writable": true
  }
  ```
