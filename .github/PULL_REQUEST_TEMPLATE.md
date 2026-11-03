## SUTRAM Pull Request

### 1. Description of Changes
<!-- Provide a concise summary of the changes introduced and why they are necessary. -->

### 2. Area / Domain
- [ ] Backend Core & Storage (`backend/app/core/`, `backend/app/db/`)
- [ ] Image Forensics (`backend/app/detectors/image/`)
- [ ] Audio Forensics (`backend/app/detectors/audio/`)
- [ ] Video Forensics (`backend/app/detectors/video/`)
- [ ] Provenance & C2PA (`backend/app/provenance/`)
- [ ] Reporting & BSA 63 (`backend/app/reporting/`)
- [ ] Frontend UI / Workbench (`frontend/`)
- [ ] Documentation / Specifications (`docs/`)

### 3. Forensic Integrity & Principles Checklist
- [ ] **Evidence Preservation**: Original evidence files are never modified (read-only enforcement respected).
- [ ] **No Fake/Invented Scores**: All outputs are derived deterministically or via validated checkpoints; unhandled branches return `status="not_implemented"`, and mocks are strictly flagged `[MOCK]`.
- [ ] **Calibrated Verbal Scale**: Findings map to the 5-tier forensic scale (Strongly supports manipulation, Supports manipulation, Inconclusive, Supports authenticity, Strongly supports authenticity).
- [ ] **Limitations Documented**: Detector limitations, parameters, and failure modes are explicitly specified in the result payload.
- [ ] **Air-Gapped Operation**: No outbound network requests are made with evidence payloads.

### 4. Testing & Verification
- [ ] Unit tests added / updated in `backend/tests/`
- [ ] `uv run ruff check backend` passes
- [ ] `uv run pytest backend/tests` passes
- [ ] Frontend builds with no TypeScript errors (`npm run build`)
