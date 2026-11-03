# SUTRAM Architecture Specification

## 1. High-Level System Architecture

SUTRAM is designed around a decoupled, modular, air-gapped digital forensics architecture that guarantees complete evidence preservation, strict auditability, and explainable evidentiary synthesis.

```mermaid
flowchart TD
    subgraph Client["Forensic Examiner Frontend (React + Vite + Tailwind)"]
        UI_Dashboard["Case & Evidence Dashboard"]
        UI_Intake["Evidence Intake Screen (Read-Only Lock)"]
        UI_Workbench["Forensic Workbench (Viewer / Slider / Timeline)"]
        UI_Assessment["4-Axis Evidentiary Assessment Panel"]
        UI_Audit["Tamper-Evident Chain Verifier"]
        UI_Report["Report Generator & BSA 63 Certificate"]
    end

    subgraph API_Layer["FastAPI Gateway (/api/v1)"]
        Auth_Middleware["RBAC / Auth (Examiner / Reviewer / Admin)"]
        Upload_Guard["Hostile Ingest Guard (Magic Bytes / Size Limit)"]
        SSE_Stream["SSE Live Analysis Stream"]
        Router_Cases["Cases & Evidence Router"]
        Router_Analysis["Analysis & Artifacts Router"]
        Router_Audit["Audit Log & Verification Router"]
        Router_Reports["Signed Reports Router"]
    end

    subgraph Core_Storage["Evidence Storage Subsystem (ISO/IEC 27037)"]
        Store_Originals["Originals Store (Read-Only Chmod 0444)"]
        Store_Working["Ephemeral Working Copies (TTL Cleanup)"]
        Hash_Engine["Dual-Hash Engine (SHA-256 + SHA-512 + pHash)"]
    end

    subgraph Pipeline_Engine["Pipeline & Evidentiary Synthesis"]
        Job_Queue["In-Process Analysis Queue"]
        Media_Router["Modality Router (Image / Video / Audio)"]
        Fusion_Engine["Confidence-Weighted Fusion Engine"]
        Axis_Engine["4-Axis Evidentiary Assessment Engine"]
        Provenance_Engine["C2PA & Lineage Verification Engine"]
    end

    subgraph Detectors["Forensic Detector Registry"]
        subgraph Img_Detectors["Image Modality"]
            D_ELA["ELA Heatmap"]
            D_CM["Copy-Move Keypoints"]
            D_Meta["EXIF/XMP Metadata"]
            D_FFT["2D FFT Frequency"]
            D_Face["Face Blend Boundary"]
            D_CNN["Deep Synthetic Classifier (Grad-CAM)"]
            D_DJPEG["Double JPEG Quantization"]
            D_Splice["Local Noise Splicing"]
        end
        subgraph Aud_Detectors["Audio Modality"]
            D_Wav2Vec["wav2vec 2.0 Classifier"]
            D_SpliceA["Noise Floor / Edit Splice"]
            D_Prosody["Pitch (F0) & Pauses"]
            D_Spec["Mel-Spectrogram & Cutoff"]
            D_Codec["Codec & Compression Guard"]
        end
        subgraph Vid_Detectors["Video Modality"]
            D_Sampler["Frame Sampler & Audio Demux"]
            D_RPPG["rPPG Facial Pulse (SNR Guard)"]
            D_Lip["Lip-Sync Lag Correlation"]
            D_Temp["Temporal Flicker / Jitter"]
            D_Cont["Container & Atom Inspection"]
            D_GOP["GOP Cadence & Re-encoding"]
            D_PTS["Timestamp PTS Jitter"]
        end
    end

    subgraph Reporting_Subsystem["Reporting & Attestation"]
        PDF_Builder["ReportLab Court PDF Generator"]
        JSON_Builder["Canonical JSON Generator"]
        Sign_Engine["Digital Signature (HMAC / Ed25519)"]
        BSA63["Section 63 BSA 2023 Certificate Template"]
    end

    subgraph Database["Database & Audit Engine (SQLite / PostgreSQL)"]
        DB_Cases["Cases Table"]
        DB_Evidence["EvidenceItems Table"]
        DB_Analysis["Analyses & Findings Table"]
        DB_Audit["Hash-Chained AuditEntry Table"]
    end

    UI_Intake -->|Upload| Upload_Guard
    Upload_Guard -->|Store & Compute Hashes| Store_Originals
    Upload_Guard --> Hash_Engine
    Hash_Engine --> DB_Evidence
    Store_Originals -.->|Read-Only Fork| Store_Working
    Store_Working --> Media_Router
    Media_Router --> Img_Detectors
    Media_Router --> Aud_Detectors
    Media_Router --> Vid_Detectors
    Img_Detectors --> Fusion_Engine
    Aud_Detectors --> Fusion_Engine
    Vid_Detectors --> Fusion_Engine
    Fusion_Engine --> Axis_Engine
    Axis_Engine --> DB_Analysis
    DB_Analysis --> PDF_Builder
    PDF_Builder --> Sign_Engine
    Sign_Engine --> UI_Report
    Router_Audit --> DB_Audit
    UI_Audit --> Router_Audit
```

---

## 2. Storage & Evidence Isolation Model

Digital evidence admissibility requires unbroken proof that media was not altered post-acquisition.
1. **Ingest Phase**:
   - Incoming stream is verified via magic bytes (not file extensions).
   - Saved directly to `evidence_store/originals/<evidence_id>.<ext>`.
   - Simultaneous hash computation yields both `SHA-256` and `SHA-512`.
   - Original file permissions are locked to read-only (`chmod 0444` on Unix, Read-Only file attribute on Windows).
2. **Analysis Phase**:
   - The pipeline creates an ephemeral duplicate in `evidence_store/working/<analysis_id>.<ext>`.
   - All frame sampling, decoding, transcoding, and filtering occur solely on the working copy.
   - Working copies are automatically cleaned up after `WORKING_COPY_TTL_HOURS`.
3. **Re-Verification**:
   - The `/api/v1/evidence/{id}/verify` endpoint recomputes `SHA-256` and `SHA-512` directly from the original stored file and validates them against the ingest record in `EvidenceItem`.

---

## 3. Tamper-Evident Audit Hash Chain

To ensure the integrity of the investigative trail, every system action is recorded in an append-only cryptographic ledger:

$$\text{current\_hash}_i = \text{SHA-256}\Big(\text{id}_i \parallel \text{timestamp}_i \parallel \text{actor}_i \parallel \text{action}_i \parallel \text{target}_i \parallel \text{details\_json}_i \parallel \text{prev\_hash}_i\Big)$$

```
+-----------------------------------------------------------------------------+
| Audit Entry 1 (Genesis)                                                     |
| action: "evidence_ingest"                                                   |
| prev_hash: "0000000000000000000000000000000000000000000000000000000000000000"|
| current_hash: "a1b2c3d4..."                                                 |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| Audit Entry 2                                                               |
| action: "analysis_run"                                                      |
| prev_hash: "a1b2c3d4..."  <--- Binds strictly to previous record            |
| current_hash: "e5f6a7b8..."                                                 |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| Audit Entry 3                                                               |
| action: "report_generated"                                                  |
| prev_hash: "e5f6a7b8..."                                                    |
| current_hash: "9c0d1e2f..."                                                 |
+-----------------------------------------------------------------------------+
```

If an adversary alters an action description, deletes an entry, or forges a timestamp in the database, the hash chain breaks from that point forward. The `/api/v1/cases/{id}/audit/verify` endpoint recalculates the chain and immediately flags the altered record.

---

## 4. The 4-Axis Evidentiary Assessment Model

Instead of collapsing complex forensic evidence into an arbitrary single "deepfake probability" percentage, SUTRAM evaluates digital evidence across four orthogonal axes:

| Axis | Forensic Question | Key Signals & Methods | Verdict Options |
|:---|:---|:---|:---|
| **1. Integrity** | Was the file altered post-acquisition? | Hash verification, container atom integrity, re-encoding traces, double-compression markers, timestamp continuity. | Intact / Suspicious / Tampered / Inconclusive |
| **2. Authenticity** | Was the content synthetically generated or manipulated? | ELA, copy-move keypoint clusters, wav2vec anti-spoofing, deep synthetic classifiers, rPPG pulse consistency, lip-sync alignment. | Authentic / Supports Authenticity / Inconclusive / Supports Manipulation / Strongly Supports Manipulation |
| **3. Provenance** | Where did the file originate, and can origin be proven? | C2PA signed manifests, EXIF/XMP hardware/software signatures, perceptual hash lineage, reverse hash search. | Verified Origin / Claimed Origin / Stripped / Unknown |
| **4. Suitability** | Is the media quality sufficient for reliable forensic analysis? | Resolution, bitrate, duration, audio sample rate, codec compression factor. | Suitable / Marginal / Unsuitable (with warnings) |

---

## 5. Security Architecture for Hostile Inputs
- **Process Isolation**: All subprocesses (`ffmpeg`, `exiftool`, `c2patool`) run via `safe_subprocess()` with `shell=False`, array-based argument vectors, explicit execution timeouts, and sanitized environment variables.
- **Image Decompression Defense**: Pillow `MAX_IMAGE_PIXELS` is strictly clamped to avoid memory exhaustion from decompression bombs.
- **Privacy & Redaction**: The platform does not log raw evidence bytes or personal user data; logs store only opaque UUIDs and cryptographic hashes.
- **Air-Gapped Operation**: System configuration disables all default external network requests, ensuring evidentiary compliance for classified or sensitive forensic laboratories.
