# SUTRAM 5-Minute Forensic Examiner Demo Script (DEMO_SCRIPT.md)

This script provides a structured, high-impact 5-minute demonstration for hackathon judges, digital forensic examiners, and cyber investigators.

---

## Demo Schedule & Timeline (Total: 5 Minutes)

| Time | Phase | Key Action & Screen | Message for Judges |
|:---|:---|:---|:---|
| **0:00 - 0:45** | **1. Intake & Chain of Custody** | Case Dashboard & Evidence Intake Screen | "Evidence is never altered. Instant SHA-256/512 hashing, read-only file locking (ISO/IEC 27037)." |
| **0:45 - 2:00** | **2. Forensic Analysis Workbench** | Viewer Slider Overlay (Original vs Heatmap) | "Explainable forensic localization: ELA highlights JPEG re-compression, copy-move clusters clones." |
| **2:00 - 3:00** | **3. Video & Audio Timeline** | Video Frame & Audio Waveform Player | "Biological & acoustic checks: rPPG skin pulse extraction and audio splice noise floor jumps." |
| **3:00 - 3:45** | **4. 4-Axis Evidentiary Assessment** | Assessment Panel | "No arbitrary single score: 4 independent axes (Integrity, Authenticity, Provenance, Suitability)." |
| **3:45 - 4:15** | **5. Tamper-Evident Audit Verification** | "Verify Audit Chain" Action | "Cryptographic hash chain (`prev_hash`). Tampering with a single log record breaks the chain instantly." |
| **4:15 - 5:00** | **6. Signed Report & BSA 63 Certificate** | PDF Preview & Digital Signature | "Court-ready PDF report with HMAC/Ed25519 signature and Section 63 BSA 2023 certificate template." |

---

## Detailed Step-by-Step Walkthrough

### Act 1: Evidence Intake & Integrity Lock (0:00 – 0:45)
1. **Navigate**: Open SUTRAM at `http://localhost:5173`.
2. **Select Case**: Open case `CFSL-2026-DEL-089` (*State vs. Unknown - Extortion*).
3. **Upload Media**: Upload test file `samples/tampered_image_copymove.jpg`.
4. **Point Out**:
   - The UI immediately shows **Dual Hash Ingest**:
     - `SHA-256: 3a7acb4f...`
     - `SHA-512: 9f8e7d6c...`
   - Green security badge: **"Stored Read-Only in Vault (`0444`)"**.
   - An immutable `AuditEntry` was appended with cryptographic hash link.

### Act 2: Image Tampering Localization (0:45 – 2:00)
1. **Launch Analysis**: Click **"Run Full Forensic Pipeline"**.
2. **Switch to Workbench**:
   - Toggle **Error Level Analysis (ELA)** heatmap: Point out the bright false-color hotspot on the forged document seal.
   - Toggle **Copy-Move**: Show the colored match vectors connecting identical cloned regions.
   - Click **"Show Raw Scores"** to reveal parameters, but emphasize the prominent verbal verdict: **"Supports Manipulation"**.

### Act 3: Video & Audio Deepfake Inspection (2:00 – 3:00)
1. **Load Video Case**: Select `samples/synthetic_video_deepfake.mp4`.
2. **Review Video Timeline**:
   - Point out red highlighted segments on the synchronized timeline where face-swap boundary blending broke down.
   - Show the **rPPG Cardiovascular Pulse Plot**: Highlight that while the authentic donor video shows periodic heartbeat peaks at 72 BPM, the synthetic deepfake displays flat noise with an explanatory note.
3. **Review Audio**:
   - Inspect the Mel-spectrogram: Show the sharp artificial vocoder cutoff above 8kHz.
   - Show splice markers where ambient room noise spiked by 14 dB.

### Act 4: 4-Axis Evidentiary Assessment (3:00 – 3:45)
1. **Scroll to Assessment Panel**:
   - **Integrity**: *VERIFIED INTACT* (Bitstream hashes match acquisition).
   - **Authenticity**: *STRONGLY SUPPORTS MANIPULATION* (Face blending and rPPG failure).
   - **Provenance**: *MODIFIED METADATA* (No C2PA manifest; Adobe Premiere tags present).
   - **Suitability**: *HIGH SUITABILITY* (1080p, 30fps, 48kHz audio).
2. **Read "What this means for the case"**: Emphasize how non-technical judges get an immediate plain-language summary.

### Act 5: Tamper-Evident Audit Verification (3:45 – 4:15)
1. **Navigate to Audit Tab**: Show the table of all case events with `prev_hash` and `current_hash`.
2. **Click "Verify Audit Chain"**:
   - System recomputes SHA-256 for all rows in real time.
   - Green verification banner: *"Audit Chain Verified: 18 entries intact, zero modifications."*
3. **Demonstrate Tamper Detection**:
   - Explain how any unauthorized manual SQL row change or deletion is detected instantly and pinpoints the corrupted entry ID.

### Act 6: Signed Court-Ready Report & BSA 63 Certificate (4:15 – 5:00)
1. **Click "Export Forensic Report"**:
2. **Inspect PDF**:
   - High-resolution document with case header, examiner credentials, acquisition hashes, and embedded heatmap visual evidence.
   - Display digital signature block: `HMAC-SHA256` signature proving report authenticity.
   - Display the **Section 63 Bharatiya Sakshya Adhiniyam, 2023 Certificate Template** ready for the investigating officer's signature.
3. **Closing Statement**:
   > *"SUTRAM provides courts with explainable, reproducible, air-gapped multimedia evidence verification from acquisition to courtroom presentation."*
