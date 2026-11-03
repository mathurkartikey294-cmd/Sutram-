# SUTRAM 4-Axis Evidentiary Assessment Framework (EVIDENTIARY_ASSESSMENT.md)

## 1. The Multi-Axis Forensic Philosophy

In judicial proceedings, presenting digital evidence through a single summary percentage (e.g. "78% probability of deepfake") is legally hazardous and scientifically flawed:
- A high deepfake score is meaningless if the video file was corrupted or recompressed so heavily that the detector is guessing.
- A file may be completely authentic in content, yet tampered in provenance (e.g. metadata stripped to hide the real recording date).
- Conversely, a video may be completely intact in container integrity, yet depict an entirely synthesized AI generated person.

SUTRAM separates evidence evaluation into **four independent, orthogonal axes**:

```
           +---------------------------------------+
           |       EVIDENTIARY ASSESSMENT         |
           +---------------------------------------+
                              |
       +----------------------+----------------------+
       |                      |                      |
       v                      v                      v
+--------------+       +--------------+       +--------------+
| 1. INTEGRITY |       |2.AUTHENTICITY|       |3. PROVENANCE |
+--------------+       +--------------+       +--------------+
| Container    |       | Synthetic AI |       | C2PA Claims  |
| Re-encoding  |       | Copy-Move    |       | EXIF / XMP   |
| Hashes       |       | Splices      |       | Lineage      |
+--------------+       +--------------+       +--------------+
                              |
                              v
                       +--------------+
                       |4. SUITABILITY|
                       +--------------+
                       | Resolution   |
                       | Bitrate      |
                       | Duration     |
                       +--------------+
```

---

## 2. Axis Definitions & Verdict Taxonomy

### Axis 1: Integrity
- **Question**: Has the binary container or bitstream been altered since acquisition?
- **Signals**:
  - SHA-256 / SHA-512 re-verification against initial ingest record.
  - Video GOP cadence regularity and absence of spliced keyframes.
  - Monotonic continuity of Presentation Timestamps (PTS).
  - Codec header consistency (no conflicting stream duration vs container duration).
- **Verdicts**:
  - `VERIFIED_INTACT`: All hashes match; stream structures show unbroken recording continuity.
  - `SUSPICIOUS_RE_ENCODED`: Stream has been re-compressed or transcoded post-recording.
  - `TAMPERED`: Hashes fail to match, or timestamp breaks/keyframe splices are detected.
  - `INCONCLUSIVE`: Container structure is corrupted or truncated.

### Axis 2: Authenticity
- **Question**: Does the media depict real biological/physical phenomena, or does it contain synthetic manipulation?
- **Signals**:
  - Error Level Analysis (ELA) error distribution.
  - Keypoint copy-move cluster presence.
  - Facial boundary transition sharpness and noise variance.
  - 2D Fourier power spectrum high-frequency anomalies.
  - wav2vec 2.0 voice clone classification score.
  - Audio splice background noise jumps.
  - Video rPPG pulse spectral peak.
  - Audiovisual lip-sync cross-correlation lag.
- **Verdicts (Calibrated Verbal Scale)**:
  - `STRONGLY_SUPPORTS_AUTHENTICITY` (Score 0.00 – 0.20)
  - `SUPPORTS_AUTHENTICITY` (Score 0.21 – 0.40)
  - `INCONCLUSIVE` (Score 0.41 – 0.59 or conflicting signals)
  - `SUPPORTS_MANIPULATION` (Score 0.60 – 0.79)
  - `STRONGLY_SUPPORTS_MANIPULATION` (Score 0.80 – 1.00)

### Axis 3: Provenance & Attribution
- **Question**: Can the origin and lineage of the media be cryptographically or empirically established?
- **Signals**:
  - C2PA Manifest: Cryptographically signed provenance assertions.
  - EXIF/XMP Metadata: Device make/model, serial numbers, software tags.
  - Perceptual Hashing Lineage: Match against known reference databases.
- **Verdicts**:
  - `VERIFIED_ORIGIN`: Valid C2PA cryptographic signature bound to authorized root certificate.
  - `CLAIMED_ORIGIN`: Metadata indicates camera hardware, but lacks cryptographic verification.
  - `MODIFIED_METADATA`: Software tags indicate post-processing (e.g. "Adobe Photoshop", "Lavf").
  - `STRIPPED_UNKNOWN`: All origin metadata has been removed (common on social media platforms).

### Axis 4: Forensic Suitability
- **Question**: Is the physical resolution, bitrate, and duration sufficient for reliable analysis?
- **Signals**:
  - Image resolution (must be $\ge 256 \times 256$ pixels).
  - Video frame rate ($\ge 15$ fps) and bitrate ($\ge 500$ kbps).
  - Audio sampling rate ($\ge 16$ kHz) and duration ($\ge 2.0$ seconds).
  - Compression artifacts (quantization noise, blocking artifacts).
- **Verdicts**:
  - `HIGH_SUITABILITY`: Resolution and quality exceed recommended forensic thresholds.
  - `MARGINAL_SUITABILITY`: Quality allows analysis, but confidence margins are reduced.
  - `UNSUITABLE`: Media is too degraded, compressed, or brief for conclusive findings.

---

## 3. Explanatory Narrative Generation

Every assessment report must produce two mandatory human-readable narrative sections:

### 1. "What This Means for the Case"
A clear, non-technical synthesis written for investigators, prosecutors, and judges:
> *"The submitted video file demonstrates high container integrity with matching cryptographic hashes. However, forensic analysis of the facial region reveals strong indicators of synthetic manipulation: Error Level Analysis demonstrates compression anomalies localized to the suspect's face, and facial skin color fluctuations fail to exhibit natural biological cardiovascular pulse signals (rPPG). While claimed device metadata lists an iPhone 14, absence of hardware-specific container atoms indicates the video was re-encoded using desktop transcoding tools prior to acquisition."*

### 2. "What Could Not Be Determined"
An explicit boundary statement preventing over-interpretation in court:
> - *The specific AI generator architecture (e.g. Midjourney vs Stable Diffusion) cannot be conclusively identified due to secondary compression.*
> - *Exact geographic location cannot be verified as GPS EXIF tags were absent.*
> - *Audio recording environment could not be verified due to aggressive 8kHz telephony compression.*
