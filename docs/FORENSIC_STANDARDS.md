# Forensic Standards & Legal Frameworks (FORENSIC_STANDARDS.md)

This document outlines the forensic principles, international standards, and statutory legal frameworks guiding SUTRAM's architectural design and evidentiary output.

---

## 1. International Digital Forensics Standards

### 1.1 ISO/IEC 27037:2012
*Guidelines for identification, collection, acquisition and preservation of digital evidence.*
- **Evidence Integrity**: SUTRAM implements digital evidence storage where original media is written to read-only directories, locked with strict filesystem attributes, and never opened in write mode.
- **Dual Hashing**: Media files are hashed using two cryptographically distinct algorithms (`SHA-256` and `SHA-512`) during ingest. A file is deemed unmodified if and only if both hashes match upon re-verification.
- **Working Copy Isolation**: All analysis processes (frame sampling, ELA resaving, audio filtering) execute exclusively on temporary working copies with a strict time-to-live (`TTL`).

### 1.2 SWGDE Guidelines (Scientific Working Group on Digital Evidence)
- **SWGDE Best Practices for Image Authentication**:
  - Requires documented, reproducible methods.
  - Analysis must consider compression history, metadata discrepancies, and physical plausibility.
  - SUTRAM adheres by outputting parameters used, algorithm versions, and visual artifacts for every test.
- **SWGDE Best Practices for Forensic Audio Analysis**:
  - Directs examiners to verify recording continuity (background noise floor, impulse clicks, electrical network frequency).
  - Explicit warning requirements when audio undergoes lossy transcoding or bandwidth reduction.

### 1.3 NIST SP 800-86
*Guide to Integrating Forensic Techniques into Incident Response.*
- Emphasizes maintaining an unbroken chain of custody, documenting tools and versions, and logging all operator actions in an immutable ledger.

---

## 2. Indian Statutory Framework: Section 63 BSA, 2023

Under the **Bharatiya Sakshya Adhiniyam, 2023 (BSA)**, which repealed and replaced the Indian Evidence Act, 1872, the admissibility of electronic records is governed primarily by **Section 63** (formerly Section 65B of the Indian Evidence Act).

### Statutory Requirements for Admissibility
Section 63 mandates that an electronic record produced by a computer system is admissible in court provided that:
1. **Lawful Control & Regular Course**: The computer output was produced by the computer during the period over which the computer was used regularly to store or process information for lawful activities.
2. **Regular Input**: During said period, information of the kind contained in the electronic record was regularly fed into the computer in the ordinary course of activities.
3. **Operational Integrity**: Throughout the material period, the computer was operating properly; or if out of operation, that fact did not affect the accuracy of the electronic record.
4. **Reproduction Fidelity**: The information contained in the electronic record reproduces or is derived from information fed into the computer in the ordinary course.

### SUTRAM Compliance Architecture
- SUTRAM automatically generates a **Certificate for Admissibility of Electronic Records under Section 63 BSA, 2023**.
- The certificate embeds the ingest timestamp, case metadata, examiner identity, hardware device hashes, SHA-256/SHA-512 hashes of the original media, and the cryptographic digital signature of the analysis report.
- **Legal Notice**: Every generated certificate carries a prominent watermark and disclaimer:
  > *"TEMPLATE FOR LEGAL REVIEW ONLY. This certificate must be reviewed, verified, and signed by the lawful custodian or investigating officer having lawful control over the computer device."*
