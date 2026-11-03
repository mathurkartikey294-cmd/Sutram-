# SUTRAM Security Policy and Forensic Integrity Architecture

## 1. Threat Model for Digital Forensics Systems

In a forensic and investigative context, media files must be treated as **untrusted and potentially hostile inputs**. Threat actors may craft files specifically designed to exploit forensic tools (e.g., buffer overflows in parsers, decompression bombs, command injection payloads, or metadata exploits).

### Core Threat Vectors
1. **Hostile Ingest Payloads**: Polyglot files, zip/decompression bombs, malformed EXIF/ID3 tags, crafted codec headers targeting media decoders (`ffmpeg`, `libvpx`, `libjpeg-turbo`).
2. **Subprocess Exploitation**: Command injection attempts against external forensic CLIs (`ffmpeg`, `exiftool`, `c2patool`).
3. **Evidence Tampering**: Accidental or malicious alteration of original submitted evidence during or after analysis.
4. **Audit Log Invalidation**: Retroactive modification of case logs to forge or hide investigative actions.
5. **Data Leakage & Cross-Contamination**: Uploading forensic evidence to third-party public cloud APIs without judicial authorization.

---

## 2. Forensic Defense-in-Depth Controls

### 2.1 Hostile Media Ingest Safeguards
- **Magic Byte Validation**: File extensions are completely ignored for execution or mime-type determination. File types are resolved strictly via magic bytes (`python-magic` or header byte tables).
- **Size and Duration Limits**: Enforce strict caps on upload payload sizes (default: 500 MB) and media durations (default: 15 minutes) to mitigate DoS attacks.
- **Decompression Bomb Guard**: Image decoders (e.g., Pillow `Image.MAX_IMAGE_PIXELS`) enforce strict limits before allocation to prevent memory exhaustion.
- **No Direct Execution**: Uploaded files are placed in isolated storage paths without execute (`+x`) permissions.

### 2.2 Subprocess Isolation & Shell Sanitization
- External tools (`ffmpeg`, `ffprobe`, `exiftool`) are **never** invoked through a shell (`shell=False` only).
- Arguments are passed as sanitized arrays of strings.
- All subprocesses enforce hard timeout limits (e.g., max 30 seconds per frame or extraction task) to prevent hung parser threads.

### 2.3 Evidence Integrity & Read-Only Storage (ISO/IEC 27037)
- Upon ingest, the original file is written to an isolated directory configured with read-only filesystem attributes.
- Dual cryptographic hashes (`SHA-256` and `SHA-512`) are computed immediately upon receipt and recorded in the database.
- The original file is **never touched** by analysis routines. The ingest pipeline generates an ephemeral **working copy** for processing.
- A background worker purges working copies after a configurable time-to-live (`WORKING_COPY_TTL_HOURS`, default 24h).

### 2.4 Tamper-Evident Audit Hash Chain
- The `AuditEntry` database table functions as a cryptographic append-only log.
- Each entry stores `prev_hash = SHA256(previous_entry_record)`.
- Any manual SQL tampering, row deletion, or retroactive alteration breaks the hash chain, immediately detected by `/api/v1/cases/{id}/audit/verify`.

### 2.5 Air-Gapped / Zero-Cloud Default
- SUTRAM is designed to operate completely offline in air-gapped forensic laboratories.
- All detectors rely on local deterministic routines or local pretrained weights. No external API calls are made with evidence unless an administrator explicitly enables an external integration.

---

## 3. Reporting Security Vulnerabilities

If you identify a security vulnerability in SUTRAM:
1. Do **NOT** open a public issue.
2. Email the core maintainers: `abracabramaster4@gmail.com` with subject `[SECURITY VULNERABILITY] SUTRAM`.
3. Include proof of concept, impact assessment, and affected components.
4. A security advisory and patch will be coordinated prior to public disclosure.
