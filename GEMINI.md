# GEMINI.md

@AGENTS.md

## Google Gemini CLI & Code Assist Directives

When acting as an AI assistant for SUTRAM:
1. **Single Source of Truth**: Adhere strictly to `AGENTS.md`.
2. **Team Member Scopes**:
   - Kartikey: `docs/team/KARTIKEY.md` (Core, Vault, Audit, PDF Structure & Reporting)
   - Shivendra: `docs/team/SHIVENDRA.md` (Image & Document Image Forensics)
   - Saksham: `docs/team/SAKSHAM.md` (Audio Forensics & Synthetic Speech)
   - Saarika: `docs/team/SAARIKA.md` (Video Forensics & Physiological Checks)
3. **Forensic Integrity Guard**:
   - Original evidence in `evidence_store/originals/` is read-only.
   - Use the 5-tier calibrated verbal scale for verdicts.
   - Run `uv run ruff check backend` and `uv run pytest backend/tests` to verify.

