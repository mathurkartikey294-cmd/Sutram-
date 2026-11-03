# CLAUDE.md

@AGENTS.md

## Claude-Specific Directives & Quick References

When working as an AI assistant in this repository:
1. **Always read `AGENTS.md` first**: It is the single source of truth for architecture, forensic principles, coding standards, and definition of done.
2. **Identify your assigned role**: Check which team member's domain you are working on:
   - Backend Core, Ingest, Audit & Reporting: [`docs/team/KARTIKEY.md`](file:///docs/team/KARTIKEY.md)
   - Image Forensics & Synthetic Detection: [`docs/team/SHIVENDRA.md`](file:///docs/team/SHIVENDRA.md)
   - Audio Forensics & Voice Cloning: [`docs/team/SAKSHAM.md`](file:///docs/team/SAKSHAM.md)
   - Video Forensics & Temporal Analysis: [`docs/team/SAARIKA.md`](file:///docs/team/SAARIKA.md)
3. **Run checks before completing any task**:
   - `uv run ruff check backend`
   - `uv run mypy backend/app`
   - `uv run pytest backend/tests`
4. **Forensic Integrity Guard**:
   - Never write to `evidence_store/originals/`.
   - Never invent random scores (`status="not_implemented"` or clear `[MOCK]` only).
   - Never use `shell=True` in subprocesses.
