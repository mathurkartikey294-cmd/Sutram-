# GitHub Copilot Instructions for SUTRAM

SUTRAM is an AI-powered multimedia and electronic document forensics platform.
When writing or refactoring code in this repository:
- Follow `AGENTS.md` as the master authority.
- Respect the role assignments in `docs/team/`.
- Ensure all detectors inherit from `BaseDetector` in `backend/app/detectors/base.py`.
- Ensure original evidence files are treated as read-only.
- All scores must map to the standardized 5-tier calibrated verbal scale.
- Run `ruff check backend` and `pytest backend/tests` to verify changes.
