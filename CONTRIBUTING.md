# Contributing to SUTRAM

Welcome to the SUTRAM project! We are building an enterprise-grade digital forensics platform for legal and investigative professionals. This guide outlines our git branching workflow, coding standards, and a beginner-friendly cheat sheet for all team members.

---

## 1. Branching Strategy

Our repository maintains two permanent branches:
- **`main`**: Production-ready branch. Protected. Direct commits are forbidden. Merges occur only via reviewed Pull Requests from `dev`.
- **`dev`**: Active integration branch. All feature branches merge into `dev` after passing CI checks.

### Feature Branch Naming Convention
Branches should clearly indicate the role/area and task name:
```bash
feat/<role>-<feature-description>
# Examples:
feat/kartikey-audit-chain
feat/shivendra-ela-detector
feat/saksham-wav2vec-classifier
feat/saarika-rppg-pulse
fix/kartikey-hash-verification
docs/forensic-standards-update
```

---

## 2. Commit Message Standards (Conventional Commits)

Write clear, structured commit messages so forensic audit logs and changelogs remain crystal clear:
```
<type>(<scope>): <short description in imperative mood>

[optional body explaining WHY this change was made]

[optional footer referencing issue number]
```

### Allowed Types
- **`feat`**: A new detector, endpoint, or platform capability.
- **`fix`**: A bug fix or forensic calculation correction.
- **`docs`**: Documentation updates in `docs/` or role markdown files.
- **`test`**: Adding or updating unit tests.
- **`refactor`**: Code restructuring without changing forensic logic.
- **`chore`**: Build scripts, dependency updates, Makefile changes.

### Examples
- `feat(image): add error level analysis (ELA) detector with false-color heatmap`
- `fix(audit): ensure canonical JSON formatting before computing prev_hash`
- `docs(team): update Saksham audio task checklist for ASVspoof models`

---

## 3. Pull Request & Review Checklist

Before opening a PR into `dev`:
1. Ensure your branch is up to date with `origin/dev`.
2. Run local linters and tests:
   ```bash
   uv run ruff check backend
   uv run mypy backend/app
   uv run pytest backend/tests
   ```
3. Verify forensic standards:
   - Original evidence files remain unmodified (`read-only`).
   - Calibrated verbal scale is implemented for verdicts.
   - Explanations and known limitations are populated.
   - No mock data without clear `[MOCK]` labeling.
4. Open PR with the provided template and request at least **one review** from another team member.

---

## 4. Beginner-Friendly Git Cheat Sheet

If you are new to Git or working with AI agents in branches, here is the exact step-by-step workflow:

### A. Start working on a new feature
```bash
# 1. Switch to dev and get the latest updates
git checkout dev
git pull origin dev

# 2. Create and switch to your new feature branch
git checkout -b feat/shivendra-ela-detector
```

### B. Save and commit your work
```bash
# 3. Check what files you have modified
git status

# 4. Stage your changes
git add backend/app/detectors/image/ela.py backend/tests/test_ela.py

# 5. Commit with a meaningful message
git commit -m "feat(image): implement Error Level Analysis with JPEG difference heatmap"
```

### C. Push your branch to GitHub
```bash
# 6. Push your branch to the remote repository
git push -u origin feat/shivendra-ela-detector
```

### D. Syncing with new changes from teammates
If someone merged new work into `dev` while you were coding:
```bash
# Switch to dev and pull latest
git checkout dev
git pull origin dev

# Switch back to your feature branch and rebase or merge dev
git checkout feat/shivendra-ela-detector
git merge dev
```

### E. Useful Emergency Commands
```bash
# Undo uncommitted changes in a specific file:
git checkout -- <filename>

# View commit history cleanly:
git log --oneline --graph -10

# Temporarily stash your changes to switch branches:
git stash
git checkout dev
git pull
git checkout feat/your-branch
git stash pop
```
