# SUTRAM GitHub Automation Script
# Usage: Run this script after installing or authenticating GitHub CLI (`gh auth login`)

param (
    [string]$RepoName = "Sutram-",
    [string]$Visibility = "private"
)

Write-Host "==> Checking GitHub CLI Authentication..." -ForegroundColor Cyan
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] 'gh' CLI is not found in PATH." -ForegroundColor Red
    Write-Host "Please install it via: winget install --id GitHub.cli" -ForegroundColor Yellow
    Write-Host "Then run: gh auth login" -ForegroundColor Yellow
    exit 1
}

gh auth status
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] GitHub CLI is not authenticated. Please run: gh auth login" -ForegroundColor Red
    exit 1
}

Write-Host "==> Creating private GitHub repository '$RepoName'..." -ForegroundColor Cyan
gh repo create $RepoName --$Visibility --source=. --remote=origin --push
if ($LASTEXITCODE -ne 0) {
    Write-Host "Remote origin might already exist or repo already created. Pushing branches..." -ForegroundColor Yellow
    git push -u origin main
}

Write-Host "==> Pushing 'dev' branch..." -ForegroundColor Cyan
git push -u origin dev

Write-Host "==> Adding Collaborators..." -ForegroundColor Cyan
$collaborators = @("kartikey", "Saksham", "Saarika", "Shivendra")
foreach ($collab in $collaborators) {
    Write-Host "Inviting collaborator: $collab..."
    gh repo collaborator add $collab --repo=":owner/$RepoName" --permission=push
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [WARN] Failed to invite '$collab' (User may not exist or needs exact username)." -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] Invited '$collab'." -ForegroundColor Green
    }
}

Write-Host "==> Creating Task Labels..." -ForegroundColor Cyan
$labels = @(
    @{ Name="backend"; Color="1d76db"; Desc="Backend core, database, storage & API" },
    @{ Name="image"; Color="d93f0b"; Desc="Image forensics and synthetic detection" },
    @{ Name="audio"; Color="0e8a16"; Desc="Audio forensics, voice cloning & splices" },
    @{ Name="video"; Color="5319e7"; Desc="Video forensics, rPPG pulse & temporal" },
    @{ Name="frontend"; Color="fbca04"; Desc="Forensic examiner UI & workbench" },
    @{ Name="docs"; Color="0075ca"; Desc="Forensic documentation and standards" }
)

foreach ($lbl in $labels) {
    gh label create $lbl.Name --color $lbl.Color --description $lbl.Desc --force
}

Write-Host "==> Creating Milestone Issues from docs/TEAM_PLAN.md..." -ForegroundColor Cyan

# Kartikey's Tasks
gh issue create --title "[BACKEND]: ISO/IEC 27037 Read-Only Evidence Vault & Dual Hashing" --label "backend" --body "Implement read-only evidence storage and SHA-256/SHA-512 dual ingest hashing. Assigned to @Kartikey. See docs/team/KARTIKEY.md Task K1."
gh issue create --title "[BACKEND]: Tamper-Evident Hash-Chained Audit Log Engine" --label "backend" --body "Implement append-only AuditEntry table with SHA-256 hash chaining (prev_hash). Assigned to @Kartikey. See docs/team/KARTIKEY.md Task K2."
gh issue create --title "[BACKEND]: 4-Axis Evidentiary Assessment & Fusion Engine" --label "backend" --body "Build multi-detector confidence fusion and 4-axis assessment (Integrity, Authenticity, Provenance, Suitability). Assigned to @Kartikey. See docs/team/KARTIKEY.md Task K3 & K4."
gh issue create --title "[BACKEND]: Court-Ready Signed PDF/JSON Report & Section 63 BSA Certificate" --label "backend" --body "Generate tamper-evident PDF reports with embedded heatmaps and Section 63 BSA 2023 legal template. Assigned to @Kartikey. See docs/team/KARTIKEY.md Task K6."

# Shivendra's Tasks
gh issue create --title "[IMAGE]: Error Level Analysis (ELA) Detector with False-Color Heatmap" --label "image" --body "Implement ELA detector to identify differential JPEG compression and export heatmap PNG. Assigned to @Shivendra. See docs/team/SHIVENDRA.md Task S2."
gh issue create --title "[IMAGE]: Keypoint Copy-Move Forgery Detector with Spatial Clustering" --label "image" --body "Implement ORB/AKAZE keypoint matching with geometric cluster verification for cloned regions. Assigned to @Shivendra. See docs/team/SHIVENDRA.md Task S3."
gh issue create --title "[IMAGE]: 2D FFT Frequency Analysis & Diffusion/GAN Grid Anomaly Detection" --label "image" --body "Implement 2D Fourier power spectrum analysis to detect synthetic upsampler patterns. Assigned to @Shivendra. See docs/team/SHIVENDRA.md Task S5."
gh issue create --title "[IMAGE]: Face Boundary Blending & Landmark Contour Transition Analysis" --label "image" --body "Detect boundary sharpness and noise variance discontinuities along facial masks. Assigned to @Shivendra. See docs/team/SHIVENDRA.md Task S6."

# Saksham's Tasks
gh issue create --title "[AUDIO]: Audio Splice & Ambient Noise Floor Discontinuity Detector" --label "audio" --body "Detect abrupt background noise jumps (>12dB) and impulse edit points with timestamps. Assigned to @Saksham. See docs/team/SAKSHAM.md Task A3."
gh issue create --title "[AUDIO]: Prosodic Pitch (F0) Dynamics & Conversational Pause Histogram" --label "audio" --body "Extract vocal fold pitch jitter/shimmer and flag robotic stability in synthetic speech. Assigned to @Saksham. See docs/team/SAKSHAM.md Task A4."
gh issue create --title "[AUDIO]: Spectral Vocoder Artifact & Mel-Spectrogram Analyzer" --label "audio" --body "Identify high-frequency cutoff (>8kHz) and phase mismatch typical of neural vocoders. Assigned to @Saksham. See docs/team/SAKSHAM.md Task A5."
gh issue create --title "[AUDIO]: wav2vec 2.0 Anti-Spoofing Voice Cloning Classifier" --label "audio" --body "Integrate wav2vec 2.0 self-supervised feature extraction for synthetic speech detection. Assigned to @Saksham. See docs/team/SAKSHAM.md Task A2."

# Saarika's Tasks
gh issue create --title "[VIDEO]: Multi-Tier Video Frame Sampler & Audio Stream Demuxer" --label "video" --body "Implement 1-2 fps sparse sampling and dense windows with audio demuxing. Assigned to @Saarika. See docs/team/SAARIKA.md Task V1."
gh issue create --title "[VIDEO]: Remote Photoplethysmography (rPPG) Facial Pulse Extraction" --label "video" --body "Extract green-channel micro-color cardiovascular pulse from facial skin with SNR guard. Assigned to @Saarika. See docs/team/SAARIKA.md Task V2."
gh issue create --title "[VIDEO]: Audiovisual Lip-Sync Desynchronization & Lag Correlator" --label "video" --body "Calculate mouth aperture vs audio RMS cross-correlation lag across +/-200ms. Assigned to @Saarika. See docs/team/SAARIKA.md Task V3."
gh issue create --title "[VIDEO]: Container Forensics, GOP Cadence & Re-Encoding Analysis" --label "video" --body "Analyze MP4 box hierarchy, Lavf encoder tags, and I/P/B frame cadences. Assigned to @Saarika. See docs/team/SAARIKA.md Task V5 & V6."

Write-Host "==> GitHub Setup & Issue Creation Completed Successfully!" -ForegroundColor Green
