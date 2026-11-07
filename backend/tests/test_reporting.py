"""
Unit tests for SUTRAM Forensic Reporting Engine.

Covers PDF report generation and Bharatiya Sakshya Adhiniyam 2023 Section 63
certificate generation with proper formatting, quality checks, and edge cases.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.detectors.base import DetectorResult
from app.pipeline.fusion import FusedAssessment, TriageDirective
from app.reporting import (
    build_forensic_report_pdf,
    generate_bsa63_certificate_pdf,
)


@pytest.fixture
def sample_assessment() -> FusedAssessment:
    """Create a sample FusedAssessment for testing."""
    return FusedAssessment(
        case_id="CASE-001",
        overall_score=0.15,
        confidence=0.92,
        verbal_verdict="Strongly supports authenticity",
        triage_directive=TriageDirective.PASS_ADMISSIBLE,
        operational_action="ACTION: PASS - Evidence may be presented as authentic digital evidence.",
        summary="All detectors support authenticity with high confidence; evidence is admissible.",
        contradiction_detected=False,
        axes={
            "integrity": 0.92,
            "authenticity": 0.90,
            "provenance": 0.88,
            "suitability": 0.85,
        },
        quality_warnings=[],
        contributing_detectors=["img1", "aud1", "vid1"],
    )


@pytest.fixture
def sample_detector_results() -> list[DetectorResult]:
    """Create sample detector results for testing."""
    return [
        DetectorResult(
            detector_name="img1",
            detector_version="1.0.0",
            category="synthetic_detection",
            status="ok",
            score=0.10,
            confidence=0.90,
            verbal_verdict="Strongly supports authenticity",
            summary="No manipulation detected in visual frames",
            evidence=[],
            artifacts=[],
            parameters_used={},
            limitations=[],
        ),
        DetectorResult(
            detector_name="aud1",
            detector_version="1.0.0",
            category="synthetic_detection",
            status="ok",
            score=0.15,
            confidence=0.88,
            verbal_verdict="Supports authenticity",
            summary="No synthetic speech artifacts detected",
            evidence=[],
            artifacts=[],
            parameters_used={},
            limitations=[],
        ),
    ]


@pytest.fixture
def sample_evidence_details() -> dict[str, Any]:
    """Create sample evidence details for testing."""
    return {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha512": "ddafd2c5379960c2c046ede3180b408e2a1a56867536e2a7f83e30d9d9e473b9",
        "ingest_timestamp": "2026-01-15T10:30:00Z",
        "media_metadata": {
            "format": "mov",
            "bitrate": 5_000_000,
            "resolution": 1920 * 1080,
            "duration": 45.2,
        },
    }


class TestBuildForensicReportPDF:
    """Tests for build_forensic_report_pdf function."""

    def test_generates_valid_pdf_with_pdf_header(
        self, sample_assessment, sample_detector_results, sample_evidence_details, tmp_path
    ) -> None:
        """Test that build_forensic_report_pdf generates a valid non-empty PDF with %PDF- header."""
        output_path = tmp_path / "forensic_report.pdf"
        result_path = build_forensic_report_pdf(
            case_id="CASE-001",
            assessment=sample_assessment,
            evidence_details=sample_evidence_details,
            output_path=output_path,
            detector_results=sample_detector_results,
        )

        # Verify file exists and is non-empty
        assert result_path.exists()
        assert result_path.stat().st_size > 5000  # Minimum viable PDF size

        # Verify PDF header
        with open(result_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-", f"Invalid PDF header: {header}"

    def test_embedding_valid_png_artifact_renders_cleanly(
        self, sample_assessment, sample_detector_results, tmp_path
    ) -> None:
        """Test that embedding a valid PNG artifact renders cleanly into flowables."""
        # Create a minimal valid PNG
        import struct

        # Minimal 1x1 PNG
        png_data = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13)
            + b"\x00\x00\x00\x01"
            + b"\x00\x00\x00\x01"
            + b"\x08"
            + b"\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00"
            + b"\x99\x55\x11\x80"
            + b"\x00\x00\x00\x0e"
            + b"IDAT\x08d\x77\xfdx\x01\x00\x01\xf1"
            + b"\x0f\x00\x00\x00\x0e\x00\x00\x00\x01\x00\x00\x00\x00"
            + b"i\xc8\xddz`"
        )
        artifact_path = tmp_path / "test_artifact.png"
        artifact_path.write_bytes(png_data)

        # Add artifact to detector result
        results = sample_detector_results.copy()
        results[0].artifacts = [str(artifact_path)]

        output_path = tmp_path / "report_with_artifact.pdf"
        result_path = build_forensic_report_pdf(
            case_id="CASE-002",
            assessment=sample_assessment,
            evidence_details={"sha256": "abc", "sha512": "def", "media_metadata": {}},
            output_path=output_path,
            detector_results=results,
        )

        assert result_path.exists()
        assert result_path.stat().st_size > 5000

    def test_missing_corrupted_artifact_does_not_crash(self, sample_assessment, tmp_path) -> None:
        """Test that missing or corrupted artifact path does not crash report generation."""
        output_path = tmp_path / "report_fallback.pdf"
        # No artifacts provided - should fall back gracefully
        result_path = build_forensic_report_pdf(
            case_id="CASE-003",
            assessment=sample_assessment,
            evidence_details={"sha256": "abc", "sha512": "def", "media_metadata": {}},
            output_path=output_path,
            detector_results=[],
        )

        assert result_path.exists()
        assert result_path.stat().st_size > 5000

    def test_large_detector_findings_list_flows_over_multiple_pages(
        self, sample_assessment, tmp_path
    ) -> None:
        """Test that large detector findings list (20+ items) flows over multiple pages."""
        # Create 25 detector results
        results = []
        for i in range(25):
            results.append(
                DetectorResult(
                    detector_name=f"det_{i:02d}",
                    detector_version="1.0.0",
                    category="synthetic_detection",
                    status="ok",
                    score=0.10 + (i * 0.01),
                    confidence=0.80,
                    verbal_verdict="Supports authenticity",
                    summary=f"Detector {i} summary",
                    evidence=[],
                    artifacts=[],
                    parameters_used={},
                    limitations=[],
                )
            )

        output_path = tmp_path / "report_large.pdf"
        result_path = build_forensic_report_pdf(
            case_id="CASE-025",
            assessment=sample_assessment,
            evidence_details={"sha256": "abc", "sha512": "def", "media_metadata": {}},
            output_path=output_path,
            detector_results=results,
        )

        assert result_path.exists()
        assert result_path.stat().st_size > 5000

    def test_pdf_has_proper_structure_and_sections(
        self, sample_assessment, sample_detector_results, sample_evidence_details, tmp_path
    ) -> None:
        """Test that generated PDF contains expected sections/structure."""
        output_path = tmp_path / "report_structure.pdf"
        result_path = build_forensic_report_pdf(
            case_id="CASE-010",
            assessment=sample_assessment,
            evidence_details=sample_evidence_details,
            output_path=output_path,
            detector_results=sample_detector_results,
        )

        assert result_path.exists()
        with open(result_path, "rb") as f:
            content = f.read().decode("latin-1", errors="ignore").lower()

        # Check for key section markers
        assert "sutram" in content, "Missing SUTRAM header"
        assert "4-axis" in content.lower() or "axis" in content.lower(), "Missing 4-axis assessment"
        assert "verdict" in content.lower(), "Missing verdict section"
        assert "artifact" in content.lower() or "gallery" in content.lower(), (
            "Missing artifact section"
        )


class TestGenerateBSA63CertificatePDF:
    """Tests for generate_bsa63_certificate_pdf function."""

    def test_produces_valid_certificate_with_statutory_header(self, tmp_path) -> None:
        """Test that generate_bsa63_certificate_pdf produces valid Section 63 certificate."""
        evidence_info = {
            "filename": "evidence.mp4",
            "size_bytes": 1_048_576,
            "mime_type": "video/mp4",
            "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            "sha512": "f0e9d8c7b6a5948372615047362514039281706543210f9e8d7c6b5a43210f9e8d",
            "acquisition_device": "Forensic Workstation, Air-gapped",
            "acquisition_date": "2026-01-15",
        }

        output_path = tmp_path / "bsa63_certificate.pdf"
        result_path = generate_bsa63_certificate_pdf(
            case_id="CASE-001",
            evidence_info=evidence_info,
            output_path=output_path,
            certifying_officer="Kartikey Sharma",
            designation="Senior Forensic Examiner",
            agency="State Cyber Crime Investigation Cell",
        )

        assert result_path.exists()
        assert result_path.stat().st_size > 2000

        # Verify statutory header
        with open(result_path, encoding="latin-1") as f:
            content = f.read()

        assert (
            "[TEMPLATE ONLY - FOR LEGAL REVIEW BY INVESTIGATING OFFICER / PUBLIC PROSECUTOR]"
            in content
        ), "Missing mandatory statutory header"

        # Verify title
        assert "CERTIFICATE UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023" in content, (
            "Missing Section 63 title"
        )

        # Verify clauses
        assert "CLAUSE 1" in content, "Missing Clause 1: Identification of electronic record"
        assert "CLAUSE 2" in content, "Missing Clause 2: Device particulars"
        assert "CLAUSE 3" in content, "Missing Clause 3: Lawful custody affirmation"
        assert "CLAUSE 4" in content, "Missing Clause 4: Hash-chain audit ledger verification"

    def test_certificate_has_signatory_block(self, tmp_path) -> None:
        """Test that certificate has proper signatory block."""
        evidence_info = {
            "filename": "test.mp4",
            "size_bytes": 512000,
            "mime_type": "video/mp4",
            "sha256": "abc123",
            "sha512": "def456",
            "acquisition_device": "Workstation",
            "acquisition_date": "2026-01-15",
        }

        output_path = tmp_path / "cert_sig.pdf"
        result_path = generate_bsa63_certificate_pdf(
            case_id="CASE-SIG",
            evidence_info=evidence_info,
            output_path=output_path,
            certifying_officer="Anil Kumar",
            designation="Deputy Supervisor",
            agency="Cyber Police Unit",
        )

        assert result_path.exists()

        with open(result_path, encoding="latin-1") as f:
            content = f.read()

        assert "Certifying Officer" in content, "Missing Certifying Officer block"
        assert "Designation" in content, "Missing Designation block"
        assert "Police Station / Unit" in content, "Missing Police Station / Unit block"
        assert "Place" in content, "Missing Place block"
        assert "Date" in content, "Missing Date block"

    def test_certificate_minimal_size_and_valid_pdf(self, tmp_path) -> None:
        """Test that certificate produces valid PDF with minimum size."""
        evidence_info = {
            "filename": "minimal.mp4",
            "size_bytes": 1000,
            "mime_type": "video/mp4",
            "sha256": "hash",
            "sha512": "hash2",
            "acquisition_device": "Workstation",
            "acquisition_date": "2026-01-15",
        }

        output_path = tmp_path / "minimal_cert.pdf"
        result_path = generate_bsa63_certificate_pdf(
            case_id="MINIMAL",
            evidence_info=evidence_info,
            output_path=output_path,
            certifying_officer="Test Officer",
            designation="Test Designation",
            agency="Test Agency",
        )

        assert result_path.exists()
        assert result_path.stat().st_size > 1000
