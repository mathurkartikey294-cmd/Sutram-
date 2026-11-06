"""
Unit tests for SUTRAM's Evidentiary Fusion Engine (fuse_detector_results).

Covers fail-closed security, weakest-link tampering, contradiction handling,
quality warnings, and the 4-axis forensic assessment model.
"""

from __future__ import annotations

import pytest

from app.detectors.base import DetectorResult
from app.pipeline.fusion import FusedAssessment, TriageDirective, fuse_detector_results


@pytest.fixture
def authentic_detector_result() -> DetectorResult:
    """Return a detector result reporting authenticity with high confidence."""
    return DetectorResult(
        detector_name="img1",
        detector_version="1.0.0",
        category="synthetic_detection",
        status="ok",
        score=0.10,
        confidence=0.90,
        verbal_verdict="Strongly supports authenticity",
        summary="Authentic image content",
        evidence=[],
        artifacts=[],
        parameters_used={},
        limitations=[],
    )


@pytest.fixture
def manipulated_detector_result() -> DetectorResult:
    """Return a detector result reporting manipulation with high confidence."""
    return DetectorResult(
        detector_name="aud1",
        detector_version="1.0.0",
        category="synthetic_detection",
        status="ok",
        score=0.85,
        confidence=0.92,
        verbal_verdict="Strongly supports manipulation",
        summary="Synthetic speech detected in audio",
        evidence=[],
        artifacts=[],
        parameters_used={},
        limitations=[],
    )


def test_empty_results_list_returns_hold_unverified() -> None:
    """Rule A: Empty results list MUST return HOLD_UNVERIFIED (fail-closed)."""
    result = fuse_detector_results([])
    assert result.triage_directive == TriageDirective.HOLD_UNVERIFIED
    assert result.overall_score == 0.50
    assert result.verbal_verdict == "Inconclusive"


def test_clean_results_with_high_confidence_returns_pass_admissible(
    authentic_detector_result: DetectorResult,
) -> None:
    """Rule A: Clean results with high confidence return PASS_ADMISSIBLE."""
    results = [authentic_detector_result, authentic_detector_result]
    result = fuse_detector_results(results)
    assert result.triage_directive == TriageDirective.PASS_ADMISSIBLE
    assert result.verbal_verdict == "Strongly supports authenticity"


def test_single_detector_failure_error_forces_hold_unverified() -> None:
    """Rule A: Single detector failure/error forces HOLD_UNVERIFIED; never passes."""
    from app.detectors.base import DetectorResult as DR

    results = [
        authentic_detector_result,
        DR(
            detector_name="broken",
            detector_version="1.0.0",
            category="synthetic_detection",
            status="error",
            score=0.0,
            confidence=0.0,
            verbal_verdict="",
            summary="",
            evidence=[],
            artifacts=[],
            parameters_used={},
            limitations=[],
        ),
    ]
    result = fuse_detector_results(results)
    assert result.triage_directive == TriageDirective.HOLD_UNVERIFIED
    assert result.verbal_verdict == "Inconclusive"


def test_four_authentic_one_manipulated_returns_reject_tampered() -> None:
    """Rule B: Four detectors say authentic, but one says manipulated -> REJECT_TAMPERED.

    Weakest-link rule: one decisive manipulation tilts the overall status.
    No contradiction flag when confidences don't meet the high-confidence threshold.
    """
    from app.detectors.base import DetectorResult as DR

    # Audio manip with confidence=0.65 (meets Rule B's 0.65 threshold but NOT Rule C's 0.70)
    manip_result = DR(
        detector_name="aud1",
        detector_version="1.0.0",
        category="synthetic_detection",
        status="ok",
        score=0.78,
        confidence=0.65,
        verbal_verdict="Supports manipulation",
        summary="Synthetic speech artifacts detected",
        evidence=[],
        artifacts=[],
        parameters_used={},
        limitations=[],
    )

    auth_results = [
        DR(
            detector_name=f"img{i}",
            detector_version="1.0.0",
            category="synthetic_detection",
            status="ok",
            score=0.10 + i * 0.02,
            confidence=0.90,
            verbal_verdict="Supports authenticity",
            summary="Authentic image content",
            evidence=[],
            artifacts=[],
            parameters_used={},
            limitations=[],
        )
        for i in range(4)
    ]

    results = auth_results + [manip_result]
    result = fuse_detector_results(results)
    assert result.triage_directive == TriageDirective.REJECT_TAMPERED
    assert result.contradiction_detected is False


def test_contradiction_between_image_and_audio_triggers_flag() -> None:
    """Rule C: Contradiction between image and audio models triggers explicit flag.

    High-confidence manipulation (score >= 0.75, conf >= 0.70) vs high-confidence
    authenticity (score <= 0.20, conf >= 0.70) -> contradiction_detected=True,
    directive REJECT_TAMPERED or SUSPECT_CORROBORATE with explanation.
    """
    from app.detectors.base import DetectorResult as DR

    image_auth = DR(
        detector_name="img1",
        detector_version="1.0.0",
        category="synthetic_detection",
        status="ok",
        score=0.10,
        confidence=0.90,
        verbal_verdict="Supports authenticity",
        summary="Visual analysis indicates unaltered frames",
        evidence=[],
        artifacts=[],
        parameters_used={},
        limitations=[],
    )

    audio_manip = DR(
        detector_name="aud1",
        detector_version="1.0.0",
        category="synthetic_detection",
        status="ok",
        score=0.85,
        confidence=0.92,
        verbal_verdict="Strongly supports manipulation",
        summary="Synthetic speech detected in audio",
        evidence=[],
        artifacts=[],
        parameters_used={},
        limitations=[],
    )

    result = fuse_detector_results([image_auth, audio_manip])
    assert result.contradiction_detected is True
    assert result.triage_directive in (
        TriageDirective.REJECT_TAMPERED,
        TriageDirective.SUSPECT_CORROBORATE,
    )
    # Summary should contain the explicit contradiction explanation
    assert "Contradiction" in result.summary


def test_low_quality_heavily_compressed_media_triggers_quality_warning() -> None:
    """Rule D: Low quality/heavily compressed media triggers quality warnings."""

    result = fuse_detector_results(
        [authentic_detector_result],
        media_metadata={"format": "whatsapp", "bitrate": 64_000, "resolution": 480 * 640},
    )
    # Should have quality warning in the output
    assert len(result.quality_warnings) > 0
    # Degraded quality should not be PASS_ADMISSIBLE
    assert result.triage_directive != TriageDirective.PASS_ADMISSIBLE


def test_output_adheres_to_4_axis_model_and_5_tier_verbal_scale() -> None:
    """Rule 7: Output adheres strictly to 4-axis model and 5-tier calibrated verbal scale."""

    result = fuse_detector_results([authentic_detector_result])

    # Verify all 4 axes are present
    assert "integrity" in result.axes
    assert "authenticity" in result.axes
    assert "provenance" in result.axes
    assert "suitability" in result.axes

    # Verify all axes are floats in [0, 1]
    for axis_name, axis_value in result.axes.items():
        assert isinstance(axis_value, float), (
            f"Axis {axis_name} should be float, got {type(axis_value)}"
        )
        assert 0.0 <= axis_value <= 1.0, f"Axis {axis_name} value {axis_value} out of [0, 1]"

    # Verify verbal verdict is one of the 5-tier calibrated values
    valid_verdicts = [
        "Strongly supports authenticity",
        "Supports authenticity",
        "Inconclusive",
        "Supports manipulation",
        "Strongly supports manipulation",
    ]
    assert result.verbal_verdict in valid_verdicts, (
        f"Invalid verbal verdict: {result.verbal_verdict}"
    )


def test_fused_assessment_model_fields() -> None:
    """Verify FusedAssessment Pydantic model has all required fields with correct types."""
    assessment = FusedAssessment(
        case_id="case-001",
        overall_score=0.75,
        confidence=0.80,
        verbal_verdict="Supports manipulation",
        triage_directive=TriageDirective.REJECT_TAMPERED,
        operational_action="ACTION: REJECT - Do not present as unaltered digital evidence in court.",
        summary="Test summary",
        contradiction_detected=False,
        axes={"integrity": 0.90, "authenticity": 0.80, "provenance": 0.70, "suitability": 0.60},
        quality_warnings=["Low bitrate detected"],
        contributing_detectors=["img1", "aud1"],
    )
    assert assessment.case_id == "case-001"
    assert assessment.overall_score == 0.75
    assert assessment.confidence == 0.80
    assert assessment.triage_directive == TriageDirective.REJECT_TAMPERED
    assert assessment.contradiction_detected is False
