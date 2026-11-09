"""
Unit tests for the SUTRAM 4-Axis Evidentiary Assessment Engine.

Covers pristine evidence, post-acquisition hash mismatch, synthetic media with a
pristine container, WhatsApp recompression penalties, empty/failed detectors,
contradiction handling, provenance states, suitability thresholds, and the
calibrated verbal scale.
"""

from __future__ import annotations

from typing import Any

from app.detectors.base import DetectorResult, EvidenceItem
from app.pipeline import AxisResult, EvidentiaryAssessment, generate_evidentiary_assessment
from app.pipeline.evidentiary_assessment import generate_evidentiary_assessment as direct_generate

_VERDICTS = {
    "Strongly supports authenticity",
    "Supports authenticity",
    "Inconclusive",
    "Supports manipulation",
    "Strongly supports manipulation",
}


def _result(
    name: str = "test_detector",
    category: str = "synthetic_detection",
    score: float = 0.10,
    confidence: float = 0.90,
    status: str = "ok",
    evidence: list[EvidenceItem] | None = None,
    parameters: dict[str, Any] | None = None,
    summary: str = "Test detector result.",
) -> DetectorResult:
    return DetectorResult(
        detector_name=name,
        detector_version="1.0.0",
        category=category,
        status=status,
        score=score,
        confidence=confidence,
        verbal_verdict="Inconclusive",
        summary=summary,
        evidence=evidence or [],
        artifacts=[],
        parameters_used=parameters or {},
        limitations=[],
    )


def _gps_evidence() -> EvidenceItem:
    return EvidenceItem(
        item_type="text",
        description="gps_coordinates",
        value={"latitude": 28.6139, "longitude": 77.2090, "altitude": 216.0},
        confidence=0.95,
    )


# ---------------------------------------------------------------------------
# Happy path and integrity failures
# ---------------------------------------------------------------------------


def test_pristine_authentic_evidence() -> None:
    results = [
        _result("image_synthetic_classifier", "synthetic_detection", score=0.05, confidence=0.92),
        _result(
            "provenance_metadata",
            "provenance",
            score=0.10,
            confidence=0.85,
            evidence=[_gps_evidence()],
        ),
    ]
    assessment = generate_evidentiary_assessment(
        results,
        media_metadata={
            "media_type": "image/jpeg",
            "width": 4032,
            "height": 3024,
            "camera_make": "Canon",
            "camera_model": "EOS R5",
        },
        integrity_verified=True,
        case_id="case-001",
    )

    assert assessment.case_id == "case-001"
    assert assessment.integrity.score <= 0.15
    assert assessment.integrity.verbal_verdict == "Strongly supports authenticity"
    assert assessment.authenticity.score <= 0.20
    assert assessment.provenance.score <= 0.20
    assert assessment.authenticity.verbal_verdict in _VERDICTS
    assert assessment.suitability.score <= 0.20
    assert assessment.recommended_judicial_action == "Admit as primary electronic record"
    assert "Section 63" in assessment.what_this_means_for_the_case
    assert assessment.quality_warnings == []


def test_hash_mismatch_flags_integrity_as_critical() -> None:
    assessment = generate_evidentiary_assessment(
        [_result("image_synthetic_classifier", score=0.05, confidence=0.90)],
        media_metadata={"width": 1920, "height": 1080},
        integrity_verified=False,
    )

    assert assessment.integrity.score == 1.0
    assert assessment.integrity.confidence == 1.0
    assert assessment.integrity.status == "flagged"
    assert assessment.integrity.verbal_verdict == "Strongly supports manipulation"
    integrity_text = " ".join(assessment.integrity.findings).lower()
    assert "hash mismatch" in integrity_text
    assert "chain-of-custody" in integrity_text
    assert assessment.recommended_judicial_action != "Admit as primary electronic record"
    assert "should NOT be admitted" in assessment.what_this_means_for_the_case


def test_deepfake_with_pristine_container_is_flagged() -> None:
    assessment = generate_evidentiary_assessment(
        [_result("deepfake_classifier", score=0.93, confidence=0.95)],
        media_metadata={"media_type": "image/png", "width": 2048, "height": 2048},
        integrity_verified=True,
    )

    assert assessment.integrity.score <= 0.15
    assert assessment.authenticity.score >= 0.75
    assert assessment.authenticity.status == "flagged"
    assert assessment.authenticity.verbal_verdict == "Strongly supports manipulation"
    assert "should NOT be admitted" in assessment.what_this_means_for_the_case
    assert (
        assessment.recommended_judicial_action == "Subpoena source hardware for physical extraction"
    )


def test_pdf_revision_and_font_tampering_drive_integrity_high() -> None:
    assessment = generate_evidentiary_assessment(
        [
            _result(
                "native_pdf_forensics",
                category="tampering",
                score=0.90,
                confidence=0.90,
                parameters={
                    "revision_count": 3,
                    "incremental_updates_detected": True,
                    "font_inconsistency_count": 2,
                    "suspicious_tool_signatures": ["pdftk"],
                },
            )
        ]
    )

    assert assessment.integrity.score >= 0.70
    assert assessment.integrity.status == "flagged"
    assert any("revision" in finding.lower() for finding in assessment.integrity.findings)
    assert any("font" in finding.lower() for finding in assessment.integrity.findings)


# ---------------------------------------------------------------------------
# Suitability and confidence downweighting
# ---------------------------------------------------------------------------


def test_whatsapp_recompressed_video_penalises_authenticity_confidence() -> None:
    assessment = generate_evidentiary_assessment(
        [_result("video_content_detector", score=0.10, confidence=0.92)],
        media_metadata={
            "media_type": "video/mp4",
            "format": "whatsapp",
            "width": 640,
            "height": 360,
            "frame_rate": 12,
            "bitrate": 450_000,
            "duration": 2.0,
        },
    )

    assert assessment.suitability.score >= 0.70
    assert assessment.suitability.status == "degraded"
    assert assessment.quality_warnings
    assert all(warning.startswith("Quality Warning:") for warning in assessment.quality_warnings)
    assert assessment.authenticity.confidence <= 0.55
    assert assessment.authenticity.confidence < 0.92
    limitations = " ".join(assessment.authenticity.limitations).lower()
    assert "downweight" in limitations
    assert assessment.authenticity.verbal_verdict in _VERDICTS


def test_low_resolution_image_is_degraded() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"media_type": "image/jpeg", "width": 200, "height": 150},
    )

    assert assessment.suitability.status == "degraded"
    assert assessment.suitability.score >= 0.60
    assert any("256x256" in warning for warning in assessment.quality_warnings)


def test_low_sample_rate_audio_is_degraded() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={
            "media_type": "audio/wav",
            "sample_rate": 8000,
            "duration": 1.0,
            "bitrate": 64_000,
        },
    )

    assert assessment.suitability.status == "degraded"
    assert assessment.suitability.score >= 0.60
    assert any("16 kHz" in warning for warning in assessment.quality_warnings)


def test_short_video_duration_is_degraded() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={
            "media_type": "video/mp4",
            "width": 1920,
            "height": 1080,
            "frame_rate": 30,
            "bitrate": 8_000_000,
            "duration": 1.0,
        },
    )

    assert assessment.suitability.status == "degraded"
    assert any("1.5 s" in warning for warning in assessment.quality_warnings)


def test_pristine_quality_metadata_has_no_warnings() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.05, confidence=0.92)],
        media_metadata={
            "media_type": "video/mp4",
            "width": 3840,
            "height": 2160,
            "frame_rate": 60,
            "bitrate": 50_000_000,
            "duration": 30.0,
        },
    )

    assert assessment.suitability.status == "ok"
    assert assessment.suitability.score <= 0.20
    assert assessment.quality_warnings == []


# ---------------------------------------------------------------------------
# Empty, failed, and contradictory detector inputs
# ---------------------------------------------------------------------------


def test_empty_or_none_detector_results_are_insufficient_data() -> None:
    for empty_input in (None, []):
        assessment = generate_evidentiary_assessment(empty_input)
        for axis in (
            assessment.integrity,
            assessment.authenticity,
            assessment.provenance,
            assessment.suitability,
        ):
            assert axis.status == "insufficient_data"
            assert axis.confidence == 0.0
            assert axis.score == 0.50
            assert axis.verbal_verdict == "Inconclusive"
        assert "No forensic detectors" in assessment.what_could_not_be_determined
        assert assessment.recommended_judicial_action == (
            "Hold pending independent secondary examination"
        )


def test_failed_detectors_are_excluded_but_listed_in_limitations() -> None:
    broken = _result(
        "broken_detector",
        status="error",
        score=0.5,
        confidence=0.0,
        summary="Model runtime failure.",
    )
    skipped = _result(
        "skipped_detector",
        status="skipped",
        score=0.5,
        confidence=0.0,
        summary="Encrypted input.",
    )
    good = _result("working_detector", score=0.05, confidence=0.92)

    assessment = generate_evidentiary_assessment([good, broken, skipped])

    assert assessment.authenticity.score <= 0.20
    limitations = " ".join(assessment.limitations)
    assert "broken_detector" in limitations
    assert "skipped_detector" in limitations
    assert "excluded from scoring" in limitations


def test_conflicting_high_confidence_detectors_resolve_inconclusive() -> None:
    authentic = _result(
        "image_forensics",
        score=0.05,
        confidence=0.90,
        summary="Visual analysis indicates unaltered frames.",
    )
    manipulated = _result(
        "audio_voice_clone_probe",
        score=0.92,
        confidence=0.93,
        summary="Synthetic speech detected.",
    )

    assessment = generate_evidentiary_assessment([authentic, manipulated])

    assert assessment.authenticity.score == 0.50
    assert assessment.authenticity.verbal_verdict == "Inconclusive"
    assert assessment.authenticity.status == "flagged"
    combined = " ".join(
        [assessment.authenticity.summary, *assessment.authenticity.findings]
    ).lower()
    assert "contradiction" in combined
    assert "conflicting" in assessment.what_could_not_be_determined.lower()


def test_low_confidence_result_defaults_to_inconclusive_verdict() -> None:
    assessment = generate_evidentiary_assessment(
        [_result("weak_detector", score=0.95, confidence=0.20)]
    )

    assert assessment.authenticity.verbal_verdict == "Inconclusive"


# ---------------------------------------------------------------------------
# Provenance states
# ---------------------------------------------------------------------------


def test_c2pa_valid_manifest_is_strongly_authentic_provenance() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"c2pa_status": "valid"},
    )

    assert assessment.provenance.score == 0.05
    assert assessment.provenance.verbal_verdict == "Strongly supports authenticity"
    assert assessment.provenance.status == "ok"
    assert any("verified" in finding.lower() for finding in assessment.provenance.findings)


def test_c2pa_invalid_signature_is_flagged() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"c2pa_status": "invalid"},
    )

    assert assessment.provenance.score == 0.95
    assert assessment.provenance.status == "flagged"
    assert assessment.provenance.verbal_verdict == "Strongly supports manipulation"
    assert any("FAILED" in finding for finding in assessment.provenance.findings)


def test_c2pa_nested_broken_signature_is_flagged() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={
            "c2pa": {"manifest_found": True, "signature_valid": False},
        },
    )

    assert assessment.provenance.score == 0.95
    assert assessment.provenance.status == "flagged"


def test_c2pa_nested_status_key_is_recognised() -> None:
    valid = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"c2pa": {"status": "verified", "present": True}},
    )
    broken = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"c2pa": {"status": "tampered"}},
    )

    assert valid.provenance.score == 0.05
    assert broken.provenance.score == 0.95


def test_stripped_metadata_is_not_marked_forged() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"platform": "whatsapp", "exif": {}},
    )

    assert assessment.provenance.score == 0.50
    assert assessment.provenance.verbal_verdict == "Inconclusive"
    assert assessment.provenance.status == "ok"
    findings = " ".join(assessment.provenance.findings).lower()
    assert "does not inherently indicate malicious tampering" in findings
    assert "forged" not in findings
    assert "stripped" in assessment.what_could_not_be_determined.lower()


def test_ai_generator_and_editing_software_tags_are_flagged() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={
            "software": "Adobe Photoshop 25.0",
            "generator": "Midjourney v6",
        },
    )

    assert assessment.provenance.score >= 0.80
    assert assessment.provenance.status == "flagged"
    findings = " ".join(assessment.provenance.findings)
    assert "Midjourney" in findings
    assert "Adobe Photoshop" in findings


def test_forged_metadata_is_distinguished_from_stripped() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"temporal_conflict": True, "metadata_stripped": False},
    )

    findings = " ".join(assessment.provenance.findings).lower()
    assert assessment.provenance.score >= 0.80
    assert assessment.provenance.status == "flagged"
    assert "forged" in findings
    assert "does not inherently indicate malicious tampering" not in findings


def test_clean_camera_gps_metadata_supports_authenticity() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={
            "camera_make": "Nikon",
            "camera_model": "Z9",
            "gps_present": True,
        },
    )

    assert assessment.provenance.score <= 0.20
    assert assessment.provenance.verbal_verdict == "Strongly supports authenticity"


# ---------------------------------------------------------------------------
# Model contracts and exports
# ---------------------------------------------------------------------------


def test_axis_result_and_assessment_models() -> None:
    axis = AxisResult(
        name="integrity",
        score=0.05,
        confidence=0.90,
        verbal_verdict="Strongly supports authenticity",
        status="ok",
        summary="Hashes match.",
        findings=["Dual hashes match."],
        limitations=["Hash match alone does not prove who handled the file."],
    )
    assessment = EvidentiaryAssessment(
        case_id="case-002",
        integrity=axis,
        authenticity=axis.model_copy(update={"name": "authenticity"}),
        provenance=axis.model_copy(update={"name": "provenance"}),
        suitability=axis.model_copy(update={"name": "suitability"}),
        what_this_means_for_the_case="Narrative.",
        what_could_not_be_determined="Limits.",
        recommended_judicial_action="Admit as primary electronic record",
    )

    assert assessment.case_id == "case-002"
    assert assessment.integrity.name == "integrity"
    assert assessment.quality_warnings == []
    assert assessment.limitations == []


def test_pipeline_package_exports_assessment_api() -> None:
    assert callable(generate_evidentiary_assessment)
    assert callable(direct_generate)
    assert generate_evidentiary_assessment is direct_generate


def test_all_axes_use_calibrated_verbal_scale() -> None:
    assessment = generate_evidentiary_assessment(
        [_result(score=0.10, confidence=0.90)],
        media_metadata={"c2pa_status": "valid", "width": 1920, "height": 1080},
    )

    for axis in (
        assessment.integrity,
        assessment.authenticity,
        assessment.provenance,
        assessment.suitability,
    ):
        assert 0.0 <= axis.score <= 1.0
        assert 0.0 <= axis.confidence <= 1.0
        assert axis.verbal_verdict in _VERDICTS
        assert axis.status in {"ok", "degraded", "insufficient_data", "flagged"}
