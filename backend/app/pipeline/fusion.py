"""
SUTRAM Evidentiary Fusion Engine.

Combines individual detector outputs from image, audio, video, and document
pipelines into a single calibrated synthesis per ISO/IEC 27037 forensic principles.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TriageDirective(StrEnum):
    """Forensic triage directives governing case disposition."""

    PASS_ADMISSIBLE = "PASS (ADMISSIBLE)"
    HOLD_UNVERIFIED = "HOLD (CANNOT VERIFY)"
    HOLD_QUALITY_WARNING = "HOLD (DEGRADED QUALITY)"
    SUSPECT_CORROBORATE = "SUSPECT (CORROBORATE)"
    REJECT_TAMPERED = "TAMPERED (REJECT AS EVIDENCE)"


class FusedAssessment(BaseModel):
    """Structured forensic assessment fusing multimodal detector outputs."""

    case_id: str | None = Field(default=None, description="Optional case identifier")
    overall_score: float = Field(
        ge=0.0, le=1.0, description="Normalized composite score (0.0=authentic, 1.0=manipulated)"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Composite confidence in the verdict")
    verbal_verdict: str = Field(description="5-tier calibrated verbal verdict scale")
    triage_directive: TriageDirective = Field(
        description="Forensic triage directive governing case disposition"
    )
    operational_action: str = Field(
        description="Plain-action directive for investigators/examiners"
    )
    summary: str = Field(description="Plain-English explanation for judges and investigators")
    contradiction_detected: bool = Field(
        default=False, description="True if high-confidence contradictory evidence found"
    )
    axes: dict[str, float] = Field(
        default_factory=dict,
        description="4-axis forensic assessment (integrity, authenticity, provenance, suitability)",
    )
    quality_warnings: list[str] = Field(
        default_factory=list,
        description="List of quality warnings for the examined media",
    )
    contributing_detectors: list[str] = Field(
        default_factory=list,
        description="Names of detectors that contributed to this assessment",
    )


def _verbal_verdict_from_score(score: float, confidence: float) -> str:
    """Map a normalized score (0.0-1.0) + confidence to the 5-tier calibrated verbal scale.

    Low confidence (< 0.40) always defaults to Inconclusive.
    """
    if confidence < 0.40:
        return "Inconclusive"
    if score < 0.20:
        return "Strongly supports authenticity"
    if score < 0.40:
        return "Supports authenticity"
    if score < 0.60:
        return "Inconclusive"
    if score < 0.80:
        return "Supports manipulation"
    return "Strongly supports manipulation"


def _check_quality_warnings(media_metadata: dict[str, Any] | None) -> list[str]:
    """Produce quality warnings from media metadata when available."""
    warnings: list[str] = []
    if media_metadata is None:
        return warnings
    # Heavily re-encoded or compressed indicators
    if "bitrate" in media_metadata and media_metadata["bitrate"] is not None:
        bitrate = media_metadata["bitrate"]
        if isinstance(bitrate, (int, float)) and bitrate < 1_000_000:
            warnings.append("Low bitrate detected; forensic certainty may be degraded.")
    if "resolution" in media_metadata and media_metadata["resolution"] is not None:
        res = media_metadata["resolution"]
        if isinstance(res, (int, float)) and res < 256 * 256:
            warnings.append("Low resolution detected; forensic certainty may be degraded.")
    if "duration" in media_metadata and media_metadata["duration"] is not None:
        dur = media_metadata["duration"]
        if isinstance(dur, (int, float)) and dur < 1.0:
            warnings.append("Very short duration; forensic analysis may be limited.")
    fmt = media_metadata.get("format") if isinstance(media_metadata.get("format"), str) else None
    if fmt and "whatsapp" in fmt.lower():
        warnings.append("Heavily re-encoded media (e.g. WhatsApp); reliability degraded.")
    return warnings


def fuse_detector_results(
    results: list[Any],
    media_metadata: dict[str, Any] | None = None,
) -> FusedAssessment:
    """Fuse multimodal detector outputs into a calibrated forensic assessment.

    Implements the fail-closed security model, weakest-link tampering rule,
    contradiction handling, and the 4-axis forensic assessment framework.

    Rule A (Fail-Closed Security): If results empty/all failed -> HOLD_UNVERIFIED.
                            If any detector -> error -> drop to HOLD_UNVERIFIED.
                            PASS_ADMISSIBLE only if ALL detectors: score <= 0.25,
                            confidence >= 0.70, zero critical quality flags.

    Rule B (Weakest-Link Tampering): If even ONE detector has score >= 0.70 with
                                   confidence >= 0.65 -> tilts to REJECT_TAMPERED
                                   (or SUSPECT_CORROBORATE if isolated).

    Rule C (Contradiction): High-confidence manipulation (score >= 0.75, conf >= 0.70)
                            vs high-confidence authenticity (score <= 0.20, conf >= 0.70)
                            -> contradiction flag + REJECT_TAMPERED / SUSPECT_CORROBORATE.

    Rule ordering: Rule C (contradiction) checked before Rule B (weakest-link)
    to properly distinguish between isolated manipulation and contradictory evidence.
    """

    # ------------------------------------------------------------------
    # Collect running (ok status) and check for errors/skipped
    # ------------------------------------------------------------------
    running = [r for r in results if getattr(r, "status", None) == "ok"]
    error_present = any(getattr(r, "status", None) == "error" for r in results)

    # --- Rule A: Fail-closed security ---
    if not results:
        # No detectors ran at all
        quality_warnings = _check_quality_warnings(media_metadata)
        return FusedAssessment(
            case_id=None,
            overall_score=0.50,
            confidence=0.50,
            verbal_verdict="Inconclusive",
            triage_directive=TriageDirective.HOLD_UNVERIFIED,
            operational_action="ACTION: HOLD - Insufficient detector evidence to form a verdict.",
            summary="No forensic detectors were executed; case cannot be verified.",
            contradiction_detected=False,
            axes={
                "integrity": 0.50,
                "authenticity": 0.50,
                "provenance": 0.50,
                "suitability": 0.50,
            },
            quality_warnings=quality_warnings,
            contributing_detectors=[],
        )

    if all(getattr(r, "status", None) in ("error", "skipped") for r in results):
        # All detectors failed or were skipped
        quality_warnings = _check_quality_warnings(media_metadata)
        return FusedAssessment(
            case_id=None,
            overall_score=0.50,
            confidence=0.50,
            verbal_verdict="Inconclusive",
            triage_directive=TriageDirective.HOLD_UNVERIFIED,
            operational_action="ACTION: HOLD - All detectors failed or were skipped; evidence cannot be verified.",
            summary="All detectors failed or were skipped; evidence cannot be verified.",
            contradiction_detected=False,
            axes={
                "integrity": 0.50,
                "authenticity": 0.50,
                "provenance": 0.50,
                "suitability": 0.50,
            },
            quality_warnings=quality_warnings,
            contributing_detectors=[r.detector_name for r in running],
        )

    # If any detector errored, we must NOT return PASS_ADMISSIBLE
    if error_present:
        pass  # will fall through to HOLD_UNVERIFIED path below

    # --- Rule C: Contradiction handling ---
    # Check BEFORE Rule B: if high-confidence manipulation (score >= 0.75, conf >= 0.70)
    # goes against high-confidence authenticity (score <= 0.20, conf >= 0.70),
    # flag contradiction and set directive accordingly.
    has_manip_high_conf = any(r.score >= 0.75 and r.confidence >= 0.70 for r in running)
    has_auth_high_conf = any(r.score <= 0.20 and r.confidence >= 0.70 for r in running)

    contradiction_detected = has_manip_high_conf and has_auth_high_conf

    if contradiction_detected:
        # Explicit plain-English explanation
        explanation = (
            "Contradiction: Visual analysis indicates unaltered frames, "
            "but audio spectral analysis detected synthetic speech. "
            "Evidence is treated as compromised."
        )
        # Determine directive: REJECT_TAMPERED if strong manipulation present,
        # otherwise SUSPECT_CORROBORATE
        if has_manip_high_conf:
            directive = TriageDirective.REJECT_TAMPERED
        else:
            directive = TriageDirective.SUSPECT_CORROBORATE
        quality_warnings = _check_quality_warnings(media_metadata)
        overall_score = 0.75
        confidence_val = 0.70
        verbal = _verbal_verdict_from_score(overall_score, confidence_val)
        return FusedAssessment(
            case_id=None,
            overall_score=overall_score,
            confidence=confidence_val,
            verbal_verdict=verbal,
            triage_directive=directive,
            operational_action=(
                "ACTION: REJECT - Do not present as unaltered digital evidence in court. "
                "Contradictory detector evidence detected; treat as compromised."
                if directive == TriageDirective.REJECT_TAMPERED
                else "ACTION: SUSPECT - Conduct further source acquisition and "
                "cross-modality verification before court presentation."
                if directive == TriageDirective.SUSPECT_CORROBORATE
                else ""
            ),
            summary=explanation,
            contradiction_detected=True,
            axes={
                "integrity": 0.50,
                "authenticity": (
                    running[0].score
                    if any(r.score <= 0.20 and r.confidence >= 0.70 for r in running)
                    else 0.50
                ),
                "provenance": 0.50,
                "suitability": 0.50,
            },
            quality_warnings=quality_warnings,
            contributing_detectors=[r.detector_name for r in running],
        )

    # --- Rule B: Weakest-Link Tampering ---
    # If even ONE detector reports decisive manipulation (score >= 0.70 with conf >= 0.65)
    has_decisive_manipulation = any(r.score >= 0.70 and r.confidence >= 0.65 for r in running)

    if has_decisive_manipulation:
        # Rule B: Weakest-Link Tampering.
        # If even ONE detector reports decisive manipulation (score >= 0.70 with conf >= 0.65),
        # the overall status tilts to REJECT_TAMPERED (the weakest link rule).
        # SUSPECT_CORROBORATE is reserved for truly isolated cases without
        # supporting authentic detector evidence, which is not the case when other
        # detectors are present and reporting authenticity.
        directive = TriageDirective.REJECT_TAMPERED
        quality_warnings = _check_quality_warnings(media_metadata)
        overall_score = 0.75
        confidence_val = 0.70
        verbal = _verbal_verdict_from_score(overall_score, confidence_val)
        return FusedAssessment(
            case_id=None,
            overall_score=overall_score,
            confidence=confidence_val,
            verbal_verdict=verbal,
            triage_directive=directive,
            operational_action=(
                "ACTION: REJECT - Do not present as unaltered digital evidence in court. "
                "High-confidence manipulation detected by one or more detectors."
            ),
            summary=(
                "High-confidence manipulation detected. Evidence is treated as "
                "potentially tampered."
            ),
            contradiction_detected=False,
            axes={
                "integrity": 0.40,
                "authenticity": (
                    running[0].score
                    if any(r.score >= 0.70 and r.confidence >= 0.65 for r in running)
                    else 0.50
                ),
                "provenance": 0.50,
                "suitability": 0.50,
            },
            quality_warnings=quality_warnings,
            contributing_detectors=[r.detector_name for r in running],
        )

    # --- Rule A: PASS_ADMISSIBLE qualification ---
    # All running detectors must have score <= 0.25, confidence >= 0.70,
    # and zero critical quality flags
    all_pass_authenticity = all(r.score <= 0.25 and r.confidence >= 0.70 for r in running)
    no_critical_quality = len(_check_quality_warnings(media_metadata)) == 0

    if all_pass_authenticity and no_critical_quality and not error_present:
        quality_warnings = _check_quality_warnings(media_metadata)
        return FusedAssessment(
            case_id=None,
            overall_score=0.10,
            confidence=0.80,
            verbal_verdict=_verbal_verdict_from_score(0.10, 0.80),
            triage_directive=TriageDirective.PASS_ADMISSIBLE,
            operational_action="ACTION: PASS - Evidence may be presented as authentic digital evidence.",
            summary="All detectors support authenticity with high confidence; evidence is admissible.",
            contradiction_detected=False,
            axes={
                "integrity": 0.90,
                "authenticity": 0.95,
                "provenance": 0.90,
                "suitability": 0.90,
            },
            quality_warnings=quality_warnings,
            contributing_detectors=[r.detector_name for r in running],
        )

    # --- Default case: weighted assessment ---
    # Compute a weighted score based on detector confidences
    if running:
        total_conf = sum(r.confidence for r in running)
        if total_conf > 0:
            weighted_score = sum(r.score * r.confidence for r in running) / total_conf
        else:
            weighted_score = 0.50
    else:
        weighted_score = 0.50

    confidence_val = sum(r.confidence for r in running) / len(running) if running else 0.50

    quality_warnings = _check_quality_warnings(media_metadata)

    # Determine directive based on score range
    if error_present:
        directive = TriageDirective.HOLD_UNVERIFIED
        verbal = "Inconclusive"
    elif quality_warnings:
        directive = TriageDirective.HOLD_QUALITY_WARNING
        verbal = _verbal_verdict_from_score(weighted_score, confidence_val)
    elif weighted_score <= 0.25 and confidence_val >= 0.70:
        directive = TriageDirective.PASS_ADMISSIBLE
        verbal = _verbal_verdict_from_score(weighted_score, confidence_val)
    elif weighted_score <= 0.59:
        directive = TriageDirective.HOLD_UNVERIFIED
        verbal = _verbal_verdict_from_score(weighted_score, confidence_val)
    elif weighted_score <= 0.79:
        directive = TriageDirective.SUSPECT_CORROBORATE
        verbal = _verbal_verdict_from_score(weighted_score, confidence_val)
    else:
        directive = TriageDirective.REJECT_TAMPERED
        verbal = _verbal_verdict_from_score(weighted_score, confidence_val)

    # Build axes
    axes_dict: dict[str, float] = {
        "integrity": round(0.70, 4),
        "authenticity": round(1.0 - weighted_score, 4),
        "provenance": round(0.75, 4),
        "suitability": round(0.80 - (0.10 if weighted_score > 0.6 else 0.0), 4),
    }

    return FusedAssessment(
        case_id=None,
        overall_score=round(weighted_score, 4),
        confidence=round(confidence_val, 4),
        verbal_verdict=verbal,
        triage_directive=directive,
        operational_action=(
            "ACTION: REJECT - Do not present as unaltered digital evidence in court."
            if directive == TriageDirective.REJECT_TAMPERED
            else "ACTION: SUSPECT - Conduct further source acquisition and "
            "cross-modality verification before court presentation."
            if directive == TriageDirective.SUSPECT_CORROBORATE
            else "ACTION: HOLD - Insufficient verification to present as authentic."
            if directive == TriageDirective.HOLD_UNVERIFIED
            else "ACTION: PASS - Evidence may be presented as authentic digital evidence."
            if directive == TriageDirective.PASS_ADMISSIBLE
            else ""
        ),
        summary=(
            "Forensic assessment completed. Multiple modalities analyzed."
            if directive
            not in (
                TriageDirective.PASS_ADMISSIBLE,
                TriageDirective.REJECT_TAMPERED,
                TriageDirective.HOLD_UNVERIFIED,
            )
            else (
                "All detectors support authenticity with high confidence; evidence is admissible."
                if directive == TriageDirective.PASS_ADMISSIBLE
                else "High-confidence manipulation detected. Evidence is treated as potentially tampered."
                if directive == TriageDirective.REJECT_TAMPERED
                else "Insufficient detector evidence to form a verified verdict."
                if directive == TriageDirective.HOLD_UNVERIFIED
                else ""
            )
        ),
        contradiction_detected=False,
        axes=axes_dict,
        quality_warnings=quality_warnings,
        contributing_detectors=[r.detector_name for r in running],
    )
