"""
SUTRAM 4-Axis Evidentiary Assessment Engine.

Forensic WHY: A single percentage cannot express evidentiary quality. Digital
evidence can be cryptographically intact yet synthetically generated, or
authentic yet too degraded for reliable automated testing. Collapsing those
dimensions into one score misleads courts and examiners. This module therefore
evaluates four independent axes:

* ``integrity``    - post-acquisition byte/container tamper status
* ``authenticity`` - synthetic generation or content manipulation indicators
* ``provenance``   - C2PA/EXIF/XMP origin attribution and metadata consistency
* ``suitability``  - resolution, bandwidth, duration and compression fitness

The output includes plain-language judicial narratives so a judge, prosecutor,
or investigating officer can act on the technical result without reading model
logits. All logic is deterministic and rule-based: no random or invented
scores are produced.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from app.detectors.base import CalibratedScale, DetectorResult, score_to_verbal_verdict

# ---------------------------------------------------------------------------
# Constants and shared vocabulary
# ---------------------------------------------------------------------------

_EXCLUDED_STATUSES = frozenset({"error", "skipped", "not_implemented"})
_AUTHENTICITY_EXCLUDED_CATEGORIES = frozenset({"provenance", "quality"})

_ACTION_ADMIT = "Admit as primary electronic record"
_ACTION_SUBPOENA = "Subpoena source hardware for physical extraction"
_ACTION_HOLD = "Hold pending independent secondary examination"

_SOCIAL_MEDIA_SIGNATURES = (
    "whatsapp",
    "twitter",
    "instagram",
    "facebook",
    "messenger",
    "telegram",
    "signal",
    "snapchat",
    "tiktok",
    "wechat",
    "line app",
)

# Canonical tool label -> lower-case aliases found in metadata.
_TOOL_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Midjourney", ("midjourney",)),
    ("Stable Diffusion", ("stable diffusion", "stable-diffusion", "sdxl", "comfyui")),
    ("Automatic1111", ("automatic1111", "a1111")),
    ("DALL-E", ("dall-e", "dall·e", "dalle")),
    ("Adobe Firefly", ("firefly", "adobe firefly")),
    ("Adobe Photoshop", ("photoshop",)),
    ("Canva", ("canva",)),
    ("ElevenLabs", ("elevenlabs", "eleven labs")),
    ("Sora", ("sora",)),
    ("Runway", ("runwayml", "runway")),
    ("Synthesia", ("synthesia",)),
    ("HeyGen", ("heygen",)),
    ("GIMP", ("gimp",)),
    ("Lightroom", ("lightroom",)),
    ("Snapseed", ("snapseed",)),
    ("Picsart", ("picsart",)),
    ("InShot", ("inshot",)),
    ("PDFtk", ("pdftk",)),
    ("iText", ("itext",)),
    ("Sejda", ("sejda",)),
    ("Ghostscript", ("ghostscript",)),
)

_SOFTWARE_KEYS = (
    "software",
    "editing_software",
    "software_signatures",
    "suspicious_tools",
    "suspicious_tool_signatures",
    "processing_software",
    "generator",
    "generated_by",
    "ai_generated",
    "synthetic",
    "generative",
    "ai_generator",
    "claim_generator",
    "c2pa_claim_generator",
    "producer",
    "creator",
    "tool",
    "encoder",
    "created_with",
    "application",
    "app",
)

_C2PA_STATUS_KEYS = frozenset(
    {
        "c2pa_status",
        "c2pa_validation_status",
        "c2pa_manifest_status",
        "c2pa_signature_status",
        "manifest_status",
    }
)
_C2PA_VALIDITY_KEYS = frozenset(
    {
        "c2pa_valid",
        "c2pa_verified",
        "c2pa_signature_valid",
        "c2pa_manifest_valid",
        "signature_valid",
        "signature_verified",
        "manifest_valid",
        "manifest_verified",
    }
)
_C2PA_PRESENCE_KEYS = frozenset(
    {
        "c2pa_present",
        "c2pa_manifest_found",
        "c2pa_found",
        "manifest_found",
        "manifest_present",
    }
)

_C2PA_NESTED_STATUS_KEYS = frozenset({"status"})
_C2PA_NESTED_VALIDITY_KEYS = frozenset(
    {"valid", "validated", "verified", "signature_verified", "manifest_verified"}
)
_C2PA_NESTED_PRESENCE_KEYS = frozenset({"present", "found"})

_CAMERA_IDENTITY_KEYS = (
    "camera_make",
    "camera_model",
    "make",
    "model",
    "device_model",
    "camera_serial",
    "serial_number",
    "body_serial_number",
    "lens_model",
)

_SUITABILITY_NESTED_KEYS = ("media_info", "technical", "quality", "file_info")
_PROVENANCE_NESTED_KEYS = ("metadata", "exif", "provenance", "c2pa")

_RESOLUTION_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*[x×]\s*(\d+(?:\.\d+)?)\s*$")


# ---------------------------------------------------------------------------
# Pydantic output contracts
# ---------------------------------------------------------------------------


class AxisResult(BaseModel):
    """Independent result for one of the four forensic dimensions."""

    name: str = Field(description="integrity | authenticity | provenance | suitability")
    score: float = Field(
        ge=0.0, le=1.0, description="0.0 = pristine/authentic, 1.0 = manipulated/unsuitable"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    verbal_verdict: str = Field(description="Calibrated 5-tier verbal scale")
    status: str = Field(description="ok | degraded | insufficient_data | flagged")
    summary: str = Field(description="Plain-English technical summary of this dimension")
    findings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EvidentiaryAssessment(BaseModel):
    """Four independent axes plus court-facing narratives for one evidence item."""

    case_id: str | None = None
    integrity: AxisResult
    authenticity: AxisResult
    provenance: AxisResult
    suitability: AxisResult
    what_this_means_for_the_case: str
    what_could_not_be_determined: str
    recommended_judicial_action: str
    quality_warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _clamp01(value: float) -> float:
    return min(max(value, 0.0), 1.0)


def _status_of(result: DetectorResult) -> str:
    return str(getattr(result, "status", "ok") or "ok").strip().lower()


def _category_of(result: DetectorResult) -> str:
    return str(getattr(result, "category", "") or "").strip().lower()


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _as_int(value: Any) -> int | None:
    number = _as_float(value)
    if number is None:
        return None
    return int(number)


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "valid", "verified", "present", "detected"}:
            return True
        if lowered in {"false", "no", "0", "invalid", "absent", "missing", "none", "not_found"}:
            return False
    return None


def _has_signal(value: Any) -> bool:
    """Return True when a loosely-typed flag/list/dict indicates a positive finding."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in {"", "none", "null", "false", "no", "0", "absent"}
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return value is not None


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        items: list[str] = []
        for key, nested in value.items():
            if isinstance(nested, bool) and nested:
                items.append(str(key))
            else:
                items.extend(_flatten_strings(nested))
        return items
    if isinstance(value, (list, tuple, set)):
        items = []
        for nested in value:
            items.extend(_flatten_strings(nested))
        return items
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    return []


def _metadata_sources(
    metadata: dict[str, Any] | None, nested_keys: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Return the top-level metadata plus any nested dictionaries of interest."""

    if not metadata:
        return []
    sources: list[dict[str, Any]] = [metadata]
    for key in nested_keys:
        nested = metadata.get(key)
        if isinstance(nested, dict) and nested not in sources:
            sources.append(nested)
    return sources


def _lookup(sources: list[dict[str, Any]], keys: tuple[str, ...]) -> Any:
    for source in sources:
        for key in keys:
            if key in source and source[key] is not None:
                return source[key]
    return None


def _match_tool_signatures(values: list[str]) -> list[str]:
    blob = " ".join(values).lower()
    matched: list[str] = []
    for canonical, aliases in _TOOL_SIGNATURES:
        if any(alias in blob for alias in aliases) and canonical not in matched:
            matched.append(canonical)
    return matched


def _build_axis(
    name: str,
    score: float,
    confidence: float,
    status: str,
    summary: str,
    findings: list[str] | None = None,
    limitations: list[str] | None = None,
) -> AxisResult:
    normalized_score = round(_clamp01(score), 3)
    normalized_confidence = round(_clamp01(confidence), 3)
    return AxisResult(
        name=name,
        score=normalized_score,
        confidence=normalized_confidence,
        verbal_verdict=score_to_verbal_verdict(normalized_score, normalized_confidence),
        status=status,
        summary=summary,
        findings=findings or [],
        limitations=limitations or [],
    )


def _insufficient_axis(name: str, summary: str, limitations: list[str] | None = None) -> AxisResult:
    return _build_axis(
        name=name,
        score=0.50,
        confidence=0.0,
        status="insufficient_data",
        summary=summary,
        findings=[],
        limitations=limitations or [],
    )


def _merge_unique(items: list[str]) -> list[str]:
    merged: list[str] = []
    for item in items:
        text = item.strip()
        if text and text not in merged:
            merged.append(text)
    return merged


# ---------------------------------------------------------------------------
# Axis 1: Integrity
# ---------------------------------------------------------------------------


def _evidence_values(result: DetectorResult) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in result.evidence:
        key = str(item.description).strip().lower()
        if key:
            values[key] = item.value
    return values


def _detector_value(result: DetectorResult, keys: tuple[str, ...]) -> Any:
    parameters = getattr(result, "parameters_used", {}) or {}
    for key in keys:
        if key in parameters and parameters[key] is not None:
            return parameters[key]
    evidence = _evidence_values(result)
    for key in keys:
        if key in evidence and evidence[key] is not None:
            return evidence[key]
    return None


def _assess_integrity(
    integrity_verified: bool,
    results: list[DetectorResult],
    metadata: dict[str, Any],
    has_any_results: bool,
) -> AxisResult:
    name = "integrity"

    if not has_any_results:
        if not integrity_verified:
            return _build_axis(
                name=name,
                score=1.0,
                confidence=1.0,
                status="flagged",
                summary=(
                    "The stored evidence file fails cryptographic hash verification against the "
                    "acquisition audit ledger. This is a critical chain-of-custody violation."
                ),
                findings=[
                    "CRITICAL: Hash mismatch against audit ledger: the stored bytes no longer "
                    "match the SHA-256/SHA-512 values recorded at acquisition."
                ],
                limitations=[
                    "A container-level structural examination was not performed because no "
                    "detector results were supplied."
                ],
            )
        return _insufficient_axis(
            name,
            "The integrity axis could not be assessed because no forensic detector results "
            "were supplied.",
            [
                "Dual-hash verification alone does not exhaustively test container structure; "
                "no detector results were provided."
            ],
        )

    findings: list[str] = []
    limitations: list[str] = [
        "Hash re-verification confirms that the stored bytes match the acquisition record but "
        "does not establish who possessed or accessed the file after acquisition.",
    ]

    structural_detector_ran = any(
        _status_of(result) == "ok"
        and any(
            token in result.detector_name.lower()
            for token in ("pdf", "container", "structural", "document")
        )
        for result in results
    )
    if not structural_detector_ran:
        limitations.append(
            "No container-structure detector ran; byte-level revisions or trailing payloads "
            "could not be independently detected."
        )

    revision_count = 0
    incremental_updates = False
    font_inconsistency_count = 0
    spurious_eof_count = 0
    trailing_payload = False
    container_errors = False
    anomaly_sources: list[str] = []

    for result in results:
        if _status_of(result) != "ok":
            continue

        result_revision_count = _as_int(_detector_value(result, ("revision_count",)))
        result_incremental = _as_bool(
            _detector_value(result, ("incremental_updates_detected", "incremental_updates"))
        )
        result_font_count = _as_int(_detector_value(result, ("font_inconsistency_count",)))
        result_spurious = _as_int(_detector_value(result, ("spurious_eof_marker_count",)))
        result_trailing = _as_bool(
            _detector_value(result, ("trailing_bytes_after_eof", "trailing_payload_detected"))
        )
        result_container_errors = _has_signal(
            _detector_value(
                result,
                (
                    "container_errors",
                    "multiplexing_errors",
                    "container_multiplexing_errors",
                    "structural_errors",
                ),
            )
        )

        if result_revision_count is not None and result_revision_count > 1:
            revision_count = max(revision_count, result_revision_count)
            incremental_updates = True
        if result_incremental:
            incremental_updates = True
        if result_font_count is not None and result_font_count > 0:
            font_inconsistency_count = max(font_inconsistency_count, result_font_count)
        if result_spurious is not None and result_spurious > 0:
            spurious_eof_count = max(spurious_eof_count, result_spurious)
        if result_trailing:
            trailing_payload = True
        if result_container_errors:
            container_errors = True

        if (
            result_revision_count is not None
            or result_incremental
            or result_font_count
            or result_spurious
            or result_trailing
            or result_container_errors
        ):
            anomaly_sources.append(result.detector_name)

    metadata_sources = _metadata_sources(metadata, ("container", "file_info"))
    meta_revision_count = _as_int(_lookup(metadata_sources, ("revision_count",)))
    meta_incremental = _as_bool(
        _lookup(metadata_sources, ("incremental_updates_detected", "incremental_updates"))
    )
    meta_font_count = _as_int(_lookup(metadata_sources, ("font_inconsistency_count",)))
    meta_spurious = _as_int(_lookup(metadata_sources, ("spurious_eof_marker_count",)))
    meta_trailing = _as_bool(
        _lookup(metadata_sources, ("trailing_bytes_after_eof", "trailing_payload_detected"))
    )
    meta_container_errors = _has_signal(
        _lookup(
            metadata_sources,
            (
                "container_errors",
                "multiplexing_errors",
                "container_multiplexing_errors",
                "structural_anomalies",
            ),
        )
    )

    if meta_revision_count is not None and meta_revision_count > 1:
        revision_count = max(revision_count, meta_revision_count)
        incremental_updates = True
    if meta_incremental:
        incremental_updates = True
    if meta_font_count is not None and meta_font_count > 0:
        font_inconsistency_count = max(font_inconsistency_count, meta_font_count)
    if meta_spurious is not None and meta_spurious > 0:
        spurious_eof_count = max(spurious_eof_count, meta_spurious)
    if meta_trailing:
        trailing_payload = True
    if meta_container_errors:
        container_errors = True

    if integrity_verified:
        findings.append(
            "Dual SHA-256/SHA-512 verification against the acquisition audit ledger succeeded; "
            "the stored bytes match the hashes recorded at ingest."
        )
    else:
        findings.insert(
            0,
            "CRITICAL: Hash mismatch against the acquisition audit ledger. The stored file no "
            "longer matches its recorded SHA-256/SHA-512 ingest hashes; this is a critical "
            "chain-of-custody violation.",
        )

    revision_anomaly = incremental_updates or revision_count > 1
    if revision_anomaly:
        findings.append(
            f"Incremental container revisions were detected (revision_count={revision_count or 2}). "
            "Appended PDF updates can change displayed values while leaving earlier bytes intact."
        )
    if font_inconsistency_count > 0:
        findings.append(
            f"{font_inconsistency_count} font stream inconsistency/inconsistencies were detected; "
            "font subsets or embedding characteristics differ within the document."
        )
    if spurious_eof_count > 0:
        findings.append(
            f"{spurious_eof_count} unvalidated %%EOF marker(s) suggest extra revision-like "
            "sections or malformed trailer data in the container."
        )
    if trailing_payload:
        findings.append(
            "Trailing payload bytes were detected after the terminal container marker, indicating "
            "possible appended data."
        )
    if container_errors:
        findings.append(
            "Container multiplexing or structural errors were reported; the file layout is not "
            "consistent with a clean single-pass acquisition."
        )

    if anomaly_sources:
        findings.append(
            "Structural anomalies were reported by: " + ", ".join(anomaly_sources) + "."
        )

    score = 0.05
    if not integrity_verified:
        score = 1.0
    else:
        penalty = 0.0
        if revision_anomaly:
            penalty = max(penalty, 0.70 + 0.05 * max(0, revision_count - 2))
        if font_inconsistency_count > 0:
            penalty = max(penalty, 0.70 + 0.05 * min(font_inconsistency_count - 1, 3))
        if revision_anomaly and font_inconsistency_count > 0:
            penalty += 0.10
        if spurious_eof_count > 0:
            penalty += 0.10
        if trailing_payload:
            penalty += 0.15
        if container_errors:
            penalty += 0.20
        if penalty > 0:
            score = 0.05 + penalty

    score = _clamp01(score)

    if not integrity_verified:
        status = "flagged"
        confidence = 1.0
        summary = (
            "The stored evidence file fails cryptographic integrity verification against the "
            "acquisition audit ledger. This is a critical chain-of-custody violation and the "
            "file must be treated as potentially altered after acquisition."
        )
    elif score >= 0.60:
        status = "flagged"
        confidence = 0.95 if structural_detector_ran else 0.80
        summary = (
            "Hash verification succeeded, but container-level anomalies were detected. The "
            "physical structure is inconsistent with a single unmodified acquisition."
        )
    elif score >= 0.25:
        status = "degraded"
        confidence = 0.90 if structural_detector_ran else 0.75
        summary = (
            "Hash verification succeeded, but minor container anomalies were reported that "
            "require examiner review."
        )
    else:
        status = "ok"
        confidence = 0.90 if structural_detector_ran else 0.82
        summary = (
            "The evidence container is physically consistent with a single unmodified "
            "acquisition: dual hashes match the audit ledger and no structural revision "
            "anomalies were detected."
        )

    return _build_axis(
        name=name,
        score=score,
        confidence=confidence,
        status=status,
        summary=summary,
        findings=findings,
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Axis 2: Authenticity
# ---------------------------------------------------------------------------


def _assess_authenticity(results: list[DetectorResult], suitability: AxisResult) -> AxisResult:
    name = "authenticity"

    viable = [
        result
        for result in results
        if _status_of(result) == "ok"
        and _category_of(result) not in _AUTHENTICITY_EXCLUDED_CATEGORIES
    ]
    scoring = [result for result in viable if result.confidence > 0.0]

    if not scoring:
        return _insufficient_axis(
            name,
            "No usable content-authenticity detector produced a measurement; the content-level "
            "authenticity of the evidence could not be established.",
            [
                "Authenticity scoring depends on synthetic-media, splice, copy-move, voice-clone, "
                "rPPG, lip-sync, or lighting detectors; none returned a usable result."
            ],
        )

    findings: list[str] = []
    limitations: list[str] = []

    manip_high = [
        result for result in scoring if result.score >= 0.75 and result.confidence >= 0.70
    ]
    auth_high = [result for result in scoring if result.score <= 0.20 and result.confidence >= 0.70]

    contradiction = bool(manip_high and auth_high)
    if contradiction:
        score = 0.50
        confidence = max(
            max(result.confidence for result in manip_high),
            max(result.confidence for result in auth_high),
        )
        status = "flagged"
        findings.append(
            "Contradiction detected: high-confidence manipulation evidence conflicts with "
            "high-confidence authenticity evidence on the same evidence item."
        )
        for result in manip_high:
            findings.append(
                f"Manipulation indicator: {result.detector_name} reported score="
                f"{result.score:.2f}, confidence={result.confidence:.2f}."
            )
        for result in auth_high:
            findings.append(
                f"Authenticity indicator: {result.detector_name} reported score="
                f"{result.score:.2f}, confidence={result.confidence:.2f}."
            )
        limitations.append(
            "Conflicting detector results cannot be resolved by score averaging; an independent "
            "secondary examination is required."
        )
        summary = (
            "Contradictory high-confidence detector results were found. The authenticity axis "
            "is therefore Inconclusive and the evidence must not be treated as verified."
        )
    elif manip_high:
        score = max(0.75, _weighted_score(scoring))
        confidence = max(result.confidence for result in manip_high)
        status = "flagged"
        for result in manip_high:
            findings.append(
                f"Decisive manipulation indicator: {result.detector_name} reported score="
                f"{result.score:.2f} with confidence={result.confidence:.2f}."
            )
        summary = (
            "One or more high-confidence detectors found decisive manipulation indicators. "
            "Under the weakest-link forensic rule, the authenticity axis tilts toward "
            "manipulation."
        )
    else:
        score = _weighted_score(scoring)
        total_confidence = sum(result.confidence for result in scoring)
        confidence = (
            sum(result.confidence * result.confidence for result in scoring) / total_confidence
            if total_confidence > 0
            else 0.0
        )
        status = "ok"
        provisional_verdict = score_to_verbal_verdict(score, confidence)
        if provisional_verdict in {
            CalibratedScale.STRONGLY_AUTHENTIC.value,
            CalibratedScale.SUPPORTS_AUTHENTIC.value,
        }:
            summary = (
                "The applied content detectors report no high-confidence synthetic-generation "
                "or manipulation indicators; the content is consistent with authentic media."
            )
        elif provisional_verdict == CalibratedScale.INCONCLUSIVE.value:
            summary = (
                "The content detectors did not reach a reliable conclusion on synthetic "
                "generation or manipulation."
            )
        else:
            summary = (
                "The content detectors report indicators that support manipulation of the "
                "evidence content."
            )
        for result in scoring:
            findings.append(
                f"{result.detector_name}: score={result.score:.2f}, "
                f"confidence={result.confidence:.2f}."
            )

    if suitability.score >= 0.70:
        original_confidence = confidence
        confidence = min(round(confidence * 0.70, 3), 0.50)
        limitations.append(
            "Authenticity confidence was downweighted because media suitability is severely "
            f"degraded (suitability score={suitability.score:.2f}); detectors are more prone to "
            "false positives and false negatives on heavily compressed media."
        )
        findings.append(
            f"Confidence penalty applied: {original_confidence:.2f} -> {confidence:.2f} due to "
            "severe suitability degradation."
        )
    elif suitability.score >= 0.60:
        limitations.append(
            "Media quality is degraded, so content-detector results may be less reliable and "
            "should be corroborated."
        )

    return _build_axis(
        name=name,
        score=score,
        confidence=confidence,
        status=status,
        summary=summary,
        findings=findings,
        limitations=limitations,
    )


def _weighted_score(results: list[DetectorResult]) -> float:
    total_confidence = sum(result.confidence for result in results)
    if total_confidence <= 0:
        return 0.50
    return sum(result.score * result.confidence for result in results) / total_confidence


# ---------------------------------------------------------------------------
# Axis 3: Provenance
# ---------------------------------------------------------------------------


@dataclass
class _ProvenanceSignals:
    c2pa_state: str | None = None
    metadata_stripped: bool = False
    stripped_reason: str | None = None
    software: list[str] = field(default_factory=list)
    ai_watermark: bool = False
    gps_present: bool = False
    camera_identity: bool = False
    temporal_conflict: bool = False
    forged_metadata: bool = False
    ambiguous: bool = False
    exif_present: bool | None = None
    signal_count: int = 0


def _normalise_c2pa_state(value: Any) -> str | None:
    text = str(value).strip().lower()
    if text in {"valid", "verified", "trusted", "ok", "success", "passed", "good"}:
        return "valid"
    if text in {
        "invalid",
        "broken",
        "tampered",
        "failed",
        "failure",
        "mismatch",
        "untrusted",
        "signature_invalid",
        "bad",
    }:
        return "invalid"
    if text in {"absent", "missing", "none", "not_found", "not found", "no_manifest"}:
        return "absent"
    if text in {"present", "found"}:
        return "present"
    return None


def _c2pa_states_from_value(value: Any) -> list[str]:
    if isinstance(value, dict):
        states: list[str] = []
        for key, nested in value.items():
            key_lower = str(key).strip().lower().replace("-", "_")
            if key_lower in _C2PA_STATUS_KEYS | _C2PA_NESTED_STATUS_KEYS:
                state = _normalise_c2pa_state(nested)
                if state is not None:
                    states.append(state)
            elif key_lower in _C2PA_VALIDITY_KEYS | _C2PA_NESTED_VALIDITY_KEYS:
                flag = _as_bool(nested)
                if flag is not None:
                    states.append("valid" if flag else "invalid")
            elif key_lower in _C2PA_PRESENCE_KEYS | _C2PA_NESTED_PRESENCE_KEYS:
                flag = _as_bool(nested)
                if flag is not None:
                    states.append("present" if flag else "absent")
        return states
    if isinstance(value, (list, tuple, set)):
        states = []
        for nested in value:
            states.extend(_c2pa_states_from_value(nested))
        return states
    if isinstance(value, bool):
        return ["present" if value else "absent"]
    state = _normalise_c2pa_state(value)
    return [state] if state is not None else []


def _collect_c2pa_state(sources: list[dict[str, Any]], results: list[DetectorResult]) -> str | None:
    states: list[str] = []

    for source in sources:
        for key, value in source.items():
            key_lower = str(key).strip().lower().replace("-", "_")
            if key_lower in _C2PA_STATUS_KEYS:
                state = _normalise_c2pa_state(value)
                if state is not None:
                    states.append(state)
            elif key_lower in _C2PA_VALIDITY_KEYS:
                flag = _as_bool(value)
                if flag is not None:
                    states.append("valid" if flag else "invalid")
            elif key_lower in _C2PA_PRESENCE_KEYS:
                flag = _as_bool(value)
                if flag is not None:
                    states.append("present" if flag else "absent")
            elif key_lower in {"c2pa", "c2pa_manifest"}:
                states.extend(_c2pa_states_from_value(value))

    for result in results:
        if _status_of(result) != "ok":
            continue
        parameters = getattr(result, "parameters_used", {}) or {}
        for key, value in parameters.items():
            key_lower = str(key).strip().lower().replace("-", "_")
            if key_lower in _C2PA_STATUS_KEYS | _C2PA_VALIDITY_KEYS | _C2PA_PRESENCE_KEYS:
                states.extend(_c2pa_states_from_value({key_lower: value}))
            elif key_lower in {"c2pa", "c2pa_manifest"}:
                states.extend(_c2pa_states_from_value(value))
        for item in result.evidence:
            if "c2pa" in str(item.description).lower():
                states.extend(_c2pa_states_from_value(item.value))
        if "c2pa" in result.detector_name.lower() and not states:
            states.extend(_c2pa_states_from_value(parameters))

    if "invalid" in states:
        return "invalid"
    if "valid" in states:
        return "valid"
    if "absent" in states:
        return "absent"
    if "present" in states:
        return "present"
    return None


def _collect_provenance_signals(
    results: list[DetectorResult], metadata: dict[str, Any]
) -> _ProvenanceSignals:
    signals = _ProvenanceSignals()
    sources = _metadata_sources(metadata, _PROVENANCE_NESTED_KEYS)
    signals.c2pa_state = _collect_c2pa_state(sources, results)

    social_text_parts: list[str] = []
    for source in sources:
        for key, value in source.items():
            key_lower = str(key).strip().lower().replace("-", "_")

            if key_lower in {"camera_make", "camera_model", "make", "model", "device_model"}:
                if _flatten_strings(value):
                    signals.camera_identity = True
            elif key_lower in {
                "camera_serial",
                "serial_number",
                "body_serial_number",
                "lens_model",
            }:
                if _flatten_strings(value):
                    signals.camera_identity = True

            if key_lower in {"gps", "gps_coordinates", "gps_position"}:
                if _has_signal(value):
                    signals.gps_present = True
            elif key_lower == "gps_present":
                flag = _as_bool(value)
                if flag:
                    signals.gps_present = True

            if key_lower in {
                "metadata_stripped",
                "stripped_metadata",
                "exif_stripped",
                "metadata_removed",
                "metadata_missing",
                "exif_missing",
                "stripped",
            }:
                flag = _as_bool(value)
                if flag:
                    signals.metadata_stripped = True
                    signals.stripped_reason = "explicit strip flag"
            elif key_lower == "exif_present":
                flag = _as_bool(value)
                if flag is not None:
                    signals.exif_present = flag
                    if not flag:
                        signals.metadata_stripped = True
                        signals.stripped_reason = "EXIF reported absent"
            elif key_lower == "exif" and (value == {} or value is None):
                signals.metadata_stripped = True
                signals.stripped_reason = "EXIF container empty"
            elif key_lower == "exif" and isinstance(value, str):
                if value.strip().lower() in {"stripped", "missing", "absent", "none", "not_found"}:
                    signals.metadata_stripped = True
                    signals.stripped_reason = "EXIF reported absent"
            elif key_lower in {"social_media", "social_media_compressed", "social_media_upload"}:
                if _as_bool(value):
                    signals.metadata_stripped = True
                    signals.stripped_reason = "social-media upload flag"
            elif key_lower in {
                "temporal_conflict",
                "timestamp_conflict",
                "metadata_temporal_conflict",
                "date_conflict",
                "moddate_before_creation",
            }:
                if _as_bool(value):
                    signals.temporal_conflict = True
            elif key_lower in {
                "metadata_forged",
                "forged_metadata",
                "forged",
                "tampered_metadata",
                "impossible_firmware_parameters",
                "impossible_camera_parameters",
            }:
                if _as_bool(value):
                    signals.forged_metadata = True

            if key_lower in {"platform", "source_platform", "source", "format", "container"}:
                social_text_parts.extend(_flatten_strings(value))
            elif key_lower in {"uploaded_via", "file_name", "filename", "original_filename"}:
                social_text_parts.extend(_flatten_strings(value))

            if key_lower in _SOFTWARE_KEYS:
                matched = _match_tool_signatures(_flatten_strings(value))
                for tool in matched:
                    if tool not in signals.software:
                        signals.software.append(tool)
                if key_lower in {"watermark", "ai_watermark", "ai_generated", "synthetic"} and (
                    _has_signal(value)
                ):
                    signals.ai_watermark = True

    if any(
        signature in " ".join(social_text_parts).lower() for signature in _SOCIAL_MEDIA_SIGNATURES
    ):
        signals.metadata_stripped = True
        if signals.stripped_reason is None:
            signals.stripped_reason = "social-media/messaging platform"

    for result in results:
        if _status_of(result) != "ok":
            continue

        for item in result.evidence:
            description = str(item.description).strip().lower()
            value = item.value

            if any(
                token in description
                for token in ("stripped_metadata", "metadata_stripped", "exif_stripped")
            ):
                if value is not True and isinstance(value, bool) and not value:
                    continue
                signals.metadata_stripped = True
                signals.stripped_reason = signals.stripped_reason or f"{result.detector_name}"

            if any(token in description for token in ("temporal_conflict", "timestamp_conflict")):
                signals.temporal_conflict = True
            if any(token in description for token in ("forged_metadata", "impossible_firmware")):
                signals.forged_metadata = True

            if "gps" in description and _has_signal(value):
                signals.gps_present = True
            if any(token in description for token in ("clean_camera_exif", "camera_exif")):
                signals.camera_identity = True
            if "ambiguous" in description:
                signals.ambiguous = True

            if any(
                token in description
                for token in (
                    "suspicious_software_signature",
                    "editing_software",
                    "software_signature",
                    "ai_generator",
                    "generator_watermark",
                    "suspicious producer",
                    "suspicious creator",
                )
            ):
                matched = _match_tool_signatures(_flatten_strings(value))
                for tool in matched:
                    if tool not in signals.software:
                        signals.software.append(tool)
                if "watermark" in description and _has_signal(value):
                    signals.ai_watermark = True

            if "c2pa" in description:
                states = _c2pa_states_from_value(value)
                if "invalid" in states:
                    signals.c2pa_state = "invalid"
                elif "valid" in states and signals.c2pa_state != "invalid":
                    signals.c2pa_state = "valid"
                elif "absent" in states and signals.c2pa_state is None:
                    signals.c2pa_state = "absent"

        parameters = getattr(result, "parameters_used", {}) or {}
        for key, value in parameters.items():
            key_lower = str(key).strip().lower().replace("-", "_")
            if key_lower in _SOFTWARE_KEYS:
                matched = _match_tool_signatures(_flatten_strings(value))
                for tool in matched:
                    if tool not in signals.software:
                        signals.software.append(tool)
            elif key_lower in {"metadata_stripped", "stripped_metadata", "exif_stripped"}:
                if _as_bool(value):
                    signals.metadata_stripped = True
            elif key_lower in {"temporal_conflict", "timestamp_conflict"}:
                if _as_bool(value):
                    signals.temporal_conflict = True
            elif key_lower in {"metadata_forged", "forged_metadata"}:
                if _as_bool(value):
                    signals.forged_metadata = True

        summary_lower = result.summary.lower()
        if "no exif metadata" in summary_lower or "no metadata" in summary_lower:
            signals.metadata_stripped = True
            signals.stripped_reason = signals.stripped_reason or f"{result.detector_name}"

    if signals.ai_watermark and not signals.software:
        signals.software.append("AI generation watermark")

    signal_flags = (
        signals.c2pa_state is not None,
        signals.metadata_stripped,
        bool(signals.software),
        signals.gps_present,
        signals.camera_identity,
        signals.temporal_conflict,
        signals.forged_metadata,
        signals.ambiguous,
        signals.exif_present is not None,
    )
    signals.signal_count = sum(1 for flag in signal_flags if flag)
    return signals


def _assess_provenance(
    results: list[DetectorResult], metadata: dict[str, Any], has_any_results: bool
) -> tuple[AxisResult, _ProvenanceSignals]:
    name = "provenance"
    signals = _collect_provenance_signals(results, metadata)

    if not has_any_results:
        signals = _ProvenanceSignals()
        return (
            _insufficient_axis(
                name,
                "The provenance axis could not be assessed because no forensic detector results "
                "were supplied.",
            ),
            signals,
        )

    limitations: list[str] = [
        "Metadata is advisory: it can be stripped, edited, or fabricated independently of the "
        "media payload.",
    ]
    if signals.c2pa_state != "valid":
        limitations.append(
            "No valid C2PA manifest was available; cryptographic origin and capture-device "
            "attribution could not be verified."
        )
    if signals.metadata_stripped:
        limitations.append(
            "Stripped metadata prevents confirmation of the original capture device, timestamp, "
            "and GPS location; absence alone does not prove malicious tampering."
        )

    if signals.c2pa_state == "invalid":
        return (
            _build_axis(
                name,
                score=0.95,
                confidence=0.95,
                status="flagged",
                summary=(
                    "A C2PA provenance manifest was present but its cryptographic signature "
                    "failed verification. The signed origin claim cannot be trusted."
                ),
                findings=[
                    "C2PA manifest signature verification FAILED: the manifest was altered or "
                    "does not match the signed payload.",
                    "A cryptographically broken provenance claim is a stronger manipulation "
                    "indicator than missing metadata.",
                ],
                limitations=limitations,
            ),
            signals,
        )

    if signals.c2pa_state == "valid":
        return (
            _build_axis(
                name,
                score=0.05,
                confidence=0.95,
                status="ok",
                summary=(
                    "A C2PA provenance manifest was present and its cryptographic signature "
                    "verified. The declared origin and edit history are cryptographically intact."
                ),
                findings=[
                    "C2PA manifest cryptographic signature verified; the signed provenance "
                    "record matches the evidence payload."
                ],
                limitations=[
                    "C2PA verifies the signed claim and edit history, not the truthfulness of the "
                    "capture event or the identity of the signer."
                ],
            ),
            signals,
        )

    if signals.forged_metadata or signals.temporal_conflict:
        finding = (
            "Metadata fields are internally inconsistent: capture and modification timestamps "
            "or camera parameters conflict. This indicates forged metadata rather than merely "
            "stripped metadata."
        )
        if signals.temporal_conflict and not signals.forged_metadata:
            finding = (
                "Timestamps conflict within the metadata record (for example, a modification "
                "date preceding the capture date). This indicates forged metadata rather than "
                "merely stripped metadata."
            )
        return (
            _build_axis(
                name,
                score=0.90,
                confidence=0.88,
                status="flagged",
                summary=(
                    "Metadata consistency testing found forged or internally contradictory "
                    "origin information."
                ),
                findings=[finding],
                limitations=limitations,
            ),
            signals,
        )

    if signals.software or signals.ai_watermark:
        tools = ", ".join(signals.software) if signals.software else "an AI generation watermark"
        return (
            _build_axis(
                name,
                score=0.85,
                confidence=0.85,
                status="flagged",
                summary=(
                    "Metadata identifies AI-generation or editing software in the origin chain. "
                    "The file is not a direct camera-original according to its own metadata."
                ),
                findings=[
                    f"AI-generator or editing-software tag detected: {tools}. This does not by "
                    "itself prove malicious alteration, but it contradicts direct camera-original "
                    "provenance."
                ],
                limitations=limitations,
            ),
            signals,
        )

    if signals.metadata_stripped:
        reason = signals.stripped_reason or "social-media or messaging transfer"
        return (
            _build_axis(
                name,
                score=0.50,
                confidence=0.65,
                status="ok",
                summary=(
                    "No usable origin metadata remains. The pattern is consistent with metadata "
                    "stripping during social-media or messaging transfer, which is not by itself "
                    "evidence of malicious tampering."
                ),
                findings=[
                    f"Metadata stripped by social media/messaging compression ({reason}); does "
                    "not inherently indicate malicious tampering."
                ],
                limitations=limitations,
            ),
            signals,
        )

    if signals.gps_present or signals.camera_identity:
        confidence = 0.85 if signals.gps_present else 0.70
        evidence_bits: list[str] = []
        if signals.gps_present:
            evidence_bits.append("GPS coordinates")
        if signals.camera_identity:
            evidence_bits.append("camera make/model identity")
        return (
            _build_axis(
                name,
                score=0.08,
                confidence=confidence,
                status="ok",
                summary=(
                    "Camera-origin metadata is present and internally consistent; no AI-generator "
                    "or editing-software tag was found."
                ),
                findings=[
                    "Camera provenance indicators present: " + ", ".join(evidence_bits) + "."
                ],
                limitations=limitations,
            ),
            signals,
        )

    if signals.c2pa_state == "present":
        return (
            _build_axis(
                name,
                score=0.50,
                confidence=0.45,
                status="ok",
                summary=(
                    "A C2PA manifest was found but its cryptographic signature could not be "
                    "verified. Provenance therefore remains inconclusive."
                ),
                findings=[
                    "C2PA manifest present but unverified; no trusted origin attribution is "
                    "available."
                ],
                limitations=limitations,
            ),
            signals,
        )

    if signals.ambiguous or signals.c2pa_state == "absent" or signals.signal_count > 0:
        return (
            _build_axis(
                name,
                score=0.50,
                confidence=0.35,
                status="insufficient_data",
                summary=(
                    "Provenance data is ambiguous or unavailable; the origin of the evidence "
                    "could not be attributed."
                ),
                findings=[
                    "No decisive C2PA, EXIF, XMP, or software-origin signal was available to "
                    "attribute the media to a capture device."
                ],
                limitations=limitations,
            ),
            signals,
        )

    return (
        _insufficient_axis(
            name,
            "No provenance detector or metadata signal was available; origin attribution could "
            "not be performed.",
            limitations,
        ),
        signals,
    )


# ---------------------------------------------------------------------------
# Axis 4: Suitability
# ---------------------------------------------------------------------------


@dataclass
class _SuitabilitySignals:
    media_kind: str | None = None
    low_resolution: bool = False
    low_audio_bandwidth: bool = False
    short_duration: bool = False
    low_frame_rate: bool = False
    low_bitrate: bool = False
    social_recompression: bool = False
    data_points: int = 0


def _parse_resolution_value(value: Any) -> tuple[float, float] | None:
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        width = _as_float(value[0])
        height = _as_float(value[1])
        if width is not None and height is not None and width > 0 and height > 0:
            return (width, height)
    if isinstance(value, dict):
        width = _as_float(value.get("width") or value.get("w"))
        height = _as_float(value.get("height") or value.get("h"))
        if width is not None and height is not None and width > 0 and height > 0:
            return (width, height)
    if isinstance(value, str):
        match = _RESOLUTION_PATTERN.match(value)
        if match is not None:
            return (float(match.group(1)), float(match.group(2)))
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        side = math.sqrt(float(value))
        if side > 0:
            return (side, side)
    return None


def _resolution_dimensions(sources: list[dict[str, Any]]) -> tuple[float, float] | None:
    for source in sources:
        for key in ("resolution", "dimensions", "frame_size", "image_size"):
            if key in source:
                parsed = _parse_resolution_value(source[key])
                if parsed is not None:
                    return parsed
    width = _as_float(_lookup(sources, ("width", "frame_width", "video_width", "image_width")))
    height = _as_float(_lookup(sources, ("height", "frame_height", "video_height", "image_height")))
    if width is not None and height is not None and width > 0 and height > 0:
        return (width, height)
    return None


def _media_kind(
    sources: list[dict[str, Any]],
    dimensions: tuple[float, float] | None,
    sample_rate: float | None,
    frame_rate: float | None,
    duration: float | None,
) -> str | None:
    type_text = " ".join(
        _flatten_strings(
            _lookup(
                sources,
                ("media_type", "mime_type", "content_type", "format", "container", "codec"),
            )
        )
    ).lower()
    if "audio" in type_text:
        return "audio"
    if "video" in type_text:
        return "video"
    if "image" in type_text:
        return "image"
    if sample_rate is not None:
        return "audio"
    if frame_rate is not None:
        return "video"
    if duration is not None and dimensions is not None:
        return "video"
    if dimensions is not None:
        return "image"
    return None


def _detect_social_recompression(sources: list[dict[str, Any]]) -> bool:
    values = _lookup(
        sources,
        (
            "platform",
            "source_platform",
            "source",
            "format",
            "container",
            "uploaded_via",
            "file_name",
            "filename",
            "original_filename",
        ),
    )
    text = " ".join(_flatten_strings(values)).lower()
    if any(signature in text for signature in _SOCIAL_MEDIA_SIGNATURES):
        return True
    for key in ("social_media", "social_media_compressed", "is_whatsapp", "whatsapp"):
        if _as_bool(_lookup(sources, (key,))) is True:
            return True
    return False


def _assess_suitability(
    metadata: dict[str, Any],
) -> tuple[AxisResult, list[str], _SuitabilitySignals]:
    name = "suitability"
    signals = _SuitabilitySignals()
    sources = _metadata_sources(metadata, _SUITABILITY_NESTED_KEYS)

    if not sources:
        return (
            _insufficient_axis(
                name,
                "Media quality could not be assessed because no technical metadata was supplied.",
                [
                    "Resolution, frame rate, sample rate, bitrate, and duration were unavailable; "
                    "suitability is unknown."
                ],
            ),
            [],
            signals,
        )

    dimensions = _resolution_dimensions(sources)
    sample_rate = _as_float(
        _lookup(
            sources,
            ("sample_rate", "sample_rate_hz", "audio_sample_rate", "sampling_rate"),
        )
    )
    frame_rate = _as_float(_lookup(sources, ("frame_rate", "fps", "video_frame_rate")))
    duration = _as_float(
        _lookup(sources, ("duration", "duration_seconds", "duration_s", "length_seconds"))
    )
    bitrate = _as_float(
        _lookup(sources, ("bitrate", "bitrate_bps", "video_bitrate", "avg_bitrate"))
    )
    bitrate_kbps = _as_float(_lookup(sources, ("bitrate_kbps", "audio_bitrate_kbps")))
    if bitrate is None and bitrate_kbps is not None:
        bitrate = bitrate_kbps * 1000.0
    crf = _as_float(_lookup(sources, ("crf", "compression_quality", "quality_factor")))

    signals.media_kind = _media_kind(sources, dimensions, sample_rate, frame_rate, duration)

    if dimensions is not None:
        signals.data_points += 1
    if sample_rate is not None:
        signals.data_points += 1
    if frame_rate is not None:
        signals.data_points += 1
    if duration is not None:
        signals.data_points += 1
    if bitrate is not None:
        signals.data_points += 1
    if crf is not None:
        signals.data_points += 1
    signals.social_recompression = _detect_social_recompression(sources)
    if signals.social_recompression:
        signals.data_points += 1

    if signals.data_points == 0:
        return (
            _insufficient_axis(
                name,
                "Media quality could not be assessed because the supplied metadata contained no "
                "technical quality fields.",
                [
                    "No resolution, frame rate, sample rate, bitrate, duration, or compression "
                    "field was available."
                ],
            ),
            [],
            signals,
        )

    score = 0.05
    warnings: list[str] = []
    limitations: list[str] = []

    if signals.media_kind == "image" and dimensions is not None:
        width, height = dimensions
        short_side = min(width, height)
        if short_side < 256:
            score += 0.55
            signals.low_resolution = True
            warnings.append(
                f"Quality Warning: Image resolution {int(width)}x{int(height)} is below the "
                "256x256 minimum required for reliable forensic analysis."
            )
            if short_side < 128:
                score += 0.20
                warnings.append(
                    "Quality Warning: Image resolution is extremely low; fine spatial and "
                    "compression artifacts required for forensic testing may be absent."
                )
    elif signals.media_kind == "video":
        if dimensions is not None:
            width, height = dimensions
            if height < 480:
                score += 0.55
                signals.low_resolution = True
                warnings.append(
                    f"Quality Warning: Video resolution {int(width)}x{int(height)} is below the "
                    "480p threshold required for reliable forensic analysis."
                )
                if height < 360:
                    score += 0.15
                if height < 240:
                    score += 0.10
        if frame_rate is not None:
            if frame_rate < 15:
                score += 0.20
                signals.low_frame_rate = True
                warnings.append(
                    f"Quality Warning: Frame rate {frame_rate:.1f} fps is below the 15 fps "
                    "minimum for reliable temporal and rPPG analysis."
                )
                if frame_rate < 10:
                    score += 0.10
        if bitrate is not None:
            if bitrate < 1_000_000:
                score += 0.15
                signals.low_bitrate = True
                warnings.append(
                    f"Quality Warning: Video bitrate {bitrate / 1000.0:.0f} kbps is below "
                    "1 Mbps; compression artifacts may mask or mimic manipulation."
                )
                if bitrate < 500_000:
                    score += 0.10
    elif signals.media_kind == "audio":
        if sample_rate is not None:
            if sample_rate < 16_000:
                score += 0.55
                signals.low_audio_bandwidth = True
                warnings.append(
                    f"Quality Warning: Audio sample rate {sample_rate:.0f} Hz is below the "
                    "16 kHz minimum required for reliable spectral and voice-clone analysis."
                )
                if sample_rate <= 8_000:
                    score += 0.15
        if bitrate is not None:
            if bitrate < 128_000:
                score += 0.10
                signals.low_bitrate = True
                warnings.append(
                    f"Quality Warning: Audio bitrate {bitrate / 1000.0:.0f} kbps is below "
                    "128 kbps; codec artifacts may obscure forensic traces."
                )
                if bitrate < 64_000:
                    score += 0.10

    if duration is not None:
        if signals.media_kind == "video" and duration < 1.5:
            score += 0.55
            signals.short_duration = True
            warnings.append(
                f"Quality Warning: Video duration {duration:.2f} s is below the 1.5 s minimum "
                "temporal sample required for reliable forensic analysis."
            )
        elif signals.media_kind == "audio" and duration < 2.0:
            score += 0.55
            signals.short_duration = True
            warnings.append(
                f"Quality Warning: Audio duration {duration:.2f} s is below the 2.0 s minimum "
                "temporal sample required for reliable forensic analysis."
            )
        elif signals.media_kind is None and duration < 2.0:
            score += 0.40
            signals.short_duration = True
            warnings.append(
                f"Quality Warning: Media duration {duration:.2f} s is too short for reliable "
                "temporal forensic analysis."
            )

    if signals.social_recompression:
        score += 0.20
        warnings.append(
            "Quality Warning: Media shows social-media/messaging recompression; compression "
            "artifacts may mask or mimic manipulation."
        )

    recompressed_flag = _lookup(sources, ("recompressed", "compressed", "recompression"))
    if _as_bool(recompressed_flag) is True:
        score += 0.15
        warnings.append(
            "Quality Warning: Media was explicitly flagged as recompressed, reducing "
            "low-level artifact reliability."
        )

    if crf is not None and crf > 32:
        score += 0.10
        warnings.append(
            f"Quality Warning: High compression parameter (crf/quality={crf:.0f}) indicates "
            "aggressive lossy encoding."
        )

    score = _clamp01(score)
    if score >= 0.60:
        status = "degraded"
        summary = " ".join(warnings)
        limitations.append(
            "Suitability is degraded; automated detector reliability is reduced and findings "
            "require corroboration."
        )
    elif warnings:
        status = "ok"
        summary = "Minor quality limitations were noted: " + " ".join(warnings)
    else:
        status = "ok"
        summary = (
            "Media quality is within forensic thresholds for the assessed dimensions; no "
            "resolution, bandwidth, duration, or compression deficiency was detected."
        )

    if signals.data_points < 3:
        confidence = 0.60
        limitations.append(
            "Suitability confidence is limited because fewer than three technical quality fields "
            "were available."
        )
    elif signals.data_points < 5:
        confidence = 0.80
    else:
        confidence = 0.90

    return (
        _build_axis(
            name=name,
            score=score,
            confidence=confidence,
            status=status,
            summary=summary,
            findings=warnings,
            limitations=limitations,
        ),
        warnings,
        signals,
    )


# ---------------------------------------------------------------------------
# Judicial narratives
# ---------------------------------------------------------------------------


def _build_narratives(
    integrity: AxisResult,
    authenticity: AxisResult,
    provenance: AxisResult,
    suitability: AxisResult,
    provenance_signals: _ProvenanceSignals,
    suitability_signals: _SuitabilitySignals,
    results: list[DetectorResult],
    has_any_results: bool,
    authentication_detector_ran: bool,
) -> tuple[str, str, str]:
    integrity_critical = integrity.status == "flagged" and integrity.score >= 0.60
    authenticity_manipulated = authenticity.score >= 0.60 and authenticity.confidence >= 0.40
    authenticity_authentic = authenticity.score <= 0.20 and authenticity.confidence >= 0.40
    provenance_flagged = provenance.score >= 0.80 and provenance.confidence >= 0.40
    suitability_degraded = suitability.status == "degraded"

    if integrity_critical:
        meaning = (
            "The electronic record fails cryptographic integrity verification against the "
            "acquisition audit ledger. This is a critical chain-of-custody violation: the file "
            "must be treated as potentially altered after acquisition and should NOT be admitted "
            "as pristine evidence. The original storage medium and source hardware must be "
            "secured for independent examination."
        )
        action = _ACTION_HOLD
    elif authenticity_manipulated:
        meaning = (
            "The electronic evidence exhibits high-confidence indicators of post-capture "
            "alteration in its container structure or content-level features. It should NOT be "
            "admitted as pristine evidence in proceedings without corroborating the original "
            "hardware capture device."
        )
        action = _ACTION_SUBPOENA
    elif provenance_flagged:
        meaning = (
            "The provenance record is internally inconsistent or identifies synthetic/editing "
            "tools in the origin chain. The file cannot be treated as a camera-original until "
            "the conflicting origin information is resolved and the source hardware is examined."
        )
        action = _ACTION_SUBPOENA
    elif not has_any_results:
        meaning = (
            "No forensic detector output was available, so the authenticity and provenance of "
            "this electronic record could not be independently established. The evidence must "
            "not be presented as verified or unaltered until a complete forensic examination is "
            "completed."
        )
        action = _ACTION_HOLD
    elif not authentication_detector_ran:
        meaning = (
            "No usable content-authenticity detector completed its examination. Container "
            "integrity and metadata alone cannot establish that the media content is genuine, "
            "so the evidence remains unverified pending a full forensic examination."
        )
        action = _ACTION_HOLD
    elif authenticity_authentic and provenance.score <= 0.20 and integrity.score <= 0.20:
        meaning = (
            "The digital record satisfies cryptographic container integrity and demonstrates "
            "authentic sensor or content patterns under the applied examinations. Subject to the "
            "stated quality caveats, the evidence is suitable for court admissibility as an "
            "electronic record under Section 63 BSA 2023 (Bharatiya Sakshya Adhiniyam, 2023)."
        )
        action = _ACTION_ADMIT
    else:
        meaning = (
            "The available examinations do not establish a sufficiently reliable conclusion on "
            "the authenticity or origin of this electronic record. The evidence should be "
            "treated as unverified pending an independent secondary examination."
        )
        action = _ACTION_HOLD

    if suitability_degraded:
        meaning += (
            " Media quality is severely degraded, so automated detector reliability is reduced "
            "and any conclusion must be corroborated by an examiner."
        )
        if action == _ACTION_ADMIT:
            action = _ACTION_HOLD

    undetermined: list[str] = []
    if not has_any_results:
        undetermined.append(
            "No forensic detectors were executed, so no detector-based authenticity, provenance, "
            "or suitability conclusion could be reached."
        )
    elif not authentication_detector_ran:
        undetermined.append(
            "None of the supplied content-authenticity detectors produced a usable result, so "
            "synthetic generation or content manipulation could not be independently assessed."
        )

    excluded = [result for result in results if _status_of(result) in _EXCLUDED_STATUSES]
    if excluded:
        details = ", ".join(f"{result.detector_name} ({_status_of(result)})" for result in excluded)
        undetermined.append(
            f"Outputs from the following detectors could not be used and were excluded from "
            f"scoring: {details}."
        )

    if provenance_signals.metadata_stripped:
        undetermined.append(
            "The original capture device, capture timestamp, and GPS location could not be "
            "confirmed because metadata was stripped during social-media or messaging transfer; "
            "stripping alone does not prove malicious tampering."
        )
    if provenance_signals.c2pa_state != "valid":
        undetermined.append(
            "Cryptographic verification of the capture device and edit history could not be "
            "performed because no valid C2PA manifest was available."
        )
    if provenance_signals.temporal_conflict or provenance_signals.forged_metadata:
        undetermined.append(
            "The conflicting metadata fields could not be reconciled, so the true capture time "
            "and originating device could not be established."
        )
    if integrity_critical:
        undetermined.append(
            "The time window during which the file was altered and the identity of the party who "
            "altered it could not be determined from the file alone."
        )
    if suitability_signals.low_resolution:
        undetermined.append(
            "Analog camera re-recording or optical recapture cannot be ruled out at the available "
            "resolution."
        )
    if suitability_signals.low_audio_bandwidth:
        undetermined.append(
            "Full-band acoustic and ENF analysis could not be performed because the audio "
            "bandwidth is limited."
        )
    if suitability_signals.short_duration:
        undetermined.append(
            "Temporal consistency could not be assessed over a longer recording because the "
            "available sample is too short."
        )
    if _authenticity_contradiction(authenticity):
        undetermined.append(
            "Conflicting high-confidence detector results prevent a single authenticity conclusion."
        )

    undetermined.append(
        "Physical possession and control of the original recording device were not verified by "
        "this software-based assessment."
    )

    return meaning, " ".join(_merge_unique(undetermined)), action


def _authenticity_contradiction(authenticity: AxisResult) -> bool:
    """Return True when the authenticity axis records a detector contradiction."""

    return "contradiction" in " ".join([authenticity.summary, *authenticity.findings]).lower()


# ---------------------------------------------------------------------------
# Public assessment entrypoint
# ---------------------------------------------------------------------------


def generate_evidentiary_assessment(
    detector_results: list[DetectorResult] | None,
    media_metadata: dict[str, Any] | None = None,
    integrity_verified: bool = True,
    case_id: str | None = None,
) -> EvidentiaryAssessment:
    """
    Build the four-axis evidentiary assessment and judicial narratives.

    Parameters
    ----------
    detector_results:
        Detector outputs. ``None`` or an empty list is handled as insufficient data.
    media_metadata:
        Optional technical/provenance metadata (resolution, duration, C2PA status, EXIF tags).
    integrity_verified:
        Result of re-computing SHA-256/SHA-512 against the acquisition audit ledger.
    case_id:
        Optional case identifier echoed into the assessment.
    """

    results = list(detector_results) if detector_results else []
    metadata = dict(media_metadata) if media_metadata else {}
    has_any_results = bool(results)

    authentication_detector_ran = any(
        _status_of(result) == "ok"
        and result.confidence > 0.0
        and _category_of(result) not in _AUTHENTICITY_EXCLUDED_CATEGORIES
        for result in results
    )

    if not has_any_results:
        if integrity_verified:
            integrity = _insufficient_axis(
                "integrity",
                "The integrity axis could not be assessed because no forensic detector results "
                "were supplied.",
                [
                    "No container-structure detector ran; byte-level revision analysis was not "
                    "performed."
                ],
            )
        else:
            integrity = _assess_integrity(False, results, metadata, has_any_results)
        authenticity = _insufficient_axis(
            "authenticity",
            "No authenticity detector results were supplied; synthetic generation and content "
            "manipulation could not be assessed.",
        )
        provenance, provenance_signals = _assess_provenance(results, metadata, has_any_results)
        suitability = _insufficient_axis(
            "suitability",
            "No forensic detector results were supplied; media suitability was not assessed.",
        )
        suitability_signals = _SuitabilitySignals()
        quality_warnings: list[str] = []
    else:
        integrity = _assess_integrity(integrity_verified, results, metadata, has_any_results)
        suitability, quality_warnings, suitability_signals = _assess_suitability(metadata)
        authenticity = _assess_authenticity(results, suitability)
        provenance, provenance_signals = _assess_provenance(results, metadata, has_any_results)

    limitations: list[str] = []
    for axis in (integrity, authenticity, provenance, suitability):
        limitations.extend(axis.limitations)
    for result in results:
        if _status_of(result) in _EXCLUDED_STATUSES:
            limitations.append(
                f"Detector '{result.detector_name}' returned status '{_status_of(result)}' and "
                f"was excluded from scoring: {result.summary}"
            )
        elif _status_of(result) == "ok":
            for item in result.limitations:
                limitations.append(f"{result.detector_name}: {item}")
    limitations.append(
        "This four-axis assessment is forensic decision support; final admissibility is a "
        "judicial determination."
    )

    meaning, undetermined, action = _build_narratives(
        integrity=integrity,
        authenticity=authenticity,
        provenance=provenance,
        suitability=suitability,
        provenance_signals=provenance_signals,
        suitability_signals=suitability_signals,
        results=results,
        has_any_results=has_any_results,
        authentication_detector_ran=authentication_detector_ran,
    )

    return EvidentiaryAssessment(
        case_id=case_id,
        integrity=integrity,
        authenticity=authenticity,
        provenance=provenance,
        suitability=suitability,
        what_this_means_for_the_case=meaning,
        what_could_not_be_determined=undetermined,
        recommended_judicial_action=action,
        quality_warnings=_merge_unique(quality_warnings),
        limitations=_merge_unique(limitations),
    )


__all__ = [
    "AxisResult",
    "EvidentiaryAssessment",
    "generate_evidentiary_assessment",
]
