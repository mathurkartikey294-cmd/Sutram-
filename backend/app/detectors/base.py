"""
SUTRAM Forensic Detector Base Interface.
All detector plugins (Image, Video, Audio) inherit from BaseDetector.
"""

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class CalibratedScale(StrEnum):

    STRONGLY_AUTHENTIC = "Strongly supports authenticity"
    SUPPORTS_AUTHENTIC = "Supports authenticity"
    INCONCLUSIVE = "Inconclusive"
    SUPPORTS_MANIPULATION = "Supports manipulation"
    STRONGLY_MANIPULATION = "Strongly supports manipulation"


def score_to_verbal_verdict(score: float, confidence: float) -> str:
    """
    Converts a normalized score (0.0 to 1.0) to the calibrated forensic verbal scale.
    If confidence is low (< 0.40), the verdict defaults to Inconclusive.
    """
    if confidence < 0.40:
        return CalibratedScale.INCONCLUSIVE.value

    if score < 0.20:
        return CalibratedScale.STRONGLY_AUTHENTIC.value
    elif score < 0.40:
        return CalibratedScale.SUPPORTS_AUTHENTIC.value
    elif score < 0.60:
        return CalibratedScale.INCONCLUSIVE.value
    elif score < 0.80:
        return CalibratedScale.SUPPORTS_MANIPULATION.value
    else:
        return CalibratedScale.STRONGLY_MANIPULATION.value


class EvidenceItem(BaseModel):
    """Specific empirical evidence extracted during forensic examination."""

    item_type: str = Field(description="metric | text | region_bbox | time_range | mask")
    description: str
    value: Any
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class DetectorResult(BaseModel):
    """Standardized output returned by every SUTRAM forensic detector."""

    detector_name: str
    detector_version: str
    category: str = Field(description="synthetic_detection | tampering | provenance | quality")
    status: str = Field(default="ok", description="ok | not_implemented | error | skipped")
    score: float = Field(ge=0.0, le=1.0, description="0.0 = authentic, 1.0 = manipulated")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in measurement (0.0 to 1.0)")
    verbal_verdict: str = Field(description="Calibrated verbal scale assessment")
    summary: str = Field(
        description="Plain-English explanation for judicial and investigative review"
    )
    evidence: list[EvidenceItem] = Field(default_factory=list)
    artifacts: list[str] = Field(
        default_factory=list, description="Paths to generated heatmaps/plots"
    )
    parameters_used: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class BaseDetector:
    """Base class for all forensic detection plugins in SUTRAM."""

    name: str = "base_detector"
    version: str = "1.0.0"
    category: str = "tampering"
    supported_media_types: list[str] = []

    def analyze(self, media_path: Path, context: dict[str, Any] | None = None) -> DetectorResult:
        """
        Execute forensic analysis on the provided media working copy.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement analyze()")
