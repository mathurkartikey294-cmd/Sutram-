"""
Unit tests for SUTRAM BaseDetector and calibrated verbal scale.
"""

from pathlib import Path

try:
    from app.detectors.base import (
        BaseDetector,
        CalibratedScale,
        DetectorResult,
        score_to_verbal_verdict,
    )
    from app.detectors.registry import DetectorRegistry
except ImportError:
    from backend.app.detectors.base import (
        BaseDetector,
        CalibratedScale,
        DetectorResult,
        score_to_verbal_verdict,
    )
    from backend.app.detectors.registry import DetectorRegistry


def test_calibrated_verbal_scale_mapping():
    # High confidence mappings
    assert score_to_verbal_verdict(0.10, 0.95) == CalibratedScale.STRONGLY_AUTHENTIC.value
    assert score_to_verbal_verdict(0.30, 0.90) == CalibratedScale.SUPPORTS_AUTHENTIC.value
    assert score_to_verbal_verdict(0.50, 0.85) == CalibratedScale.INCONCLUSIVE.value
    assert score_to_verbal_verdict(0.70, 0.90) == CalibratedScale.SUPPORTS_MANIPULATION.value
    assert score_to_verbal_verdict(0.90, 0.95) == CalibratedScale.STRONGLY_MANIPULATION.value

    # Low confidence must always map to Inconclusive
    assert score_to_verbal_verdict(0.95, 0.20) == CalibratedScale.INCONCLUSIVE.value
    assert score_to_verbal_verdict(0.05, 0.35) == CalibratedScale.INCONCLUSIVE.value


def test_custom_detector_subclass_and_registry():
    registry = DetectorRegistry()

    class DummyDetector(BaseDetector):
        name = "dummy_detector"
        version = "1.0.0"
        category = "tampering"
        supported_media_types = ["image/jpeg"]

        def analyze(self, media_path: Path, context=None) -> DetectorResult:
            return DetectorResult(
                detector_name=self.name,
                detector_version=self.version,
                category=self.category,
                status="ok",
                score=0.85,
                confidence=0.90,
                verbal_verdict=score_to_verbal_verdict(0.85, 0.90),
                summary="Dummy manipulation detected.",
            )

    detector = DummyDetector()
    registry.register(detector)

    assert registry.get("dummy_detector") is not None
    assert len(registry.get_by_media_type("image/jpeg")) == 1
    assert len(registry.get_by_media_type("audio/wav")) == 0

    result = detector.analyze(Path("dummy.jpg"))
    assert result.status == "ok"
    assert result.verbal_verdict == CalibratedScale.STRONGLY_MANIPULATION.value
