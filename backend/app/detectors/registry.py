"""
SUTRAM Global Detector Registry.
Allows automatic discovery and invocation of detectors by modality.
"""

from .base import BaseDetector


class DetectorRegistry:
    """Registry holding all active forensic detectors."""

    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a new forensic detector instance."""
        self._detectors[detector.name] = detector

    def get(self, name: str) -> BaseDetector | None:
        """Retrieve a registered detector by name."""
        return self._detectors.get(name)

    def list_all(self) -> list[BaseDetector]:
        """List all currently registered detectors."""
        return list(self._detectors.values())

    def get_by_media_type(self, mime_type: str) -> list[BaseDetector]:
        """Return all detectors that support the given MIME type."""
        return [
            d
            for d in self._detectors.values()
            if mime_type in d.supported_media_types or not d.supported_media_types
        ]

    def clear(self) -> None:
        """Clear the registry (useful for testing)."""
        self._detectors.clear()


detector_registry = DetectorRegistry()
