"""Provenance and native-document forensic detectors for SUTRAM."""

from .pdf_document import NativePDFForensicsDetector, detector

__all__ = ["NativePDFForensicsDetector", "detector"]
