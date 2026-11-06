"""Provenance and native-document forensic detectors for SUTRAM.

This package aggregates:

* :func:`compute_cryptographic_hashes` / :func:`compute_perceptual_hashes`
  / :func:`hamming_distance` / :func:`compute_all_hashes` from
  :mod:`provenance.hashing`.
* :class:`ProvenanceDetector` from :mod:`provenance.metadata`, a
  :class:`~app.detectors.base.BaseDetector` subclass for provenance‑related
  metadata extraction.
* The global :data:`detector_registry` so that the detector is discoverable
  via ``detector_registry.get("provenance_metadata")``.
"""

from .hashing import (
    compute_all_hashes,
    compute_cryptographic_hashes,
    compute_perceptual_hashes,
    hamming_distance,
)
from .metadata import ProvenanceDetector
from .pdf_document import NativePDFForensicsDetector, detector

__all__ = [
    "compute_all_hashes",
    "compute_cryptographic_hashes",
    "compute_perceptual_hashes",
    "hamming_distance",
    "ProvenanceDetector",
    "NativePDFForensicsDetector",
    "detector",
]
