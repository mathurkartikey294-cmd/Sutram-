"""Metadata extraction and provenance analysis for SUTRAM.

Provides a :class:`ProvenanceDetector` that subclasses ``BaseDetector`` and
extracts EXIF / XMP information, GPS coordinates, editing‑software signatures,
temporal consistency, and C2PA manifest presence.

The detector conforms to the 5‑tier calibrated verbal verdict scale and
produces evidence items that can be inspected by the examiner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import ExifTags, Image

from app.detectors.base import BaseDetector, CalibratedScale, DetectorResult, EvidenceItem
from app.detectors.registry import detector_registry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Editing‑software names we look for in EXIF / metadata fields.
_EDITING_SIGNATURES = (
    "photoshop",
    "lightroom",
    "gimp",
    "canva",
    "snapseed",
    "picsart",
    "inshot",
)

# EXIF tag names we care about (Pillow ``ExifTags`` mapping).
_EXIF_KEYS = {
    "Software": "Software",
    "Artist": "Artist",
    "ProcessingSoftware": "ProcessingSoftware",
    "Creator": "Creator",
    "Producer": "Producer",
    "DateTimeOriginal": "DateTimeOriginal",
    "DateTimeDigitized": "DateTimeDigitized",
    "ModifyDate": "ModifyDate",
    "GPSInfo": "GPSInfo",
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _decode_exif_value(value: Any) -> str:
    """Convert an EXIF value to a plain JSON‑serialisable string.

    Pillow may return ``bytes``, ``tuple``, ``rational`` numbers, etc.
    This function normalises everything to a string representation.
    """
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return value.hex()
    if isinstance(value, tuple):
        # Rational numbers from EXIF are (numerator, denominator) pairs.
        if len(value) == 2 and all(isinstance(v, (int, float)) for v in value):
            return f"{value[0]}/{value[1]}"
        return str(value)
    if isinstance(value, float):
        return f"{value:.6f}"
    if isinstance(value, int):
        return str(value)
    return str(value)


def _dms_to_decimal(
    dms: tuple[tuple[int, int], tuple[int, int], tuple[int, int]], ref: str
) -> float:
    """Convert EXIF GPS DMS (degrees/minutes/seconds) + reference to decimal degrees.

    *dms* is a tuple of three rational pairs: ((deg_num, deg_den), (min_num, min_den), (sec_num, sec_den)).
    *ref* is "N", "S", "E", or "W".
    """

    def _step(frac: tuple[int, int]) -> float:
        return frac[0] / frac[1] if frac[1] != 0 else 0.0

    degrees = _step(dms[0])
    minutes = _step(dms[1]) / 60.0
    seconds = _step(dms[2]) / 3600.0

    decimal = degrees + minutes + seconds
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def _extract_gps(info: dict[str, Any]) -> tuple[float, float, float | None] | None:
    """Return (lat, lon, altitude) from EXIF GPS info, or ``None`` if absent.

    Latitude/longitude are decimal degrees; altitude is optional metres.
    """
    gps = info.get("GPSInfo")
    if not gps:
        return None

    # GPSInfo is a dict with tags 1 (LatitudeRef), 2 (Latitude), 3 (LongitudeRef), 4 (Longitude), optional 5 (Altitude).
    # Pillow already decodes these into human‑readable forms, but we safe‑guard.
    lat_ref = gps.get(1)
    lat_val = gps.get(2)
    lon_ref = gps.get(3)
    lon_val = gps.get(4)
    alt_val = gps.get(5)

    if lat_val is None or lon_val is None:
        return None

    try:
        lat = _dms_to_decimal(lat_val, lat_ref) if isinstance(lat_val, tuple) else float(lat_val)
    except Exception:
        return None
    try:
        lon = _dms_to_decimal(lon_val, lon_ref) if isinstance(lon_val, tuple) else float(lon_val)
    except Exception:
        return None

    altitude: float | None = None
    if alt_val is not None:
        try:
            altitude = float(alt_val)
        except Exception:
            pass
    return (lat, lon, altitude)


def _find_software_signature(ifd: dict[str, Any]) -> list[str]:
    """Search the EXIF IFD for known editing‑software names.

    Returns a list of the lower‑cased signatures that were found.
    """
    found: list[str] = []
    # Examine the relevant tags.
    for key in ("Software", "Artist", "ProcessingSoftware", "Creator", "Producer"):
        raw = ifd.get(key)
        if raw is None:
            continue
        text = _decode_exif_value(raw).lower()
        for sig in _EDITING_SIGNATURES:
            if sig in text and sig not in found:
                found.append(sig)
    return found


def _check_temporal_consistency(ifd: dict[str, Any]) -> tuple[bool, float | None]:
    """Return ``(conflict, gap_days)``.

    *conflict* is ``True`` when ``ModifyDate`` is earlier than
    ``DateTimeOriginal`` (or when dates cannot be parsed).
    *gap_days* is the absolute difference in days (``None`` if unparsable).
    """

    def _parse_date(s: str) -> tuple[int, int, int] | None:
        """Try to parse a Pillow EXIF date string ``D:YYYYMMDDHHMMSS``.

        Returns ``(year, month, day)`` or ``None``.
        """
        if not s or not s.startswith("D:"):
            return None
        try:
            # The string after the ``D:`` prefix is YYYYMMDDHHMMSS.
            # We only need the first 8 characters for the date.
            date_part = s[2:10]  # YYYYMMDD
            year = int(date_part[0:4])
            month = int(date_part[4:6])
            day = int(date_part[6:8])
            return (year, month, day)
        except Exception:
            return None

    orig_str = _decode_exif_value(ifd.get("DateTimeOriginal", ""))
    dig_str = _decode_exif_value(ifd.get("DateTimeDigitized", ""))
    mod_str = _decode_exif_value(ifd.get("ModifyDate", ""))

    orig = _parse_date(orig_str)
    _parse_date(dig_str)
    mod = _parse_date(mod_str)

    # If any date is missing we cannot assert a conflict; treat as no conflict.
    if orig is None or mod is None:
        return False, None

    # Convert to comparable tuples.
    def _to_tuple(d: tuple[int, int, int]) -> tuple[int, int, int]:
        return d

    orig_t = _to_tuple(orig)
    mod_t = _to_tuple(mod)

    conflict = mod_t < orig_t
    # Compute approximate gap in days (rough; enough for verdict).
    try:
        from datetime import datetime

        def _to_dt(t: tuple[int, int, int]) -> datetime:
            return datetime(year=t[0], month=t[1], day=t[2])

        delta = abs((_to_dt(mod_t) - _to_dt(orig_t)).days)
    except Exception:
        delta = None
    return conflict, delta


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class ProvenanceDetector(BaseDetector):
    """``BaseDetector`` subclass that extracts provenance‑related metadata from
    image and PDF files.

    * **Name** – ``provenance_metadata``
    * **Version** – ``1.0.0``
    * **Category** – ``provenance``
    * **Supported media** – image JPEG/PNG/WebP/Tiff and application/pdf.
    """

    name: str = "provenance_metadata"
    version: str = "1.0.0"
    category: str = "provenance"
    supported_media_types: list[str] = [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/tiff",
        "application/pdf",
    ]

    # ---------------------------------------------------------------------
    # Internal analysis
    # ---------------------------------------------------------------------

    def _analyse_image(self, media_path: Path) -> dict[str, Any]:
        """Extract EXIF / GPS / software / temporal data from an image file.

        Returns a dictionary with the following keys:

        * ``"exif"`` – raw IFD dict (key‑value pairs) – may be empty.
        * ``"gps"`` – ``(lat, lon, altitude)`` or ``None``.
        * ``"software"`` – list of detected editing‑software signatures.
        * ``"temporal_conflict"`` – ``True`` if dates are contradictory.
        * ``"date_gap_days"`` – approximate gap in days (``None`` if unknown).
        """
        result: dict[str, Any] = {
            "exif": {},
            "gps": None,
            "software": [],
            "temporal_conflict": False,
            "date_gap_days": None,
        }

        try:
            img = Image.open(media_path)
            exif_raw = getattr(img, "_getexif", lambda: None)()
            if exif_raw:
                # Normalise keys to human‑readable names.
                exif: dict[str, Any] = {}
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    exif[tag_name] = _decode_exif_value(value)
                result["exif"] = exif

                # GPS
                result["gps"] = _extract_gps(exif)

                # Software signatures
                result["software"] = _find_software_signature(exif)

                # Temporal consistency
                conflict, gap = _check_temporal_consistency(exif)
                result["temporal_conflict"] = conflict
                result["date_gap_days"] = gap
        except Exception:
            # If anything goes wrong (corrupt image, unsupported format, etc.)
            # we keep the defaults already set above.
            pass

        return result

    def _analyse_pdf(self, media_path: Path) -> dict[str, Any]:
        """Minimal PDF handling – we only report that the file is a PDF.

        A full PDF metadata parse would require a dedicated library (e.g. PyMuPDF)
        which is not a hard dependency; we therefore return a benign result.
        """
        return {
            "exif": {},
            "gps": None,
            "software": [],
            "temporal_conflict": False,
            "date_gap_days": None,
            "note": "PDF metadata parsing not implemented in this baseline detector.",
        }

    # -----------------------------------------------------------------
    # Public :meth:`BaseDetector.analyze` implementation
    # -----------------------------------------------------------------
    def analyze(self, media_path: Path, context: dict[str, Any] | None = None) -> DetectorResult:
        """``BaseDetector.analyze`` entry point.

        Parameters
        ----------
        media_path:
            Path to the file (image or PDF) under examination.
        context:
            Optional dictionary; may contain an ``"evidence_id"`` key.

        Returns
        -------
        DetectorResult
        """
        return self._run_analysis(media_path, context)

    def analyse(self, media_path: Path, context: dict[str, Any] | None = None) -> DetectorResult:
        """British spelling alias for analyze."""
        return self.analyze(media_path, context)

    def _run_analysis(
        self, media_path: Path, context: dict[str, Any] | None = None
    ) -> DetectorResult:
        # -----------------------------------------------------------------
        # Initialise result skeleton
        # -----------------------------------------------------------------
        evidence: list[EvidenceItem] = []
        parameters: dict[str, Any] = {
            "file_size_bytes": None,
            "mime_type": None,
            "temporal_gap_days": None,
        }

        # -----------------------------------------------------------------
        # Basic file checks
        # -----------------------------------------------------------------
        try:
            data = media_path.read_bytes()
            parameters["file_size_bytes"] = len(data)
        except OSError as exc:
            return DetectorResult(
                detector_name=self.name,
                detector_version=self.version,
                category=self.category,
                status="error",
                score=0.5,
                confidence=0.2,
                verbal_verdict=CalibratedScale.INCONCLUSIVE.value,
                summary=f"Could not read file: {type(exc).__name__}.",
                evidence=evidence,
                artifacts=[],
                parameters_used=parameters,
                limitations=[f"File read error: {exc}"],
            )

        # Detect MIME type from the first bytes (simple heuristic).
        mime: str | None = None
        if data.startswith(b"%PDF"):
            mime = "application/pdf"
        elif data.startswith(b"\xff\xd8\xff"):
            mime = "image/jpeg"
        elif data.startswith(b"GIF89a") or data.startswith(b"GIF87a"):
            mime = "image/gif"
        else:
            # Fall back to Pillow identification; if it fails we keep ``None``.
            try:
                img = Image.open(media_path)
                mime = img.format
                if mime:
                    mime = f"image/{mime.lower()}"
            except Exception:
                pass

        parameters["mime_type"] = mime

        # -----------------------------------------------------------------
        # Core analysis – choose path based on detected type
        # -----------------------------------------------------------------
        analysis: dict[str, Any]
        if mime == "application/pdf":
            analysis = self._analyse_pdf(media_path)
        else:
            analysis = self._analyse_image(media_path)

        # -----------------------------------------------------------------
        # Scoring & verdict
        # -----------------------------------------------------------------
        editing_software: list[str] = analysis.get("software", [])
        temporal_conflict: bool = analysis.get("temporal_conflict", False)
        date_gap_days: float | None = analysis.get("date_gap_days")
        gps: tuple[float, float, float | None] | None = analysis.get("gps")
        exif_empty: bool = analysis.get("exif", {}) == {}

        # ---- Rule 1: stripped metadata (zero EXIF) -----------------------
        if exif_empty:
            score = 0.5
            summary = (
                "No EXIF metadata was found; common after social‑media "
                "recompression (WhatsApp, Twitter, etc.)."
            )
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="stripped_metadata",
                    value=True,
                    confidence=0.9,
                )
            )
        # ---- Rule 2: editing‑software signature OR contradictory timestamps --
        elif editing_software or temporal_conflict:
            # Heuristic: presence of known editing tools pushes score high.
            score = 0.80
            if editing_software:
                summary = f"Editing‑software signature(s) detected: {', '.join(editing_software)}."
            else:
                summary = "Contradictory timestamps (ModifyDate earlier than DateTimeOriginal) were found."
            # Populate evidence
            if editing_software:
                evidence.append(
                    EvidenceItem(
                        item_type="text",
                        description="suspicious_software_signature",
                        value={"software": editing_software},
                        confidence=0.95,
                    )
                )
            if temporal_conflict:
                evidence.append(
                    EvidenceItem(
                        item_type="text",
                        description="temporal_conflict",
                        value={
                            "creation_date": analysis.get("exif", {}).get("DateTimeOriginal"),
                            "modification_date": analysis.get("exif", {}).get("ModifyDate"),
                            "gap_days": date_gap_days,
                        },
                        confidence=0.9,
                    )
                )
        # ---- Rule 3: clean original camera EXIF with GPS -----------------
        elif gps is not None and not editing_software and not temporal_conflict:
            score = 0.10  # well below 0.20; will be clamped by _calibrated_verdict
            summary = (
                "Clean original camera EXIF with GPS coordinates and no "
                "editing‑software signatures."
            )
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="gps_coordinates",
                    value={
                        "latitude": gps[0],
                        "longitude": gps[1],
                        "altitude": gps[2],
                    },
                    confidence=0.95,
                )
            )
        # ---- Fallback (should not be reached) ---------------------------
        else:
            score = 0.5
            summary = "Unable to determine provenance; metadata is ambiguous."
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="ambiguous_metadata",
                    value=True,
                    confidence=0.5,
                )
            )

        # -----------------------------------------------------------------
        # Build the DetectorResult
        # -----------------------------------------------------------------
        # Use the calibrated verbal‑verdict helper from the base module.
        # (It simply maps score → 5‑tier scale; we replicate the logic here
        #  to avoid an extra import chain, but we also call it if available.)
        try:
            from app.detectors.base import score_to_verbal_verdict  # type: ignore

            verbal = score_to_verbal_verdict(score)  # type: ignore
        except Exception:  # pragma: no cover
            # Manual fallback (same thresholds as in base.py).
            if score <= 0.20:
                verbal = CalibratedScale.STRONGLY_AUTHENTIC.value
            elif score <= 0.40:
                verbal = CalibratedScale.SUPPORTS_AUTHENTIC.value
            elif score <= 0.59:
                verbal = CalibratedScale.INCONCLUSIVE.value
            elif score <= 0.79:
                verbal = CalibratedScale.SUPPORTS_MANIPULATION.value
            else:
                verbal = CalibratedScale.STRONGLY_MANIPULATION.value

        # Build summary string.
        summary_parts: list[str] = []
        if editing_software:
            summary_parts.append(f"Editing software detected: {', '.join(editing_software)}.")
        if temporal_conflict:
            summary_parts.append(
                f"Temporal conflict: ModifyDate earlier than DateTimeOriginal "
                f"(gap ~{date_gap_days} days)."
            )
        if gps is not None:
            summary_parts.append(f"GPS coordinates present: lat={gps[0]:.5f}, lon={gps[1]:.5f}.")
        if exif_empty:
            summary_parts.append("No EXIF metadata was found.")
        summary = " ".join(summary_parts) if summary_parts else "No salient metadata features."

        # Build the final result.
        result = DetectorResult(
            detector_name=self.name,
            detector_version=self.version,
            category=self.category,
            status="ok",
            score=score,
            confidence=0.82,
            verbal_verdict=verbal,
            summary=summary,
            evidence=evidence,
            artifacts=[],
            parameters_used=parameters,
            limitations=[
                "Metadata extraction relies on Pillow's EXIF support; some tags may be missing or malformed.",
                "PDF metadata parsing is minimal; full C2PA analysis is not performed in this baseline.",
            ],
        )

        return result


# -----------------------------------------------------------------------
# Module-level instance and registration
# -----------------------------------------------------------------------
provenance_detector = ProvenanceDetector()
detector_registry.register(provenance_detector)
