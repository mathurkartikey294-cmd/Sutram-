"""
Native PDF structure forensics for SUTRAM.

Forensic WHY: Electronic records such as invoices, affidavits, and bank
statements can be altered without re-rendering the page. PDF's incremental
update mechanism appends replacement objects and a new cross-reference table
while leaving the prior revision intact in the byte stream. This module parses
that structure directly, extracts the earliest revision as a comparison
artifact, and reports metadata, font, and hidden-text indicators that warrant
examiner review.

The parser is intentionally self-contained (standard library only) so analysis
remains air-gapped and does not depend on external office suites or CLI tools.
It is a structural triage tool: findings are investigative indicators, not a
substitute for pixel-level comparison by a qualified examiner.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, NamedTuple

from ..detectors.base import BaseDetector, CalibratedScale, DetectorResult, EvidenceItem
from ..detectors.registry import detector_registry

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ARTIFACT_SUBDIR = Path("evidence_store") / "artifacts"

_BASELINE_SCORE = 0.05
_REVISION_PENALTY = 0.56
_REVISION_STEP_PENALTY = 0.10
_TOOL_PENALTY_WITH_UPDATES = 0.18
_TOOL_PENALTY_SINGLE_REVISION = 0.40
_TEMPORAL_PENALTY_WITH_UPDATES = 0.12
_TEMPORAL_PENALTY_SINGLE_REVISION = 0.37
_FONT_PENALTY_WITH_UPDATES = 0.20
_FONT_PENALTY_SINGLE_REVISION = 0.40
_INVISIBLE_TEXT_PENALTY = 0.03
_INVISIBLE_WITHOUT_IMAGE_PENALTY = 0.35
_MAX_DECOMPRESSED_STREAM_BYTES = 16 * 1024 * 1024
_TEMPORAL_GAP_DAYS = 30.0

_SUSPICIOUS_TOOLS: tuple[str, ...] = (
    "pdftk",
    "itext",
    "acrobat pro",
    "canva",
    "sejda",
    "photoshop",
    "ghostscript",
)

_FONT_FILE_KEYS: tuple[str, ...] = ("FontFile", "FontFile2", "FontFile3")
_METADATA_KEYS: tuple[str, ...] = ("Producer", "Creator", "CreationDate", "ModDate")

_XREF_REVISION_RE = re.compile(rb"startxref\s+(\d+)\s+%%EOF")
_INFO_REF_RE = re.compile(rb"/Info\s+(\d+)\s+(\d+)\s+R")
_ENCRYPT_RE = re.compile(rb"/Encrypt\s+(?:\d+\s+\d+\s+R|<<)")
_INVISIBLE_TEXT_RE = re.compile(rb"(?<![\d.])3\s*Tr\b")
_OBJECT_HEADER_RE = re.compile(rb"(?m)(?:^|(?<=[\r\n]))[ \t]*(\d+)\s+(\d+)\s+obj\b")
_SUBSET_PREFIX_RE = re.compile(r"^([A-Z]{6})\+(.+)$")
_NUMBER_RE = re.compile(rb"[+-]?(?:\d+\.\d*|\.\d+|\d+)")
_REF_TAIL_RE = re.compile(rb"\s+(\d+)\s+R(?![A-Za-z0-9])")
_PDF_DATE_RE = re.compile(
    r"^(?:D:)?"
    r"(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
    r"(?:(Z)|([+-])(\d{2})'?(\d{2})?'?)?"
)

_PDF_WHITESPACE = b"\x00\t\n\f\r "
_PDF_DELIMITERS = b"()<>[]{}/%"


class _PdfName(str):
    """PDF name object (for example ``/Page``), kept distinct from text strings."""


class _PdfRef(NamedTuple):
    """Indirect object reference such as ``12 0 R``."""

    number: int
    generation: int


@dataclass(slots=True)
class _PdfStream:
    """A PDF stream object split into its dictionary and raw stream bytes."""

    dictionary: dict[str, Any]
    data: bytes
    source_position: int = 0
    data_start: int = 0
    data_end: int = 0


@dataclass(slots=True)
class _Revision:
    """One validated ``startxref`` / ``%%EOF`` revision boundary."""

    startxref_position: int
    xref_offset: int
    eof_position: int
    eof_end: int


@dataclass(slots=True)
class _FontUsage:
    """A font resource observed on a specific page."""

    page: int | None
    resource_name: str
    base_font: str
    normalized_font: str
    subset_tag: str | None
    embedded: bool


def _skip_whitespace(data: bytes, position: int) -> int:
    """Skip PDF whitespace and comments, which may separate any two tokens."""

    length = len(data)
    while position < length:
        byte = data[position]
        if byte in _PDF_WHITESPACE:
            position += 1
        elif byte == 0x25:
            while position < length and data[position] not in b"\r\n":
                position += 1
        else:
            break
    return position


def _is_token_boundary(data: bytes, position: int) -> bool:
    if position >= len(data):
        return True
    byte = data[position]
    return byte in _PDF_WHITESPACE or byte in _PDF_DELIMITERS


def _decode_pdf_text(raw: bytes) -> str:
    """Decode PDF text strings, honouring UTF-16 byte-order marks."""

    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _parse_literal_string(data: bytes, position: int) -> tuple[str, int]:
    """Parse a parenthesized PDF string with escapes and balanced parentheses."""

    position += 1
    depth = 1
    output = bytearray()
    length = len(data)
    while position < length:
        byte = data[position]
        if byte == 0x5C:
            position += 1
            if position >= length:
                break
            escaped = data[position]
            mapping = {
                0x6E: 0x0A,
                0x72: 0x0D,
                0x74: 0x09,
                0x62: 0x08,
                0x66: 0x0C,
                0x28: 0x28,
                0x29: 0x29,
                0x5C: 0x5C,
            }
            if escaped in mapping:
                output.append(mapping[escaped])
            elif escaped in b"\r\n":
                if escaped == 0x0D and position + 1 < length and data[position + 1] == 0x0A:
                    position += 1
            elif 0x30 <= escaped <= 0x37:
                octal = bytearray()
                while position < length and len(octal) < 3 and 0x30 <= data[position] <= 0x37:
                    octal.append(data[position])
                    position += 1
                output.append(int(octal, 8) & 0xFF)
                continue
            else:
                output.append(escaped)
            position += 1
        elif byte == 0x28:
            depth += 1
            output.append(byte)
            position += 1
        elif byte == 0x29:
            depth -= 1
            position += 1
            if depth == 0:
                return _decode_pdf_text(bytes(output)), position
            output.append(byte)
        else:
            output.append(byte)
            position += 1
    return _decode_pdf_text(bytes(output)), position


def _parse_hex_string(data: bytes, position: int) -> tuple[str, int]:
    position += 1
    digits = bytearray()
    length = len(data)
    while position < length:
        byte = data[position]
        position += 1
        if byte == 0x3E:
            break
        if byte in _PDF_WHITESPACE:
            continue
        digits.append(byte)
    if len(digits) % 2:
        digits.append(0x30)
    try:
        raw = binascii.unhexlify(bytes(digits))
    except (binascii.Error, ValueError):
        raw = b""
    return _decode_pdf_text(raw), position


def _parse_name(data: bytes, position: int) -> tuple[_PdfName, int]:
    position += 1
    raw = bytearray()
    length = len(data)
    while position < length:
        byte = data[position]
        if byte in _PDF_WHITESPACE or byte in _PDF_DELIMITERS:
            break
        if byte == 0x23 and position + 2 < length:
            try:
                raw.append(int(data[position + 1 : position + 3], 16))
                position += 3
                continue
            except ValueError:
                pass
        raw.append(byte)
        position += 1
    return _PdfName(raw.decode("latin-1")), position


def _parse_array(data: bytes, position: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    length = len(data)
    while True:
        position = _skip_whitespace(data, position)
        if position >= length:
            raise ValueError("unterminated PDF array")
        if data[position] == 0x5D:
            return items, position + 1
        item, position = _parse_object(data, position)
        items.append(item)


def _parse_dictionary(data: bytes, position: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    length = len(data)
    while True:
        position = _skip_whitespace(data, position)
        if position >= length:
            raise ValueError("unterminated PDF dictionary")
        if data.startswith(b">>", position):
            return result, position + 2
        key, position = _parse_object(data, position)
        if not isinstance(key, _PdfName):
            raise ValueError("PDF dictionary key is not a name")
        value, position = _parse_object(data, position)
        result[str(key)] = value


def _parse_object(data: bytes, position: int) -> tuple[Any, int]:
    """Parse one PDF object value, returning the value and the next offset."""

    position = _skip_whitespace(data, position)
    if position >= len(data):
        raise ValueError("unexpected end of PDF object")

    byte = data[position]
    if data.startswith(b"<<", position):
        return _parse_dictionary(data, position + 2)
    if byte == 0x5B:
        return _parse_array(data, position + 1)
    if byte == 0x28:
        return _parse_literal_string(data, position)
    if byte == 0x3C:
        return _parse_hex_string(data, position)
    if byte == 0x2F:
        return _parse_name(data, position)

    for keyword, value in ((b"true", True), (b"false", False), (b"null", None)):
        if data.startswith(keyword, position) and _is_token_boundary(data, position + len(keyword)):
            return value, position + len(keyword)

    number = _NUMBER_RE.match(data, position)
    if number is not None:
        token = number.group(0)
        end = number.end()
        if b"." not in token:
            reference = _REF_TAIL_RE.match(data, end)
            if reference is not None:
                return (
                    _PdfRef(int(token), int(reference.group(1))),
                    reference.end(),
                )
            return int(token), end
        return float(token), end

    end = position
    while end < len(data) and not _is_token_boundary(data, end):
        end += 1
    if end == position:
        raise ValueError(f"unrecognised PDF token at offset {position}")
    return data[position:end].decode("latin-1"), end


def _parse_indirect_object(data: bytes, header: re.Match[bytes]) -> tuple[Any, int, int]:
    """Parse ``N G obj ... endobj`` and split stream payloads when present."""

    value, end = _parse_object(data, header.end())
    after = _skip_whitespace(data, end)
    if isinstance(value, dict) and data.startswith(b"stream", after):
        stream_start = after + len(b"stream")
        if data[stream_start : stream_start + 2] == b"\r\n":
            stream_start += 2
        elif data[stream_start : stream_start + 1] in (b"\r", b"\n"):
            stream_start += 1
        else:
            stream_start = _skip_whitespace(data, stream_start)

        stream_end: int | None = None
        length = value.get("Length")
        if isinstance(length, int) and length >= 0:
            candidate = stream_start + length
            if data[candidate : candidate + 32].lstrip().startswith(b"endstream"):
                stream_end = candidate
        if stream_end is None:
            found = data.find(b"endstream", stream_start)
            if found < 0:
                raise ValueError("unterminated PDF stream")
            stream_end = found
            while stream_end > stream_start and data[stream_end - 1] in b"\r\n":
                stream_end -= 1

        stream = _PdfStream(
            dict(value),
            data[stream_start:stream_end],
            header.start(),
            stream_start,
            stream_end,
        )
        return stream, stream_end, header.start()

    return value, end, header.start()


def _name(value: Any) -> str | None:
    if isinstance(value, str):
        return str(value)
    return None


def _safe_flate_decode(data: bytes) -> bytes | None:
    try:
        decompressor = zlib.decompressobj()
        return decompressor.decompress(data, _MAX_DECOMPRESSED_STREAM_BYTES)
    except zlib.error:
        return None


def _decode_stream(stream: _PdfStream, document: _PdfDocument) -> bytes | None:
    filters = document.resolve(stream.dictionary.get("Filter"))
    if filters is None:
        return stream.data[:_MAX_DECOMPRESSED_STREAM_BYTES]

    filter_list: list[Any]
    if isinstance(filters, list):
        filter_list = filters
    else:
        filter_list = [filters]

    decoded = stream.data
    for filter_value in filter_list:
        filter_name = _name(document.resolve(filter_value))
        if filter_name == "FlateDecode":
            flate = _safe_flate_decode(decoded)
            if flate is None:
                return None
            decoded = flate
        elif filter_name == "ASCIIHexDecode":
            cleaned = re.sub(rb"\s+", b"", decoded).rstrip(b">")
            if len(cleaned) % 2:
                cleaned += b"0"
            try:
                decoded = binascii.unhexlify(cleaned)
            except (binascii.Error, ValueError):
                return None
        elif filter_name == "ASCII85Decode":
            cleaned = re.sub(rb"\s+", b"", decoded)
            if cleaned.startswith(b"<~"):
                cleaned = cleaned[2:]
            if cleaned.endswith(b"~>"):
                cleaned = cleaned[:-2]
            try:
                decoded = base64.a85decode(cleaned)
            except (ValueError, binascii.Error):
                return None
        else:
            return None
        if len(decoded) > _MAX_DECOMPRESSED_STREAM_BYTES:
            decoded = decoded[:_MAX_DECOMPRESSED_STREAM_BYTES]
    return decoded


class _PdfDocument:
    """Lightweight object graph assembled from direct and compressed objects."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.objects: dict[int, Any] = {}
        self.object_positions: dict[int, int] = {}
        self.streams: list[_PdfStream] = []
        self._parse_direct_objects()
        self._expand_object_streams()

    def _parse_direct_objects(self) -> None:
        for header in _OBJECT_HEADER_RE.finditer(self.data):
            try:
                value, _, source_position = _parse_indirect_object(self.data, header)
            except (ValueError, IndexError):
                continue
            number = int(header.group(1))
            self.objects[number] = value
            self.object_positions[number] = source_position
            if isinstance(value, _PdfStream):
                self.streams.append(value)

    def _expand_object_streams(self) -> None:
        for stream in list(self.streams):
            if _name(self.resolve(stream.dictionary.get("Type"))) != "ObjStm":
                continue
            count = self.resolve(stream.dictionary.get("N"))
            first = self.resolve(stream.dictionary.get("First"))
            if not isinstance(count, int) or not isinstance(first, int):
                continue
            decoded = _decode_stream(stream, self)
            if decoded is None:
                continue
            header_numbers = decoded[:first].split()
            pairs: list[tuple[int, int]] = []
            for index in range(0, min(len(header_numbers), count * 2), 2):
                try:
                    pairs.append((int(header_numbers[index]), int(header_numbers[index + 1])))
                except (ValueError, IndexError):
                    break
            for number, offset in pairs:
                if self.object_positions.get(number, -1) >= stream.source_position:
                    continue
                try:
                    value, _ = _parse_object(decoded, first + offset)
                except (ValueError, IndexError):
                    continue
                self.objects[number] = value
                self.object_positions[number] = stream.source_position
                if isinstance(value, _PdfStream):
                    self.streams.append(value)

    def resolve(self, value: Any, depth: int = 0) -> Any:
        while isinstance(value, _PdfRef) and depth < 16:
            value = self.objects.get(value.number)
            depth += 1
        return value

    def objects_by_position(self) -> list[tuple[int, Any]]:
        ordered = sorted(self.object_positions.items(), key=lambda item: item[1])
        return [(number, self.objects[number]) for number, _ in ordered if number in self.objects]

    def stream_spans(self) -> list[tuple[int, int]]:
        return [
            (stream.data_start, stream.data_end)
            for stream in self.streams
            if stream.data_end > stream.data_start
        ]


def _valid_xref_offset(data: bytes, offset: int) -> bool:
    """Confirm that a startxref target really begins an xref table or stream."""

    if offset < 0 or offset >= len(data):
        return False
    window = data[offset : offset + 2048].lstrip()
    if window.startswith(b"xref"):
        return True
    if re.match(rb"\d+\s+\d+\s+obj\b", window):
        return b"/XRef" in window[:1024]
    return False


def _eof_line_end(data: bytes, eof_end: int) -> int:
    if data[eof_end : eof_end + 2] == b"\r\n":
        return eof_end + 2
    if data[eof_end : eof_end + 1] in (b"\r", b"\n"):
        return eof_end + 1
    return eof_end


def _inside_stream(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def _find_revisions(
    data: bytes,
    stream_spans: list[tuple[int, int]] | None = None,
    *,
    allow_unvalidated: bool = True,
) -> tuple[list[_Revision], int, bool]:
    """
    Return validated revision boundaries and the raw %%EOF count.

    A revision is normally proven by a ``startxref`` pointer to a real xref
    table or xref stream immediately before ``%%EOF``. Additional line-aligned
    markers outside stream payloads are retained as revision candidates so a
    deliberately appended update is still visible even if its trailer was
    malformed; markers embedded in text or image streams are ignored.
    """

    revisions: list[_Revision] = []
    valid_positions: set[int] = set()
    spans = stream_spans or []
    all_pairs = [
        match
        for match in _XREF_REVISION_RE.finditer(data)
        if not _inside_stream(match.start(), spans)
    ]
    for match in all_pairs:
        xref_offset = int(match.group(1))
        if not _valid_xref_offset(data, xref_offset):
            continue
        eof_position = match.end() - len(b"%%EOF")
        valid_positions.add(eof_position)
        revisions.append(
            _Revision(
                startxref_position=match.start(),
                xref_offset=xref_offset,
                eof_position=eof_position,
                eof_end=_eof_line_end(data, match.end()),
            )
        )

    if not revisions:
        for match in all_pairs:
            revisions.append(
                _Revision(
                    startxref_position=match.start(),
                    xref_offset=int(match.group(1)),
                    eof_position=match.end() - len(b"%%EOF"),
                    eof_end=_eof_line_end(data, match.end()),
                )
            )

    has_document_skeleton = (
        b"trailer" in data
        or b"/Type /Catalog" in data
        or b"/Type/Catalog" in data
        or b"/Type /Page" in data
        or b"/Type/Page" in data
    )
    if not revisions and allow_unvalidated and b"endobj" in data and has_document_skeleton:
        for match in re.finditer(rb"%%EOF", data):
            position = match.start()
            if _inside_stream(position, spans):
                continue
            if position > 0 and data[position - 1] not in b"\r\n":
                continue
            after = data[match.end() : match.end() + 1]
            if after and after not in b" \t\r\n\f\x00":
                continue
            revisions.append(
                _Revision(
                    startxref_position=position,
                    xref_offset=-1,
                    eof_position=position,
                    eof_end=_eof_line_end(data, match.end()),
                )
            )

    if revisions and allow_unvalidated:
        last_valid_eof = max(revision.eof_position for revision in revisions)
        for match in re.finditer(rb"%%EOF", data):
            position = match.start()
            if position <= last_valid_eof or _inside_stream(position, spans):
                continue
            if data[position - 1] not in b"\r\n":
                continue
            after = data[match.end() : match.end() + 1]
            if after and after not in b" \t\r\n\f\x00":
                continue
            revisions.append(
                _Revision(
                    startxref_position=position,
                    xref_offset=-1,
                    eof_position=position,
                    eof_end=_eof_line_end(data, match.end()),
                )
            )

    revisions.sort(key=lambda revision: revision.eof_position)
    return revisions, data.count(b"%%EOF"), bool(valid_positions)


def _is_encrypted(data: bytes) -> bool:
    return _ENCRYPT_RE.search(data) is not None or b"/Filter/Standard" in data


def _find_info_dictionary(document: _PdfDocument) -> dict[str, Any] | None:
    references = list(_INFO_REF_RE.finditer(document.data))
    for match in reversed(references):
        info = document.resolve(_PdfRef(int(match.group(1)), int(match.group(2))))
        if isinstance(info, dict):
            return info
    for _, candidate in reversed(document.objects_by_position()):
        if isinstance(candidate, dict) and any(key in candidate for key in _METADATA_KEYS):
            return candidate
    return None


def _metadata_text(document: _PdfDocument, info: dict[str, Any], key: str) -> str | None:
    value = document.resolve(info.get(key))
    if value is None:
        return None
    if isinstance(value, str):
        return str(value).strip("\x00 \t\r\n")
    return None


def _parse_pdf_date(value: str | None) -> datetime | None:
    if not value:
        return None
    match = _PDF_DATE_RE.match(value)
    if match is None:
        return None
    year = int(match.group(1))
    month = int(match.group(2) or 1)
    day = int(match.group(3) or 1)
    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    second = int(match.group(6) or 0)
    try:
        zone: tzinfo = UTC
        if match.group(8):
            offset_hours = int(match.group(9) or 0)
            offset_minutes = int(match.group(10) or 0)
            offset = timedelta(hours=offset_hours, minutes=offset_minutes)
            zone = timezone(offset if match.group(8) == "+" else -offset)
        parsed = datetime(year, month, day, hour, minute, second, tzinfo=zone)
    except ValueError:
        return None
    return parsed.astimezone(UTC)


def _match_suspicious_tools(*values: str | None) -> list[str]:
    found: list[str] = []
    for value in values:
        if not value:
            continue
        lowered = value.lower()
        for signature in _SUSPICIOUS_TOOLS:
            if signature in lowered and signature not in found:
                found.append(signature)
    return found


def _font_descriptor_embedded(document: _PdfDocument, font: dict[str, Any]) -> bool:
    if any(key in font for key in _FONT_FILE_KEYS):
        return True
    descriptors: list[dict[str, Any]] = []
    descriptor = document.resolve(font.get("FontDescriptor"))
    if isinstance(descriptor, dict):
        descriptors.append(descriptor)
    descendants = document.resolve(font.get("DescendantFonts"))
    if isinstance(descendants, list):
        for descendant in descendants:
            resolved = document.resolve(descendant)
            if not isinstance(resolved, dict):
                continue
            descendant_descriptor = document.resolve(resolved.get("FontDescriptor"))
            if isinstance(descendant_descriptor, dict):
                descriptors.append(descendant_descriptor)
    for item in descriptors:
        if any(key in item for key in _FONT_FILE_KEYS):
            return True
    subtype = _name(document.resolve(font.get("Subtype")))
    return subtype == "Type3"


def _normalize_font_family(font_name: str) -> str:
    family = re.sub(r"(?i)MT$", "", font_name)
    return re.sub(
        r"(?i)[-,](?:bold|italic|oblique|regular|roman|light|medium|semibold|black|bolditalic)$",
        "",
        family,
    )


def _font_usage(
    document: _PdfDocument,
    page: int | None,
    resource_name: str,
    font: dict[str, Any],
) -> _FontUsage:
    base_font = _name(document.resolve(font.get("BaseFont"))) or resource_name
    subset_tag: str | None = None
    normalized = base_font
    subset_match = _SUBSET_PREFIX_RE.match(base_font)
    if subset_match is not None:
        subset_tag = subset_match.group(1)
        normalized = subset_match.group(2)
    normalized = _normalize_font_family(normalized)
    return _FontUsage(
        page=page,
        resource_name=resource_name,
        base_font=base_font,
        normalized_font=normalized,
        subset_tag=subset_tag,
        embedded=_font_descriptor_embedded(document, font),
    )


def _page_resources(document: _PdfDocument, page: dict[str, Any]) -> dict[str, Any] | None:
    seen: set[int] = set()
    current: dict[str, Any] | None = page
    for _ in range(16):
        if current is None:
            return None
        resources = document.resolve(current.get("Resources"))
        if isinstance(resources, dict):
            return resources
        parent = document.resolve(current.get("Parent"))
        if not isinstance(parent, dict) or id(parent) in seen:
            return None
        seen.add(id(parent))
        current = parent
    return None


def _collect_font_usages(document: _PdfDocument) -> list[_FontUsage]:
    pages = [
        (number, value)
        for number, value in document.objects_by_position()
        if isinstance(value, dict) and _name(document.resolve(value.get("Type"))) == "Page"
    ]
    usages: list[_FontUsage] = []
    for page_number, page in enumerate(pages, start=1):
        resources = _page_resources(document, page[1])
        if resources is None:
            continue
        font_map = document.resolve(resources.get("Font"))
        if not isinstance(font_map, dict):
            continue
        seen_keys: set[int] = set()
        for resource_name, font_value in font_map.items():
            font = document.resolve(font_value)
            if not isinstance(font, dict):
                continue
            key = font_value.number if isinstance(font_value, _PdfRef) else id(font)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            usages.append(_font_usage(document, page_number, str(resource_name), font))

    if usages:
        return usages

    for _, candidate in document.objects_by_position():
        if isinstance(candidate, dict) and "BaseFont" in candidate:
            usages.append(_font_usage(document, None, "document", candidate))
    return usages


def _font_inconsistencies(
    usages: list[_FontUsage],
) -> tuple[int, list[_FontUsage], list[int]]:
    if len(usages) < 2:
        return 0, [], []

    families = {usage.normalized_font for usage in usages}
    embedded = [usage for usage in usages if usage.embedded]
    unembedded = [usage for usage in usages if not usage.embedded]
    subset_families = {usage.normalized_font for usage in usages if usage.subset_tag}
    mixed_embedding = bool(embedded and unembedded)
    mixed_subset_families = len(families) > 1 and bool(subset_families)

    if not mixed_embedding and not mixed_subset_families:
        return 0, [], []

    inconsistent = usages if len(families) > 1 else unembedded
    affected_pages = sorted({usage.page for usage in inconsistent if usage.page is not None})
    return len(inconsistent), inconsistent, affected_pages


def _image_objects(document: _PdfDocument) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    for _, value in document.objects_by_position():
        if not isinstance(value, dict):
            continue
        if _name(document.resolve(value.get("Subtype"))) != "Image":
            continue
        images.append(value)
    return images


def _calibrated_verdict(score: float) -> str:
    if score <= 0.20:
        return CalibratedScale.STRONGLY_AUTHENTIC.value
    if score <= 0.40:
        return CalibratedScale.SUPPORTS_AUTHENTIC.value
    if score <= 0.59:
        return CalibratedScale.INCONCLUSIVE.value
    if score <= 0.79:
        return CalibratedScale.SUPPORTS_MANIPULATION.value
    return CalibratedScale.STRONGLY_MANIPULATION.value


def _safe_evidence_id(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value)).strip("_")
    return cleaned[:96] or "doc"


def _write_revision_artifact(evidence_id: str, revision_bytes: bytes) -> str | None:
    try:
        artifact_directory = _REPO_ROOT / _ARTIFACT_SUBDIR
        artifact_directory.mkdir(parents=True, exist_ok=True)
        filename = f"{evidence_id}_revision_1.pdf"
        artifact_path = artifact_directory / filename
        artifact_path.write_bytes(revision_bytes)
    except OSError:
        return None
    return f"{_ARTIFACT_SUBDIR.as_posix()}/{filename}"


class NativePDFForensicsDetector(BaseDetector):
    """Detect structural and typographic tampering indicators in native PDFs."""

    name = "native_pdf_forensics"
    version = "1.0.0"
    category = "tampering"
    supported_media_types = ["application/pdf"]

    def _terminal_result(
        self,
        *,
        status: str,
        score: float,
        confidence: float,
        summary: str,
        limitations: list[str],
        parameters: dict[str, Any],
        evidence: list[EvidenceItem] | None = None,
    ) -> DetectorResult:
        clamped = round(min(max(score, 0.0), 1.0), 3)
        return DetectorResult(
            detector_name=self.name,
            detector_version=self.version,
            category=self.category,
            status=status,
            score=clamped,
            confidence=round(min(max(confidence, 0.0), 1.0), 3),
            verbal_verdict=_calibrated_verdict(clamped),
            summary=summary,
            evidence=evidence or [],
            artifacts=[],
            parameters_used=parameters,
            limitations=limitations,
        )

    def analyze(self, media_path: Path, context: dict[str, Any] | None = None) -> DetectorResult:
        context = context or {}
        evidence_id = _safe_evidence_id(context.get("evidence_id") or "doc")
        limitations = [
            "Native PDF structure analysis cannot establish pixel-level equivalence between "
            "rendered appearance and extracted text layers.",
            "Incremental revisions and editing-tool signatures are investigative indicators, "
            "not conclusive proof of forgery; extracted revisions require examiner comparison.",
            "Derived artifacts are working copies; the original evidence file is never modified.",
        ]
        parameters: dict[str, Any] = {
            "parser": "stdlib-pdf-structure",
            "parser_version": "1.0.0",
            "evidence_id": evidence_id,
            "temporal_gap_threshold_days": _TEMPORAL_GAP_DAYS,
        }

        try:
            data = Path(media_path).read_bytes()
        except OSError as exc:
            parameters["file_size_bytes"] = None
            return self._terminal_result(
                status="error",
                score=0.5,
                confidence=0.2,
                summary=f"PDF could not be read for forensic analysis ({type(exc).__name__}).",
                limitations=[*limitations, "The evidence file could not be opened in read mode."],
                parameters=parameters,
            )

        parameters["file_size_bytes"] = len(data)

        if not data.startswith(b"%PDF-"):
            return self._terminal_result(
                status="error",
                score=0.5,
                confidence=0.2,
                summary="The file does not begin with a valid %PDF- header.",
                limitations=[*limitations, "Input is not a recognisable native PDF document."],
                parameters=parameters,
            )

        if _is_encrypted(data):
            parameters["encrypted"] = True
            return self._terminal_result(
                status="skipped",
                score=0.5,
                confidence=0.4,
                summary=(
                    "PDF is encrypted or password protected; structural revision, font, and "
                    "hidden-text analysis was not performed."
                ),
                limitations=[
                    *limitations,
                    "Encrypted/password-protected PDFs cannot be structurally parsed without "
                    "the decryption key; the verdict is inconclusive.",
                ],
                parameters=parameters,
                evidence=[
                    EvidenceItem(
                        item_type="text",
                        description="Encrypted PDF container",
                        value="The trailer contains an /Encrypt dictionary.",
                        confidence=0.95,
                    )
                ],
            )

        try:
            document = _PdfDocument(data)
        except Exception as exc:
            return self._terminal_result(
                status="error",
                score=0.5,
                confidence=0.25,
                summary=(
                    "PDF object parsing failed; structural findings are unavailable "
                    f"({type(exc).__name__})."
                ),
                limitations=[
                    *limitations,
                    "The PDF object graph is corrupt or uses unsupported compression.",
                ],
                parameters=parameters,
            )

        linearized = b"/Linearized" in data[:1024]
        parameters["linearized"] = linearized
        revisions, raw_eof_count, xref_validated = _find_revisions(
            data,
            document.stream_spans(),
            allow_unvalidated=not linearized,
        )
        revision_count = len(revisions)
        incremental_updates = revision_count > 1
        parameters["revision_count"] = revision_count
        parameters["xref_target_validated"] = xref_validated
        parameters["validated_revision_count"] = revision_count if xref_validated else 0
        parameters["incremental_updates_detected"] = incremental_updates
        parameters["incremental_updates"] = incremental_updates
        parameters["raw_eof_marker_count"] = raw_eof_count
        parameters["spurious_eof_marker_count"] = max(0, raw_eof_count - revision_count)
        if revision_count and not xref_validated:
            limitations.append(
                "Cross-reference targets could not be fully validated; revision boundaries "
                "were inferred from %%EOF markers and require manual confirmation."
            )

        if not revisions:
            return self._terminal_result(
                status="error",
                score=0.5,
                confidence=0.25,
                summary=(
                    "No valid startxref/%%EOF revision boundary was found; the PDF is truncated "
                    "or structurally malformed."
                ),
                limitations=[
                    *limitations,
                    "Revision analysis failed because the cross-reference trailer could not be "
                    "validated.",
                ],
                parameters=parameters,
            )

        info = _find_info_dictionary(document)
        producer = _metadata_text(document, info, "Producer") if info is not None else None
        creator = _metadata_text(document, info, "Creator") if info is not None else None
        creation_date = _metadata_text(document, info, "CreationDate") if info is not None else None
        modification_date = _metadata_text(document, info, "ModDate") if info is not None else None
        creation_timestamp = _parse_pdf_date(creation_date)
        modification_timestamp = _parse_pdf_date(modification_date)
        metadata_found = info is not None

        parameters["producer"] = producer
        parameters["creator"] = creator
        parameters["creation_date"] = creation_date
        parameters["modification_date"] = modification_date
        parameters["mod_date"] = modification_date

        suspicious_tools = _match_suspicious_tools(producer, creator)
        parameters["suspicious_tool_signatures"] = suspicious_tools
        parameters["suspicious_tools"] = suspicious_tools

        temporal_gap_days: float | None = None
        temporal_conflict = False
        if creation_timestamp is not None and modification_timestamp is not None:
            gap_seconds = (modification_timestamp - creation_timestamp).total_seconds()
            temporal_gap_days = round(gap_seconds / 86400.0, 2)
            temporal_conflict = abs(gap_seconds) > _TEMPORAL_GAP_DAYS * 86400.0
        parameters["temporal_gap_days"] = temporal_gap_days
        parameters["temporal_conflict"] = temporal_conflict
        if (creation_date and creation_timestamp is None) or (
            modification_date and modification_timestamp is None
        ):
            limitations.append(
                "One or more PDF metadata dates could not be parsed, so temporal consistency "
                "was not fully assessed."
            )

        font_usages: list[_FontUsage] = []
        try:
            font_usages = _collect_font_usages(document)
        except Exception as exc:
            limitations.append(
                f"Page font resources could not be fully parsed ({type(exc).__name__})."
            )
        font_inconsistency_count, inconsistent_fonts, affected_pages = _font_inconsistencies(
            font_usages
        )
        parameters["font_resource_count"] = len(font_usages)
        parameters["font_inconsistency_count"] = font_inconsistency_count

        invisible_text_streams = 0
        decoded_stream_count = 0
        for stream in document.streams:
            stream_type = _name(document.resolve(stream.dictionary.get("Type")))
            if stream_type in {"XRef", "ObjStm"}:
                continue
            try:
                decoded = _decode_stream(stream, document)
            except Exception:
                continue
            if decoded is None:
                continue
            decoded_stream_count += 1
            if _INVISIBLE_TEXT_RE.search(decoded):
                invisible_text_streams += 1
        parameters["decoded_stream_count"] = decoded_stream_count
        parameters["invisible_text_stream_count"] = invisible_text_streams
        parameters["invisible_text_streams"] = invisible_text_streams
        parameters["invisible_text_detected"] = bool(invisible_text_streams)

        images = _image_objects(document)
        high_resolution_images = 0
        for image in images:
            width = document.resolve(image.get("Width"))
            height = document.resolve(image.get("Height"))
            if (
                isinstance(width, int)
                and isinstance(height, int)
                and width >= 1000
                and height >= 1000
            ):
                high_resolution_images += 1
        parameters["image_object_count"] = len(images)
        parameters["high_resolution_image_count"] = high_resolution_images
        parameters["invisible_text_without_images"] = bool(invisible_text_streams and not images)
        parameters["potential_ocr_visual_discrepancy"] = bool(
            invisible_text_streams and (not images or high_resolution_images > 0)
        )

        revision_penalty = 0.0
        if incremental_updates:
            revision_penalty = _REVISION_PENALTY + _REVISION_STEP_PENALTY * (revision_count - 2)

        metadata_penalty = 0.0
        if suspicious_tools:
            metadata_penalty += (
                _TOOL_PENALTY_WITH_UPDATES if incremental_updates else _TOOL_PENALTY_SINGLE_REVISION
            )
        if temporal_conflict:
            metadata_penalty += (
                _TEMPORAL_PENALTY_WITH_UPDATES
                if incremental_updates
                else _TEMPORAL_PENALTY_SINGLE_REVISION
            )
        if not incremental_updates and font_inconsistency_count == 0:
            metadata_penalty = min(metadata_penalty, 0.40)

        font_penalty = 0.0
        if font_inconsistency_count:
            font_penalty = (
                _FONT_PENALTY_WITH_UPDATES if incremental_updates else _FONT_PENALTY_SINGLE_REVISION
            )

        invisible_penalty = 0.0
        if invisible_text_streams:
            invisible_penalty = _INVISIBLE_TEXT_PENALTY
            if not images:
                invisible_penalty += _INVISIBLE_WITHOUT_IMAGE_PENALTY

        score = (
            _BASELINE_SCORE + revision_penalty + metadata_penalty + font_penalty + invisible_penalty
        )
        score = round(min(max(score, 0.0), 1.0), 3)
        parameters["scoring_components"] = {
            "baseline": _BASELINE_SCORE,
            "revision": round(revision_penalty, 3),
            "metadata": round(metadata_penalty, 3),
            "font": round(font_penalty, 3),
            "invisible_text": round(invisible_penalty, 3),
        }

        confidence = 0.82
        if metadata_found:
            confidence += 0.03
        if font_usages:
            confidence += 0.03
        if linearized:
            confidence += 0.02
        confidence = round(min(confidence, 0.95), 3)

        evidence: list[EvidenceItem] = [
            EvidenceItem(
                item_type="metric",
                description="revision_count",
                value=revision_count,
                confidence=0.95,
            ),
            EvidenceItem(
                item_type="metric",
                description="incremental_updates_detected",
                value=incremental_updates,
                confidence=0.95,
            ),
            EvidenceItem(
                item_type="metric",
                description="font_inconsistency_count",
                value=font_inconsistency_count,
                confidence=0.9 if font_usages else 0.5,
            ),
        ]

        if linearized:
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="linearized_pdf",
                    value=(
                        "The first 1024 bytes contain a /Linearized dictionary. Linearization "
                        "creates a second cross-reference section for fast web view but is not "
                        "counted as an incremental edit by itself."
                    ),
                    confidence=0.9,
                )
            )

        if suspicious_tools:
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="Suspicious Producer or Creator software signature",
                    value={
                        "producer": producer,
                        "creator": creator,
                        "matched_signatures": suspicious_tools,
                    },
                    confidence=0.85,
                )
            )

        if temporal_conflict:
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="metadata_temporal_conflict",
                    value={
                        "creation_date": creation_date,
                        "modification_date": modification_date,
                        "gap_days": temporal_gap_days,
                    },
                    confidence=0.8,
                )
            )

        if font_inconsistency_count:
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description=(
                        "Font stream inconsistency: mixed embedded/un-embedded or subset fonts"
                    ),
                    value={
                        "affected_pages": affected_pages,
                        "fonts": [
                            {
                                "page": usage.page,
                                "resource": usage.resource_name,
                                "base_font": usage.base_font,
                                "normalized_font": usage.normalized_font,
                                "subset_tag": usage.subset_tag,
                                "embedded": usage.embedded,
                            }
                            for usage in inconsistent_fonts
                        ],
                    },
                    confidence=0.75,
                )
            )

        if invisible_text_streams:
            evidence.append(
                EvidenceItem(
                    item_type="text",
                    description="invisible_text_layer",
                    value={
                        "streams_with_3_Tr": invisible_text_streams,
                        "image_objects": len(images),
                        "high_resolution_images": high_resolution_images,
                        "visual_representation_missing": not images,
                        "potential_ocr_visual_discrepancy": parameters[
                            "potential_ocr_visual_discrepancy"
                        ],
                    },
                    confidence=0.8,
                )
            )
            limitations.append(
                "Invisible text (3 Tr) can be a legitimate OCR layer; glyph overlap with image "
                "objects was not measured and requires visual inspection."
            )

        artifacts: list[str] = []
        if incremental_updates:
            original_revision = data[: revisions[0].eof_end]
            artifact = _write_revision_artifact(evidence_id, original_revision)
            if artifact is not None:
                artifacts.append(artifact)
                evidence.append(
                    EvidenceItem(
                        item_type="text",
                        description="extracted_original_revision",
                        value={
                            "artifact": artifact,
                            "sha256": hashlib.sha256(original_revision).hexdigest(),
                            "size_bytes": len(original_revision),
                        },
                        confidence=0.95,
                    )
                )
            else:
                limitations.append(
                    "The original revision could not be written to the artifact directory."
                )

        if linearized:
            limitations.append(
                "Linearized (fast web view) cross-reference sections are treated as benign unless "
                "additional %%EOF revision boundaries are present."
            )
        if not metadata_found:
            limitations.append(
                "No document Info dictionary was parsed; Producer/Creator/date consistency could "
                "not be assessed."
            )
        if not font_usages:
            limitations.append(
                "No page font resources were parsed; typography consistency could not be assessed."
            )

        summary_parts = [
            (
                f"{revision_count} PDF revisions detected; incremental updates are present."
                if incremental_updates
                else "Single PDF revision detected."
            )
        ]
        if linearized:
            summary_parts.append(
                "The document is linearized; its streaming cross-reference section is not treated "
                "as tampering by itself."
            )
        if suspicious_tools:
            summary_parts.append(
                "Editing software signatures were found in metadata: "
                + ", ".join(suspicious_tools)
                + "."
            )
        if temporal_conflict:
            summary_parts.append(
                "CreationDate and ModDate differ by approximately "
                f"{temporal_gap_days} day(s), which warrants metadata review."
            )
        if font_inconsistency_count:
            summary_parts.append(
                f"{font_inconsistency_count} font usage(s) show mixed embedding or subset "
                "characteristics across pages."
            )
        if invisible_text_streams:
            summary_parts.append(
                "Invisible text rendering mode (3 Tr) was found; compare the text layer against "
                "the rendered page."
            )

        return DetectorResult(
            detector_name=self.name,
            detector_version=self.version,
            category=self.category,
            status="ok",
            score=score,
            confidence=confidence,
            verbal_verdict=_calibrated_verdict(score),
            summary=" ".join(summary_parts),
            evidence=evidence,
            artifacts=artifacts,
            parameters_used=parameters,
            limitations=limitations,
        )


NativePDFDetector = NativePDFForensicsDetector
NativePDFDocumentDetector = NativePDFForensicsDetector
PDFDocumentDetector = NativePDFForensicsDetector
PDFDocumentForensicsDetector = NativePDFForensicsDetector
PDFForensicsDetector = NativePDFForensicsDetector
PDFTamperingDetector = NativePDFForensicsDetector

detector = NativePDFForensicsDetector()
detector_registry.register(detector)

__all__ = [
    "NativePDFDetector",
    "NativePDFDocumentDetector",
    "NativePDFForensicsDetector",
    "PDFDocumentDetector",
    "PDFDocumentForensicsDetector",
    "PDFForensicsDetector",
    "PDFTamperingDetector",
    "detector",
]
