"""
RFC 8785 JSON Canonicalization Scheme (JCS) and chain-hash helpers.

Forensic WHY: Under Bharatiya Sakshya Adhiniyam 2023 Section 63, an electronic
record's authenticity depends on reproducible computation. Audit records must
hash to the exact same bytes on every operating system and Python runtime,
regardless of dictionary insertion order, locale, or whitespace. This module
therefore emits a single canonical UTF-8 representation with Unicode
code-point key ordering and then binds each entry to its predecessor by
appending the previous chain hash before taking the SHA-256 digest.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

GENESIS_HASH: str = "0" * 64

_STRING_ESCAPES: dict[str, str] = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def normalize_utc(value: datetime) -> datetime:
    """
    Convert a datetime to UTC, treating naive values as already-UTC.

    The audit log normalizes timestamps before hashing so that the same
    instant produces the same canonical string whether it arrived timezone
    aware or naive from a SQLite DATETIME column.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_string(value: str) -> str:
    """
    Escape only what JSON mandates and emit all other Unicode as raw UTF-8.

    RFC 8785 requires short escapes for the five named control characters and
    lowercase ``\\u00xx`` escapes for the remaining U+0000-U+001F range.
    Non-ASCII text such as Devanagari and non-BMP emoji must pass through
    unmodified to preserve evidentiary content exactly. Lone UTF-16 surrogate
    code points cannot be encoded as UTF-8 and are escaped instead.
    """

    parts: list[str] = ['"']
    for character in value:
        escaped = _STRING_ESCAPES.get(character)
        if escaped is not None:
            parts.append(escaped)
        elif character < " ":
            parts.append(f"\\u{ord(character):04x}")
        elif 0xD800 <= ord(character) <= 0xDFFF:
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _serialize_float(value: float) -> str:
    """
    Serialize a finite float deterministically using Python's shortest repr.

    NaN and infinities are not valid JSON numbers and are rejected so a
    malformed detector payload can never enter the audit chain.
    """

    if not math.isfinite(value):
        raise ValueError(f"Non-finite float is not valid JSON: {value!r}")
    return repr(value)


def _serialize_datetime(value: datetime) -> str:
    normalized = normalize_utc(value)
    return _serialize_string(normalized.isoformat())


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _serialize_float(value)
    if isinstance(value, datetime):
        return _serialize_datetime(value)
    if isinstance(value, Decimal):
        raise ValueError("Decimal values are not valid JSON numbers")
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("bytes-like values are not JSON serializable")
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}")
            items.append((key, item))
        items.sort(key=lambda pair: pair[0])
        body = ",".join(f"{_serialize_string(key)}:{_serialize(item)}" for key, item in items)
        return "{" + body + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    raise TypeError(f"Type {type(value).__name__} is not JSON serializable")


def canonical_json_bytes(data: Any) -> bytes:
    """
    Serialize a JSON-compatible value to RFC 8785 canonical UTF-8 bytes.

    Keys are recursively sorted by Unicode code point, tokens contain no
    whitespace, and no byte-order mark is emitted. Datetimes are converted to
    normalized ISO 8601 UTC strings before escaping.
    """

    return _serialize(data).encode("utf-8")


def canonical_json_hash(data: Any) -> str:
    """Return the lowercase SHA-256 hex digest of canonical_json_bytes(data)."""

    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


def compute_entry_hash(payload: dict[str, Any], prev_hash: str) -> str:
    """
    Bind a canonical audit payload to its predecessor's chain hash.

    The previous hash is appended as UTF-8 text after the canonical JSON so
    even an identical payload produces a different digest at a different chain
    position. This is what makes deletion, reordering, and insertion detectable.
    """

    if not isinstance(prev_hash, str):
        raise TypeError("prev_hash must be a string")
    canonical = canonical_json_bytes(payload)
    return hashlib.sha256(canonical + prev_hash.encode("utf-8")).hexdigest()
