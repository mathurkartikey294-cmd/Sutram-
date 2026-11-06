"""
Unit tests for SUTRAM's read-only evidence ingest and integrity engine.

These tests exercise the ISO/IEC 27037 invariants that justify admitting media
into an investigation: magic-byte authentication, dual-hash accuracy, immutable
originals, isolated working copies, and tamper detection on re-verification.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from PIL import Image

try:
    from app.core import security, storage
    from app.core.storage import EvidenceStorage
except ImportError:
    from backend.app.core import security, storage
    from backend.app.core.storage import EvidenceStorage


def _png_bytes(size: tuple[int, int] = (64, 64)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, color=(12, 34, 56)).save(buffer, format="PNG")
    return buffer.getvalue()


def _png_size_bytes(width: int, height: int) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), color=(200, 10, 10)).save(buffer, format="PNG")
    return buffer.getvalue()


def _make_writable(path: Path) -> None:
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[EvidenceStorage]:
    instance = EvidenceStorage(
        originals_dir=tmp_path / "originals",
        working_dir=tmp_path / "working",
    )
    yield instance
    for path in tmp_path.rglob("*"):
        if path.is_file():
            try:
                _make_writable(path)
            except OSError:
                pass


def test_magic_bytes_are_authoritative_over_extension(
    engine: EvidenceStorage, tmp_path: Path
) -> None:
    disguised = tmp_path / "submitted-as-jpeg.jpg"
    payload = _png_bytes()
    disguised.write_bytes(payload)

    result = engine.ingest_file(disguised, "ev-magic")

    assert result.mime_type == "image/png"
    assert result.extension == ".png"
    assert result.original_path.name == "ev-magic.png"
    assert result.original_path.read_bytes() == payload


def test_unsupported_signature_is_rejected(engine: EvidenceStorage, tmp_path: Path) -> None:
    fake = tmp_path / "malware.jpg"
    fake.write_bytes(b"MZ" + b"\x00" * 128)

    with pytest.raises(security.UnsupportedMediaTypeError):
        engine.ingest_file(fake, "ev-bad")

    assert [path for path in engine.originals_dir.iterdir() if path.is_file()] == []


def test_truncated_image_with_valid_magic_is_preserved(engine: EvidenceStorage) -> None:
    payload = b"\x89PNG\r\n\x1a\n" + b"truncated evidence bytes"

    result = engine.ingest_stream(io.BytesIO(payload), "ev-damaged")

    assert result.mime_type == "image/png"
    assert result.original_path.read_bytes() == payload
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_path_traversal_evidence_id_is_rejected(engine: EvidenceStorage) -> None:
    with pytest.raises(ValueError):
        engine.ingest_stream(io.BytesIO(_png_bytes()), "../escape")
    with pytest.raises(ValueError):
        engine.ingest_stream(io.BytesIO(_png_bytes()), "nested/evidence")

    assert [path for path in engine.originals_dir.iterdir() if path.is_file()] == []


@pytest.mark.parametrize(
    ("header", "mime_type"),
    [
        (b"%PDF-1.7\n", "application/pdf"),
        (b"RIFF\x24\x00\x00\x00WAVEfmt ", "audio/wav"),
        (b"\x00\x00\x00\x18ftypisom", "video/mp4"),
        (b"\x00\x00\x00\x18ftypqt  ", "video/quicktime"),
        (b"ID3\x04\x00\x00", "audio/mpeg"),
        (b"fLaC\x00\x00\x00\x22", "audio/flac"),
    ],
)
def test_container_signature_detection(header: bytes, mime_type: str) -> None:
    media_type = security.identify_media_type(header)

    assert media_type is not None
    assert media_type.mime_type == mime_type


def test_size_limit_is_enforced_during_stream_write(tmp_path: Path) -> None:
    guarded = EvidenceStorage(
        originals_dir=tmp_path / "originals",
        working_dir=tmp_path / "working",
        max_upload_size_bytes=1024,
    )
    oversized = _png_bytes() + b"\x00" * 4096

    with pytest.raises(security.FileSizeLimitExceeded):
        guarded.ingest_stream(io.BytesIO(oversized), "ev-oversized")

    assert [path for path in guarded.originals_dir.iterdir() if path.is_file()] == []


def test_size_limit_is_enforced_before_filesystem_copy(tmp_path: Path) -> None:
    source = tmp_path / "oversized.png"
    source.write_bytes(_png_bytes() + b"\x00" * 4096)

    with pytest.raises(security.FileSizeLimitExceeded):
        security.validate_media_file(source, max_size_bytes=1024)

    with pytest.raises(security.FileSizeLimitExceeded):
        EvidenceStorage(
            originals_dir=tmp_path / "originals",
            working_dir=tmp_path / "working",
            max_upload_size_bytes=1024,
        ).ingest_file(source, "ev-oversized-file")


def test_ingest_refuses_to_overwrite_an_existing_original(engine: EvidenceStorage) -> None:
    first_payload = _png_bytes()
    first = engine.ingest_stream(io.BytesIO(first_payload), "ev-immutable")

    with pytest.raises(FileExistsError):
        engine.ingest_stream(io.BytesIO(_png_size_bytes(96, 96)), "ev-immutable")

    assert first.original_path.read_bytes() == first_payload
    assert engine.verify_original_integrity("ev-immutable", first.sha256, first.sha512)


def test_dual_hash_computation_matches_hashlib(engine: EvidenceStorage) -> None:
    payload = _png_bytes((80, 60))

    result = engine.ingest_stream(io.BytesIO(payload), "ev-hash")

    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.sha512 == hashlib.sha512(payload).hexdigest()
    assert result.size_bytes == len(payload)
    assert storage.compute_file_hashes(result.original_path) == (
        result.sha256,
        result.sha512,
    )


def test_original_file_is_locked_against_writes(engine: EvidenceStorage) -> None:
    result = engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-locked")
    mode = result.original_path.stat().st_mode

    assert mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can bypass POSIX read-only permission bits")

    with pytest.raises(PermissionError):
        result.original_path.open("r+b")
    with pytest.raises(PermissionError):
        result.original_path.open("wb")


def test_create_working_copy_is_writable_and_isolated(engine: EvidenceStorage) -> None:
    payload = _png_bytes()
    result = engine.ingest_stream(io.BytesIO(payload), "ev-work")

    copy_path = engine.create_working_copy("ev-work", analysis_id="analysis-42")

    assert copy_path == engine.working_dir / "analysis-42.png"
    assert copy_path.read_bytes() == payload
    assert copy_path != result.original_path
    assert copy_path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    with copy_path.open("ab") as handle:
        handle.write(b"detector mutation")

    assert result.original_path.read_bytes() == payload
    assert engine.verify_original_integrity("ev-work", result.sha256, result.sha512)


def test_create_working_copy_generates_unique_name(engine: EvidenceStorage) -> None:
    engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-unique")

    first_copy = engine.create_working_copy("ev-unique")
    second_copy = engine.create_working_copy("ev-unique")

    assert first_copy.name.startswith("ev-unique_")
    assert second_copy.name.startswith("ev-unique_")
    assert first_copy != second_copy
    assert first_copy.exists()
    assert second_copy.exists()


def test_integrity_verification_matching_digests(engine: EvidenceStorage) -> None:
    result = engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-verify")

    assert engine.verify_original_integrity("ev-verify", result.sha256, result.sha512)
    assert not engine.verify_original_integrity("ev-verify", "0" * 64, result.sha512)
    assert not engine.verify_original_integrity("ev-verify", result.sha256, "0" * 128)
    assert not engine.verify_original_integrity("ev-missing", result.sha256, result.sha512)


def test_integrity_verification_detects_tampered_original(engine: EvidenceStorage) -> None:
    result = engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-tampered")
    assert engine.verify_original_integrity("ev-tampered", result.sha256, result.sha512)

    _make_writable(result.original_path)
    with result.original_path.open("r+b") as handle:
        first_byte = handle.read(1)
        handle.seek(0)
        handle.write(bytes([first_byte[0] ^ 0xFF]))

    os.chmod(result.original_path, stat.S_IREAD)

    assert not engine.verify_original_integrity("ev-tampered", result.sha256, result.sha512)


def test_decompression_bomb_is_rejected_before_copy(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.png"
    bomb.write_bytes(_png_size_bytes(128, 128))

    guarded = EvidenceStorage(
        originals_dir=tmp_path / "originals",
        working_dir=tmp_path / "working",
        max_image_pixels=1000,
    )

    with pytest.raises(security.ImagePixelLimitExceeded):
        security.validate_media_file(bomb, max_image_pixels=1000)

    with pytest.raises(security.ImagePixelLimitExceeded):
        guarded.ingest_stream(io.BytesIO(bomb.read_bytes()), "ev-bomb")

    assert [path for path in guarded.originals_dir.iterdir() if path.is_file()] == []


def test_module_level_helpers_accept_storage_engine(engine: EvidenceStorage) -> None:
    payload = _png_bytes()

    result = storage.ingest_evidence(io.BytesIO(payload), "ev-wrapper", storage=engine)
    copy_path = storage.create_working_copy("ev-wrapper", storage=engine)

    assert copy_path.read_bytes() == payload
    assert storage.verify_original_integrity(
        "ev-wrapper",
        result.sha256,
        result.sha512,
        storage=engine,
    )


def test_safe_subprocess_uses_argument_vector_not_shell() -> None:
    completed = security.safe_subprocess([sys.executable, "-c", "print('sutram-ok')"])
    assert completed.stdout.strip() == "sutram-ok"

    with pytest.raises(ValueError):
        security.safe_subprocess("echo hacked")  # type: ignore[arg-type]

    with pytest.raises(security.SubprocessExecutionError):
        security.safe_subprocess(["_sutram_missing_executable_"])

    with pytest.raises(security.SubprocessExecutionError):
        security.safe_subprocess([sys.executable, "-c", "raise SystemExit(7)"])


def test_find_original_does_not_collide_on_prefix(engine: EvidenceStorage) -> None:
    engine.ingest_stream(io.BytesIO(_png_bytes()), "item")
    engine.ingest_stream(io.BytesIO(_png_bytes((32, 32))), "item.1")

    orig_item = engine.find_original("item")
    orig_item_1 = engine.find_original("item.1")

    assert orig_item is not None and orig_item.name == "item.png"
    assert orig_item_1 is not None and orig_item_1.name == "item.1.png"


def test_cleanup_working_copy_success_and_traversal_guard(engine: EvidenceStorage) -> None:
    res = engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-clean")
    working_copy = engine.create_working_copy("ev-clean")
    assert working_copy.exists()

    # Success cleanup
    assert engine.cleanup_working_copy(working_copy)
    assert not working_copy.exists()

    # Deleting outside working_dir is forbidden
    with pytest.raises(ValueError, match="outside working directory"):
        engine.cleanup_working_copy(res.original_path)

    # Calling module-level cleanup helper
    new_copy = engine.create_working_copy("ev-clean")
    assert storage.cleanup_working_copy(new_copy, storage=engine)
    assert not new_copy.exists()


def test_working_copy_suffix_normalizes_dot(engine: EvidenceStorage) -> None:
    engine.ingest_stream(io.BytesIO(_png_bytes()), "ev-suffix")
    copy_without_dot = engine.create_working_copy("ev-suffix", suffix="png")
    assert copy_without_dot.suffix == ".png"
    assert copy_without_dot.exists()


@pytest.mark.parametrize(
    ("header", "expected_mime"),
    [
        (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00", "image/heic"),
        (b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00", "image/avif"),
        (b"\x00\x00\x00\x14moov\x00\x00\x00\x00", "video/quicktime"),
    ],
)
def test_extended_container_signatures(header: bytes, expected_mime: str) -> None:
    media_type = security.identify_media_type(header)
    assert media_type is not None
    assert media_type.mime_type == expected_mime
