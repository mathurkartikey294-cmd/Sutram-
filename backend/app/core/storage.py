"""
Read-only evidence storage engine for SUTRAM.

Forensic WHY: ISO/IEC 27037 requires that acquired digital evidence is
preserved without alteration. Originals are streamed into the evidence store
while SHA-256 and SHA-512 are computed in the same pass, then locked read-only
(0444 on POSIX, read-only attribute on Windows). Detectors never touch those
originals; they receive ephemeral copies in the working directory. Integrity
verification re-reads the stored original and compares both independent digests
against the values recorded at ingest.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import stat
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from . import security

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CHUNK_SIZE = 1024 * 1024
_SUFFIX_PATTERN = re.compile(r"^\.[A-Za-z0-9]{1,12}$")
_EVIDENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def _store_path_from_env(variable: str, default: Path) -> Path:
    raw = os.getenv(variable)
    if raw is None or not raw.strip():
        return default
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = _REPO_ROOT / candidate
    return candidate.resolve()


ORIGINALS_DIR = _store_path_from_env(
    "EVIDENCE_STORE_PATH", _REPO_ROOT / "evidence_store" / "originals"
)
WORKING_DIR = _store_path_from_env("WORKING_COPY_PATH", _REPO_ROOT / "evidence_store" / "working")


class StorageIntegrityError(RuntimeError):
    """Raised when stored evidence violates a storage invariant."""


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Cryptographic and descriptive metadata produced during ingest."""

    evidence_id: str
    original_path: Path
    mime_type: str
    extension: str
    size_bytes: int
    sha256: str
    sha512: str


def validate_evidence_id(evidence_id: str) -> str:
    """
    Restrict evidence identifiers to inert filesystem-safe tokens.

    Evidence identifiers become filename stems inside the originals directory,
    so path separators, traversal segments, and Windows device names must be
    rejected before any filesystem operation occurs.
    """

    if not isinstance(evidence_id, str) or not _EVIDENCE_ID_PATTERN.fullmatch(evidence_id):
        raise ValueError(f"Invalid evidence identifier: {evidence_id!r}")
    if evidence_id in {".", ".."}:
        raise ValueError(f"Invalid evidence identifier: {evidence_id!r}")
    if evidence_id.split(".", 1)[0].lower() in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Reserved evidence identifier: {evidence_id!r}")
    return evidence_id


def _normalize_suffix(suffix: str) -> str:
    normalized = suffix if suffix.startswith(".") else f".{suffix}"
    if not _SUFFIX_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid working-copy suffix: {suffix!r}")
    return normalized


def compute_file_hashes(
    path: str | os.PathLike[str],
    *,
    chunk_size: int = _CHUNK_SIZE,
) -> tuple[str, str]:
    """Return the SHA-256 and SHA-512 digests of a file in one streaming pass."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()


def compute_hashes(
    path: str | os.PathLike[str],
    *,
    chunk_size: int = _CHUNK_SIZE,
) -> tuple[str, str]:
    """Backward-compatible alias for compute_file_hashes."""

    return compute_file_hashes(path, chunk_size=chunk_size)


def _read_header(stream: BinaryIO) -> bytes:
    chunks: list[bytes] = []
    remaining = security.HEADER_SIZE
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _prepare_stream(stream: BinaryIO) -> bool:
    try:
        if stream.seekable():
            stream.seek(0)
            return True
    except (AttributeError, OSError):
        return False
    return False


def _stream_chunks(stream: BinaryIO, header: bytes, seekable: bool) -> Iterator[bytes]:
    if seekable:
        yield from iter(lambda: stream.read(_CHUNK_SIZE), b"")
        return
    yield header
    yield from iter(lambda: stream.read(_CHUNK_SIZE), b"")


class EvidenceStorage:
    """Filesystem-backed evidence store with read-only originals."""

    def __init__(
        self,
        originals_dir: str | os.PathLike[str] | None = None,
        working_dir: str | os.PathLike[str] | None = None,
        *,
        max_upload_size_mb: int | None = None,
        max_upload_size_bytes: int | None = None,
        max_image_pixels: int | None = None,
    ) -> None:
        if max_upload_size_mb is not None and max_upload_size_bytes is not None:
            raise ValueError("Specify max_upload_size_mb or max_upload_size_bytes, not both")

        self.originals_dir = (
            Path(originals_dir).expanduser() if originals_dir is not None else ORIGINALS_DIR
        )
        self.working_dir = (
            Path(working_dir).expanduser() if working_dir is not None else WORKING_DIR
        )

        if max_upload_size_bytes is not None:
            if max_upload_size_bytes <= 0:
                raise ValueError("max_upload_size_bytes must be greater than zero")
            self.max_upload_size_bytes = max_upload_size_bytes
        else:
            size_mb = (
                max_upload_size_mb
                if max_upload_size_mb is not None
                else security.get_max_upload_size_mb()
            )
            if size_mb <= 0:
                raise ValueError("max_upload_size_mb must be greater than zero")
            self.max_upload_size_bytes = size_mb * security.BYTES_PER_MB

        pixel_limit = (
            max_image_pixels if max_image_pixels is not None else security.get_max_image_pixels()
        )
        if pixel_limit <= 0:
            raise ValueError("max_image_pixels must be greater than zero")
        self.max_image_pixels = pixel_limit

        self.ensure_directories()

    def ensure_directories(self) -> None:
        """Create the originals and working directories when missing."""

        self.originals_dir.mkdir(parents=True, exist_ok=True)
        self.working_dir.mkdir(parents=True, exist_ok=True)

    def find_original(self, evidence_id: str) -> Path | None:
        """Locate the single stored original belonging to an evidence identifier."""

        validated_id = validate_evidence_id(evidence_id)
        candidates = [
            candidate
            for candidate in self.originals_dir.glob(f"{validated_id}.*")
            if candidate.is_file()
            and not candidate.name.endswith(".partial")
            and candidate.name.rsplit(".", 1)[0] == validated_id
        ]
        if not candidates:
            return None
        if len(candidates) > 1:
            raise StorageIntegrityError(
                f"Multiple originals found for evidence {validated_id}: "
                + ", ".join(candidate.name for candidate in candidates)
            )
        return candidates[0]

    def store_original(
        self,
        source: str | os.PathLike[str] | BinaryIO,
        evidence_id: str,
    ) -> IngestResult:
        """Dispatch ingest from a filesystem path or a binary stream."""

        if isinstance(source, (str, os.PathLike)):
            return self.ingest_file(source, evidence_id)
        return self.ingest_stream(source, evidence_id)

    def ingest_file(
        self,
        source_path: str | os.PathLike[str],
        evidence_id: str,
    ) -> IngestResult:
        """Validate a file on disk, then copy it into the read-only store."""

        media_path = Path(source_path)
        security.validate_media_file(
            media_path,
            max_size_bytes=self.max_upload_size_bytes,
            max_image_pixels=self.max_image_pixels,
        )
        with media_path.open("rb") as stream:
            return self._store_stream(stream, evidence_id)

    def ingest_stream(self, stream: BinaryIO, evidence_id: str) -> IngestResult:
        """Ingest an upload stream, hashing and size-checking as bytes arrive."""

        return self._store_stream(stream, evidence_id)

    def _store_stream(self, stream: BinaryIO, evidence_id: str) -> IngestResult:
        validated_id = validate_evidence_id(evidence_id)
        self.ensure_directories()

        header = _read_header(stream)
        media_type = security.validate_media_header(header)
        target = self.originals_dir / f"{validated_id}{media_type.extension}"
        if target.exists():
            raise FileExistsError(f"Evidence already exists: {target.name}")

        seekable = _prepare_stream(stream)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{validated_id}-",
            suffix=".partial",
            dir=self.originals_dir,
        )
        temporary_path = Path(temporary_name)

        try:
            sha256_hex, sha512_hex, size_bytes = self._write_stream(
                stream, descriptor, header, seekable
            )
            if media_type.mime_type.startswith("image/"):
                security.validate_image_dimensions(temporary_path, self.max_image_pixels)
            if target.exists():
                raise FileExistsError(f"Evidence already exists: {target.name}")
            os.replace(temporary_path, target)
        except Exception:
            _remove_file(temporary_path)
            raise

        try:
            _lock_read_only(target)
        except Exception:
            _remove_file(target)
            raise

        return IngestResult(
            evidence_id=validated_id,
            original_path=target,
            mime_type=media_type.mime_type,
            extension=media_type.extension,
            size_bytes=size_bytes,
            sha256=sha256_hex,
            sha512=sha512_hex,
        )

    def _write_stream(
        self,
        stream: BinaryIO,
        descriptor: int,
        header: bytes,
        seekable: bool,
    ) -> tuple[str, str, int]:
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        size_bytes = 0

        with os.fdopen(descriptor, "wb") as destination:
            for chunk in _stream_chunks(stream, header, seekable):
                if not chunk:
                    continue
                size_bytes += len(chunk)
                if size_bytes > self.max_upload_size_bytes:
                    raise security.FileSizeLimitExceeded(
                        f"Evidence exceeds the {self.max_upload_size_bytes} byte limit"
                    )
                sha256.update(chunk)
                sha512.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())

        return sha256.hexdigest(), sha512.hexdigest(), size_bytes

    def create_working_copy(
        self,
        evidence_id: str,
        analysis_id: str | None = None,
        *,
        suffix: str | None = None,
    ) -> Path:
        """
        Duplicate an original into working/ for detector pipelines.

        Working copies are intentionally writable because decoders, resampling,
        and audio filtering mutate their inputs. The original is only ever
        opened for reading.
        """

        original = self.find_original(evidence_id)
        if original is None:
            raise FileNotFoundError(f"No stored original for evidence {evidence_id!r}")

        copy_name = (
            validate_evidence_id(analysis_id)
            if analysis_id is not None
            else f"{validate_evidence_id(evidence_id)}_{uuid.uuid4().hex}"
        )
        extension = _normalize_suffix(suffix) if suffix is not None else original.suffix
        destination = self.working_dir / f"{copy_name}{extension}"
        if destination.exists():
            raise FileExistsError(f"Working copy already exists: {destination.name}")

        self.working_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        os.chmod(destination, stat.S_IREAD | stat.S_IWRITE)
        return destination

    def cleanup_working_copy(self, copy_path: str | os.PathLike[str]) -> bool:
        """
        Safely remove an ephemeral working copy from the working directory.

        Forensic WHY: ISO/IEC 27037 dictates that temporary analysis artifacts
        must be strictly controlled. Before deletion, the path is checked to
        ensure it is strictly contained within the designated working directory.
        Original evidence files can never be removed via this path.
        """

        path = Path(copy_path).resolve()
        try:
            path.relative_to(self.working_dir.resolve())
        except ValueError:
            raise ValueError(f"Target path is outside working directory: {path}") from None

        if path.is_file():
            _remove_file(path)
            return True
        return False

    def verify_original_integrity(
        self,
        evidence_id: str,
        original_sha256: str,
        original_sha512: str,
    ) -> bool:
        """
        Recompute both digests from the stored original and compare them.

        A mismatch in either algorithm means the bytes changed after ingest.
        Both comparisons are performed in constant time to avoid side channels.
        """

        if not isinstance(original_sha256, str) or not isinstance(original_sha512, str):
            return False
        if not original_sha256.strip() or not original_sha512.strip():
            return False

        try:
            original = self.find_original(evidence_id)
        except (OSError, StorageIntegrityError, ValueError):
            return False
        if original is None:
            return False

        try:
            sha256_hex, sha512_hex = compute_file_hashes(original)
        except OSError:
            return False

        return hmac.compare_digest(
            sha256_hex, original_sha256.strip().lower()
        ) and hmac.compare_digest(sha512_hex, original_sha512.strip().lower())


def _remove_file(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IWRITE if os.name == "nt" else 0o644)
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _lock_read_only(path: Path) -> None:
    os.chmod(path, stat.S_IREAD if os.name == "nt" else 0o444)
    mode = path.stat().st_mode
    if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise StorageIntegrityError(f"Failed to make evidence read-only: {path}")


_default_storage: EvidenceStorage | None = None


def get_default_storage() -> EvidenceStorage:
    """Return the process-wide storage engine configured from the environment."""

    global _default_storage
    if _default_storage is None:
        _default_storage = EvidenceStorage()
    return _default_storage


def ingest_evidence(
    source: str | os.PathLike[str] | BinaryIO,
    evidence_id: str,
    *,
    storage: EvidenceStorage | None = None,
) -> IngestResult:
    """Module-level ingest helper using the default or supplied storage engine."""

    return (storage or get_default_storage()).store_original(source, evidence_id)


def store_original(
    source: str | os.PathLike[str] | BinaryIO,
    evidence_id: str,
    *,
    storage: EvidenceStorage | None = None,
) -> IngestResult:
    """Alias for ingest_evidence."""

    return ingest_evidence(source, evidence_id, storage=storage)


def ingest_file(
    source_path: str | os.PathLike[str],
    evidence_id: str,
    *,
    storage: EvidenceStorage | None = None,
) -> IngestResult:
    """Module-level filesystem ingest helper."""

    return (storage or get_default_storage()).ingest_file(source_path, evidence_id)


def ingest_stream(
    stream: BinaryIO,
    evidence_id: str,
    *,
    storage: EvidenceStorage | None = None,
) -> IngestResult:
    """Module-level binary-stream ingest helper."""

    return (storage or get_default_storage()).ingest_stream(stream, evidence_id)


def create_working_copy(
    evidence_id: str,
    analysis_id: str | None = None,
    *,
    suffix: str | None = None,
    storage: EvidenceStorage | None = None,
) -> Path:
    """Module-level working-copy helper using the default or supplied engine."""

    return (storage or get_default_storage()).create_working_copy(
        evidence_id, analysis_id, suffix=suffix
    )


def cleanup_working_copy(
    copy_path: str | os.PathLike[str],
    *,
    storage: EvidenceStorage | None = None,
) -> bool:
    """Module-level cleanup helper using the default or supplied engine."""

    return (storage or get_default_storage()).cleanup_working_copy(copy_path)


def verify_original_integrity(
    evidence_id: str,
    original_sha256: str,
    original_sha512: str,
    *,
    storage: EvidenceStorage | None = None,
) -> bool:
    """Module-level integrity helper using the default or supplied engine."""

    return (storage or get_default_storage()).verify_original_integrity(
        evidence_id, original_sha256, original_sha512
    )


StorageEngine = EvidenceStorage
