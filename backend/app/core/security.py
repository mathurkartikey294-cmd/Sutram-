"""
Hostile-input validation for SUTRAM's evidence acquisition boundary.

Forensic WHY: ISO/IEC 27037 requires digital evidence to be identified and
authenticated before it is acquired. Client-supplied file extensions and MIME
headers are attacker-controlled, so SUTRAM classifies media by byte-level
container signatures instead of trusting names. The same boundary caps upload
size and blocks Pillow decompression bombs to prevent memory-exhaustion attacks
from destroying the integrity of an examination. External forensic tools are
invoked with explicit argument vectors and never through a shell.
"""

from __future__ import annotations

import os
import subprocess
import threading
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError

DEFAULT_MAX_UPLOAD_SIZE_MB = 500
DEFAULT_MAX_IMAGE_PIXELS = 89_478_485
HEADER_SIZE = 8192
BYTES_PER_MB = 1024 * 1024


class MediaSecurityError(ValueError):
    """Base class for rejected or unsafe evidence input."""


class EmptyMediaError(MediaSecurityError):
    """Raised when a zero-byte upload reaches the ingest boundary."""


class UnsupportedMediaTypeError(MediaSecurityError):
    """Raised when no approved container signature matches the input."""


class FileSizeLimitExceeded(MediaSecurityError):
    """Raised when an upload exceeds the configured forensic size cap."""


class ImagePixelLimitExceeded(MediaSecurityError):
    """Raised when an image would exceed the decompression-bomb pixel budget."""


class SubprocessExecutionError(RuntimeError):
    """Raised when a forensic subprocess fails, times out, or is missing."""


@dataclass(frozen=True, slots=True)
class MediaType:
    """Authoritative media classification derived from bytes, not filenames."""

    mime_type: str
    extension: str


@dataclass(frozen=True, slots=True)
class MediaValidation:
    """Result of validating a file at the ingest boundary."""

    mime_type: str
    extension: str
    size_bytes: int


_JPEG = MediaType("image/jpeg", ".jpg")
_PNG = MediaType("image/png", ".png")
_GIF = MediaType("image/gif", ".gif")
_BMP = MediaType("image/bmp", ".bmp")
_TIFF = MediaType("image/tiff", ".tif")
_WEBP = MediaType("image/webp", ".webp")
_HEIC = MediaType("image/heic", ".heic")
_AVIF = MediaType("image/avif", ".avif")
_PDF = MediaType("application/pdf", ".pdf")
_WAV = MediaType("audio/wav", ".wav")
_MP3 = MediaType("audio/mpeg", ".mp3")
_FLAC = MediaType("audio/flac", ".flac")
_OGG = MediaType("audio/ogg", ".ogg")
_M4A = MediaType("audio/mp4", ".m4a")
_MP4 = MediaType("video/mp4", ".mp4")
_MOV = MediaType("video/quicktime", ".mov")
_AVI = MediaType("video/x-msvideo", ".avi")
_MKV = MediaType("video/x-matroska", ".mkv")
_WEBM = MediaType("video/webm", ".webm")


def _env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero, got {value}")
    return value


def get_max_upload_size_mb() -> int:
    """Read the operational upload cap from the environment."""

    return _env_positive_int("MAX_UPLOAD_SIZE_MB", DEFAULT_MAX_UPLOAD_SIZE_MB)


def get_max_image_pixels() -> int:
    """Read the decompression-bomb pixel ceiling from the environment."""

    return _env_positive_int("MAX_IMAGE_PIXELS", DEFAULT_MAX_IMAGE_PIXELS)


MAX_UPLOAD_SIZE_MB = get_max_upload_size_mb()
MAX_IMAGE_PIXELS = get_max_image_pixels()
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
_IMAGE_GUARD_LOCK = threading.Lock()


def max_upload_size_bytes() -> int:
    """Return the configured upload cap in bytes."""

    return get_max_upload_size_mb() * BYTES_PER_MB


def identify_media_type(header: bytes) -> MediaType | None:
    """
    Classify media from its leading container bytes.

    The order of checks matters: RIFF containers share a common preamble, while
    ISO base media files place their brand at offset 8 rather than offset 0.
    """

    if not header:
        return None

    if header.startswith(b"\xff\xd8\xff"):
        return _JPEG
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return _PNG
    if header.startswith((b"GIF87a", b"GIF89a")):
        return _GIF
    if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        return _TIFF
    if header.startswith(b"BM"):
        return _BMP
    if header.startswith(b"%PDF-"):
        return _PDF
    if header.startswith(b"fLaC"):
        return _FLAC
    if header.startswith(b"OggS"):
        return _OGG
    if header.startswith(b"ID3"):
        return _MP3

    if len(header) >= 12 and header.startswith(b"RIFF"):
        container = header[8:12]
        if container == b"WEBP":
            return _WEBP
        if container == b"WAVE":
            return _WAV
        if container == b"AVI ":
            return _AVI

    if len(header) >= 12 and header[4:8] == b"ftyp":
        brand = header[8:12]
        if brand == b"qt  ":
            return _MOV
        if brand in (b"M4A ", b"M4B ", b"M4P "):
            return _M4A
        if brand in (b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1"):
            return _HEIC
        if brand in (b"avif", b"avis"):
            return _AVIF
        return _MP4

    if len(header) >= 8 and header[4:8] in (b"moov", b"mdat", b"wide", b"free"):
        return _MOV

    if header.startswith(b"\x1aE\xdf\xa3"):
        if b"webm" in header[:4096]:
            return _WEBM
        return _MKV

    if _looks_like_mpeg_audio(header):
        return _MP3

    return None


def _looks_like_mpeg_audio(header: bytes) -> bool:
    """
    Detect a raw MPEG audio frame without confusing AAC ADTS or JPEG data.

    MPEG audio frames carry an 11-bit sync word and a reserved layer value of
    zero, which distinguishes them from ADTS AAC streams.
    """

    if len(header) < 4:
        return False
    if header[0] != 0xFF or (header[1] & 0xE0) != 0xE0:
        return False
    version = (header[1] >> 3) & 0x03
    layer = (header[1] >> 1) & 0x03
    bitrate_index = (header[2] >> 4) & 0x0F
    sample_rate_index = (header[2] >> 2) & 0x03
    return version != 0x01 and layer != 0x00 and bitrate_index != 0x0F and sample_rate_index != 0x03


def validate_media_header(header: bytes) -> MediaType:
    """Reject an empty or unrecognized container signature immediately."""

    if not header:
        raise EmptyMediaError("Evidence upload is empty")
    media_type = identify_media_type(header)
    if media_type is None:
        preview = header[:16].hex()
        raise UnsupportedMediaTypeError(
            f"Unsupported or spoofed media signature (first bytes: {preview})"
        )
    return media_type


def validate_image_dimensions(
    path: str | os.PathLike[str],
    max_image_pixels: int | None = None,
) -> tuple[int, int] | None:
    """
    Enforce Pillow's decompression-bomb guard without decoding pixel data.

    Image.open reads only the header, so a hostile 100000 x 100000 PNG is
    rejected before any large allocation occurs. The warning path is promoted
    to an exception because forensic ingest must fail closed. If the image
    header is damaged or truncated, Pillow cannot determine dimensions; the
    evidence is still admitted by its magic bytes because ISO/IEC 27037
    requires preserving even partially corrupted exhibits.
    """

    image_path = Path(path)
    limit = max_image_pixels if max_image_pixels is not None else MAX_IMAGE_PIXELS
    if limit <= 0:
        raise ValueError("max_image_pixels must be greater than zero")

    with _IMAGE_GUARD_LOCK:
        previous_limit = Image.MAX_IMAGE_PIXELS
        Image.MAX_IMAGE_PIXELS = limit
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                try:
                    with Image.open(image_path) as image:
                        width, height = image.size
                except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
                    raise ImagePixelLimitExceeded(
                        f"Image exceeds the {limit} pixel decompression-bomb limit"
                    ) from exc
                except (UnidentifiedImageError, OSError, SyntaxError):
                    return None
        finally:
            Image.MAX_IMAGE_PIXELS = previous_limit

    if width * height > limit:
        raise ImagePixelLimitExceeded(
            f"Image dimensions {width}x{height} exceed the {limit} pixel limit"
        )
    return width, height


def validate_media_file(
    path: str | os.PathLike[str],
    *,
    max_size_bytes: int | None = None,
    max_image_pixels: int | None = None,
) -> MediaValidation:
    """Validate a file on disk before it is admitted to the evidence store."""

    media_path = Path(path)
    stat_result = media_path.stat()
    if not media_path.is_file():
        raise MediaSecurityError(f"Evidence path is not a regular file: {media_path}")

    size_bytes = stat_result.st_size
    if size_bytes == 0:
        raise EmptyMediaError("Evidence file is empty")

    limit = max_size_bytes if max_size_bytes is not None else max_upload_size_bytes()
    if limit <= 0:
        raise ValueError("max_size_bytes must be greater than zero")
    if size_bytes > limit:
        raise FileSizeLimitExceeded(
            f"Evidence size {size_bytes} bytes exceeds the {limit} byte limit"
        )

    with media_path.open("rb") as handle:
        header = handle.read(HEADER_SIZE)
    media_type = validate_media_header(header)

    if media_type.mime_type.startswith("image/"):
        validate_image_dimensions(media_path, max_image_pixels)

    return MediaValidation(
        mime_type=media_type.mime_type,
        extension=media_type.extension,
        size_bytes=size_bytes,
    )


def safe_subprocess(
    args: Sequence[str | os.PathLike[str]],
    *,
    timeout: float = 30.0,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Execute an external forensic tool without shell interpretation.

    Arguments are always passed as an argv vector, so filenames containing
    spaces, quotes, ampersands, or shell metacharacters cannot be reinterpreted
    as commands. Failures are normalized into SubprocessExecutionError so a
    missing codec or malformed evidence container cannot crash the API server.
    """

    if isinstance(args, (str, bytes)) or not args:
        raise ValueError("args must be a non-empty argument vector, not a command string")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    argv = [os.fspath(arg) for arg in args]
    try:
        return subprocess.run(
            argv,
            check=True,
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
        )
    except FileNotFoundError as exc:
        raise SubprocessExecutionError(f"Executable not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SubprocessExecutionError(
            f"Executable {argv[0]} timed out after {timeout} seconds"
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise SubprocessExecutionError(
            f"Executable {argv[0]} exited with status {exc.returncode}{detail}"
        ) from exc


detect_media_type = identify_media_type
