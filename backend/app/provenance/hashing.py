"""Multi‑hash calculation engine for SUTRAM.

Provides fast cryptographic hashes (SHA‑256 / SHA‑512) in a streaming fashion,
perceptual image hashes (phash, dhash, aHash, whash) via the **imagehash**
library, and a Hamming‑distance helper.

All functions are fully type‑annotated and safe for use in a forensic pipeline
(MUST NOT use ``shell=True``, never load the whole file into memory).
"""

import hashlib
from pathlib import Path
from typing import Any

import imagehash
from PIL import Image

# ---------------------------------------------------------------------------
# Cryptographic hashes (streamed, 1 MiB chunks)
# ---------------------------------------------------------------------------


def compute_cryptographic_hashes(file_path: Path) -> dict[str, str]:
    """Compute SHA‑256 and SHA‑512 hashes of *file_path* using 1 MiB chunks.

    The file is never fully loaded into memory; each chunk is read, hashed,
    and discarded.  Returns a dictionary with lowercase hex strings.

    Parameters
    ----------
    file_path:
        Path to the file to hash.  Must exist and be readable.

    Returns
    -------
    dict[str, str]
        ``{"sha256": "<hex>", "sha512": "<hex>"}``.
    """
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(1_048_576)  # 1 MiB
            if not chunk:
                break
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


# ---------------------------------------------------------------------------
# Perceptual image hashes
# ---------------------------------------------------------------------------


def _load_image_rgb(image_path: Path) -> Image.Image | None:
    """Try to open *image_path* as an image and convert it to RGB.

    Returns ``None`` if the file cannot be opened or is not a supported
    image format.  No exceptions are propagated to the caller.
    """
    try:
        img = Image.open(image_path)
        # Pillow may give us Palette, RGBA, CMYK, etc.
        # Convert to RGB for consistent perceptual hashing.
        rgb_img = img.convert("RGB")
        return rgb_img
    except Exception:  # pylint: disable=bare-except
        return None


def compute_perceptual_hashes(image_path: Path) -> dict[str, str] | None:
    """Compute four perceptual hashes for *image_path*.

    Returns a dictionary with the lowercase hex strings of each hash:

    * ``phash``  – 64‑bit perceptual hash
    * ``dhash``  – 64‑bit difference hash
    * ``ahash``  – 64‑bit average hash
    * ``whash``  – 64‑bit wavelet hash

    If *image_path* is not a decodable image (e.g. PDF, audio, video) or
    cannot be opened, ``None`` is returned **without raising**.

    Parameters
    ----------
    image_path:
        Path to an image file (JPEG, PNG, WEBP, BMP, TIFF…).

    Returns
    -------
    dict[str, str] | None
        ``{
            "phash": "<hex>",
            "dhash": "<hex>",
            "ahash": "<hex>",
            "whash": "<hex>",
        }`` or ``None``.
    """
    img = _load_image_rgb(image_path)
    if img is None:
        return None

    try:
        phash_val = imagehash.phash(img)
        dhash_val = imagehash.dhash(img)
        ahash_val = imagehash.average_hash(img)
        whash_val = imagehash.whash(img)
    except Exception:  # pylint: disable=bare-except
        return None

    # imagehash returns an ``ImageHash`` object; its ``__str__`` is the lowercase hex string.
    return {
        "phash": str(phash_val).lower(),
        "dhash": str(dhash_val).lower(),
        "ahash": str(ahash_val).lower(),
        "whash": str(whash_val).lower(),
    }


# ---------------------------------------------------------------------------
# Hamming distance
# ---------------------------------------------------------------------------


def hamming_distance(hash1: str, hash2: str) -> int:
    """Return the bit‑level Hamming distance between two hex‑encoded hashes.

    Both strings must be the same length (even number of hex characters).
    The function performs the comparison using XOR on the integer values,
    which is effectively a constant‑time operation for the purpose of forensic
    scoring (the result itself is small and deterministic).

    Parameters
    ----------
    hash1:
        Hex string of the first hash (e.g. a SHA‑256 hex or an image‑hash).
    hash2:
        Hex string of the second hash, same length as *hash1*.

    Returns
    -------
    int
        Number of differing bits (0 – len*8).
    """
    if len(hash1) != len(hash2):
        raise ValueError("Hash strings must have equal length")
    a = int(hash1, 16)
    b = int(hash2, 16)
    xored = a ^ b
    # Python 3.8+ provides int.bit_count(); fall back to bin count for safety.
    return xored.bit_count() if hasattr(xored, "bit_count") else bin(xored).count("1")


# ---------------------------------------------------------------------------
# Combined helper
# ---------------------------------------------------------------------------


def compute_all_hashes(
    file_path: Path,
    mime_type: str | None = None,
) -> dict[str, Any]:
    """Convenience wrapper that returns *both* cryptographic and perceptual hashes.

    *Cryptographic* hashes (SHA‑256 / SHA‑512) are always computed.
    *Perceptual* hashes are added only when the file type is recognised as an
    image (the check is based on *mime_type* or, if *mime_type* is ``None``,
    on the file extension).

    Parameters
    ----------
    file_path:
        Path to the file to analyse.
    mime_type:
        Optional MIME type string (``"image/jpeg"``, ``"image/png"``, etc.).
        If ``None`` the function falls back to checking the suffix.

    Returns
    -------
    dict[str, Any]
        A dictionary containing:

        * ``"sha256"`` – hex string
        * ``"sha512"`` – hex string
        * ``"phash"`` – (optional) hex perceptual hash – present when the file
          is recognised as an image.
        * ``"dhash"`` – same.
        * ``"ahash"`` – same.
        * ``"whash"`` – same.
        * ``"mime_type"`` – the MIME type that was used, if known.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist.
    """
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    crypto: dict[str, str] = compute_cryptographic_hashes(file_path)

    result: dict[str, Any] = {
        "sha256": crypto["sha256"],
        "sha512": crypto["sha512"],
        "mime_type": mime_type,
    }

    # Determine whether we should attempt perceptual hashing.
    is_image = False
    if mime_type is not None:
        is_image = mime_type.startswith("image/")
    else:
        # Fallback to extension check.
        suffix = file_path.suffix.lower()
        is_image = suffix in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff"}

    if is_image:
        perc = compute_perceptual_hashes(file_path)
        if perc is not None:
            result.update(perc)  # type: ignore[arg-type]

    return result
