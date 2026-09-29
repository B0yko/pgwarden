"""Strip and verify PNG metadata so the committed screenshots identify nothing.

`strip_metadata` rebuilds the image from its raw pixels (a fresh Pillow image carries
no `info`, EXIF or ICC profile) and saves it with the default encoder, which writes
only IHDR, IDAT and IEND. `chunk_types` and `check_clean` read the file's chunk list
directly, so the check does not depend on the library that wrote it.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

from PIL import Image

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Chunks that can carry text, timestamps, EXIF or a colour profile naming a device or
# program. Anything outside the allow-list below is reported too.
FORBIDDEN_CHUNKS = frozenset({"tEXt", "zTXt", "iTXt", "eXIf", "tIME", "iCCP"})
ALLOWED_CHUNKS = frozenset({"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "sRGB", "gAMA", "pHYs"})


def chunk_types(data: bytes) -> list[str]:
    """The chunk types of a PNG, in file order."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG file")
    types: list[str] = []
    pos = len(PNG_SIGNATURE)
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos : pos + 8])
        types.append(kind.decode("ascii"))
        pos += 8 + length + 4  # header, payload, CRC
    return types


def strip_metadata(png: bytes, *, keep_alpha: bool = False) -> bytes:
    """Re-encode `png` from its pixels alone (RGB, or RGBA with `keep_alpha`)."""
    mode = "RGBA" if keep_alpha else "RGB"
    with Image.open(io.BytesIO(png)) as source:
        pixels = source.convert(mode)
        clean = Image.frombytes(mode, pixels.size, pixels.tobytes())
    out = io.BytesIO()
    clean.save(out, format="PNG", optimize=True)
    return out.getvalue()


def check_clean(data: bytes, *, label: str = "png") -> None:
    """Raise AssertionError if the PNG has text/EXIF chunks or any unexpected chunk."""
    types = chunk_types(data)
    bad = [t for t in types if t in FORBIDDEN_CHUNKS]
    assert not bad, f"{label}: metadata chunks present: {bad}"
    extra = [t for t in types if t not in ALLOWED_CHUNKS]
    assert not extra, f"{label}: unexpected chunks: {extra}"
    with Image.open(io.BytesIO(data)) as image:
        assert not image.info.get("exif"), f"{label}: EXIF data present"
        text = {k: v for k, v in image.info.items() if k in ("Software", "Comment", "Author")}
        assert not text, f"{label}: text metadata present: {sorted(text)}"


def check_file(path: Path) -> list[str]:
    data = path.read_bytes()
    check_clean(data, label=path.name)
    return chunk_types(data)
