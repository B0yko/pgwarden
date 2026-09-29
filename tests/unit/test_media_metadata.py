"""The README screenshots carry no metadata (no PNG text chunks, EXIF, time or ICC)."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("PIL")

REPO_ROOT = Path(__file__).parent.parent.parent
MEDIA = REPO_ROOT / "docs" / "media"
sys.path.insert(0, str(REPO_ROOT / "devtools" / "screenshots"))

from PIL import Image  # noqa: E402
from PIL.PngImagePlugin import PngInfo  # noqa: E402

import pngmeta  # noqa: E402  (devtools/screenshots/pngmeta.py, not part of the wheel)


def _png_with_metadata() -> bytes:
    info = PngInfo()
    info.add_text("Software", "some-tool 1.0")
    info.add_itxt("Comment", "written on my laptop")
    exif = Image.Exif()
    exif[0x0131] = "some-tool"  # Software
    out = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 20, 30)).save(out, format="PNG", pnginfo=info, exif=exif)
    return out.getvalue()


def test_check_flags_text_and_exif_chunks() -> None:
    dirty = _png_with_metadata()
    types = pngmeta.chunk_types(dirty)
    assert {"tEXt", "iTXt", "eXIf"} <= set(types)
    with pytest.raises(AssertionError, match="metadata chunks present"):
        pngmeta.check_clean(dirty)


def test_strip_metadata_rebuilds_from_pixels() -> None:
    clean = pngmeta.strip_metadata(_png_with_metadata())
    pngmeta.check_clean(clean)
    assert set(pngmeta.chunk_types(clean)) <= {"IHDR", "IDAT", "IEND"}
    with Image.open(io.BytesIO(clean)) as image:
        assert image.size == (8, 8)
        assert image.convert("RGB").getpixel((0, 0)) == (10, 20, 30)


def test_committed_screenshots_are_clean_and_referenced() -> None:
    files = sorted(MEDIA.glob("*.png"))
    assert files, "docs/media has no screenshots; run devtools/screenshots/run.py"
    for path in files:
        types = pngmeta.check_file(path)
        assert not {"tEXt", "zTXt", "iTXt", "eXIf"} & set(types), path.name
        with Image.open(path) as image:
            assert image.size == (1440, 900), f"{path.name}: not the fixed viewport"
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(re.findall(r"docs/media/([\w.-]+\.png)", readme))
    assert referenced == {p.name for p in files}, "README and docs/media disagree"


def test_brand_images_are_clean_and_referenced() -> None:
    assets = REPO_ROOT / "docs" / "assets"
    banners = sorted(assets.glob("banner-*.png"))
    assert {p.name for p in banners} == {"banner-dark.png", "banner-light.png"}
    for path in [*banners, REPO_ROOT / ".github" / "social-preview.png"]:
        types = pngmeta.check_file(path)
        assert not {"tEXt", "zTXt", "iTXt", "eXIf"} & set(types), path.name
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/assets/banner-dark.png" in readme and "docs/assets/banner-light.png" in readme
    with Image.open(REPO_ROOT / ".github" / "social-preview.png") as image:
        assert image.size == (1280, 640)
