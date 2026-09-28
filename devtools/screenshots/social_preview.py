"""Render the repository's social preview card (1280x640) to .github/social-preview.png.

GitHub shows this image when the repository link is shared. It has no API: upload the
file under Settings > General > Social preview. The card is plain HTML rendered by the
same Chromium the screenshot script uses, then stripped of metadata like the README
screenshots.

    uv run python devtools/screenshots/social_preview.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pngmeta  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / ".github" / "social-preview.png"

HTML = """<!doctype html>
<html><head><meta charset="utf-8"><style>
  * { box-sizing: border-box; margin: 0; }
  body { width: 1280px; height: 640px; background: #0b1220; color: #e8eefc;
         font-family: -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif;
         padding: 64px 72px; position: relative; overflow: hidden; }
  .glow { position: absolute; right: -180px; top: -220px; width: 720px; height: 720px;
          border-radius: 50%; background: radial-gradient(circle, #1d4ed8 0%, #0b1220 68%);
          opacity: .55; }
  h1 { font-size: 112px; letter-spacing: -3px; font-weight: 800; position: relative; }
  h1 span { color: #60a5fa; }
  .tag { font-size: 44px; line-height: 1.2; margin-top: 18px; max-width: 900px;
         color: #cfe0ff; font-weight: 500; position: relative; }
  .flow { position: absolute; left: 72px; right: 72px; bottom: 140px; display: flex;
          align-items: center; gap: 22px; font-size: 27px; font-weight: 600; }
  .box { border: 2px solid #3b82f6; border-radius: 14px; padding: 16px 26px;
         background: #101a30; white-space: nowrap; }
  .box.mid { background: #1d4ed8; border-color: #93c5fd; color: #fff; }
  .arrow { color: #60a5fa; font-size: 34px; }
  .chips { position: absolute; left: 72px; right: 72px; bottom: 56px; display: flex;
           flex-wrap: wrap; gap: 10px; font-size: 20px; color: #9db4de; }
  .chips b { font-weight: 600; border: 1px solid #263a63; border-radius: 999px;
             padding: 6px 15px; background: #0f1a30; white-space: nowrap; }
</style></head><body>
  <div class="glow"></div>
  <h1>pg<span>warden</span></h1>
  <div class="tag">Governed Postgres access for AI assistants</div>
  <div class="flow">
    <div class="box">MCP client</div><div class="arrow">&rarr;</div>
    <div class="box mid">pgwarden gateway</div><div class="arrow">&rarr;</div>
    <div class="box">Postgres, as the person asking</div>
  </div>
  <div class="chips">
    <b>OAuth 2.1 + OIDC</b><b>one role per person</b><b>RLS + masking</b>
    <b>human-approved writes</b><b>hash-chained audit</b>
  </div>
</body></html>"""


def main() -> None:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 640}, device_scale_factor=1)
        page.set_content(HTML)
        png = page.screenshot(type="png")
        browser.close()
    OUTPUT.write_bytes(pngmeta.strip_metadata(png))
    pngmeta.check_clean(OUTPUT.read_bytes())
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
