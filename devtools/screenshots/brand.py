"""Render the repository's brand images from one stylesheet.

- ``docs/assets/banner-dark.png`` and ``docs/assets/banner-light.png``: the README
  header, picked by a ``<picture>`` element from the reader's colour scheme;
- ``.github/social-preview.png``: the 1280x640 card GitHub shows when the repository
  link is shared. There is no API for it: upload the file under Settings > General >
  Social preview.

The mark is ``docs/assets/logo.svg``. The images are plain HTML rendered by the same
Chromium the screenshot script uses, and every PNG is stripped of metadata like the
README screenshots.

    uv run python devtools/screenshots/brand.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pngmeta  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
LOGO = (REPO_ROOT / "docs" / "assets" / "logo.svg").read_text(encoding="utf-8")

THEMES = {
    "dark": {
        "bg": "linear-gradient(135deg, #0b1220 0%, #0e1830 55%, #13244a 100%)",
        "border": "#1c2b4d",
        "glow": "rgba(37, 99, 235, 0.55)",
        "grid": "rgba(96, 165, 250, 0.07)",
        "ink": "#eef3ff",
        "accent": "#60a5fa",
        "tag": "#cfdcf5",
        "muted": "#8196bd",
        "node_bg": "#101b33",
        "node_border": "#2f4f8f",
        "node_ink": "#dbe6fb",
        "hub_bg": "#2563eb",
        "hub_border": "#93c5fd",
        "arrow": "#4f86e8",
    },
    "light": {
        "bg": "linear-gradient(135deg, #fbfcff 0%, #f1f6ff 55%, #e6efff 100%)",
        "border": "#d6e2f8",
        "glow": "rgba(59, 130, 246, 0.20)",
        "grid": "rgba(37, 99, 235, 0.06)",
        "ink": "#0b1220",
        "accent": "#2563eb",
        "tag": "#1e293b",
        "muted": "#5b6b86",
        "node_bg": "#ffffff",
        "node_border": "#bcd0f5",
        "node_ink": "#1e293b",
        "hub_bg": "#2563eb",
        "hub_border": "#1d4ed8",
        "arrow": "#6b93e0",
    },
}

BASE_CSS = """
  * { box-sizing: border-box; margin: 0; }
  html, body { background: transparent; }
  body { font-family: -apple-system, "SF Pro Display", "Helvetica Neue", Helvetica, Arial,
         sans-serif; -webkit-font-smoothing: antialiased; }
  .card { position: relative; overflow: hidden; background: var(--bg);
          border: 1px solid var(--border); }
  .glow { position: absolute; border-radius: 50%;
          background: radial-gradient(circle, var(--glow) 0%, transparent 68%); }
  .grid { position: absolute; inset: 0;
          background-image: linear-gradient(var(--grid) 1px, transparent 1px),
                            linear-gradient(90deg, var(--grid) 1px, transparent 1px);
          background-size: 32px 32px;
          -webkit-mask-image: linear-gradient(90deg, transparent 30%, #000 85%); }
  .brand { position: relative; display: flex; align-items: center; }
  .brand svg { flex: none; }
  .word { font-weight: 800; color: var(--ink); line-height: 1; }
  .word b { color: var(--accent); font-weight: 800; }
  .tag { position: relative; color: var(--tag); font-weight: 500; }
  .meta { position: relative; color: var(--muted); font-weight: 600;
          letter-spacing: 0.02em; }
  .node { border: 1.5px solid var(--node_border); background: var(--node_bg);
          color: var(--node_ink); font-weight: 600; white-space: nowrap; text-align: center; }
  .node.hub { background: var(--hub_bg); border-color: var(--hub_border); color: #fff; }
  .arrow { color: var(--arrow); display: block; flex: none; }
"""


def _arrow(direction: str, size: int) -> str:
    """A drawn arrow (a font glyph is too thin at these sizes)."""
    path = (
        "M12 3 V19 M5.5 12.5 L12 19 L18.5 12.5"
        if direction == "down"
        else ("M3 12 H19 M12.5 5.5 L19 12 L12.5 18.5")
    )
    return (
        f'<svg class="arrow" width="{size}" height="{size}" viewBox="0 0 22 22" fill="none" '
        f'stroke="currentColor" stroke-width="2.6" stroke-linecap="round" '
        f'stroke-linejoin="round"><path d="{path}"/></svg>'
    )


def _vars(theme: str) -> str:
    return "".join(f"--{k}: {v};" for k, v in THEMES[theme].items())


def banner_html(theme: str) -> str:
    """The README header: the mark, the name, one line of purpose and the request path."""
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{BASE_CSS}
  :root {{ {_vars(theme)} }}
  body {{ width: 1000px; height: 250px; }}
  .card {{ width: 1000px; height: 250px; border-radius: 22px; padding: 0 0 0 56px;
           display: flex; align-items: center; }}
  .glow {{ right: -140px; top: -210px; width: 560px; height: 560px; }}
  .left {{ position: relative; flex: 1; }}
  .brand svg {{ width: 74px; height: 74px; margin: 0 8px 0 -11px; transform: translateY(3px); }}
  .word {{ font-size: 76px; letter-spacing: -2.6px; }}
  .tag {{ font-size: 25px; margin-top: 16px; }}
  .meta {{ font-size: 15px; margin-top: 12px; text-transform: uppercase; }}
  .flow {{ position: relative; width: 300px; margin-right: 52px; display: flex;
           flex-direction: column; align-items: stretch; gap: 5px; }}
  .node {{ font-size: 16px; padding: 10px 14px; border-radius: 11px; }}
  .arrow {{ margin: 0 auto; }}
</style></head><body><div class="card"><div class="glow"></div><div class="grid"></div>
  <div class="left">
    <div class="brand">{LOGO}<span class="word">pg<b>warden</b></span></div>
    <div class="tag">Governed Postgres access for AI assistants</div>
    <div class="meta">MCP gateway &nbsp;·&nbsp; OAuth 2.1 &nbsp;·&nbsp; Postgres decides</div>
  </div>
  <div class="flow">
    <div class="node">MCP client</div>{_arrow("down", 20)}
    <div class="node hub">pgwarden</div>{_arrow("down", 20)}
    <div class="node">Postgres, as the person asking</div>
  </div>
</div></body></html>"""


def social_html() -> str:
    """The 1280x640 card for link previews, in the dark theme."""
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{BASE_CSS}
  :root {{ {_vars("dark")} }}
  body {{ width: 1280px; height: 640px; }}
  .card {{ width: 1280px; height: 640px; border: 0; padding: 70px 76px; }}
  .glow {{ right: -200px; top: -240px; width: 780px; height: 780px; }}
  .brand svg {{ width: 112px; height: 112px; margin: 0 12px 0 -16px; transform: translateY(4px); }}
  .word {{ font-size: 116px; letter-spacing: -3.6px; }}
  .tag {{ font-size: 44px; margin-top: 26px; }}
  .flow {{ position: absolute; left: 76px; right: 76px; bottom: 138px; display: flex;
           align-items: center; gap: 22px; }}
  .node {{ font-size: 27px; padding: 16px 26px; border-radius: 14px; border-width: 2px; }}
  .chips {{ position: absolute; left: 76px; right: 76px; bottom: 58px; display: flex;
            gap: 10px; font-size: 20px; color: var(--muted); }}
  .chips b {{ font-weight: 600; border: 1px solid #263a63; border-radius: 999px;
              padding: 6px 15px; background: #0f1a30; white-space: nowrap; }}
</style></head><body><div class="card"><div class="glow"></div><div class="grid"></div>
  <div class="brand">{LOGO}<span class="word">pg<b>warden</b></span></div>
  <div class="tag">Governed Postgres access for AI assistants</div>
  <div class="flow">
    <div class="node">MCP client</div>{_arrow("right", 34)}
    <div class="node hub">pgwarden gateway</div>{_arrow("right", 34)}
    <div class="node">Postgres, as the person asking</div>
  </div>
  <div class="chips">
    <b>OAuth 2.1 + OIDC</b><b>one role per person</b><b>RLS + masking</b>
    <b>human-approved writes</b><b>hash-chained audit</b>
  </div>
</div></body></html>"""


# (output path, html, css width, css height, device scale, transparent corners)
TARGETS = [
    (REPO_ROOT / "docs" / "assets" / "banner-dark.png", banner_html("dark"), 1000, 250, 2, True),
    (REPO_ROOT / "docs" / "assets" / "banner-light.png", banner_html("light"), 1000, 250, 2, True),
    (REPO_ROOT / ".github" / "social-preview.png", social_html(), 1280, 640, 1, False),
]


def main() -> None:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for output, html, width, height, scale, alpha in TARGETS:
            page = browser.new_page(
                viewport={"width": width, "height": height}, device_scale_factor=scale
            )
            page.set_content(html)
            png = page.screenshot(type="png", omit_background=alpha)
            page.close()
            output.write_bytes(pngmeta.strip_metadata(png, keep_alpha=alpha))
            pngmeta.check_clean(output.read_bytes(), label=output.name)
            print(f"wrote {output.relative_to(REPO_ROOT)}")
        browser.close()


if __name__ == "__main__":
    main()
