"""Jinja2 rendering for the gateway's server-side pages (autoescaped, no JS)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.responses import HTMLResponse

from pgwarden.web.security import apply_security_headers

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(
    template: str,
    context: dict[str, Any],
    *,
    status_code: int = 200,
    form_targets: tuple[str, ...] = (),
) -> HTMLResponse:
    html = _env.get_template(template).render(**context)
    response = HTMLResponse(html, status_code=status_code)
    apply_security_headers(response, form_targets=form_targets)
    return response


def message(
    title: str, text: str, *, status_code: int = 400, detail: str | None = None
) -> HTMLResponse:
    return render(
        "message.html", {"title": title, "message": text, "detail": detail}, status_code=status_code
    )


__all__ = ["STATIC_DIR", "TEMPLATE_DIR", "message", "render"]
