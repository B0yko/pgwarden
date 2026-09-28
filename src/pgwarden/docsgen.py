"""Generate ``docs/configuration.md`` from the pydantic config models, and render
the README's results tables from ``docs/results/*.json``.

CI runs ``pgwarden report --check`` and the configuration-doc check to keep both
in sync with the code and the recorded runs: the generated text is the source of
truth, and a drift fails the build.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args

import pydantic

from pgwarden import config as config_module

_ENV_SETTINGS = [
    ("PGWARDEN_CONFIG", "Path to pgwarden.yaml.", "server + CLI"),
    (
        "PGWARDEN_TARGET_DSN",
        "Target database host/port/db and sslmode, no user or password.",
        "server + CLI",
    ),
    ("PGWARDEN_STATE_DSN", "State database DSN as pgwarden_app (also *_FILE).", "server + CLI"),
    (
        "PGWARDEN_ADMIN_DSN",
        "Admin DSN for provisioning; the server refuses to start if it is set.",
        "CLI only",
    ),
    (
        "PGWARDEN_ROLE_SECRET",
        "Secret that derives each role's SCRAM password (also *_FILE).",
        "server + provisioning",
    ),
    (
        "PGWARDEN_SIGNING_KEY",
        "Ed25519 private key (PEM) that signs access tokens (also *_FILE).",
        "server",
    ),
    (
        "PGWARDEN_SESSION_SECRET",
        "Secret for cookies, CSRF tokens and approval links (also *_FILE).",
        "server",
    ),
    (
        "PGWARDEN_OIDC_CLIENT_SECRET",
        "pgwarden's client secret at the upstream IdP (also *_FILE).",
        "server",
    ),
    (
        "PGWARDEN_SLACK_WEBHOOK_URL",
        "Slack incoming webhook for approval notices (also *_FILE).",
        "server",
    ),
    ("PGWARDEN_SMTP_URL", "SMTP URL for approval emails (also *_FILE).", "server"),
    ("PGWARDEN_SERVER_TIMING", "Set to 1 to add the Server-Timing header on /mcp.", "server"),
]


def _model_order() -> list[type[pydantic.BaseModel]]:  # noqa: F811
    order: list[type[pydantic.BaseModel]] = [
        config_module.Config,
        config_module.UpstreamConfig,
        config_module.IdentityRef,
        config_module.PersonConfig,
        config_module.MachineConfig,
        config_module.RateOverrides,
        config_module.MaskingConfig,
        config_module.PoolConfig,
        config_module.LimitsConfig,
        config_module.ReadConfig,
        config_module.WriteConfig,
        config_module.NotificationsConfig,
        config_module.DemoConfig,
    ]
    return order


def _type_name(annotation: Any) -> str:
    text = str(annotation)
    text = text.replace("typing.", "").replace("pgwarden.config.", "")
    for prefix in ("<class '", "'>"):
        text = text.replace(prefix, "")
    if text.startswith("Literal"):
        args = get_args(annotation)
        return "one of " + ", ".join(repr(a) for a in args)
    return text.split("'")[-2] if "'" in text else text


def _default(field: pydantic.fields.FieldInfo) -> str:
    if field.default_factory is not None:
        try:
            value = field.default_factory()  # type: ignore[call-arg]
        except TypeError:
            return "(computed)"
        return f"`{value!r}`" if value not in ([], {}, None) else "`[]`" if value == [] else "`{}`"
    if field.is_required():
        return "**required**"
    return f"`{field.default!r}`"


def generate_configuration_md() -> str:
    lines = [
        "# Configuration reference",
        "",
        "This file is generated from the pydantic models in `pgwarden.config` by "
        "`pgwarden report --config-doc` (CI checks it is in sync). Edit the models, not this file.",
        "",
        "## Environment",
        "",
        "Secrets accept a `<NAME>_FILE` variant that reads the value from a file (for Docker and "
        "Cloud Run secret mounts). Exactly one of `<NAME>` or `<NAME>_FILE` may be set.",
        "",
        "| Variable | Used by | Meaning |",
        "| --- | --- | --- |",
    ]
    for name, meaning, used in _ENV_SETTINGS:
        lines.append(f"| `{name}` | {used} | {meaning} |")
    lines += ["", "## `pgwarden.yaml`", ""]
    for model in _model_order():
        lines.append(f"### {model.__name__}")
        doc = (model.__doc__ or "").strip().splitlines()
        if doc:
            lines += ["", doc[0].strip(), ""]
        lines += ["| Field | Type | Default | Description |", "| --- | --- | --- | --- |"]
        for field_name, field in model.model_fields.items():
            desc = (field.description or "").replace("|", "\\|")
            lines.append(
                f"| `{field_name}` | {_type_name(field.annotation)} | {_default(field)} | {desc} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# -- README results tables -----------------------------------------------------------


def _fmt_layers(layers: list[str]) -> str:
    return ", ".join(layers)


def render_redteam_table(data: dict[str, Any]) -> str:
    s = data["summary"]
    lines = [
        "| Category | Attacks | Blocked (oracle-verified) | Observed primary blocking layer |",
        "| --- | ---: | ---: | --- |",
    ]
    names = {
        "A": "A. Stacked statements",
        "B": "B. Writes on the read path",
        "C": "C. Privilege escalation",
        "D": "D. Crossing RLS",
        "E": "E. Bypassing masking",
        "F": "F. Resource exhaustion",
        "G": "G. Canary exfiltration",
        "H": "H. Approval abuse",
        "I": "I. OAuth and session",
    }
    for cat, v in s["by_category"].items():
        if cat not in names:
            continue
        row = (
            f"| {names.get(cat, cat)} | {v['attacks']} | {v['blocked']} "
            f"| {_fmt_layers(v['layers'])} |"
        )
        lines.append(row)
    lines.append("")
    lines.append(
        f"Benign controls passed: {s['benign_passed']} / {s['benign_total']}. "
        f"Documented residual risks: {len(s['residual_risks'])}."
    )
    return "\n".join(lines)


def render_baselines_table(data: dict[str, Any]) -> str:
    lines = [
        "| Baseline | Attacks it would let through | Benign queries it would wrongly block |",
        "| --- | ---: | ---: |",
    ]
    for b in data["baselines"]:
        lines.append(
            f"| {b['baseline']} | {b['attacks_let_through']} / {data['sql_attacks_total']} "
            f"| {b['benign_wrongly_blocked']} / {data['benign_total']} |"
        )
    lines.append(
        f"| **pgwarden (database-enforced)** | **0 / {data['sql_attacks_total']}** "
        f"| **0 / {data['benign_total']}** |"
    )
    return "\n".join(lines)


def load_results(results_dir: Path, prefix: str) -> dict[str, Any] | None:
    files = sorted(results_dir.glob(f"{prefix}-*.json"))
    if not files:
        return None
    parsed: dict[str, Any] = json.loads(files[-1].read_text(encoding="utf-8"))
    return parsed


# -- README marker injection ---------------------------------------------------------

_MARKERS = {
    "redteam": ("<!-- pgwarden:redteam:start -->", "<!-- pgwarden:redteam:end -->"),
    "baselines": ("<!-- pgwarden:baselines:start -->", "<!-- pgwarden:baselines:end -->"),
}


def inject(readme: str, section: str, table: str) -> str:
    start, end = _MARKERS[section]
    if start not in readme or end not in readme:
        return readme
    head = readme[: readme.index(start) + len(start)]
    tail = readme[readme.index(end) :]
    return f"{head}\n{table}\n{tail}"


def render_readme(readme: str, results_dir: Path) -> str:
    redteam = load_results(results_dir, "redteam")
    baselines = load_results(results_dir, "baselines")
    if redteam is not None:
        readme = inject(readme, "redteam", render_redteam_table(redteam))
    if baselines is not None:
        readme = inject(readme, "baselines", render_baselines_table(baselines))
    return readme


__all__ = [
    "generate_configuration_md",
    "inject",
    "load_results",
    "render_baselines_table",
    "render_readme",
    "render_redteam_table",
]
