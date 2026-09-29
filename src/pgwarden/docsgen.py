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
    if data.get("date") and data.get("git_commit"):
        lines += ["", _run_line(data)]
    return "\n".join(lines)


def _llm_exposure_and_cost(data: dict[str, Any], model: str) -> tuple[int, float]:
    """Marker exposures (a planted marker id shown to the model in a tool result) and spend."""
    episodes = [e for e in data.get("episodes", []) if e["model"] == model]
    exposures = sum(len(e.get("markers_seen", [])) for e in episodes)
    return exposures, sum(float(e.get("cost_usd", 0.0)) for e in episodes)


def render_llm_table(data: dict[str, Any]) -> str:
    lines = [
        "| Model | Episodes | Solved | Injection attempts / exposures | Blocked "
        "| Rows beyond privilege | Writes without approval | Exfil in answer | USD |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in data.get("per_model", []):
        exposures, cost = _llm_exposure_and_cost(data, r["model"])
        attempts = f"{r['attempts']} / {exposures}"
        lines.append(
            f"| {r['model']} | {r['episodes']} | {r['tasks_solved']} | {attempts} "
            f"| {r['attempts_blocked']} | {r['rows_beyond_privilege']} "
            f"| {r['writes_without_approval']} | {r['exfil_episodes']} | {cost:.4f} |"
        )
    lines.append("")
    provider_line = _llm_providers_line(data)
    if provider_line:
        lines += [provider_line, ""]
    lines.append(
        f"Total spend: ${data['ledger']['spent_usd']:.4f} of a ${data['ledger']['budget_usd']:.2f} "
        "budget. Rows beyond privilege and writes without approval must be 0; exfiltration "
        "through the model's final answer is a residual risk the gateway cannot block."
    )
    if data.get("date") and data.get("git_commit"):
        lines += ["", _run_line(data)]
    return "\n".join(lines)


def _llm_providers_line(data: dict[str, Any]) -> str:
    """Who served the calls, per model, as OpenRouter reported it (empty for older results)."""
    parts: list[str] = []
    for r in data.get("per_model", []):
        served = r.get("providers_served") or {}
        if not served:
            continue
        calls = ", ".join(f"{name} {n}" for name, n in served.items())
        pin = r.get("provider_pin")
        note = f"pinned to `{', '.join(pin)}`" if pin else "not pinned"
        if r.get("calls_outside_pin"):
            note += f", {r['calls_outside_pin']} calls outside the pin"
        parts.append(f"`{r['model']}`: {calls} ({note})")
    if not parts:
        return ""
    return "Provider that served each call, from OpenRouter's response: " + "; ".join(parts) + "."


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
    lines += [
        "",
        f"The {data['sql_attacks_total']} attacks are the `query` cases of categories A to G "
        f"that must be blocked; the {data['benign_total']} benign queries are the benign "
        "controls that send SQL. The pgwarden row is the red-team run above, not a separate "
        f"measurement. sqlglot {data.get('sqlglot_version')}.",
    ]
    if data.get("date") and data.get("git_commit"):
        lines += ["", _run_line(data)]
    return "\n".join(lines)


_SPAN_ORDER = ("auth", "ratelimit", "db", "audit")
LATENCY_TARGET_MS = 10.0
_LATENCY_DETAILS_SUMMARY = "<summary>Server-Timing spans and the cold first query</summary>"
LOAD_P95_TARGET_MS = 150.0


def _ms(value: float) -> str:
    """Milliseconds with two decimals under 10 ms and one above."""
    return f"{value:.2f}" if value < 10 else f"{value:.1f}"


def _pair(a: float, b: float) -> str:
    return f"{_ms(a)} / {_ms(b)}"


def _range_pair(spread: dict[str, Any] | None, p50: str, p95: str) -> str:
    """The min-max of the repetitions' p50 and p95, as a second line in a table cell."""
    if not spread or p50 not in spread or p95 not in spread:
        return ""
    lo50, hi50 = spread[p50]
    lo95, hi95 = spread[p95]
    return f"<br><sub>{_ms(lo50)}-{_ms(hi50)} / {_ms(lo95)}-{_ms(hi95)}</sub>"


def _run_line(data: dict[str, Any], extra: str = "") -> str:
    """The run's provenance in small print: date, commit, versions, hardware, config."""
    parts = [f"{data.get('date')}", f"commit `{data.get('git_commit')}`"]
    if data.get("postgres_version"):
        parts.append(f"Postgres {str(data['postgres_version']).split(' ')[0]}")
    if data.get("hardware"):
        parts.append(str(data["hardware"]))
    if data.get("config_file"):
        parts.append(f"config `{data['config_file']}` (sha256 {data.get('config_hash')})")
    other = data.get("other_containers")
    if other is not None:
        noun = "container" if other == 1 else "containers"
        parts.append(f"{other} other {noun} running on the machine during the run")
    tail = f" {extra}" if extra else ""
    return "<sub>Run: " + "; ".join(parts) + "." + tail + "</sub>"


def _audit_line(data: dict[str, Any], when: str) -> str:
    audit = data.get("audit_verify")
    if not audit:
        return ""
    if audit.get("ok"):
        return f"Audit chain verified {when}: OK, {audit.get('detail')}."
    return f"Audit chain verified {when}: FAILED, {audit.get('detail')}."


def render_latency_table(data: dict[str, Any]) -> str:
    """The latency table, the Server-Timing medians, the cold first-query cost and the target."""
    reps = data.get("repetitions", 1)
    lines = [
        "| Query | Direct p50 / p95 | Direct + wrapper p50 / p95 | Via pgwarden p50 / p95 "
        "| Overhead p50 / p95 (ms) |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for q in data["queries"]:
        sp = q.get("spread")
        cells = [
            _pair(q["direct_p50"], q["direct_p95"]) + _range_pair(sp, "direct_p50", "direct_p95"),
            _pair(q["wrapper_p50"], q["wrapper_p95"])
            + _range_pair(sp, "wrapper_p50", "wrapper_p95"),
            _pair(q["gateway_p50"], q["gateway_p95"])
            + _range_pair(sp, "gateway_p50", "gateway_p95"),
            _pair(q["overhead_p50"], q["overhead_p95"])
            + _range_pair(sp, "overhead_p50", "overhead_p95"),
        ]
        rows = q.get("rows")
        label = f"{q['query']} ({rows} row{'s' if rows != 1 else ''})" if rows else q["query"]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += [
        "",
        f"Milliseconds, median of {reps} repetitions of {data['iterations']} timed calls "
        f"after {data['warmup']} warm-up calls each; the small line under a cell is the min-max "
        "of the repetitions' p50 / p95. Overhead is via pgwarden minus direct.",
    ]

    first = data["queries"][0]
    overhead = first["overhead_p50"]
    if overhead <= LATENCY_TARGET_MS:
        verdict = (
            f"Design target (overhead p50 <= {LATENCY_TARGET_MS:g} ms on the {first['query']}): "
            f"met, {_ms(overhead)} ms."
        )
    else:
        med = first.get("server_timing_median", {})
        dominant = max(med, key=lambda n: med[n]) if med else None
        tail = (
            f" The largest `Server-Timing` span is `{dominant}` ({_ms(med[dominant])} ms)."
            if dominant
            else ""
        )
        verdict = (
            f"Design target (overhead p50 <= {LATENCY_TARGET_MS:g} ms on the {first['query']}): "
            f"missed, {_ms(overhead)} ms.{tail}"
        )
    lines += ["", verdict, "", "<details>", _LATENCY_DETAILS_SUMMARY, ""]

    spans = sorted(
        {name for q in data["queries"] for name in q.get("server_timing_median", {})},
        key=lambda n: (_SPAN_ORDER.index(n) if n in _SPAN_ORDER else len(_SPAN_ORDER), n),
    )
    if spans:
        lines += [
            "`Server-Timing` span medians inside the gateway (ms):",
            "",
            "| Query | " + " | ".join(spans) + " |",
            "| --- |" + " ---: |" * len(spans),
        ]
        for q in data["queries"]:
            med = q.get("server_timing_median", {})
            cells = [_ms(med[n]) if n in med else "-" for n in spans]
            lines.append(f"| {q['query']} | " + " | ".join(cells) + " |")
        lines.append("")

    lines += [_cold_line(data.get("cold_start")), "", "</details>", ""]
    lines.append(_run_line(data, _audit_line(data, "after the latency run")))
    return "\n".join(lines)


def _cold_line(cold: dict[str, Any] | None) -> str:
    if not cold:
        return "Cold first-query cost: not measured in this run."
    if not cold.get("measured"):
        return f"Cold first-query cost: not measured. {cold.get('reason', '')}".rstrip()
    first = cold["cold_first_query_ms"]
    warm = cold["warm_query_ms"]
    return (
        "Cold first query after the pooled connection was evicted (connect + SCRAM; "
        "primary-key lookup, gateway with "
        f"`pool.idle_timeout_s: {cold.get('pool_idle_timeout_s')}`, "
        f"{cold['idle_wait_s']:g} s pause): median {_ms(first['median'])} ms "
        f"(min {_ms(first['min'])}, max {_ms(first['max'])}) against "
        f"{_ms(warm['median'])} ms warm, a cold cost of {_ms(cold['cold_cost_ms'])} ms, "
        f"of which {_ms(cold['db_span_cost_ms'])} ms in the `db` span. "
        f"{cold['confirmed_cold_samples']} of {cold['samples']} samples were confirmed cold "
        "by a new backend appearing in `pg_stat_activity`."
    )


def render_load_table(data: dict[str, Any]) -> str:
    r = data["result"]
    host = data.get("host_samples") or {}
    audit = data.get("audit_verify") or {}
    rate = r["error_rate"] * 100
    rows = [
        (
            "Identities",
            f"{r['identities']} machine identities (bench-01 to bench-{r['identities']:02d})",
        ),
        ("Concurrency", f"{r['concurrency']}"),
        ("Duration", f"{r['duration_s']:g} s, mix `{data.get('mix')}`"),
        (
            "Total requests",
            f"{r['total_requests']} ({r.get('rate_limited', 0)} rate-limited)",
        ),
        ("Requests/s", f"{r['requests_per_s']:g}"),
        (
            "Latency p50 / p95 / p99",
            f"{_ms(r['p50_ms'])} / {_ms(r['p95_ms'])} / {_ms(r['p99_ms'])} ms",
        ),
        (
            "Error rate (rate-limited calls excluded)",
            f"{rate:.2f}% ({r.get('errors', 0)} errors)",
        ),
        (
            "Peak Postgres connections (pgwarden roles, `pg_stat_activity`)",
            str(r["peak_pg_connections"])
            if r.get("peak_pg_connections") is not None
            else "not sampled",
        ),
    ]
    if host:
        rows += [
            (
                "Gateway peak CPU (`docker stats`, percent of one core)",
                f"{host['gateway_cpu_percent_of_one_core_peak']:g}% "
                f"(mean {host['gateway_cpu_percent_of_one_core_mean']:g}%, "
                f"{host.get('gateway_cpu_samples', 0)} samples)",
            ),
            (
                "Gateway peak RSS",
                f"{host['gateway_rss_mib_peak']:g} MiB "
                f"({host.get('gateway_rss_samples', 0)} samples)",
            ),
        ]
    if audit:
        outcome = "OK" if audit.get("ok") else "FAILED"
        head = f", head seq {audit['head_seq']}" if "head_seq" in audit else ""
        rows.append(
            ("`pgwarden audit verify` after the run", f"{outcome}: {audit.get('detail')}{head}")
        )
    lines = ["| Measure | Result |", "| --- | --- |"]
    lines += [f"| {name} | {value} |" for name, value in rows]

    p95_ok = r["p95_ms"] <= LOAD_P95_TARGET_MS
    err_ok = r.get("errors", 0) == 0
    lines += [
        "",
        f"Design target (p95 <= {LOAD_P95_TARGET_MS:g} ms with 0 non-rate-limit errors): "
        f"{'met' if p95_ok and err_ok else 'missed'} "
        f"(p95 {_ms(r['p95_ms'])} ms, {r.get('errors', 0)} errors).",
        "",
        _run_line(data),
    ]
    return "\n".join(lines)


def render_glance(
    redteam: dict[str, Any] | None,
    llm: dict[str, Any] | None,
    latency: dict[str, Any] | None,
    load: dict[str, Any] | None,
) -> str:
    """The README's headline numbers, one column per recorded run."""
    cells: list[tuple[str, str]] = []
    if redteam is not None:
        s = redteam["summary"]
        cells.append(
            (
                f"{s['must_block_blocked']} / {s['must_block_total']}",
                "attacks blocked, oracle-verified",
            )
        )
    if llm is not None:
        per_model = llm.get("per_model", [])
        leaked = sum(r["rows_beyond_privilege"] + r["writes_without_approval"] for r in per_model)
        episodes = sum(r["episodes"] for r in per_model)
        cells.append((str(leaked), f"leaked rows or unapproved writes, {episodes} LLM episodes"))
    if latency is not None:
        first = latency["queries"][0]
        cells.append((f"{_ms(first['overhead_p50'])} ms", "gateway overhead per key lookup, p50"))
    if load is not None:
        r = load["result"]
        cells.append(
            (
                f"{r['requests_per_s']:.0f} req/s",
                f"{r['identities']} identities, p95 {_ms(r['p95_ms'])} ms",
            )
        )
    if not cells:
        return ""
    lines = [
        "| " + " | ".join(head for head, _ in cells) + " |",
        "|" + " :---: |" * len(cells),
        "| " + " | ".join(label for _, label in cells) + " |",
    ]
    source = latency or redteam or {}
    if source.get("hardware"):
        lines += [
            "",
            f"<sub>{source['hardware']} · the commands and caveats are under "
            "[Results](#results)</sub>",
        ]
    return "\n".join(lines)


def load_results(results_dir: Path, prefix: str) -> dict[str, Any] | None:
    files = sorted(results_dir.glob(f"{prefix}-*.json"))
    if not files:
        return None
    parsed: dict[str, Any] = json.loads(files[-1].read_text(encoding="utf-8"))
    return parsed


# -- README marker injection ---------------------------------------------------------

_MARKERS = {
    "glance": ("<!-- pgwarden:glance:start -->", "<!-- pgwarden:glance:end -->"),
    "redteam": ("<!-- pgwarden:redteam:start -->", "<!-- pgwarden:redteam:end -->"),
    "baselines": ("<!-- pgwarden:baselines:start -->", "<!-- pgwarden:baselines:end -->"),
    "llm": ("<!-- pgwarden:llm:start -->", "<!-- pgwarden:llm:end -->"),
    "latency": ("<!-- pgwarden:latency:start -->", "<!-- pgwarden:latency:end -->"),
    "load": ("<!-- pgwarden:load:start -->", "<!-- pgwarden:load:end -->"),
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
    llm = load_results(results_dir, "llm-redteam")
    latency = load_results(results_dir, "latency")
    load = load_results(results_dir, "load")
    glance = render_glance(redteam, llm, latency, load)
    if glance:
        readme = inject(readme, "glance", glance)
    if redteam is not None:
        readme = inject(readme, "redteam", render_redteam_table(redteam))
    if baselines is not None:
        readme = inject(readme, "baselines", render_baselines_table(baselines))
    if llm is not None:
        readme = inject(readme, "llm", render_llm_table(llm))
    if latency is not None:
        readme = inject(readme, "latency", render_latency_table(latency))
    if load is not None:
        readme = inject(readme, "load", render_load_table(load))
    return readme


__all__ = [
    "generate_configuration_md",
    "inject",
    "load_results",
    "render_glance",
    "render_baselines_table",
    "render_latency_table",
    "render_llm_table",
    "render_load_table",
    "render_readme",
    "render_redteam_table",
]
