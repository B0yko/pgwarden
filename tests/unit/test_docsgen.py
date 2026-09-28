"""Unit tests for the configuration-doc generator and the README table renderers."""

from __future__ import annotations

from pgwarden.docsgen import (
    generate_configuration_md,
    inject,
    render_baselines_table,
    render_redteam_table,
)


def test_configuration_md_covers_every_field() -> None:
    text = generate_configuration_md()
    assert "# Configuration reference" in text
    assert "`PGWARDEN_SIGNING_KEY`" in text
    for field in ("public_url", "trusted_proxy_hops", "max_replicas", "queries_per_minute"):
        assert f"`{field}`" in text


def test_redteam_table_excludes_non_attack_categories() -> None:
    data = {
        "summary": {
            "by_category": {
                "A": {"attacks": 10, "blocked": 10, "layers": ["protocol"]},
                "benign": {"attacks": 0, "blocked": 0, "layers": []},
            },
            "benign_passed": 32,
            "benign_total": 32,
            "residual_risks": [{"id": "D05"}],
        }
    }
    table = render_redteam_table(data)
    assert "A. Stacked statements | 10 | 10" in table
    assert "| benign |" not in table  # the pseudo-category is not a table row
    assert "Benign controls passed: 32 / 32" in table


def test_baselines_table_shows_pgwarden_zero() -> None:
    data = {
        "sql_attacks_total": 66,
        "benign_total": 29,
        "baselines": [
            {
                "baseline": "keyword/regex blocklist",
                "attacks_let_through": 39,
                "benign_wrongly_blocked": 3,
            },
        ],
    }
    table = render_baselines_table(data)
    assert "39 / 66" in table
    assert "**0 / 66**" in table


def test_inject_replaces_between_markers() -> None:
    readme = "before\n<!-- pgwarden:redteam:start -->\nOLD\n<!-- pgwarden:redteam:end -->\nafter\n"
    out = inject(readme, "redteam", "NEW TABLE")
    assert "NEW TABLE" in out and "OLD" not in out
    assert out.startswith("before") and out.rstrip().endswith("after")
