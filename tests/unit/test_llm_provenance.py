"""Provenance of the LLM run: provider pins, who served each call, and the run metadata.

No network: the OpenRouter transport, the gateway client and the episodes are fakes.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from pgwarden.cli import app
from pgwarden.docsgen import render_llm_table
from pgwarden.redteam import llm as llm_mod
from pgwarden.redteam import mcp_client
from pgwarden.redteam.ledger import (
    Ledger,
    ModelPrice,
    completion_cost,
    completion_provider,
    fetch_generation_stats,
)
from pgwarden.redteam.llm import (
    EpisodeResult,
    OpenRouterClient,
    OpenRouterError,
    estimate_cost_usd,
    parse_provider_pins,
    provider_matches_pin,
    run_episode,
    run_metadata,
    summarize_episodes,
)

DEEPSEEK = "deepseek/deepseek-v4-flash-0731"
QWEN = "qwen/qwen3.7-flash"


def _completion(
    provider: str | None, *, content: str = "42", cost: float | None = 0.0001, gen_id: str = "gen-1"
) -> dict[str, Any]:
    usage: dict[str, Any] = {"prompt_tokens": 100, "completion_tokens": 10}
    if cost is not None:
        usage["cost"] = cost
    out: dict[str, Any] = {
        "id": gen_id,
        "usage": usage,
        "choices": [{"message": {"role": "assistant", "content": content}}],
    }
    if provider is not None:
        out["provider"] = provider
    return out


# --- the request field -------------------------------------------------------------


def test_pinned_model_gets_order_and_fallbacks_off() -> None:
    client = OpenRouterClient(
        "https://x/api/v1", "k", provider_orders={QWEN: ["alibaba"], DEEPSEEK: ["a", "b"]}
    )
    assert client.provider_field(QWEN) == {"order": ["alibaba"], "allow_fallbacks": False}
    assert client.provider_field(DEEPSEEK) == {"order": ["a", "b"], "allow_fallbacks": False}


def test_unpinned_model_gets_fallbacks_off_only() -> None:
    client = OpenRouterClient("https://x/api/v1", "k", provider_orders={QWEN: ["alibaba"]})
    assert client.provider_field(DEEPSEEK) == {"allow_fallbacks": False}
    assert OpenRouterClient("https://x/api/v1", "k").provider_field(QWEN) == {
        "allow_fallbacks": False
    }


async def test_request_actually_sends_the_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=_completion("Alibaba"))

    real = httpx.AsyncClient
    monkeypatch.setattr(
        llm_mod.httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )
    client = OpenRouterClient("https://x/api/v1", "k", provider_orders={QWEN: ["alibaba"]})
    await client.complete(QWEN, [{"role": "user", "content": "hi"}])
    await client.complete(DEEPSEEK, [{"role": "user", "content": "hi"}])
    assert seen[0]["provider"] == {"order": ["alibaba"], "allow_fallbacks": False}
    assert seen[0]["temperature"] == 0
    assert seen[1]["provider"] == {"allow_fallbacks": False}


def _mock_openrouter(
    monkeypatch: pytest.MonkeyPatch, responses: list[httpx.Response]
) -> tuple[list[float], list[httpx.Request]]:
    """Serve ``responses`` in order; return the sleeps taken and the requests seen."""
    sleeps: list[float] = []
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return responses.pop(0)

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    real = httpx.AsyncClient
    monkeypatch.setattr(
        llm_mod.httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(llm_mod.asyncio, "sleep", fake_sleep)
    return sleeps, requests


async def test_complete_retries_rate_limits_and_error_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps, requests = _mock_openrouter(
        monkeypatch,
        [
            httpx.Response(429, headers={"retry-after": "7"}, text="slow down"),
            httpx.Response(200, json={"error": {"message": "provider failed", "code": 502}}),
            httpx.Response(503, text="unavailable"),
            httpx.Response(200, json=_completion("DeepInfra")),
        ],
    )
    client = OpenRouterClient("https://x/api/v1", "k", provider_orders={DEEPSEEK: ["deepinfra"]})
    out = await client.complete(DEEPSEEK, [{"role": "user", "content": "hi"}])
    assert completion_provider(out) == "DeepInfra"
    assert len(requests) == 4
    assert sleeps == [7.0, 4.0, 8.0]  # Retry-After first, then doubling from 2 s (2, 4, 8)


async def test_complete_gives_up_with_the_last_status(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps, requests = _mock_openrouter(
        monkeypatch, [httpx.Response(429, text="rate limited by upstream")] * llm_mod.MAX_ATTEMPTS
    )
    client = OpenRouterClient("https://x/api/v1", "k")
    with pytest.raises(OpenRouterError, match=r"HTTP 429: rate limited by upstream"):
        await client.complete(QWEN, [{"role": "user", "content": "hi"}])
    assert len(requests) == llm_mod.MAX_ATTEMPTS
    assert len(sleeps) == llm_mod.MAX_ATTEMPTS - 1
    assert max(sleeps) <= llm_mod.MAX_BACKOFF_S


async def test_complete_does_not_retry_a_rejected_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps, requests = _mock_openrouter(
        monkeypatch, [httpx.Response(400, text="unsupported parameter")]
    )
    client = OpenRouterClient("https://x/api/v1", "k")
    with pytest.raises(OpenRouterError, match="HTTP 400: unsupported parameter"):
        await client.complete(QWEN, [{"role": "user", "content": "hi"}])
    assert len(requests) == 1 and sleeps == []


def test_parse_provider_pins() -> None:
    models = [DEEPSEEK, QWEN]
    assert parse_provider_pins([f"{QWEN}=alibaba", f"{DEEPSEEK}=deepinfra, together"], models) == {
        QWEN: ["alibaba"],
        DEEPSEEK: ["deepinfra", "together"],
    }
    assert parse_provider_pins([], models) == {}
    for bad in (
        "alibaba",  # no model
        f"{QWEN}=",  # no provider
        "=alibaba",  # no model id
        "other/model=alibaba",  # not in --models
    ):
        with pytest.raises(ValueError):
            parse_provider_pins([bad], models)
    with pytest.raises(ValueError, match="twice"):
        parse_provider_pins([f"{QWEN}=a", f"{QWEN}=b"], models)


def test_provider_matches_pin_compares_slug_and_display_name() -> None:
    assert provider_matches_pin("DeepInfra", ["deepinfra"])
    assert provider_matches_pin("Sail Research", ["sail-research"])
    assert provider_matches_pin("Sail Research", ["sail-research/fp4"])
    assert provider_matches_pin("Google Vertex", ["google-vertex/us-east5"])
    assert not provider_matches_pin("Together", ["deepinfra"])
    assert not provider_matches_pin("unknown", ["deepinfra"])


# --- reading the response ----------------------------------------------------------


def test_completion_provider_and_cost_come_from_the_response() -> None:
    body = _completion("DeepInfra", cost=0.00042)
    assert completion_provider(body) == "DeepInfra"
    assert completion_cost(body) == 0.00042
    assert completion_provider(_completion(None)) is None
    assert completion_provider({"provider": "  "}) is None
    assert completion_cost(_completion("X", cost=None)) is None
    assert completion_cost({"usage": {"cost": True}}) is None


async def test_generation_stats_parse_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["id"] == "gen-ok":
            return httpx.Response(
                200, json={"data": {"total_cost": 0.5, "provider_name": "Nebius"}}
            )
        return httpx.Response(404, json={"error": {"message": "not found"}})

    real = httpx.AsyncClient
    monkeypatch.setattr(
        "pgwarden.redteam.ledger.httpx.AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )
    stats = await fetch_generation_stats("https://x/api/v1", "k", "gen-ok")
    assert stats is not None and stats.total_cost == 0.5 and stats.provider_name == "Nebius"
    assert await fetch_generation_stats("https://x/api/v1", "k", "gen-late") is None
    assert await fetch_generation_stats("https://x/api/v1", "k", "") is None


# --- an episode records who served each call ---------------------------------------


class _FakeStack:
    resource = "http://gateway/mcp"

    async def login(self, sub: str) -> Any:
        class _Tokens:
            access_token = "t"

        return _Tokens()


class _ScriptedLLM:
    """Answers with one tool call, then the final answer; providers come from a script."""

    base_url = "https://x/api/v1"
    api_key = "k"

    def __init__(self, completions: list[dict[str, Any]]) -> None:
        self._completions = list(completions)

    async def complete(self, model: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return self._completions.pop(0)


def _tool_call_completion(provider: str | None, **kw: Any) -> dict[str, Any]:
    body = _completion(provider, **kw)
    body["choices"] = [
        {
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "whoami", "arguments": "{}"},
                    }
                ],
            }
        }
    ]
    return body


async def _episode(
    monkeypatch: pytest.MonkeyPatch, completions: list[dict[str, Any]], ledger: Ledger
) -> EpisodeResult:
    async def fake_answer(*_a: Any, **_k: Any) -> str:
        return "42"

    async def fake_call_tool(*_a: Any, **_k: Any) -> mcp_client.ToolResponse:
        return mcp_client.ToolResponse(status=200, text="{}", body={})

    monkeypatch.setattr(llm_mod, "expected_answer", fake_answer)
    monkeypatch.setattr(mcp_client, "call_tool", fake_call_tool)
    return await run_episode(
        model=QWEN,
        task={"id": "T1", "identity": "bob", "prompt": "how many?", "answer_sql": "select 42"},
        trial=1,
        client=_FakeStack(),  # type: ignore[arg-type]
        llm=_ScriptedLLM(completions),  # type: ignore[arg-type]
        target_dsn="postgresql://h/db",
        role_secret="s",
        injections=[],
        ledger=ledger,
    )


async def test_episode_counts_providers_and_uses_reported_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = Ledger(budget_usd=1.0, prices={QWEN: ModelPrice(1e-6, 1e-6)})
    ep = await _episode(
        monkeypatch,
        [_tool_call_completion("Alibaba", cost=0.001), _completion("Alibaba", cost=0.002)],
        ledger,
    )
    assert ep.providers_served == {"Alibaba": 2}
    assert ep.solved
    assert ep.cost_usd == pytest.approx(0.003)
    assert ledger.calls == 2 and ledger.estimated_calls == 0


async def test_episode_falls_back_to_the_generation_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pgwarden.redteam.ledger import GenerationStats

    asked: list[str] = []

    async def fake_stats(base: str, key: str, gen_id: str) -> GenerationStats | None:
        asked.append(gen_id)
        if gen_id == "gen-a":
            return GenerationStats(total_cost=0.01, provider_name="Nebius")
        return None  # the endpoint has not caught up yet

    monkeypatch.setattr(llm_mod, "fetch_generation_stats", fake_stats)
    ledger = Ledger(budget_usd=1.0, prices={QWEN: ModelPrice(1e-6, 1e-6)})
    ep = await _episode(
        monkeypatch,
        [
            _tool_call_completion(None, cost=None, gen_id="gen-a"),
            _completion(None, cost=None, gen_id="gen-b"),
        ],
        ledger,
    )
    assert asked == ["gen-a", "gen-b"]
    assert ep.providers_served == {"Nebius": 1, llm_mod.UNKNOWN_PROVIDER: 1}
    # gen-a priced by the endpoint, gen-b estimated from tokens: 110 x 1e-6
    assert ep.cost_usd == pytest.approx(0.01 + 110e-6)
    assert ledger.estimated_calls == 1


async def test_episode_does_not_call_the_generation_endpoint_when_the_response_has_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the response already carried provider and cost")

    monkeypatch.setattr(llm_mod, "fetch_generation_stats", boom)
    ledger = Ledger(budget_usd=1.0)
    await _episode(monkeypatch, [_completion("Alibaba")], ledger)


# --- aggregation per model ---------------------------------------------------------


def _ep(model: str, providers: dict[str, int], **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "model": model,
        "solved": True,
        "out_of_policy_attempts": [],
        "rows_beyond_privilege": 0,
        "writes_executed_without_approval": 0,
        "exfil_in_answer": False,
        "providers_served": providers,
    }
    base.update(over)
    return base


def test_summarize_counts_providers_per_model() -> None:
    episodes = [
        _ep(DEEPSEEK, {"DeepInfra": 4}),
        _ep(DEEPSEEK, {"DeepInfra": 3}, solved=False),
        _ep(QWEN, {"Alibaba": 5}),
        _ep(QWEN, {"Alibaba": 2}),
    ]
    rows = {r["model"]: r for r in summarize_episodes(episodes, {DEEPSEEK: ["deepinfra"]})}
    assert rows[DEEPSEEK]["providers_served"] == {"DeepInfra": 7}
    assert rows[DEEPSEEK]["provider_pin"] == ["deepinfra"]
    assert rows[DEEPSEEK]["calls_outside_pin"] == 0
    assert rows[DEEPSEEK]["tasks_solved"] == 1 and rows[DEEPSEEK]["episodes"] == 2
    assert rows[QWEN]["providers_served"] == {"Alibaba": 7}
    assert rows[QWEN]["provider_pin"] is None
    assert rows[QWEN]["calls_outside_pin"] == 0


def test_summarize_flags_calls_outside_the_pin() -> None:
    episodes = [
        _ep(DEEPSEEK, {"DeepInfra": 2, "Together": 1, llm_mod.UNKNOWN_PROVIDER: 3}),
        _ep(QWEN, {"Anything": 9}),  # unpinned: nothing to violate
    ]
    rows = {r["model"]: r for r in summarize_episodes(episodes, {DEEPSEEK: ["deepinfra"]})}
    assert rows[DEEPSEEK]["providers_served"] == {
        "DeepInfra": 2,
        "Together": 1,
        llm_mod.UNKNOWN_PROVIDER: 3,
    }
    assert rows[DEEPSEEK]["calls_outside_pin"] == 4
    assert rows[QWEN]["calls_outside_pin"] == 0


def test_summarize_reads_older_results_without_providers() -> None:
    old = {k: v for k, v in _ep(QWEN, {}).items() if k != "providers_served"}
    rows = summarize_episodes([old])
    assert rows[0]["providers_served"] == {} and rows[0]["calls_outside_pin"] == 0


# --- ledger and estimate -----------------------------------------------------------


def test_ledger_summary_records_prices_and_estimated_calls() -> None:
    ledger = Ledger(budget_usd=1.0, prices={QWEN: ModelPrice(3e-8, 1.3e-7)})
    ledger.record(QWEN, 100, 10, actual_usd=0.001)
    ledger.record(QWEN, 100, 10, actual_usd=None)
    summary = ledger.summary()
    assert summary["calls"] == 2 and summary["calls_cost_estimated_from_tokens"] == 1
    assert summary["prices_usd_per_token"] == {QWEN: {"prompt": 3e-8, "completion": 1.3e-7}}


def test_estimate_uses_prices_and_skips_unknown_models() -> None:
    prices = {QWEN: ModelPrice(1e-6, 2e-6)}
    one_episode = (
        llm_mod.EST_PROMPT_TOKENS_PER_EPISODE * 1e-6
        + llm_mod.EST_COMPLETION_TOKENS_PER_EPISODE * 2e-6
    )
    assert estimate_cost_usd(prices, [QWEN, DEEPSEEK], 30) == pytest.approx(30 * one_episode)


# --- run metadata ------------------------------------------------------------------


def test_run_metadata_records_what_a_reader_needs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "pgwarden.llm.yaml").write_text("public_url: http://localhost:8080\n", encoding="utf-8")
    monkeypatch.setattr(llm_mod, "_git_commit", lambda: "abc1234")
    monkeypatch.setattr(llm_mod, "_git_dirty", lambda: False)
    meta = run_metadata(
        argv=["redteam", "llm", "--models", f"{QWEN},{DEEPSEEK}", "--trials", "3"],
        env={
            "PGWARDEN_DEMO_CONFIG": "pgwarden.llm.yaml",
            "PGWARDEN_HARDWARE": "MacBook Air M5, 24 GB",
            "PGWARDEN_RUN_DATE": "2026-09-28",
            "OPENROUTER_API_KEY": "sk-or-secret",
        },
        injections_path=demo / "injections.yaml",
        models=[QWEN, DEEPSEEK],
        provider_pins={QWEN: ["alibaba"]},
        tasks=10,
        trials=3,
        max_turns=12,
        gateway_limits={"queries_per_minute": 600, "proposals_per_hour": 600},
    )
    assert meta["command"] == f"pgwarden redteam llm --models {QWEN},{DEEPSEEK} --trials 3"
    assert meta["date"] == "2026-09-28"
    assert meta["git_commit"] == "abc1234" and meta["git_dirty"] is False
    assert meta["hardware"] == "MacBook Air M5, 24 GB"
    assert meta["config_file"] == "pgwarden.llm.yaml"
    assert isinstance(meta["config_hash"], str) and len(meta["config_hash"]) == 16
    assert meta["gateway_limits"] == {"queries_per_minute": 600, "proposals_per_hour": 600}
    assert meta["models"] == [QWEN, DEEPSEEK]
    assert meta["provider_pins"] == {QWEN: ["alibaba"]}
    assert (meta["tasks"], meta["trials"], meta["max_turns"], meta["temperature"]) == (10, 3, 12, 0)
    assert "sk-or-secret" not in json.dumps(meta)


def test_run_metadata_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(llm_mod, "_git_commit", lambda: None)
    monkeypatch.setattr(llm_mod, "_git_dirty", lambda: None)
    meta = run_metadata(
        argv=[],
        env={},
        injections_path=tmp_path / "injections.yaml",
        models=[],
        provider_pins={},
        tasks=0,
        trials=1,
        max_turns=12,
        gateway_limits=None,
    )
    assert meta["hardware"] == llm_mod.HARDWARE_FALLBACK
    assert meta["config_file"] == "pgwarden.yaml" and meta["config_hash"] is None
    assert meta["gateway_limits"] is None
    assert meta["git_commit"] is None and meta["git_dirty"] is None


# --- the command -------------------------------------------------------------------

_ENV = {
    "PGWARDEN_ADMIN_DSN": "postgresql://a:b@localhost:5432/shop",
    "PGWARDEN_TARGET_DSN": "postgresql://a:b@localhost:5432/shop",
    "PGWARDEN_ROLE_SECRET": "role-secret",
    "OPENROUTER_API_KEY": "sk-or-secret",
    "PGWARDEN_DEMO_CONFIG": "pgwarden.llm.yaml",
    "PGWARDEN_HARDWARE": "Test box, 8 GB",
    "PGWARDEN_RUN_DATE": "2026-09-28",
}


def test_cli_rejects_a_pin_for_a_model_that_is_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    result = CliRunner().invoke(
        app,
        [
            "redteam",
            "llm",
            "--models",
            QWEN,
            "--provider",
            f"{DEEPSEEK}=deepinfra",
            "--target-url",
            "http://localhost:1",
        ],
    )
    assert result.exit_code == 1
    assert "not in --models" in result.output


def test_cli_writes_provenance_fields_and_per_model_providers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "llm.json"
    argv = [
        "pgwarden", "redteam", "llm", "--models", f"{DEEPSEEK},{QWEN}", "--trials", "2",
        "--tasks", "2", "--provider", f"{DEEPSEEK}=deepinfra", "--provider", f"{QWEN}=alibaba",
        "--target-url", "http://localhost:1", "--report", str(out),
    ]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)

    async def fake_prices(base: str, key: str, models: list[str]) -> dict[str, ModelPrice]:
        return {DEEPSEEK: ModelPrice(6e-8, 1.8e-7), QWEN: ModelPrice(3e-8, 1.3e-7)}

    async def fake_limits(client: Any) -> dict[str, Any]:
        return {"queries_per_minute": 600, "proposals_per_hour": 600}

    served = {DEEPSEEK: "DeepInfra", QWEN: "Alibaba"}
    pins_seen: list[dict[str, list[str]]] = []

    real_client = llm_mod.OpenRouterClient

    def spy_client(*a: Any, **kw: Any) -> OpenRouterClient:
        pins_seen.append(kw["provider_orders"])
        return real_client(*a, **kw)

    async def fake_episode(**kw: Any) -> EpisodeResult:
        return EpisodeResult(
            model=kw["model"],
            task_id=kw["task"]["id"],
            trial=kw["trial"],
            identity=kw["task"]["identity"],
            solved=True,
            turns=2,
            markers_seen=[],
            out_of_policy_attempts=[],
            rows_beyond_privilege=0,
            writes_executed_without_approval=0,
            exfil_in_answer=False,
            final_answer="ok",
            cost_usd=0.001,
            providers_served={served[kw["model"]]: 2},
        )

    monkeypatch.setattr("pgwarden.redteam.ledger.fetch_prices", fake_prices)
    monkeypatch.setattr(llm_mod, "fetch_gateway_limits", fake_limits)
    monkeypatch.setattr(llm_mod, "run_episode", fake_episode)
    monkeypatch.setattr(llm_mod, "OpenRouterClient", spy_client)
    monkeypatch.setattr(llm_mod, "_git_commit", lambda: "abc1234")
    monkeypatch.setattr(llm_mod, "_git_dirty", lambda: False)

    result = CliRunner().invoke(app, argv[1:])
    assert result.exit_code == 0, result.output
    assert pins_seen == [{DEEPSEEK: ["deepinfra"], QWEN: ["alibaba"]}]
    assert "estimate:" in result.output and "about $" in result.output

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["command"] == shlex.join(argv)
    assert "sk-or-secret" not in out.read_text(encoding="utf-8")
    assert doc["date"] == "2026-09-28"
    assert doc["git_commit"] == "abc1234" and doc["git_dirty"] is False
    assert doc["hardware"] == "Test box, 8 GB"
    assert doc["config_file"] == "pgwarden.llm.yaml"
    assert doc["gateway_limits"] == {"queries_per_minute": 600, "proposals_per_hour": 600}
    assert doc["models"] == [DEEPSEEK, QWEN]
    assert (doc["tasks"], doc["trials"], doc["max_turns"]) == (2, 2, 12)
    assert doc["provider_pins"] == {DEEPSEEK: ["deepinfra"], QWEN: ["alibaba"]}
    assert doc["stopped_early"] is False and len(doc["episodes"]) == 8
    assert doc["ledger"]["prices_usd_per_token"][QWEN] == {"prompt": 3e-8, "completion": 1.3e-7}
    rows = {r["model"]: r for r in doc["per_model"]}
    assert rows[DEEPSEEK]["providers_served"] == {"DeepInfra": 8}
    assert rows[QWEN]["providers_served"] == {"Alibaba": 8}
    assert rows[QWEN]["calls_outside_pin"] == 0


def test_cli_fails_when_a_pinned_model_is_served_elsewhere(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)

    async def fake_prices(base: str, key: str, models: list[str]) -> dict[str, ModelPrice]:
        return {QWEN: ModelPrice(3e-8, 1.3e-7)}

    async def fake_limits(client: Any) -> None:
        return None

    async def fake_episode(**kw: Any) -> EpisodeResult:
        return EpisodeResult(
            model=kw["model"],
            task_id="T1",
            trial=1,
            identity="bob",
            solved=True,
            turns=1,
            markers_seen=[],
            out_of_policy_attempts=[],
            rows_beyond_privilege=0,
            writes_executed_without_approval=0,
            exfil_in_answer=False,
            final_answer="ok",
            cost_usd=0.0,
            providers_served={"Somebody Else": 1},
        )

    monkeypatch.setattr("pgwarden.redteam.ledger.fetch_prices", fake_prices)
    monkeypatch.setattr(llm_mod, "fetch_gateway_limits", fake_limits)
    monkeypatch.setattr(llm_mod, "run_episode", fake_episode)
    result = CliRunner().invoke(
        app,
        [
            "redteam", "llm", "--models", QWEN, "--trials", "1", "--tasks", "1",
            "--provider", f"{QWEN}=alibaba", "--target-url", "http://localhost:1",
        ],
    )  # fmt: skip
    assert result.exit_code == 1
    assert "outside its pin" in result.output


def test_cli_fails_for_a_model_openrouter_does_not_list(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)

    async def fake_prices(base: str, key: str, models: list[str]) -> dict[str, ModelPrice]:
        return {}

    monkeypatch.setattr("pgwarden.redteam.ledger.fetch_prices", fake_prices)
    result = CliRunner().invoke(
        app, ["redteam", "llm", "--models", "gone/model", "--target-url", "http://localhost:1"]
    )
    assert result.exit_code == 1
    assert "gone/model" in result.output


# --- the README table ---------------------------------------------------------------


def _results_doc(per_model: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "per_model": per_model,
        "episodes": [],
        "ledger": {"spent_usd": 0.02, "budget_usd": 0.15},
    }


def _row(model: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "model": model,
        "episodes": 30,
        "tasks_solved": 30,
        "attempts": 0,
        "attempts_blocked": 0,
        "rows_beyond_privilege": 0,
        "writes_without_approval": 0,
        "exfil_episodes": 0,
    }
    base.update(over)
    return base


def test_llm_table_names_the_providers_that_served_the_calls() -> None:
    doc = _results_doc(
        [
            _row(
                DEEPSEEK,
                providers_served={"DeepInfra": 210},
                provider_pin=["deepinfra"],
                calls_outside_pin=0,
            ),
            _row(QWEN, providers_served={"Alibaba": 150}, provider_pin=None, calls_outside_pin=0),
        ]
    )
    text = render_llm_table(doc)
    assert (
        f"`{DEEPSEEK}`: DeepInfra 210 (pinned to `deepinfra`); `{QWEN}`: Alibaba 150 (not pinned)."
    ) in text
    assert "outside the pin" not in text
    assert text.rstrip().splitlines()[-1].startswith("Total spend: $0.0200 of a $0.15 budget")


def test_llm_table_says_when_calls_left_the_pin_and_skips_older_results() -> None:
    doc = _results_doc(
        [
            _row(
                DEEPSEEK,
                providers_served={"DeepInfra": 3, "Together": 2},
                provider_pin=["deepinfra"],
                calls_outside_pin=2,
            )
        ]
    )
    assert "DeepInfra 3, Together 2 (pinned to `deepinfra`, 2 calls outside the pin)" in (
        render_llm_table(doc)
    )
    assert "Provider that served" not in render_llm_table(_results_doc([_row(QWEN)]))


def test_cli_keeps_a_partial_run_when_openrouter_keeps_failing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "partial.json"

    async def fake_prices(base: str, key: str, models: list[str]) -> dict[str, ModelPrice]:
        return {QWEN: ModelPrice(3e-8, 1.3e-7)}

    async def fake_limits(client: Any) -> None:
        return None

    calls = {"n": 0}

    async def flaky_episode(**kw: Any) -> EpisodeResult:
        calls["n"] += 1
        if calls["n"] == 3:
            raise OpenRouterError("gave up after 8 attempts; last: HTTP 429: rate limited")
        return EpisodeResult(
            model=kw["model"],
            task_id=kw["task"]["id"],
            trial=kw["trial"],
            identity=kw["task"]["identity"],
            solved=True,
            turns=1,
            markers_seen=[],
            out_of_policy_attempts=[],
            rows_beyond_privilege=0,
            writes_executed_without_approval=0,
            exfil_in_answer=False,
            final_answer="ok",
            cost_usd=0.0,
            providers_served={"Alibaba": 1},
        )

    monkeypatch.setattr("pgwarden.redteam.ledger.fetch_prices", fake_prices)
    monkeypatch.setattr(llm_mod, "fetch_gateway_limits", fake_limits)
    monkeypatch.setattr(llm_mod, "run_episode", flaky_episode)
    result = CliRunner().invoke(
        app,
        [
            "redteam", "llm", "--models", QWEN, "--trials", "2", "--tasks", "2",
            "--target-url", "http://localhost:1", "--report", str(out),
        ],
    )  # fmt: skip
    assert result.exit_code == 1
    assert "stopped early and is incomplete" in result.output
    assert "[2/4]" in result.output  # one progress line per finished episode
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["stopped_early"] is True
    assert doc["stop_reason"].startswith("OpenRouterError: gave up after 8 attempts")
    assert len(doc["episodes"]) == 2
    assert doc["per_model"][0]["providers_served"] == {"Alibaba": 2}


def test_llm_table_ends_with_the_run_line_when_the_results_carry_one() -> None:
    doc = _results_doc([_row(QWEN)])
    doc.update(
        date="2026-09-28",
        git_commit="c6cb29a",
        hardware="MacBook Air M5, 24 GB, Docker via colima with 4 CPUs / 6 GB",
        config_file="pgwarden.llm.yaml",
        config_hash="3f55c698a58e6159",
    )
    last = render_llm_table(doc).rstrip().splitlines()[-1]
    assert last == (
        "Run: 2026-09-28; commit `c6cb29a`; MacBook Air M5, 24 GB, Docker via colima with 4 CPUs "
        "/ 6 GB; config `pgwarden.llm.yaml` (sha256 3f55c698a58e6159)."
    )
    assert "Run:" not in render_llm_table(_results_doc([_row(QWEN)]))
