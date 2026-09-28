"""A cost ledger for the LLM run: tokens x published price, with a hard budget stop.

Prices are fetched once from OpenRouter's models endpoint. Each call's cost is the
figure OpenRouter reports in the completion's ``usage.cost``; when that is missing the
generation-stats endpoint is asked, and when that is missing too the cost is estimated
from token counts (and counted in ``estimated_calls``). The same two sources carry the
provider that served a call: the completion's top-level ``provider`` field, then the
generation stats' ``provider_name``. ``check_before`` refuses to start a call once the
budget is spent.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import httpx


class BudgetExceeded(RuntimeError):
    """Raised when a call would exceed the configured USD budget."""


@dataclasses.dataclass
class ModelPrice:
    prompt_per_token: float
    completion_per_token: float


@dataclasses.dataclass
class Ledger:
    budget_usd: float
    prices: dict[str, ModelPrice] = dataclasses.field(default_factory=dict)
    spent_usd: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    estimated_calls: int = 0

    def check_before(self, headroom_usd: float = 0.05) -> None:
        if self.spent_usd >= self.budget_usd - headroom_usd:
            raise BudgetExceeded(
                f"spent ${self.spent_usd:.4f} of ${self.budget_usd:.2f}; stopping before the cap"
            )

    def record(
        self, model: str, prompt_tokens: int, completion_tokens: int, actual_usd: float | None
    ) -> float:
        price = self.prices.get(model, ModelPrice(0.0, 0.0))
        cost = (
            actual_usd
            if actual_usd is not None
            else prompt_tokens * price.prompt_per_token
            + completion_tokens * price.completion_per_token
        )
        self.spent_usd += cost
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.calls += 1
        if actual_usd is None:
            self.estimated_calls += 1
        return cost

    def summary(self) -> dict[str, object]:
        return {
            "budget_usd": self.budget_usd,
            "spent_usd": round(self.spent_usd, 4),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "calls": self.calls,
            "calls_cost_estimated_from_tokens": self.estimated_calls,
            "prices_usd_per_token": {
                model: {
                    "prompt": price.prompt_per_token,
                    "completion": price.completion_per_token,
                }
                for model, price in sorted(self.prices.items())
            },
        }


async def fetch_prices(base_url: str, api_key: str, models: list[str]) -> dict[str, ModelPrice]:
    async with httpx.AsyncClient(timeout=30.0) as http:
        resp = await http.get(
            f"{base_url.rstrip('/')}/models", headers={"Authorization": f"Bearer {api_key}"}
        )
        resp.raise_for_status()
    wanted = set(models)
    prices: dict[str, ModelPrice] = {}
    for m in resp.json().get("data", []):
        if m["id"] in wanted:
            p = m["pricing"]
            prices[m["id"]] = ModelPrice(float(p["prompt"]), float(p["completion"]))
    return prices


@dataclasses.dataclass
class GenerationStats:
    """What OpenRouter's generation endpoint knows about one call."""

    total_cost: float | None
    provider_name: str | None


def completion_cost(completion: dict[str, Any]) -> float | None:
    """The USD cost OpenRouter reports in the completion's ``usage`` block, if any."""
    usage = completion.get("usage")
    cost = usage.get("cost") if isinstance(usage, dict) else None
    if isinstance(cost, bool) or not isinstance(cost, (int, float)):
        return None
    return float(cost)


def completion_provider(completion: dict[str, Any]) -> str | None:
    """The provider that served the call: the completion's top-level ``provider`` field."""
    provider = completion.get("provider")
    return provider.strip() if isinstance(provider, str) and provider.strip() else None


async def fetch_generation_stats(
    base_url: str, api_key: str, generation_id: str
) -> GenerationStats | None:
    """One try at the generation endpoint (it can lag a completion by 10 s or more)."""
    if not generation_id:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            resp = await http.get(
                f"{base_url.rstrip('/')}/generation",
                params={"id": generation_id},
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code != 200:
            return None
        data = resp.json()["data"]
        cost = data.get("total_cost")
        provider = data.get("provider_name")
        return GenerationStats(
            total_cost=float(cost) if cost is not None else None,
            provider_name=provider if isinstance(provider, str) and provider else None,
        )
    except (httpx.HTTPError, KeyError, ValueError, TypeError):
        return None


__all__ = [
    "BudgetExceeded",
    "GenerationStats",
    "Ledger",
    "ModelPrice",
    "completion_cost",
    "completion_provider",
    "fetch_generation_stats",
    "fetch_prices",
]
