"""A cost ledger for the LLM run: tokens x published price, with a hard budget stop.

Prices are fetched once from OpenRouter's models endpoint; each generation's real
cost is read back from the generation-stats endpoint when available, else estimated
from token counts. ``check_before`` refuses to start a call once the budget is spent.
"""

from __future__ import annotations

import dataclasses

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
        return cost

    def summary(self) -> dict[str, object]:
        return {
            "budget_usd": self.budget_usd,
            "spent_usd": round(self.spent_usd, 4),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "calls": self.calls,
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


async def fetch_generation_cost(base_url: str, api_key: str, generation_id: str) -> float | None:
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            resp = await http.get(
                f"{base_url.rstrip('/')}/generation",
                params={"id": generation_id},
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code != 200:
            return None
        return float(resp.json()["data"]["total_cost"])
    except (httpx.HTTPError, KeyError, ValueError):
        return None


__all__ = ["BudgetExceeded", "Ledger", "ModelPrice", "fetch_generation_cost", "fetch_prices"]
