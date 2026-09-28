"""The live compose stack's coordinates, for stack tests and red-team tooling."""

from __future__ import annotations

import dataclasses
from pathlib import Path


def _dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


@dataclasses.dataclass(frozen=True)
class Stack:
    base_url: str
    idp_url: str
    mailpit_url: str
    secrets_dir: Path
    project: str

    def secret(self, relative: str) -> str:
        return (self.secrets_dir / relative).read_text(encoding="utf-8").strip()

    @property
    def admin_dsn(self) -> str:
        return self.secret("admin/admin_dsn_host")

    @property
    def state_dsn(self) -> str:
        return self.secret("host/state_dsn_host")

    def machine_secret(self, name: str) -> str:
        return self.secret(f"machines/machine-{name}")
