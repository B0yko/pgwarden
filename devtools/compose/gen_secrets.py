"""Create the demo stack's secrets in ./.pgwarden-dev/ (the `secrets` service).

Runs once before Postgres starts. Every secret is created only if it is missing,
so `docker compose up` is idempotent and existing secrets survive restarts.
Nothing here is ever committed: .pgwarden-dev/ is gitignored.

Layout (each directory is mounted only where it is needed):

  postgres/   postgres_password                       -> postgres
  gateway/    state_dsn role_secret signing_key.pem
              session_secret oidc_client_secret       -> gateway (read-only)
  idp/        oidc_client_secret                      -> mock-idp
  admin/      admin_dsn admin_dsn_host                -> init only (never the gateway)
  host/       state_dsn_host                          -> host-side tests and CLI
  machines/   machine-<name>                          <- written by init

Container-facing DSNs use the compose service name; the *_host variants use the
published host port for tests and CLI commands that run on the host.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from pgwarden.oauth.keys import generate_signing_key_pem

OUT = Path(os.environ.get("PGWARDEN_DEV_SECRETS", "/dev-secrets"))
PG_HOST_PORT = os.environ.get("POSTGRES_PORT", "5432")
GATEWAY_UID = 10001


def _dir(name: str, *, owner_uid: int | None = None) -> Path:
    path = OUT / name
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o755)  # traversable by the postgres (999) and gateway (10001) users
    if owner_uid is not None and os.geteuid() == 0:
        os.chown(path, owner_uid, owner_uid)
    return path


def _write(path: Path, value: str, *, keep: bool) -> bool:
    if keep and path.is_file():
        return False
    path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")
    path.chmod(0o644)
    return True


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    OUT.chmod(0o755)
    postgres = _dir("postgres")
    gateway = _dir("gateway")
    idp = _dir("idp")
    admin = _dir("admin")
    host = _dir("host")
    _dir("machines", owner_uid=GATEWAY_UID)
    private = _dir("private")

    created: list[str] = []
    generated = {
        postgres / "postgres_password": lambda: secrets.token_urlsafe(24),
        private / "pgwarden_app_password": lambda: secrets.token_urlsafe(24),
        gateway / "role_secret": lambda: secrets.token_urlsafe(32),
        gateway / "session_secret": lambda: secrets.token_urlsafe(32),
        gateway / "oidc_client_secret": lambda: secrets.token_urlsafe(32),
        gateway / "signing_key.pem": generate_signing_key_pem,
    }
    for path, factory in generated.items():
        if _write(path, factory(), keep=True):
            created.append(f"{path.parent.name}/{path.name}")

    pg_pw = _read(postgres / "postgres_password")
    app_pw = _read(private / "pgwarden_app_password")
    derived = {
        gateway / "state_dsn": (
            f"postgresql://pgwarden_app:{app_pw}@postgres:5432/pgwarden?sslmode=disable"
        ),
        idp / "oidc_client_secret": _read(gateway / "oidc_client_secret"),
        admin / "admin_dsn": f"postgresql://postgres:{pg_pw}@postgres:5432/postgres?sslmode=disable",
        admin / "admin_dsn_host": (
            f"postgresql://postgres:{pg_pw}@127.0.0.1:{PG_HOST_PORT}/postgres?sslmode=disable"
        ),
        host / "state_dsn_host": (
            f"postgresql://pgwarden_app:{app_pw}@127.0.0.1:{PG_HOST_PORT}/pgwarden?sslmode=disable"
        ),
    }
    for path, value in derived.items():
        _write(path, value, keep=False)
    print(f"secrets ready in {OUT} (created: {', '.join(created) or 'none'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
