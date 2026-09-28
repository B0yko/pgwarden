"""Run docs/own-database.md, block by block, against a real Postgres.

``doc_blocks`` extracts the document's fenced blocks (each one is opened with a
language and a name, such as ``sql admin``, and the parser fails on any block
without a name, so nothing in the document goes unexecuted). ``Scenario`` renames the
document's example hosts and identifiers for one run (a unique suffix on every
cluster-global name), executes the blocks as the document says, and removes
everything it created. Only the renames in ``Scenario.render`` differ from the text
a reader copies.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx

DOC = Path(__file__).resolve().parents[2] / "docs" / "own-database.md"

# Names in the document that are cluster-global (roles) or must not collide (databases).
# ``pw_masker`` is deliberately absent: pgwarden fixes that name.
_RENAMED = (
    "analyst",
    "pgwarden_admin",
    "pgwarden_app",
    "pgwarden_state",
    "app",
    "alice",
    "reporting_bot",
    "pw_u_alice",
    "pw_m_reporting_bot",
)
_RENAME_RE = re.compile(r"\b(" + "|".join(sorted(_RENAMED, key=len, reverse=True)) + r")\b")

EXPECTED_BLOCKS = {"migration", "pgwarden.yaml", "admin", "provision", "serve", "check"}
MASKER_ROLE = "pw_masker"


def doc_blocks() -> dict[str, str]:
    """The document's fenced blocks by name; fails on an unnamed or unexpected block."""
    blocks: dict[str, str] = {}
    lines = DOC.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("```"):
            info = lines[i][3:].split()
            assert len(info) == 2, f"{DOC.name}:{i + 1}: fence needs '<language> <name>': {info}"
            end = next(j for j in range(i + 1, len(lines)) if lines[j].startswith("```"))
            assert info[1] not in blocks, f"duplicate block name {info[1]}"
            blocks[info[1]] = "\n".join(lines[i + 1 : end]) + "\n"
            i = end
        i += 1
    assert set(blocks) == EXPECTED_BLOCKS, f"blocks in {DOC.name}: {sorted(blocks)}"
    return blocks


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def with_database(dsn: str, dbname: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))


async def _execute(dsn: str, *statements: str) -> None:
    conn = await asyncpg.connect(dsn, timeout=10)
    try:
        for statement in statements:
            await conn.execute(statement)
    finally:
        await conn.close()


async def _role_exists(dsn: str, role: str) -> bool:
    conn = await asyncpg.connect(dsn, timeout=10)
    try:
        return bool(await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role))
    finally:
        await conn.close()


@dataclasses.dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


@dataclasses.dataclass
class Scenario:
    """One renamed run of the document in its own database and working directory."""

    superuser_dsn: str
    workdir: Path
    suffix: str = dataclasses.field(default_factory=lambda: "od" + secrets.token_hex(3))
    gateway_port: int = dataclasses.field(default_factory=free_port)
    blocks: dict[str, str] = dataclasses.field(default_factory=doc_blocks)
    created_masker: bool = False
    _servers: list[subprocess.Popen[str]] = dataclasses.field(init=False, default_factory=list)

    def name(self, documented: str) -> str:
        return f"{documented}_{self.suffix}"

    @property
    def public_url(self) -> str:
        return f"http://127.0.0.1:{self.gateway_port}"

    def render(self, text: str) -> str:
        """The document's text with this run's host, ports and names."""
        parts = urlsplit(self.superuser_dsn)
        renames = {
            "db.example.com:5432": f"{parts.hostname}:{parts.port or 5432}",
            "sslmode=verify-full": "sslmode=disable",
            "https://pgwarden.example.com": self.public_url,
            "--host 0.0.0.0 --port 8080": f"--host 127.0.0.1 --port {self.gateway_port}",
        }
        for documented, actual in renames.items():
            text = text.replace(documented, actual)
        return _RENAME_RE.sub(lambda m: self.name(m.group(1)), text)

    def database_dsn(self, documented: str = "app") -> str:
        return with_database(self.superuser_dsn, self.name(documented))

    # -- the DBA's side: database, migration, admin role -------------------------------

    def create_database(self) -> None:
        asyncio.run(_execute(self.superuser_dsn, f'CREATE DATABASE "{self.name("app")}"'))

    def run_migration(self) -> None:
        asyncio.run(_execute(self.database_dsn(), self.render(self.blocks["migration"])))

    def create_admin(self, edits: dict[str, str] | None = None) -> None:
        """Run the document's admin block as the superuser.

        ``edits`` maps a piece of the documented text to its replacement (``""`` removes
        it), to show that a privilege the document lists is really needed.
        """
        sql = self.render(self.blocks["admin"])
        if asyncio.run(_role_exists(self.superuser_dsn, MASKER_ROLE)):
            # the document says to skip this line when pw_masker already exists
            create_masker = f"CREATE ROLE {MASKER_ROLE} NOLOGIN;\n"
            assert create_masker in sql
            sql = sql.replace(create_masker, "")
        else:
            self.created_masker = True
        for documented, replacement in (edits or {}).items():
            old = self.render(documented)
            assert sql.count(old) == 1, f"the admin block must contain {old!r} exactly once"
            sql = sql.replace(old, self.render(replacement))
        asyncio.run(_execute(self.database_dsn(), sql))

    # -- the operator's side: the document's shell blocks -----------------------------

    def env(self) -> dict[str, str]:
        """A clean environment: the pgwarden executable and nothing of ours."""
        path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
        return {"PATH": path, "HOME": str(self.workdir), "PYTHONIOENCODING": "utf-8"}

    def write_config(self) -> None:
        (self.workdir / "pgwarden.yaml").write_text(
            self.render(self.blocks["pgwarden.yaml"]), encoding="utf-8"
        )

    def bash(self, script: str, *, timeout: float = 180) -> Result:
        done = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script],
            cwd=self.workdir,
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return Result(done.returncode, done.stdout, done.stderr)

    def provision(self, *, without: str | None = None) -> Result:
        """Run the document's ``provision`` block, optionally leaving out one command line."""
        script = self.render(self.blocks["provision"])
        if without is not None:
            kept = [line for line in script.splitlines() if not line.startswith(without)]
            assert len(kept) == len(script.splitlines()) - 1, f"no single line starts {without!r}"
            script = "\n".join(kept) + "\n"
        return self.bash(script)

    def install_oidc_client_secret(self) -> None:
        """The one file the document tells the operator to supply themselves."""
        path = self.workdir / "secrets" / "oidc_client_secret"
        path.write_text("secret-issued-by-the-identity-provider\n", encoding="utf-8")

    def start_serve(self, *, before: str = "") -> subprocess.Popen[str]:
        """Start the document's ``serve`` block; ``before`` is shell run first (a negative)."""
        log = (self.workdir / f"serve-{len(self._servers)}.log").open("w", encoding="utf-8")
        proc = subprocess.Popen(
            ["bash", "-euo", "pipefail", "-c", before + self.render(self.blocks["serve"])],
            cwd=self.workdir,
            env=self.env(),
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self._servers.append(proc)
        return proc

    def serve_log(self, proc: subprocess.Popen[str]) -> str:
        return (self.workdir / f"serve-{self._servers.index(proc)}.log").read_text(encoding="utf-8")

    def wait_ready(self, proc: subprocess.Popen[str], *, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(f"serve exited {proc.returncode}:\n{self.serve_log(proc)}")
            with contextlib.suppress(httpx.HTTPError):
                ready = httpx.get(f"{self.public_url}/readyz", timeout=2, trust_env=False)
                if ready.status_code == 200:
                    return
            time.sleep(0.3)
        raise AssertionError(f"serve was not ready in {timeout}s:\n{self.serve_log(proc)}")

    def check(self) -> Result:
        return self.bash(self.render(self.blocks["check"]))

    def admin_attributes(self) -> dict[str, bool]:
        """The admin role's superuser and RLS-bypass flags, read back from the catalog."""

        async def read() -> dict[str, bool]:
            conn = await asyncpg.connect(self.superuser_dsn, timeout=10)
            try:
                row = await conn.fetchrow(
                    "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
                    "WHERE rolname = $1",
                    self.name("pgwarden_admin"),
                )
            finally:
                await conn.close()
            assert row is not None
            return {key: bool(value) for key, value in row.items()}

        return asyncio.run(read())

    def machine_secret(self) -> str:
        return (self.workdir / "secrets" / "machine-reporting-bot").read_text().strip()

    # -- cleanup --------------------------------------------------------------------

    def close(self) -> None:
        for proc in self._servers:
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=10)
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
        statements = [
            f'DROP DATABASE IF EXISTS "{self.name("app")}" WITH (FORCE)',
            f'DROP DATABASE IF EXISTS "{self.name("pgwarden_state")}" WITH (FORCE)',
            # the admin granted the bundle to these roles, so they go before the admin
            f'DROP ROLE IF EXISTS "pw_u_{self.name("alice")}"',
            f'DROP ROLE IF EXISTS "pw_m_{self.name("reporting_bot")}"',
            f'DROP ROLE IF EXISTS "{self.name("analyst")}"',
            f'DROP ROLE IF EXISTS "{self.name("pgwarden_app")}"',
            f'DROP ROLE IF EXISTS "{self.name("pgwarden_admin")}"',
        ]
        if self.created_masker:
            statements.append(f"DROP ROLE IF EXISTS {MASKER_ROLE}")
        asyncio.run(_execute(self.superuser_dsn, *statements))


@contextlib.contextmanager
def scenario(superuser_dsn: str, workdir: Path) -> Iterator[Scenario]:
    run = Scenario(superuser_dsn=superuser_dsn, workdir=workdir)
    try:
        yield run
    finally:
        run.close()
