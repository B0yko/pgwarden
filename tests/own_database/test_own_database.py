"""Follow docs/own-database.md literally against a plain Postgres 16.

The document's fenced blocks are the test's script (``helpers/own_database.py``): the
DBA's migration and the admin role run as SQL, the provisioning commands and
``pgwarden serve`` run as the document's own shell blocks with the real CLI, and the
check block makes a real MCP round trip over HTTP. The admin is a role created from
the document's SQL, never a superuser. The superuser DSN in ``OWN_DB_ADMIN_DSN`` (or
``PGWARDEN_TEST_ADMIN_DSN``) only plays the DBA who runs steps 1 and 3 and cleans up.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from helpers.own_database import Scenario, scenario
from pgwarden.redteam.mcp_client import call_tool
from pgwarden.redteam.stack import StackClient

pytestmark = pytest.mark.pg


def _required(what: str) -> None:
    if os.environ.get("PGWARDEN_REQUIRE_PG") == "1":
        pytest.fail(f"{what} is required when PGWARDEN_REQUIRE_PG=1")
    pytest.skip(f"{what} not available for the own-database test")


@pytest.fixture(scope="module")
def superuser_dsn() -> str:
    dsn = os.environ.get("OWN_DB_ADMIN_DSN") or os.environ.get("PGWARDEN_TEST_ADMIN_DSN")
    if not dsn:
        _required("OWN_DB_ADMIN_DSN (or PGWARDEN_TEST_ADMIN_DSN)")
    assert dsn is not None
    for tool in ("bash", "curl", "jq"):  # the document's check block uses them
        if shutil.which(tool) is None:
            _required(tool)
    return dsn


@pytest.fixture
def run(superuser_dsn: str, tmp_path: Path) -> Iterator[Scenario]:
    """A fresh database with the document's steps 1 to 3 done (no pgwarden command yet)."""
    with scenario(superuser_dsn, tmp_path) as sc:
        sc.create_database()
        sc.run_migration()
        sc.create_admin()
        sc.write_config()
        yield sc


def _json_documents(text: str) -> list[dict[str, Any]]:
    """The JSON values ``jq`` printed one after another."""
    decoder = json.JSONDecoder()
    documents: list[dict[str, Any]] = []
    position = 0
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        value, position = decoder.raw_decode(text, position)
        documents.append(value)
    return documents


def test_the_document_end_to_end(run: Scenario) -> None:
    # the admin the document creates is an ordinary role, not a superuser
    assert run.admin_attributes() == {
        "rolsuper": False,
        "rolbypassrls": False,
        "rolcreaterole": True,
        "rolcreatedb": True,
    }

    # step 4: provision as that admin (`bash -e`: any failing command fails the block)
    provisioned = run.provision()
    assert provisioned.returncode == 0, provisioned.output
    assert "[PASS] pooler_mode" in provisioned.stdout, provisioned.stdout
    assert "[PASS] masking_invariant" in provisioned.stdout, provisioned.stdout
    assert "[PASS] rls_required" in provisioned.stdout, provisioned.stdout
    assert "[FAIL]" not in provisioned.stdout, provisioned.stdout
    run.install_oidc_client_secret()

    # running the block again reconciles with no changes (it only skips the once-only key
    # generation), so the same privileges also cover a rerun
    rerun = run.provision(without="pgwarden keys generate")
    assert rerun.returncode == 0, rerun.output
    assert rerun.stdout.count("no changes") == 2, rerun.stdout  # roles sync, masking apply

    # step 5: serve refuses to start while the admin credential is in its environment ...
    for variable in ("PGWARDEN_ADMIN_DSN", "PGWARDEN_ADMIN_DSN_FILE"):
        refused = run.start_serve(before=f"export {variable}=anything\n")
        assert refused.wait(timeout=60) != 0
        assert f"{variable} must not be set" in run.serve_log(refused)

    # ... and starts with exactly the variables the document lists.
    server = run.start_serve()
    run.wait_ready(server)

    # step 6: the document's own check, over HTTP as a machine identity
    checked = run.check()
    assert checked.returncode == 0, checked.output
    who, rows = _json_documents(checked.stdout)
    assert who["pg_role"] == f"pw_m_{run.name('reporting_bot')}"
    assert who["bundles"] == [run.name("analyst")]
    assert who["masking_applies"] is True
    # RLS keyed on session_user kept the "us" row out, and the masked view hid the email
    assert rows["rows_untrusted"] == [{"team": "eu", "owner_email": "a***@example.com"}], rows

    # the base table stays out of reach when the view is bypassed by name
    async def bypass_attempts() -> tuple[dict[str, Any] | None, list[Any]]:
        client = StackClient(run.public_url)
        tokens = await client.machine_token("reporting-bot", run.machine_secret())
        raw = await call_tool(
            client.mcp_endpoint,
            tokens.access_token,
            "query",
            {"sql": "SELECT owner_email FROM public.reports"},
        )
        count = await call_tool(
            client.mcp_endpoint,
            tokens.access_token,
            "query",
            {"sql": "SELECT count(*) AS n FROM reports"},
        )
        return raw.tool_error, count.result.get("rows_untrusted", [])

    raw_error, counted = asyncio.run(bypass_attempts())
    assert raw_error is not None and "permission denied" in json.dumps(raw_error), raw_error
    assert counted == [{"n": 1}]


# What each provisioning command has printed by the time the next one runs, so a failure
# can be pinned on the command the document says needs the privilege.
_REACHED = {
    "db init": ("wrote ", "applied migrations"),
    "roles sync": ("applied migrations", "ran: [pw_"),
    "masking apply": ("ran: [pw_u_", "[function-schema]"),
}

# Each privilege the document's step 3 grants, removed on its own: the command that then
# fails, and the Postgres error it fails with.
ABLATIONS = [
    pytest.param(
        {" CREATEDB": ""}, "db init", "permission denied to create database", id="no-createdb"
    ),
    pytest.param(
        {" CREATEROLE": ""}, "db init", "permission denied to create role", id="no-createrole"
    ),
    pytest.param(
        {"GRANT analyst TO pgwarden_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;\n": ""},
        "roles sync",
        "permission denied to grant role",
        id="no-admin-option-on-the-bundle",
    ),
    pytest.param(
        {"GRANT CREATE ON DATABASE app TO pgwarden_admin;\n": ""},
        "masking apply",
        "permission denied for database",
        id="no-create-on-database",
    ),
    pytest.param(
        {"GRANT pw_masker TO pgwarden_admin WITH INHERIT TRUE, SET TRUE;\n": ""},
        "masking apply",
        'must be able to SET ROLE "pw_masker"',
        id="no-membership-in-pw_masker",
    ),
    pytest.param(
        {"WITH INHERIT TRUE, SET TRUE": "WITH INHERIT FALSE, SET TRUE"},
        "masking apply",
        "permission denied for schema pw_fn",
        id="pw_masker-without-inherit",
    ),
    pytest.param(
        {"GRANT SELECT ON public.reports TO pgwarden_admin WITH GRANT OPTION;\n": ""},
        "masking apply",
        "permission denied for table reports",
        id="no-grant-option-on-the-masked-table",
    ),
]


@pytest.mark.parametrize(("edits", "command", "error"), ABLATIONS)
def test_every_listed_admin_privilege_is_needed(
    superuser_dsn: str, tmp_path: Path, edits: dict[str, str], command: str, error: str
) -> None:
    with scenario(superuser_dsn, tmp_path) as sc:
        sc.create_database()
        sc.run_migration()
        sc.create_admin(edits)
        sc.write_config()
        provisioned = sc.provision()
        assert provisioned.returncode != 0, provisioned.output
        assert error in provisioned.output, provisioned.output
        ran, not_yet = _REACHED[command]
        assert ran in provisioned.stdout, f"{command} was not reached:\n{provisioned.output}"
        assert not_yet not in provisioned.stdout, f"{command} got through:\n{provisioned.output}"
