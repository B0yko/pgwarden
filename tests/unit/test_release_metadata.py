"""Every place that names the release agrees: the package version, server.json for the
MCP Registry, the image label the registry checks, and the README's pull command.

A release bumps all of them together; this test fails if one is left behind.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pgwarden

REPO_ROOT = Path(__file__).resolve().parents[2]


def _version() -> str:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(pyproject["project"]["version"])


def _server() -> dict[str, object]:
    data = json.loads((REPO_ROOT / "server.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _oci_package() -> dict[str, object]:
    packages = _server()["packages"]
    assert isinstance(packages, list)
    oci = [p for p in packages if p["registryType"] == "oci"]
    assert len(oci) == 1
    package = oci[0]
    assert isinstance(package, dict)
    return package


def test_package_and_module_versions_match() -> None:
    assert pgwarden.__version__ == _version()


def test_server_json_names_this_release_image() -> None:
    assert _server()["version"] == _version()
    assert _oci_package()["identifier"] == f"ghcr.io/b0yko/pgwarden:{_version()}"


def test_runtime_image_carries_the_registry_ownership_label() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    final_stage = re.split(r"^FROM\s", dockerfile, flags=re.MULTILINE)[-1]
    label = re.search(r'io\.modelcontextprotocol\.server\.name="([^"]+)"', final_stage)
    assert label is not None, "the final Dockerfile stage has no MCP Registry label"
    # The registry compares the label with server.json's name, case-sensitively.
    assert label.group(1) == _server()["name"] == "io.github.B0yko/pgwarden"


def test_server_json_env_matches_the_documented_serve_block() -> None:
    doc = (REPO_ROOT / "docs" / "own-database.md").read_text(encoding="utf-8")
    block = re.search(r"```bash serve\n(.*?)```", doc, re.DOTALL)
    assert block is not None
    documented = set(re.findall(r"^export (PGWARDEN_\w+)=", block.group(1), re.MULTILINE))
    env = _oci_package()["environmentVariables"]
    assert isinstance(env, list)
    assert {v["name"] for v in env} == documented


def test_readme_pulls_this_release() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    tags = set(re.findall(r"ghcr\.io/b0yko/pgwarden:(\S+)", readme))
    assert tags == {_version()}


def test_release_workflow_publishes_to_the_mcp_registry_after_the_image() -> None:
    import yaml

    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["mcp-registry"]
    assert job["needs"] == "image"
    assert job["permissions"]["id-token"] == "write"
    assert re.fullmatch(r"v\d+\.\d+\.\d+", job["env"]["MCP_PUBLISHER_VERSION"])
    assert re.fullmatch(r"[0-9a-f]{64}", job["env"]["MCP_PUBLISHER_SHA256"])
    assert job["env"]["TAG"] == "${{ inputs.tag || github.ref_name }}"
    dispatch = workflow[True]["workflow_dispatch"]  # PyYAML reads the `on` key as True
    assert dispatch["inputs"]["tag"]["required"] is True
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "sha256sum -c" in commands
    assert "mcp-publisher login github-oidc" in commands
    assert "mcp-publisher publish" in commands
