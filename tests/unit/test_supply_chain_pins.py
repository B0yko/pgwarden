"""Build inputs are pinned: actions by commit SHA, Dockerfile and compose images by digest,
Python dependencies by hash in uv.lock.

CI database service containers deliberately use the official Postgres major-version tags,
because the matrix exists to test those majors; they are not covered here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    unpinned: list[str] = []
    for workflow in (REPO_ROOT / ".github" / "workflows").glob("*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = re.search(r"\buses:\s*(\S+)", line)
            if match and not re.search(r"@[0-9a-f]{40}$", match.group(1)):
                unpinned.append(f"{workflow.name}: {match.group(1)}")
    assert unpinned == []


def test_dockerfile_base_images_are_pinned_by_digest() -> None:
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
    assert froms, "no FROM lines found"
    unpinned = [ref for ref in froms if "@sha256:" not in ref and ref not in _stage_names(text)]
    assert unpinned == []


def _stage_names(dockerfile: str) -> set[str]:
    return set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", dockerfile, re.MULTILINE | re.IGNORECASE))


def test_compose_images_are_pinned_by_digest_unless_built_here() -> None:
    compose = yaml.safe_load((REPO_ROOT / "compose.yaml").read_text(encoding="utf-8"))
    unpinned: list[str] = []
    for name, service in compose["services"].items():
        image = service.get("image")
        if image and "build" not in service and "@sha256:" not in image:
            unpinned.append(f"{name}: {image}")
    # services that reuse the locally built gateway image through a YAML anchor carry a
    # `build:` key after merge; anything else must name a digest
    assert unpinned == []


def test_uv_lock_records_hashes() -> None:
    lock = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    assert lock.count('hash = "sha256:') > 100
