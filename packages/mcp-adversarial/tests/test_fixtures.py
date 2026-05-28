from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).parent.parent / "src" / "mcp_adversarial" / "fixtures"
REQUIRED_KEYS = {"id", "category", "args"}
KNOWN_CATEGORIES = {
    "injection",
    "exfil",
    "oversize",
    "traversal",
    "malformed",
    "nesting",
    "sanitize",
}


def _all_fixture_paths():
    return sorted(FIXTURE_ROOT.rglob("*.json"))


def test_fixture_root_exists():
    assert FIXTURE_ROOT.exists(), f"missing {FIXTURE_ROOT}"


def test_at_least_one_generic_and_terraform_fixture():
    generic = list((FIXTURE_ROOT / "generic").glob("*.json"))
    terraform = list((FIXTURE_ROOT / "terraform").glob("*.json"))
    assert generic, "no generic fixtures shipped"
    assert terraform, "no terraform fixtures shipped"


@pytest.mark.parametrize("path", _all_fixture_paths(), ids=lambda p: p.name)
def test_fixture_is_valid_json(path: Path):
    json.loads(path.read_text())


@pytest.mark.parametrize("path", _all_fixture_paths(), ids=lambda p: p.name)
def test_fixture_has_required_keys(path: Path):
    fx = json.loads(path.read_text())
    missing = REQUIRED_KEYS - set(fx)
    assert not missing, f"{path.name} missing keys {missing}"
    assert isinstance(fx["id"], str) and fx["id"].strip()
    assert isinstance(fx["category"], str) and fx["category"].strip()
    assert isinstance(fx["args"], dict)


@pytest.mark.parametrize("path", _all_fixture_paths(), ids=lambda p: p.name)
def test_fixture_category_is_known(path: Path):
    fx = json.loads(path.read_text())
    assert fx["category"] in KNOWN_CATEGORIES, (
        f"{path.name}: category {fx['category']!r} not in {sorted(KNOWN_CATEGORIES)}"
    )


def test_fixture_ids_are_unique():
    ids = []
    for path in _all_fixture_paths():
        fx = json.loads(path.read_text())
        ids.append(fx["id"])
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"duplicate fixture ids: {duplicates}"


def test_terraform_fixtures_target_tf_tool():
    """Terraform-flavored fixtures must name a tf-review-mcp tool."""
    expected_tools = {"review_plan", "suggest_review_comments", "estimate_cost_delta"}
    for path in (FIXTURE_ROOT / "terraform").glob("*.json"):
        fx = json.loads(path.read_text())
        assert "tool" in fx, f"{path.name}: terraform fixtures must specify a tool"
        assert fx["tool"] in expected_tools, (
            f"{path.name}: tool {fx['tool']!r} not in tf-review-mcp's surface"
        )


def test_generic_fixtures_omit_tool():
    """Generic fixtures should fan out across whatever tools the server has."""
    for path in (FIXTURE_ROOT / "generic").glob("*.json"):
        fx = json.loads(path.read_text())
        assert "tool" not in fx, (
            f"{path.name}: generic fixtures should not pin a tool name"
        )
