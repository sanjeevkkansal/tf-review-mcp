"""Canary test: run mcp-adversarial against tf-review-mcp itself.

This is the test that earns the "tested against mcp-adversarial" claim.
Spawns the real server via `python -m tf_review_mcp.server`, drives it
through the harness, and asserts every packaged Terraform fixture
passes.

The test is skipped when the optional sibling package is not importable
(e.g. someone running a stripped-down pip install of tf-review-mcp
without the workspace), so a partial install does not break CI.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest

mcp_adversarial = pytest.importorskip("mcp_adversarial")
from mcp_adversarial.runner import run_harness  # noqa: E402


SERVER_CMD = shlex.join([sys.executable, "-m", "tf_review_mcp.server"])
FIXTURE_ROOT = (
    Path(mcp_adversarial.__file__).parent / "fixtures"
)


def _retarget_fixtures(fixtures_in: Path, tmp_path: Path, new_tool: str) -> Path:
    """Copy terraform fixtures into tmp_path with `tool` rewritten."""
    import json

    out = tmp_path / "fx"
    out.mkdir()
    for src in (fixtures_in / "terraform").glob("*.json"):
        fx = json.loads(src.read_text())
        fx["tool"] = new_tool
        (out / src.name).write_text(json.dumps(fx))
    return out


def test_canary_review_plan_against_terraform_fixtures(tmp_path):
    fixtures = _retarget_fixtures(FIXTURE_ROOT, tmp_path, "review_plan")
    report = run_harness(server_command=SERVER_CMD, fixtures_dir=fixtures, timeout=20.0)

    assert report.fixtures_total > 0, "expected packaged terraform fixtures"
    failures = [r for r in report.results if not r.passed]
    assert not failures, _format_failures(report)


def test_canary_suggest_review_comments_against_terraform_fixtures(tmp_path):
    fixtures = _retarget_fixtures(FIXTURE_ROOT, tmp_path, "suggest_review_comments")
    report = run_harness(server_command=SERVER_CMD, fixtures_dir=fixtures, timeout=20.0)

    assert report.fixtures_total > 0
    failures = [r for r in report.results if not r.passed]
    assert not failures, _format_failures(report)


def test_canary_estimate_cost_delta_returns_structured_error_without_infracost(
    tmp_path, monkeypatch
):
    """Even without infracost on PATH, cost tool must not crash on
    adversarial input; it must return a structured error string."""
    monkeypatch.setenv("PATH", "/nonexistent")
    fixtures = _retarget_fixtures(FIXTURE_ROOT, tmp_path, "estimate_cost_delta")
    report = run_harness(server_command=SERVER_CMD, fixtures_dir=fixtures, timeout=20.0)

    failures = [r for r in report.results if not r.passed]
    assert not failures, _format_failures(report)


def _format_failures(report) -> str:
    lines = [f"{report.fixtures_failed} fixture(s) failed:"]
    for r in report.results:
        if not r.passed:
            lines.append(f"  - {r.fixture_id}: {'; '.join(r.reasons)}")
    return "\n".join(lines)
