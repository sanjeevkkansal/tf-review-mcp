"""Tests for the Infracost wrapper in `cost.py`.

The Infracost binary is never actually invoked; `subprocess.run` and
`shutil.which` are mocked so the suite runs in CI without external deps.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tf_review_mcp.config import ReviewConfig, default_config
from tf_review_mcp.cost import CostSummary, estimate_cost_delta_from_plan

FIXTURE = Path(__file__).parent / "fixtures" / "example_plan.json"


def _infracost_payload(
    total: float,
    past: float,
    resources: list[dict] | None = None,
) -> dict:
    return {
        "version": "0.10.40",
        "currency": "USD",
        "totalMonthlyCost": str(total),
        "pastTotalMonthlyCost": str(past),
        "projects": [
            {
                "breakdown": {
                    "resources": resources or [],
                }
            }
        ],
    }


def _patch_infracost(payload: dict, returncode: int = 0, stderr: str = ""):
    """Return a context manager that patches shutil.which + _run_infracost."""
    return (
        patch("tf_review_mcp.cost.shutil.which", return_value="/usr/local/bin/infracost"),
        patch(
            "tf_review_mcp.cost._run_infracost",
            return_value=(returncode, json.dumps(payload), stderr),
        ),
    )


def test_estimate_returns_zero_for_noop_plan():
    payload = _infracost_payload(total=100.0, past=100.0, resources=[])
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, CostSummary)
    assert result.total_monthly_cost_delta_usd == 0.0
    assert result.top_contributors == []
    assert result.currency == "USD"
    assert result.infracost_version == "0.10.40"
    assert any("No monthly cost delta" in n for n in result.notes)


def test_estimate_surfaces_top_contributors_sorted_by_absolute_delta():
    resources = [
        {"name": "aws_db_instance.small", "monthlyCost": "20", "pastMonthlyCost": "10"},
        {"name": "aws_db_instance.huge", "monthlyCost": "600", "pastMonthlyCost": "100"},
        {"name": "aws_instance.web", "monthlyCost": "5", "pastMonthlyCost": "55"},
    ]
    payload = _infracost_payload(total=625.0, past=165.0, resources=resources)
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, CostSummary)
    assert result.total_monthly_cost_delta_usd == 460.0
    addrs = [c.address for c in result.top_contributors]
    assert addrs[0] == "aws_db_instance.huge"
    assert addrs[1] == "aws_instance.web"
    assert addrs[2] == "aws_db_instance.small"


def test_estimate_emits_warn_threshold_note():
    resources = [
        {"name": "aws_db_instance.huge", "monthlyCost": "600", "pastMonthlyCost": "0"},
    ]
    payload = _infracost_payload(total=600.0, past=0.0, resources=resources)
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, CostSummary)
    assert any("$500" in n for n in result.notes)


def test_estimate_emits_blocker_threshold_note():
    payload = _infracost_payload(total=2000.0, past=0.0)
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, CostSummary)
    assert any("Strong review recommended" in n for n in result.notes)


def test_estimate_handles_missing_binary():
    with patch("tf_review_mcp.cost.shutil.which", return_value=None):
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, dict)
    assert "not installed" in result["error"]
    assert "install" in result


def test_estimate_handles_infracost_nonzero_exit():
    which, run = _patch_infracost({}, returncode=1, stderr="boom: bad project")
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, dict)
    assert "non-zero" in result["error"]
    assert "boom" in result["stderr"]


def test_estimate_handles_timeout():
    import subprocess as _subprocess

    with (
        patch("tf_review_mcp.cost.shutil.which", return_value="/usr/local/bin/infracost"),
        patch(
            "tf_review_mcp.cost._run_infracost",
            side_effect=_subprocess.TimeoutExpired(cmd="infracost", timeout=60),
        ),
    ):
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, dict)
    assert "timed out" in result["error"]


def test_estimate_handles_missing_plan_file(tmp_path):
    missing = tmp_path / "nope.json"
    result = estimate_cost_delta_from_plan(missing)
    assert isinstance(result, dict)
    assert "not found" in result["error"]


def test_estimate_rejects_non_plan_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": "world"}))
    with patch("tf_review_mcp.cost.shutil.which", return_value="/usr/local/bin/infracost"):
        result = estimate_cost_delta_from_plan(bad)
    assert isinstance(result, dict)
    assert "terraform show" in result["hint"]


def test_cost_summary_to_dict_serializes_contributors():
    resources = [
        {"name": "aws_db_instance.huge", "monthlyCost": "600", "pastMonthlyCost": "100"},
    ]
    payload = _infracost_payload(total=600.0, past=100.0, resources=resources)
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE)
    assert isinstance(result, CostSummary)
    d = result.to_dict()
    assert d["top_contributors"][0]["address"] == "aws_db_instance.huge"
    assert d["top_contributors"][0]["monthly_cost_delta_usd"] == 500.0


def test_custom_cost_thresholds_change_note_level():
    """A $200 delta is normally info-level; lowering warn_usd to 150 promotes it."""
    base = default_config()
    cfg = ReviewConfig(
        high_risk_types=base.high_risk_types,
        stateful_types=base.stateful_types,
        public_cidrs=base.public_cidrs,
        cost_thresholds={"info_usd": 50.0, "warn_usd": 150.0, "blocker_usd": 999999.0},
        disabled_rules=frozenset(),
    )
    payload = _infracost_payload(total=200.0, past=0.0)
    which, run = _patch_infracost(payload)
    with which, run:
        result = estimate_cost_delta_from_plan(FIXTURE, config=cfg)
    assert isinstance(result, CostSummary)
    assert any("$150" in n for n in result.notes)


def test_disabled_cost_rule_short_circuits():
    cfg = ReviewConfig(
        high_risk_types=frozenset(),
        stateful_types=frozenset(),
        public_cidrs=frozenset(),
        cost_thresholds={"info_usd": 100.0, "warn_usd": 500.0, "blocker_usd": 1000.0},
        disabled_rules=frozenset({"cost-delta"}),
    )
    # No mocks needed: should bail before touching the filesystem or infracost.
    result = estimate_cost_delta_from_plan(FIXTURE, config=cfg)
    assert isinstance(result, dict)
    assert "disabled" in result["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
