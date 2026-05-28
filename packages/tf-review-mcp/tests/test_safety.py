from __future__ import annotations

import json
from pathlib import Path

import pytest

from tf_review_mcp.cost import estimate_cost_delta_from_plan
from tf_review_mcp.review import review_plan_file
from tf_review_mcp.safety import (
    DEFAULT_MAX_PLAN_BYTES,
    PolicyError,
    policy_snapshot,
    validate_plan_path,
)


def _write_plan(p: Path, contents: dict | bytes | str = None) -> Path:
    if contents is None:
        contents = {
            "format_version": "1.2",
            "terraform_version": "1.7.0",
            "resource_changes": [],
        }
    if isinstance(contents, (dict, list)):
        p.write_text(json.dumps(contents))
    elif isinstance(contents, bytes):
        p.write_bytes(contents)
    else:
        p.write_text(contents)
    return p


class TestValidatePlanPath:
    def test_returns_resolved_path_for_normal_file(self, tmp_path):
        plan = _write_plan(tmp_path / "plan.json")
        result = validate_plan_path(str(plan))
        assert result == plan.resolve()

    def test_does_not_raise_on_missing_file(self, tmp_path):
        result = validate_plan_path(str(tmp_path / "missing.json"))
        assert result == (tmp_path / "missing.json").resolve()

    def test_rejects_nul_byte(self):
        with pytest.raises(PolicyError):
            validate_plan_path("plan\x00.json")

    def test_size_limit_rejects_oversize_file(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "big.json", b"x" * 200)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "100")
        with pytest.raises(PolicyError) as excinfo:
            validate_plan_path(str(plan))
        assert "exceeds" in str(excinfo.value)

    def test_size_limit_passes_at_limit(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "ok.json", b"x" * 100)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "100")
        validate_plan_path(str(plan))  # should not raise

    def test_invalid_size_env_falls_back_to_default(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "ok.json", b"x" * 1024)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "not-a-number")
        validate_plan_path(str(plan))  # default 50MB; 1KB fine

    def test_negative_size_env_falls_back_to_default(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "ok.json", b"x" * 1024)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "-1")
        validate_plan_path(str(plan))

    def test_allowlist_blocks_outside_path(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        plan = _write_plan(outside / "plan.json")
        monkeypatch.setenv("TF_REVIEW_ALLOWED_DIRS", str(allowed))
        with pytest.raises(PolicyError) as excinfo:
            validate_plan_path(str(plan))
        assert "outside" in str(excinfo.value)

    def test_allowlist_permits_inside_path(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        plan = _write_plan(allowed / "plan.json")
        monkeypatch.setenv("TF_REVIEW_ALLOWED_DIRS", str(allowed))
        validate_plan_path(str(plan))  # no raise

    def test_allowlist_supports_colon_separated_list(self, tmp_path, monkeypatch):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        plan = _write_plan(b / "plan.json")
        monkeypatch.setenv("TF_REVIEW_ALLOWED_DIRS", f"{a}:{b}")
        validate_plan_path(str(plan))

    def test_unset_allowlist_permits_anywhere(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TF_REVIEW_ALLOWED_DIRS", raising=False)
        plan = _write_plan(tmp_path / "plan.json")
        validate_plan_path(str(plan))


class TestPolicySnapshot:
    def test_defaults_when_unset(self, monkeypatch):
        monkeypatch.delenv("TF_REVIEW_ALLOWED_DIRS", raising=False)
        monkeypatch.delenv("TF_REVIEW_MAX_PLAN_BYTES", raising=False)
        snap = policy_snapshot()
        assert snap["allowed_dirs"] is None
        assert snap["max_plan_bytes"] == DEFAULT_MAX_PLAN_BYTES

    def test_reflects_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TF_REVIEW_ALLOWED_DIRS", str(tmp_path))
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "12345")
        snap = policy_snapshot()
        assert snap["max_plan_bytes"] == 12345
        assert snap["allowed_dirs"] == [str(tmp_path.resolve())]


class TestReviewPlanFileWithPolicy:
    def test_policy_error_propagates(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "plan.json", b"x" * 200)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "100")
        with pytest.raises(PolicyError):
            review_plan_file(str(plan))


class TestCostEstimateWithPolicy:
    def test_policy_error_returns_structured_dict(self, tmp_path, monkeypatch):
        plan = _write_plan(tmp_path / "plan.json", b"x" * 200)
        monkeypatch.setenv("TF_REVIEW_MAX_PLAN_BYTES", "100")
        result = estimate_cost_delta_from_plan(str(plan))
        assert isinstance(result, dict)
        assert "error" in result
        assert "policy" in result["error"].lower() or "exceeds" in result["error"]
