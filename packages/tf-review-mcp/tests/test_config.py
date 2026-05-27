"""Tests for `.tf-review.yml` discovery, parsing, and merging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tf_review_mcp.config import (
    ConfigError,
    default_config,
    load_config,
)
from tf_review_mcp.review import review_plan_file

GCP_FIXTURE = Path(__file__).parent / "fixtures" / "gcp_plan.json"
EXAMPLE_CONFIG = Path(__file__).parent / "fixtures" / "example_config.yml"


@pytest.fixture
def isolated_cwd(tmp_path, monkeypatch):
    """Run with a clean cwd far from any real `.tf-review.yml`."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TF_REVIEW_CONFIG", raising=False)
    return tmp_path


def test_load_with_no_config_returns_defaults(isolated_cwd):
    cfg = load_config()
    assert cfg.source_path is None
    assert "aws_db_instance" in cfg.high_risk_types
    assert cfg.cost_thresholds["warn_usd"] == 500.0
    assert cfg.disabled_rules == frozenset()


def test_load_merges_extras_with_defaults(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\n"
        "extra_high_risk_types:\n  - cloudflare_record\n"
        "extra_stateful_types:\n  - mongodbatlas_cluster\n"
        "extra_public_cidrs:\n  - '10.0.0.0/8'\n"
    )
    cfg = load_config()
    # Defaults preserved
    assert "aws_db_instance" in cfg.high_risk_types
    assert "0.0.0.0/0" in cfg.public_cidrs
    # Extras merged in
    assert "cloudflare_record" in cfg.high_risk_types
    assert "mongodbatlas_cluster" in cfg.stateful_types
    assert "10.0.0.0/8" in cfg.public_cidrs
    assert cfg.source_path is not None and cfg.source_path.endswith(".tf-review.yml")


def test_load_overrides_cost_thresholds(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\ncost_thresholds:\n  warn_usd: 250\n"
    )
    cfg = load_config()
    assert cfg.cost_thresholds["warn_usd"] == 250.0
    # Untouched defaults remain
    assert cfg.cost_thresholds["info_usd"] == 100.0
    assert cfg.cost_thresholds["blocker_usd"] == 1000.0


def test_load_unknown_cost_threshold_key_raises(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\ncost_thresholds:\n  bogus_usd: 1\n"
    )
    with pytest.raises(ConfigError, match="unknown `cost_thresholds.bogus_usd`"):
        load_config()


def test_load_unknown_rule_raises(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\ndisabled_rules:\n  - not-a-real-rule\n"
    )
    with pytest.raises(ConfigError, match="unknown rule"):
        load_config()


def test_load_unsupported_version_raises(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text("version: 99\n")
    with pytest.raises(ConfigError, match="unsupported config version"):
        load_config()


def test_load_invalid_yaml_raises(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text("version: 1\n  bad: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config()


def test_env_var_overrides_cwd(tmp_path, monkeypatch):
    cwd_dir = tmp_path / "cwd"
    cwd_dir.mkdir()
    (cwd_dir / ".tf-review.yml").write_text(
        "version: 1\nextra_high_risk_types: [cwd_type]\n"
    )
    env_config = tmp_path / "env.yml"
    env_config.write_text("version: 1\nextra_high_risk_types: [env_type]\n")
    monkeypatch.chdir(cwd_dir)
    monkeypatch.setenv("TF_REVIEW_CONFIG", str(env_config))

    cfg = load_config()
    assert "env_type" in cfg.high_risk_types
    assert "cwd_type" not in cfg.high_risk_types


def test_env_var_missing_file_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TF_REVIEW_CONFIG", str(tmp_path / "nope.yml"))
    with pytest.raises(ConfigError, match="points to a missing file"):
        load_config()


def test_walk_up_finds_config_in_parent(tmp_path, monkeypatch):
    parent = tmp_path / "repo"
    child = parent / "modules" / "vpc"
    child.mkdir(parents=True)
    (parent / ".tf-review.yml").write_text(
        "version: 1\nextra_high_risk_types: [walked_type]\n"
    )
    monkeypatch.chdir(child)
    monkeypatch.delenv("TF_REVIEW_CONFIG", raising=False)

    cfg = load_config()
    assert "walked_type" in cfg.high_risk_types


def test_example_fixture_loads(monkeypatch):
    monkeypatch.setenv("TF_REVIEW_CONFIG", str(EXAMPLE_CONFIG))
    cfg = load_config()
    assert "cloudflare_record" in cfg.high_risk_types
    assert "mongodbatlas_cluster" in cfg.stateful_types
    assert "10.0.0.0/8" in cfg.public_cidrs
    assert cfg.cost_thresholds["warn_usd"] == 250.0


def test_to_dict_is_json_serializable():
    cfg = default_config()
    d = cfg.to_dict()
    raw = json.dumps(d)  # must not raise
    parsed = json.loads(raw)
    assert "aws_db_instance" in parsed["high_risk_types"]
    assert parsed["disabled_rules"] == []


# Integration: review.py honors disabled_rules ---------------------------------


def test_disabling_public_exposure_suppresses_finding(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\ndisabled_rules:\n  - public-exposure\n"
    )
    cfg = load_config()
    summary = review_plan_file(GCP_FIXTURE, config=cfg)
    assert summary.public_exposure_changes == []
    # Other rules still fire
    assert summary.stateful_destroys, "stateful-destroy rule should still fire"
    assert any("disabled via config" in n for n in summary.notes)


def test_disabling_high_risk_suppresses_high_risk(isolated_cwd):
    (isolated_cwd / ".tf-review.yml").write_text(
        "version: 1\ndisabled_rules:\n  - high-risk\n"
    )
    cfg = load_config()
    summary = review_plan_file(GCP_FIXTURE, config=cfg)
    assert summary.high_risk_changes == []


def test_extra_stateful_type_flagged_as_blocker(tmp_path):
    """Custom stateful type in config is honored by review_plan_json."""
    from tf_review_mcp.review import review_plan_json

    plan = {
        "resource_changes": [
            {
                "address": "mongodbatlas_cluster.primary",
                "type": "mongodbatlas_cluster",
                "change": {"actions": ["delete", "create"]},
            }
        ]
    }
    (tmp_path / ".tf-review.yml").write_text(
        "version: 1\nextra_stateful_types:\n  - mongodbatlas_cluster\n"
    )
    import os

    os.chdir(tmp_path)
    cfg = load_config()
    summary = review_plan_json(plan, config=cfg)
    assert any(
        c.address == "mongodbatlas_cluster.primary" for c in summary.stateful_destroys
    )
