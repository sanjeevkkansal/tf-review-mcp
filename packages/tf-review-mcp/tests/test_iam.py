from __future__ import annotations

import json
from pathlib import Path

import pytest

from tf_review_mcp.config import ReviewConfig, default_config
from tf_review_mcp.iam import (
    DEFAULT_ESCALATION_PATTERNS,
    DEFAULT_EXFIL_PATTERNS,
    DEFAULT_LATERAL_PATTERNS,
    IAM_RESOURCE_TYPES,
    review_iam_changes_from_json,
    review_iam_changes_from_plan,
)

FIXTURES = Path(__file__).parent / "fixtures" / "iam"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestClassification:
    def test_aws_inline_escalation(self):
        result = review_iam_changes_from_json(_load("iam_escalation.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "escalation" in ic.classifications
        assert ic.severity == "blocker"
        assert any("iam:*" in p for p in ic.added_permissions)

    def test_aws_trust_lateral(self):
        result = review_iam_changes_from_json(_load("iam_lateral.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "lateral" in ic.classifications
        assert ic.severity == "blocker"
        assert any("999999999999" in p for p in ic.added_permissions)

    def test_aws_exfil(self):
        result = review_iam_changes_from_json(_load("iam_exfil.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "exfil" in ic.classifications
        assert ic.severity == "warn"
        assert any("s3:GetObject" in p for p in ic.added_permissions)

    def test_aws_tightening_only(self):
        result = review_iam_changes_from_json(_load("iam_tightening.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "tightening" in ic.classifications
        # Tightening alone is info, not a blocker.
        assert ic.severity == "info"

    def test_aws_mixed_classifications(self):
        result = review_iam_changes_from_json(_load("iam_mixed.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "escalation" in ic.classifications
        assert "exfil" in ic.classifications
        assert ic.severity == "blocker"

    def test_gcp_escalation(self):
        result = review_iam_changes_from_json(_load("iam_gcp_escalation.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "escalation" in ic.classifications
        assert ic.severity == "blocker"
        assert "roles/owner" in ic.added_permissions[0]

    def test_azure_escalation(self):
        result = review_iam_changes_from_json(_load("iam_azure_escalation.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "escalation" in ic.classifications
        assert ic.severity == "blocker"

    def test_managed_admin_attachment(self):
        result = review_iam_changes_from_json(_load("iam_attach_admin.json"))
        assert len(result.iam_changes) == 1
        ic = result.iam_changes[0]
        assert "escalation" in ic.classifications

    def test_no_iam_changes(self):
        result = review_iam_changes_from_json(_load("iam_no_findings.json"))
        assert result.iam_changes == []
        assert result.summary["total"] == 0


class TestSummary:
    def test_counts(self):
        plan_data = {
            "resource_changes": (
                _load("iam_escalation.json")["resource_changes"]
                + _load("iam_lateral.json")["resource_changes"]
                + _load("iam_exfil.json")["resource_changes"]
            )
        }
        result = review_iam_changes_from_json(plan_data)
        assert result.summary["escalation_count"] == 1
        assert result.summary["lateral_count"] == 1
        assert result.summary["exfil_count"] == 1
        assert result.summary["total"] == 3


class TestConfigIntegration:
    def test_extra_escalation_pattern(self):
        cfg = ReviewConfig(
            **{**default_config().__dict__, "extra_escalation_patterns": frozenset({"customaction:dangerous"})}
        )
        plan_data = {
            "resource_changes": [{
                "address": "aws_iam_policy.x",
                "type": "aws_iam_policy",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"policy": json.dumps({
                        "Statement": [
                            {"Effect": "Allow", "Action": "CustomAction:dangerous", "Resource": "*"}
                        ]
                    })},
                },
            }]
        }
        result = review_iam_changes_from_json(plan_data, config=cfg)
        assert len(result.iam_changes) == 1
        assert "escalation" in result.iam_changes[0].classifications

    def test_disabled_rule_does_not_apply_at_iam_level(self):
        # Note: rule disabling lives in the server; iam.py runs regardless.
        # Sanity check that the config doesn't break the classifier.
        cfg = ReviewConfig(
            **{**default_config().__dict__, "disabled_rules": frozenset({"iam-review"})}
        )
        result = review_iam_changes_from_json(_load("iam_escalation.json"), config=cfg)
        assert len(result.iam_changes) == 1


class TestEntryPoint:
    def test_from_plan_reads_disk(self, tmp_path):
        plan_path = tmp_path / "plan.json"
        plan_path.write_text((FIXTURES / "iam_escalation.json").read_text())
        result = review_iam_changes_from_plan(str(plan_path))
        assert len(result.iam_changes) == 1
        assert "escalation" in result.iam_changes[0].classifications


class TestPatternSets:
    def test_default_pattern_sets_nonempty(self):
        assert DEFAULT_ESCALATION_PATTERNS
        assert DEFAULT_LATERAL_PATTERNS
        assert DEFAULT_EXFIL_PATTERNS

    def test_iam_resource_types_cover_three_providers(self):
        assert any(t.startswith("aws_iam_") for t in IAM_RESOURCE_TYPES)
        assert any(t.startswith("google_") for t in IAM_RESOURCE_TYPES)
        assert any(t.startswith("azurerm_") for t in IAM_RESOURCE_TYPES)
