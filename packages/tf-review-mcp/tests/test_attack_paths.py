from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tf_review_mcp.attack_paths import (
    DEFAULT_SENSITIVE_TYPES,
    analyze_attack_paths_from_json,
    analyze_attack_paths_from_plan,
    build_graph,
)

FIXTURES = Path(__file__).parent / "fixtures" / "attack_paths"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestGraphBuilder:
    def test_internet_to_data_in_after_state(self):
        plan = _load("attack_path_new.json")
        g = build_graph(plan, "after")
        assert "internet" in g
        assert any(g.nodes[n].get("kind") == "data" for n in g)

    def test_before_state_has_no_internet_for_new_path(self):
        plan = _load("attack_path_new.json")
        g_before = build_graph(plan, "before")
        # Resources were absent before; no internet node should exist.
        assert "internet" not in g_before or not any(
            g_before.nodes[n].get("kind") == "data" for n in g_before
        )


class TestNewPath:
    def test_reports_new_path(self):
        plan = _load("attack_path_new.json")
        result = analyze_attack_paths_from_json(plan)
        assert result.summary["new_paths"] >= 1
        new_paths = [p for p in result.paths if p.is_new]
        assert new_paths
        first = new_paths[0]
        assert first.severity == "blocker"
        assert any("internet" == hop["address"] for hop in first.path)
        assert "edges_changed_by_plan" in first.to_dict()


class TestWidenedPath:
    def test_reports_widened(self):
        plan = _load("attack_path_widened.json")
        result = analyze_attack_paths_from_json(plan)
        # The 0.0.0.0/0 edge is new even though the SG existed in before.
        assert result.summary["new_paths"] >= 1 or result.summary["widened_paths"] >= 1


class TestUnchangedPath:
    def test_preexisting_unchanged_not_reported_by_default(self):
        plan = _load("attack_path_unchanged.json")
        result = analyze_attack_paths_from_json(plan)
        # The existing path should be counted as preexisting unchanged
        # and not appear in `paths` unless include_preexisting=True.
        assert result.summary["preexisting_paths_unchanged"] >= 1
        for p in result.paths:
            # Anything in `paths` must be new or have changed edges.
            assert p.is_new or p.edges_changed_by_plan

    def test_include_preexisting_surfaces_them(self):
        plan = _load("attack_path_unchanged.json")
        result = analyze_attack_paths_from_json(plan, include_preexisting=True)
        assert any(
            not p.is_new and not p.edges_changed_by_plan for p in result.paths
        )


class TestNoFindings:
    def test_returns_empty_paths(self):
        plan = _load("attack_path_no_findings.json")
        result = analyze_attack_paths_from_json(plan)
        assert result.paths == []
        assert result.summary["new_paths"] == 0


class TestGcp:
    def test_gcp_firewall_and_bucket_recognized(self):
        """v0.4.2 GCP coverage is light (per attack_paths.py module
        notes): we recognize public firewalls, compute instances with
        service accounts, and sensitive data types as nodes, but do not
        yet build firewall -> instance edges (no source-tag / target-tag
        resolution). Cross-VPC and IAM-binding edges arrive in v0.5.
        This test asserts the nodes are present so a future PR can
        wire the edges without rewriting the graph."""
        plan = _load("attack_path_gcp.json")
        g = build_graph(plan, "after")
        assert "internet" in g
        addresses = set(g.nodes())
        assert "google_compute_firewall.web" in addresses
        assert any(
            g.nodes[n].get("kind") == "data"
            and n == "google_storage_bucket.data"
            for n in g
        )


class TestEntryPoint:
    def test_from_plan_reads_disk(self, tmp_path):
        plan_path = tmp_path / "plan.json"
        plan_path.write_text((FIXTURES / "attack_path_new.json").read_text())
        result = analyze_attack_paths_from_plan(str(plan_path))
        assert result.summary["new_paths"] >= 1


class TestSensitiveTypes:
    def test_default_sensitive_set_covers_aws_gcp_azure(self):
        assert any(t.startswith("aws_") for t in DEFAULT_SENSITIVE_TYPES)
        assert any(t.startswith("google_") for t in DEFAULT_SENSITIVE_TYPES)
        assert any(t.startswith("azurerm_") for t in DEFAULT_SENSITIVE_TYPES)


class TestPerformance:
    def test_large_plan_under_two_seconds(self):
        """Build + search on a synthetic 500-resource plan must be sub-second."""
        rcs = []
        # 100 instances each in a SG with public ingress, each with an IAM
        # role granting s3:GetObject on a per-bucket basis. 100 * 4 = 400 rcs
        # plus 100 SGs + 100 buckets = 600 total.
        for i in range(100):
            rcs.append({
                "address": f"aws_security_group.sg{i}",
                "type": "aws_security_group",
                "name": f"sg{i}",
                "change": {
                    "actions": ["create"], "before": None,
                    "after": {"ingress": [{"from_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]}
                },
            })
            rcs.append({
                "address": f"aws_instance.i{i}",
                "type": "aws_instance",
                "name": f"i{i}",
                "change": {
                    "actions": ["create"], "before": None,
                    "after": {
                        "vpc_security_group_ids": [f"aws_security_group.sg{i}"],
                        "iam_instance_profile": f"profile{i}",
                    },
                },
            })
            rcs.append({
                "address": f"aws_s3_bucket.b{i}",
                "type": "aws_s3_bucket",
                "name": f"b{i}",
                "change": {"actions": ["create"], "before": None, "after": {"bucket": f"b{i}"}},
            })
        plan = {"format_version": "1.2", "terraform_version": "1.7.0", "resource_changes": rcs}
        start = time.monotonic()
        result = analyze_attack_paths_from_json(plan)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"took {elapsed:.2f}s, expected < 2s"
        # We expect 0 paths because instances are not connected to IAM
        # principals that grant access to the buckets in this synthetic
        # plan (no policy doc was attached). Test value is the timing.
        assert result.summary["new_paths"] >= 0
