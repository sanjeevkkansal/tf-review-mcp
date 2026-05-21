"""Terraform plan review logic.

Parses the JSON output of `terraform show -json plan.out` and produces a
structured review focused on blast radius. Pure functions, no I/O beyond
reading the plan file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# Resource types that are stateful or carry high blast radius when destroyed
# or modified. Conservative list. Extend per-org policy as needed.
HIGH_RISK_TYPES: set[str] = {
    # AWS
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_kms_key",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_route53_zone",
    "aws_route53_record",
    "aws_vpc",
    "aws_subnet",
    "aws_eks_cluster",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    # GCP
    "google_sql_database_instance",
    "google_container_cluster",
    "google_container_node_pool",
    "google_kms_crypto_key",
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_storage_bucket",
    "google_compute_firewall",
    "google_dns_managed_zone",
    "google_dns_record_set",
    # Azure
    "azurerm_sql_server",
    "azurerm_kubernetes_cluster",
    "azurerm_key_vault",
}

# Stateful resources where a destroy or replace is almost always a mistake
# without an explicit migration plan. google_compute_instance is included
# because many users attach local SSDs and rely on boot-disk persistence;
# a replace nukes both.
STATEFUL_TYPES: set[str] = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_compute_instance",
    "azurerm_sql_server",
}

# IP ranges that represent unrestricted public exposure when added to a
# firewall's source_ranges.
PUBLIC_CIDRS: set[str] = {"0.0.0.0/0", "::/0"}


@dataclass
class ResourceChange:
    address: str
    type: str
    actions: list[str]
    is_high_risk: bool
    is_stateful_destroy: bool


@dataclass
class ExposureChange:
    """A diff-aware finding: a resource change that widens public exposure."""
    address: str
    type: str
    actions: list[str]
    finding: str


@dataclass
class ReviewSummary:
    counts: dict[str, int]
    high_risk_changes: list[ResourceChange]
    stateful_destroys: list[ResourceChange]
    public_exposure_changes: list[ExposureChange]
    total_changes: int
    terraform_version: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Flatten nested dataclasses for JSON cleanliness
        d["high_risk_changes"] = [asdict(c) for c in self.high_risk_changes]
        d["stateful_destroys"] = [asdict(c) for c in self.stateful_destroys]
        d["public_exposure_changes"] = [asdict(c) for c in self.public_exposure_changes]
        return d


def _firewall_exposure_finding(rc: dict[str, Any]) -> str | None:
    """Return a finding string if a google_compute_firewall change widens
    public exposure (adds 0.0.0.0/0 or ::/0 to source_ranges), else None.

    Fires on create + update + replace. Does not fire on delete.
    """
    if rc.get("type") != "google_compute_firewall":
        return None
    change = rc.get("change") or {}
    before = change.get("before") or {}
    after = change.get("after") or {}
    before_ranges = set(before.get("source_ranges") or [])
    after_ranges = set(after.get("source_ranges") or [])
    newly_public = (after_ranges & PUBLIC_CIDRS) - before_ranges
    if newly_public:
        return (
            f"source_ranges now includes {', '.join(sorted(newly_public))} "
            "(public exposure)"
        )
    added = after_ranges - before_ranges
    if added and not before_ranges:
        # Brand-new firewall with non-public ranges. Worth noting only if any
        # range is broad enough to matter; skip for now to avoid noise.
        return None
    if added:
        return f"source_ranges widened: added {', '.join(sorted(added))}"
    return None


def _classify_actions(actions: list[str]) -> str:
    """Map a Terraform actions array to a single bucket name.

    Terraform represents replacements as ["delete", "create"] or
    ["create", "delete"]. Treat any list containing "delete" + "create"
    as a replace.
    """
    if not actions:
        return "no-op"
    s = set(actions)
    if s == {"no-op"}:
        return "no-op"
    if "delete" in s and "create" in s:
        return "replace"
    if "delete" in s:
        return "delete"
    if "create" in s:
        return "create"
    if "update" in s:
        return "update"
    if "read" in s:
        return "read"
    return ",".join(sorted(s))


def review_plan_json(plan: dict[str, Any]) -> ReviewSummary:
    """Build a ReviewSummary from a parsed Terraform plan JSON object."""
    resource_changes = plan.get("resource_changes") or []
    counts: dict[str, int] = {}
    high_risk: list[ResourceChange] = []
    stateful_destroys: list[ResourceChange] = []
    public_exposure: list[ExposureChange] = []
    total = 0

    for rc in resource_changes:
        change = rc.get("change") or {}
        actions = list(change.get("actions") or [])
        bucket = _classify_actions(actions)
        if bucket == "no-op":
            continue
        total += 1
        counts[bucket] = counts.get(bucket, 0) + 1

        rtype = rc.get("type") or ""
        address = rc.get("address") or ""
        is_high_risk = rtype in HIGH_RISK_TYPES
        is_stateful_destroy = rtype in STATEFUL_TYPES and bucket in {"delete", "replace"}

        if is_high_risk or is_stateful_destroy:
            entry = ResourceChange(
                address=address,
                type=rtype,
                actions=actions,
                is_high_risk=is_high_risk,
                is_stateful_destroy=is_stateful_destroy,
            )
            if is_high_risk:
                high_risk.append(entry)
            if is_stateful_destroy:
                stateful_destroys.append(entry)

        finding = _firewall_exposure_finding(rc)
        if finding is not None:
            public_exposure.append(
                ExposureChange(
                    address=address,
                    type=rtype,
                    actions=actions,
                    finding=finding,
                )
            )

    notes: list[str] = []
    if stateful_destroys:
        notes.append(
            f"{len(stateful_destroys)} stateful resource(s) scheduled for destroy/replace. "
            "Verify backups and migration plan before applying."
        )
    if public_exposure:
        notes.append(
            f"{len(public_exposure)} firewall change(s) widen public exposure. "
            "Confirm intent before applying."
        )
    if counts.get("delete", 0) > 0 and not stateful_destroys:
        notes.append(f"{counts['delete']} resource(s) will be destroyed.")
    if total == 0:
        notes.append("Plan is a no-op. Nothing to apply.")

    return ReviewSummary(
        counts=counts,
        high_risk_changes=high_risk,
        stateful_destroys=stateful_destroys,
        public_exposure_changes=public_exposure,
        total_changes=total,
        terraform_version=plan.get("terraform_version"),
        notes=notes,
    )


def review_plan_file(path: str | Path) -> ReviewSummary:
    """Load a plan JSON file from disk and review it."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Plan file not found: {p}")
    with p.open() as f:
        plan = json.load(f)
    return review_plan_json(plan)
