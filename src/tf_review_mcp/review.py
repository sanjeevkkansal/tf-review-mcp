"""Terraform plan review logic.

Parses the JSON output of `terraform show -json plan.out` and produces a
structured review focused on blast radius. Pure functions, no I/O beyond
reading the plan file.

Classifications (high-risk types, stateful types, public CIDRs) are owned
by `config.py`. Pass a `ReviewConfig` to override built-in defaults.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import ReviewConfig, default_config


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
        d["high_risk_changes"] = [asdict(c) for c in self.high_risk_changes]
        d["stateful_destroys"] = [asdict(c) for c in self.stateful_destroys]
        d["public_exposure_changes"] = [asdict(c) for c in self.public_exposure_changes]
        return d


def _firewall_exposure_finding(
    rc: dict[str, Any], public_cidrs: frozenset[str]
) -> str | None:
    """Return a finding string if a google_compute_firewall change widens
    public exposure (adds a CIDR from `public_cidrs` to source_ranges), else None.

    Fires on create + update + replace. Does not fire on delete.
    """
    if rc.get("type") != "google_compute_firewall":
        return None
    change = rc.get("change") or {}
    before = change.get("before") or {}
    after = change.get("after") or {}
    before_ranges = set(before.get("source_ranges") or [])
    after_ranges = set(after.get("source_ranges") or [])
    newly_public = (after_ranges & public_cidrs) - before_ranges
    if newly_public:
        return (
            f"source_ranges now includes {', '.join(sorted(newly_public))} "
            "(public exposure)"
        )
    added = after_ranges - before_ranges
    if added and not before_ranges:
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


def review_plan_json(
    plan: dict[str, Any], config: ReviewConfig | None = None
) -> ReviewSummary:
    """Build a ReviewSummary from a parsed Terraform plan JSON object."""
    cfg = config or default_config()

    high_risk_disabled = cfg.is_rule_disabled("high-risk")
    stateful_disabled = cfg.is_rule_disabled("stateful-destroy")
    exposure_disabled = cfg.is_rule_disabled("public-exposure")

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
        is_high_risk = rtype in cfg.high_risk_types
        is_stateful_destroy = (
            rtype in cfg.stateful_types and bucket in {"delete", "replace"}
        )

        if is_high_risk or is_stateful_destroy:
            entry = ResourceChange(
                address=address,
                type=rtype,
                actions=actions,
                is_high_risk=is_high_risk,
                is_stateful_destroy=is_stateful_destroy,
            )
            if is_high_risk and not high_risk_disabled:
                high_risk.append(entry)
            if is_stateful_destroy and not stateful_disabled:
                stateful_destroys.append(entry)

        if not exposure_disabled:
            finding = _firewall_exposure_finding(rc, cfg.public_cidrs)
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
    if cfg.disabled_rules:
        notes.append(
            f"{len(cfg.disabled_rules)} rule(s) disabled via config: "
            f"{', '.join(sorted(cfg.disabled_rules))}."
        )

    return ReviewSummary(
        counts=counts,
        high_risk_changes=high_risk,
        stateful_destroys=stateful_destroys,
        public_exposure_changes=public_exposure,
        total_changes=total,
        terraform_version=plan.get("terraform_version"),
        notes=notes,
    )


def review_plan_file(
    path: str | Path, config: ReviewConfig | None = None
) -> ReviewSummary:
    """Load a plan JSON file from disk and review it."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Plan file not found: {p}")
    with p.open() as f:
        plan = json.load(f)
    return review_plan_json(plan, config=config)
