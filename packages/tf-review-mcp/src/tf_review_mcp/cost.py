"""Cost-delta estimation by wrapping the Infracost CLI.

Pure functions, no MCP imports. The server module calls
`estimate_cost_delta_from_plan` and serializes the result.

Infracost must be installed separately and authenticated once via
`infracost auth login`. This module does not manage credentials.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import ReviewConfig, default_config
from .safety import PolicyError, validate_plan_path

INFRACOST_TIMEOUT_SECONDS = 60
TOP_CONTRIBUTORS_LIMIT = 10


@dataclass
class CostContributor:
    address: str
    monthly_cost_delta_usd: float


@dataclass
class CostSummary:
    total_monthly_cost_delta_usd: float
    top_contributors: list[CostContributor]
    currency: str = "USD"
    infracost_version: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["top_contributors"] = [asdict(c) for c in self.top_contributors]
        return d


def _run_infracost(plan_json_path: Path) -> tuple[int, str, str]:
    """Invoke infracost. Split out for ease of mocking in tests."""
    proc = subprocess.run(
        [
            "infracost",
            "breakdown",
            "--path",
            str(plan_json_path),
            "--format",
            "json",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=INFRACOST_TIMEOUT_SECONDS,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _walk_resources(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten an Infracost resource tree (resources may have subresources)."""
    out: list[dict[str, Any]] = []
    for r in resources or []:
        out.append(r)
        out.extend(_walk_resources(r.get("subresources") or []))
    return out


def _contributors_from_infracost(payload: dict[str, Any]) -> list[CostContributor]:
    contributors: list[CostContributor] = []
    for project in payload.get("projects") or []:
        breakdown = project.get("breakdown") or {}
        for r in _walk_resources(breakdown.get("resources") or []):
            address = r.get("name") or r.get("address") or ""
            if not address:
                continue
            current = _parse_float(r.get("monthlyCost"))
            previous = _parse_float(
                r.get("pastMonthlyCost")
                if "pastMonthlyCost" in r
                else r.get("baselineMonthlyCost")
            )
            delta = current - previous
            if delta == 0:
                continue
            contributors.append(
                CostContributor(address=address, monthly_cost_delta_usd=round(delta, 2))
            )
    contributors.sort(key=lambda c: abs(c.monthly_cost_delta_usd), reverse=True)
    return contributors[:TOP_CONTRIBUTORS_LIMIT]


def _build_notes(total_delta: float, thresholds: dict[str, float]) -> list[str]:
    notes: list[str] = []
    abs_delta = abs(total_delta)
    direction = "increase" if total_delta > 0 else "decrease"
    blocker = thresholds.get("blocker_usd", 1000.0)
    warn = thresholds.get("warn_usd", 500.0)
    info = thresholds.get("info_usd", 100.0)
    if abs_delta >= blocker:
        notes.append(
            f"Estimated monthly cost {direction} of ${abs_delta:,.2f} exceeds "
            f"${blocker:,.0f}. Strong review recommended."
        )
    elif abs_delta >= warn:
        notes.append(
            f"Estimated monthly cost {direction} of ${abs_delta:,.2f} exceeds "
            f"${warn:,.0f}."
        )
    elif abs_delta >= info:
        notes.append(
            f"Estimated monthly cost {direction} of ${abs_delta:,.2f}."
        )
    elif total_delta == 0:
        notes.append("No monthly cost delta detected.")
    return notes


def estimate_cost_delta_from_plan(
    plan_json_path: str | Path, config: ReviewConfig | None = None
) -> CostSummary | dict[str, Any]:
    """Run `infracost breakdown` on a Terraform plan JSON and parse the result.

    Returns a `CostSummary` on success. On a recoverable error (missing binary,
    non-zero exit, timeout, bad plan file) returns a structured error dict so
    the MCP tool surfaces actionable text rather than a stack trace.
    """
    cfg = config or default_config()
    if cfg.is_rule_disabled("cost-delta"):
        return {
            "error": "cost-delta rule disabled by config",
            "source_path": cfg.source_path,
        }

    try:
        p = validate_plan_path(plan_json_path)
    except PolicyError as exc:
        return {"error": f"plan path rejected by host policy: {exc}"}
    if not p.exists():
        return {
            "error": f"Plan file not found: {p}",
        }

    if shutil.which("infracost") is None:
        return {
            "error": "infracost not installed",
            "install": "https://www.infracost.io/docs/",
            "hint": "brew install infracost && infracost auth login",
        }

    try:
        with p.open() as f:
            plan = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"could not read plan JSON: {exc}"}

    if not isinstance(plan, dict) or "resource_changes" not in plan:
        return {
            "error": "plan file does not look like `terraform show -json` output",
            "hint": "Generate with: terraform show -json plan.out > plan.json",
        }

    try:
        returncode, stdout, stderr = _run_infracost(p)
    except subprocess.TimeoutExpired:
        return {"error": f"infracost timed out after {INFRACOST_TIMEOUT_SECONDS}s"}
    except FileNotFoundError:
        return {
            "error": "infracost not installed",
            "install": "https://www.infracost.io/docs/",
        }

    if returncode != 0:
        return {
            "error": "infracost exited non-zero",
            "returncode": returncode,
            "stderr": (stderr or "").strip()[:2000],
        }

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"could not parse infracost output: {exc}"}

    total_current = _parse_float(payload.get("totalMonthlyCost"))
    total_previous = _parse_float(payload.get("pastTotalMonthlyCost"))
    total_delta = round(total_current - total_previous, 2)

    contributors = _contributors_from_infracost(payload)
    notes = _build_notes(total_delta, cfg.cost_thresholds)

    return CostSummary(
        total_monthly_cost_delta_usd=total_delta,
        top_contributors=contributors,
        currency=payload.get("currency") or "USD",
        infracost_version=payload.get("version"),
        notes=notes,
    )
