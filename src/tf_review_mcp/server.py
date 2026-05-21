"""MCP server entry point for tf-review-mcp.

Exposes Terraform plan review as MCP tools so a model can pull structured
plan analysis on demand.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from .config import ConfigError, ReviewConfig, default_config, load_config
from .cost import CostSummary, estimate_cost_delta_from_plan
from .review import review_plan_file

mcp = FastMCP("tf-review-mcp")


def _active_config() -> ReviewConfig:
    """Load the active config lazily so tests and tools see fresh state.

    Discovery runs on every call (cheap: stat at most a few dirs). If YAML
    parsing fails, fall back to defaults and surface the reason via the
    `get_active_config` tool rather than crashing the server.
    """
    try:
        return load_config()
    except ConfigError:
        return default_config()


@mcp.tool()
def review_plan(plan_json_path: str) -> str:
    """Review a Terraform plan JSON file.

    Produce `plan.out` and pass it through `terraform show -json` first:

        terraform plan -out plan.out
        terraform show -json plan.out > plan.json

    Returns a structured JSON summary covering action counts, high-blast-radius
    resource changes (IAM, security groups, RDS, KMS, etc.), and any stateful
    destroys that warrant explicit review.

    Built-in classifications can be extended via `.tf-review.yml`; use
    `get_active_config` to see the merged config.
    """
    summary = review_plan_file(plan_json_path, config=_active_config())
    return json.dumps(summary.to_dict(), indent=2)


@mcp.tool()
def suggest_review_comments(plan_json_path: str) -> str:
    """Suggest GitHub-style PR review comments for a Terraform plan.

    Returns a JSON list of {address, severity, comment} objects derived from
    the structured review. The model is expected to refine wording before
    posting; this tool only surfaces what to comment on.
    """
    summary = review_plan_file(plan_json_path, config=_active_config())
    comments: list[dict[str, str]] = []
    flagged: set[str] = set()

    for c in summary.stateful_destroys:
        comments.append(
            {
                "address": c.address,
                "severity": "blocker",
                "comment": (
                    f"`{c.address}` is being {'/'.join(c.actions)}d. This is a stateful "
                    f"`{c.type}`. Confirm backup, migration, and rollback plan before merging."
                ),
            }
        )
        flagged.add(c.address)

    for e in summary.public_exposure_changes:
        if e.address in flagged:
            continue
        comments.append(
            {
                "address": e.address,
                "severity": "blocker",
                "comment": (
                    f"`{e.address}` ({e.type}): {e.finding}. "
                    "Confirm this is intentional and matches the firewall policy."
                ),
            }
        )
        flagged.add(e.address)

    for c in summary.high_risk_changes:
        if c.address in flagged:
            continue
        comments.append(
            {
                "address": c.address,
                "severity": "warn",
                "comment": (
                    f"`{c.address}` ({c.type}) touches a high-blast-radius resource "
                    f"(actions: {', '.join(c.actions)}). Double-check the diff."
                ),
            }
        )
        flagged.add(c.address)

    if not comments and summary.total_changes > 0:
        comments.append(
            {
                "address": "(plan)",
                "severity": "info",
                "comment": (
                    f"Plan applies {summary.total_changes} change(s) "
                    f"({summary.counts}). No high-risk resources touched."
                ),
            }
        )

    return json.dumps(comments, indent=2)


@mcp.tool()
def estimate_cost_delta(plan_json_path: str) -> str:
    """Estimate the monthly cost delta for a Terraform plan via Infracost.

    Requires `infracost` to be installed and on PATH. Run `infracost auth login`
    once to set up the free API token.

    Returns a JSON object with:
      - total_monthly_cost_delta_usd: net change in monthly cost
      - top_contributors: resources with the largest absolute cost delta
      - currency: typically "USD"
      - infracost_version: which CLI version produced the estimate
      - notes: human-readable strings, e.g., "Estimated monthly cost
        increase of $612.40 exceeds $500."

    Thresholds default to $100/$500/$1000 and can be overridden via
    `cost_thresholds` in `.tf-review.yml`.

    On a recoverable error (missing binary, infracost non-zero exit,
    timeout, bad plan file) returns `{"error": "..."}` instead.
    """
    result = estimate_cost_delta_from_plan(plan_json_path, config=_active_config())
    if isinstance(result, CostSummary):
        return json.dumps(result.to_dict(), indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_active_config() -> str:
    """Return the active ReviewConfig: built-in defaults merged with any
    `.tf-review.yml` overrides found in cwd / parent dirs / TF_REVIEW_CONFIG.

    Useful for debugging when an expected finding doesn't appear (a rule may
    be disabled, or a custom resource type may be missing from the extend
    list). If config parsing failed, the response includes an `error` field
    and falls back to defaults.
    """
    try:
        cfg = load_config()
        return json.dumps(cfg.to_dict(), indent=2)
    except ConfigError as exc:
        fallback = default_config().to_dict()
        fallback["error"] = str(exc)
        return json.dumps(fallback, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
