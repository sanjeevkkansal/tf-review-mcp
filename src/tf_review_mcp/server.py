"""MCP server entry point for tf-review-mcp.

Exposes Terraform plan review as MCP tools so a model can pull structured
plan analysis on demand.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from .review import review_plan_file

mcp = FastMCP("tf-review-mcp")


@mcp.tool()
def review_plan(plan_json_path: str) -> str:
    """Review a Terraform plan JSON file.

    Produce `plan.out` and pass it through `terraform show -json` first:

        terraform plan -out plan.out
        terraform show -json plan.out > plan.json

    Returns a structured JSON summary covering action counts, high-blast-radius
    resource changes (IAM, security groups, RDS, KMS, etc.), and any stateful
    destroys that warrant explicit review.
    """
    summary = review_plan_file(plan_json_path)
    return json.dumps(summary.to_dict(), indent=2)


@mcp.tool()
def suggest_review_comments(plan_json_path: str) -> str:
    """Suggest GitHub-style PR review comments for a Terraform plan.

    Returns a JSON list of {address, severity, comment} objects derived from
    the structured review. The model is expected to refine wording before
    posting; this tool only surfaces what to comment on.
    """
    summary = review_plan_file(plan_json_path)
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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
