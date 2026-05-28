"""MCP server entry point for tf-review-mcp.

Exposes Terraform plan review as MCP tools so a model can pull structured
plan analysis on demand.

This module is the single place where MCP imports live. The classification
and cost modules stay pure. Sanitization of LLM-facing strings happens
here, at the serialization boundary, using mcp-adversarial's sanitize
helpers; the dataclass values stay truthful so other callers (CLI, CI)
see the raw data.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_adversarial import sanitize_address_or_marker, sanitize_for_model

from .config import ConfigError, ReviewConfig, default_config, load_config
from .cost import CostSummary, estimate_cost_delta_from_plan
from .review import review_plan_file
from .safety import PolicyError, policy_snapshot

mcp = FastMCP("tf-review-mcp")

_ADDRESS_FIELDS = frozenset({"address"})
_LONG_TEXT_MAX = 1024


def _active_config() -> ReviewConfig:
    """Load the active config lazily so tests and tools see fresh state."""
    try:
        return load_config()
    except ConfigError:
        return default_config()


def _sanitize_node(value: Any) -> Any:
    """Recursively sanitize string fields in a JSON-shaped value."""
    if isinstance(value, str):
        return sanitize_for_model(value, max_len=_LONG_TEXT_MAX)
    if isinstance(value, dict):
        return {k: _sanitize_field(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_node(item) for item in value]
    return value


def _sanitize_field(key: str, value: Any) -> Any:
    if key in _ADDRESS_FIELDS and isinstance(value, str):
        return sanitize_address_or_marker(value)
    return _sanitize_node(value)


def _structured_error(exc: Exception, *, kind: str) -> str:
    return json.dumps(
        {
            "error": sanitize_for_model(str(exc), max_len=512),
            "kind": kind,
        },
        indent=2,
    )


@mcp.tool()
def review_plan(plan_json_path: str) -> str:
    """Review a Terraform plan JSON file.

    Produce `plan.out` and pass it through `terraform show -json` first:

        terraform plan -out plan.out
        terraform show -json plan.out > plan.json

    Returns a structured JSON summary covering action counts, high-blast-radius
    resource changes (IAM, security groups, RDS, KMS, etc.), and any stateful
    destroys that warrant explicit review.

    All string fields in the output are sanitized for safe display to a
    language model: known prompt-injection preambles are marked with
    "[sus]", control characters are stripped, and addresses are validated.
    """
    try:
        summary = review_plan_file(plan_json_path, config=_active_config())
    except PolicyError as exc:
        return _structured_error(exc, kind="policy")
    except FileNotFoundError as exc:
        return _structured_error(exc, kind="not_found")
    return json.dumps(_sanitize_node(summary.to_dict()), indent=2)


@mcp.tool()
def suggest_review_comments(plan_json_path: str) -> str:
    """Suggest GitHub-style PR review comments for a Terraform plan.

    Returns a JSON list of {address, severity, comment} objects derived from
    the structured review. Severity is one of `blocker | warn | info`.
    All strings are sanitized before serialization.
    """
    try:
        summary = review_plan_file(plan_json_path, config=_active_config())
    except PolicyError as exc:
        return _structured_error(exc, kind="policy")
    except FileNotFoundError as exc:
        return _structured_error(exc, kind="not_found")

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

    sanitized = [_sanitize_node(c) for c in comments]
    return json.dumps(sanitized, indent=2)


@mcp.tool()
def estimate_cost_delta(plan_json_path: str) -> str:
    """Estimate the monthly cost delta for a Terraform plan via Infracost.

    Requires `infracost` to be installed and on PATH. Run `infracost auth login`
    once to set up the free API token.

    Returns a JSON object with structured cost data on success, or
    `{"error": "..."}` on a recoverable error (missing binary,
    non-zero exit, timeout, bad plan file, policy violation).
    """
    result = estimate_cost_delta_from_plan(plan_json_path, config=_active_config())
    if isinstance(result, CostSummary):
        return json.dumps(_sanitize_node(result.to_dict()), indent=2)
    return json.dumps(_sanitize_node(result), indent=2)


@mcp.tool()
def get_active_config() -> str:
    """Return the active config: built-in defaults merged with any
    `.tf-review.yml` overrides found in cwd / parent dirs / TF_REVIEW_CONFIG.

    Also includes the host policy snapshot (TF_REVIEW_ALLOWED_DIRS,
    TF_REVIEW_MAX_PLAN_BYTES).
    """
    try:
        cfg = load_config().to_dict()
    except ConfigError as exc:
        cfg = default_config().to_dict()
        cfg["error"] = str(exc)
    cfg["host_policy"] = policy_snapshot()
    return json.dumps(cfg, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
