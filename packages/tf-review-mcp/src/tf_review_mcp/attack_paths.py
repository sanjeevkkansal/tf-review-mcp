"""Attack-path analysis for a Terraform plan.

Builds a directed graph from `resource_changes` (compute, IAM,
data stores, network edges, public ingress), searches for simple
paths from a synthetic `internet` node to anything tagged sensitive,
and reports paths that are *new* or *widened* by the plan.

Layers (each is a pure function):

  1. build_graph(plan, state)        before-graph + after-graph
  2. enumerate_paths(graph)          simple paths from internet -> sensitive
  3. diff_paths(before, after)       new / widened / preexisting
  4. narrate(path)                   template string, deterministic

No MCP imports. Pulls in `networkx` for path search.

Scope notes for v0.4.2:
  - AWS coverage is the most complete (SG/ALB/CloudFront/instance/lambda/ECS/S3/
    KMS/Secrets/RDS).
  - GCP coverage is light (firewall + instance + service_account + sensitive
    types).
  - No cross-VPC, transit-gateway, or VPC endpoint traversal. Same-VPC
    reachability is implicit. Adding cross-network plumbing is v0.5 work.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

import networkx as nx

from .config import ReviewConfig, default_config
from .iam import (
    DEFAULT_ESCALATION_PATTERNS,
    DEFAULT_EXFIL_PATTERNS,
    _matches_any,
    _parse_policy,
    _policy_doc_pairs,
)
from .safety import validate_plan_path

INTERNET_NODE = "internet"

PUBLIC_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})

DEFAULT_SENSITIVE_TYPES: frozenset[str] = frozenset(
    {
        # AWS data stores
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        # AWS secrets / keys
        "aws_secretsmanager_secret",
        "aws_kms_key",
        "aws_ssm_parameter",
        # GCP
        "google_sql_database_instance",
        "google_storage_bucket",
        "google_secret_manager_secret",
        # Azure
        "azurerm_key_vault",
        "azurerm_sql_server",
        "azurerm_storage_account",
    }
)

# Cap path search to keep output bounded.
DEFAULT_MAX_PATH_DEPTH = 8
DEFAULT_MAX_PATHS = 50


@dataclass(frozen=True)
class GraphNode:
    address: str
    kind: str  # internet | ingress | sg | compute | principal | data | network

    def to_dict(self) -> dict[str, str]:
        return {"address": self.address, "kind": self.kind}


@dataclass
class AttackPath:
    path: list[dict[str, str]]
    is_new: bool
    edges_changed_by_plan: list[str]
    severity: str
    narrative: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathSummary:
    paths: list[AttackPath]
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": [p.to_dict() for p in self.paths],
            "summary": dict(self.summary),
        }


# ---------------- plan helpers ----------------


def _state_value(rc: dict[str, Any], state: Literal["before", "after"]) -> dict[str, Any]:
    """Return the before or after attribute dict for a resource change."""
    change = rc.get("change") or {}
    v = change.get(state)
    if isinstance(v, dict):
        return v
    return {}


def _resource_present(rc: dict[str, Any], state: Literal["before", "after"]) -> bool:
    change = rc.get("change") or {}
    actions = change.get("actions") or []
    if state == "before":
        return "create" not in actions or "delete" in actions
    return "delete" not in actions or "create" in actions


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# ---------------- graph builder ----------------


def _add_node(g: nx.DiGraph, address: str, kind: str) -> None:
    g.add_node(address, kind=kind)


def _add_edge(g: nx.DiGraph, src: str, dst: str, reason: str) -> None:
    if g.has_edge(src, dst):
        # Accumulate reasons but keep one edge.
        prev = g.edges[src, dst].get("reason") or ""
        if reason not in prev:
            g.edges[src, dst]["reason"] = (prev + "; " + reason) if prev else reason
    else:
        g.add_edge(src, dst, reason=reason)


def _build_aws_edges(
    g: nx.DiGraph,
    rc: dict[str, Any],
    state: Literal["before", "after"],
    sensitive_types: frozenset[str],
) -> None:
    rtype = rc.get("type")
    address = rc.get("address") or ""
    if not _resource_present(rc, state):
        return
    attrs = _state_value(rc, state)

    # Public ingress edges (internet -> resource).
    if rtype == "aws_security_group":
        _add_node(g, address, "sg")
        for ingress in _as_list(attrs.get("ingress")):
            if not isinstance(ingress, dict):
                continue
            cidrs = set(ingress.get("cidr_blocks") or []) | set(
                ingress.get("ipv6_cidr_blocks") or []
            )
            if cidrs & PUBLIC_CIDRS:
                _add_node(g, INTERNET_NODE, "internet")
                from_port = ingress.get("from_port")
                _add_edge(
                    g,
                    INTERNET_NODE,
                    address,
                    f"sg-allows-public-ingress port={from_port}",
                )

    elif rtype in ("aws_vpc_security_group_ingress_rule", "aws_security_group_rule"):
        sg_id = attrs.get("security_group_id")
        cidr = attrs.get("cidr_ipv4") or attrs.get("cidr_blocks") or attrs.get("cidr_ipv6")
        cidrs = set(_as_list(cidr))
        if isinstance(sg_id, str) and (cidrs & PUBLIC_CIDRS):
            _add_node(g, sg_id, "sg")
            _add_node(g, INTERNET_NODE, "internet")
            _add_edge(
                g,
                INTERNET_NODE,
                sg_id,
                f"sg-rule-public-ingress address={address}",
            )

    elif rtype == "aws_lb":
        scheme = attrs.get("internal")
        if scheme is False or attrs.get("scheme") == "internet-facing":
            _add_node(g, INTERNET_NODE, "internet")
            _add_node(g, address, "ingress")
            _add_edge(g, INTERNET_NODE, address, "public-lb")
            for sg_id in _as_list(attrs.get("security_groups")):
                if isinstance(sg_id, str):
                    _add_node(g, sg_id, "sg")
                    _add_edge(g, address, sg_id, f"{address} uses {sg_id}")

    elif rtype == "aws_cloudfront_distribution":
        _add_node(g, INTERNET_NODE, "internet")
        _add_node(g, address, "ingress")
        _add_edge(g, INTERNET_NODE, address, "cloudfront-public")

    elif rtype in ("aws_api_gateway_rest_api", "aws_api_gateway_stage", "aws_apigatewayv2_api"):
        _add_node(g, INTERNET_NODE, "internet")
        _add_node(g, address, "ingress")
        _add_edge(g, INTERNET_NODE, address, f"{rtype}-public")

    elif rtype == "aws_instance":
        _add_node(g, address, "compute")
        for sg_id in _as_list(attrs.get("vpc_security_group_ids")) + _as_list(
            attrs.get("security_groups")
        ):
            if isinstance(sg_id, str):
                _add_node(g, sg_id, "sg")
                _add_edge(g, sg_id, address, f"{sg_id} attached to {address}")
        profile = attrs.get("iam_instance_profile")
        if isinstance(profile, str):
            principal = f"aws_iam_instance_profile.{profile}"
            _add_node(g, principal, "principal")
            _add_edge(g, address, principal, "instance profile")
        elif isinstance(profile, dict) and isinstance(profile.get("name"), str):
            principal = f"aws_iam_instance_profile.{profile['name']}"
            _add_node(g, principal, "principal")
            _add_edge(g, address, principal, "instance profile")

    elif rtype == "aws_lambda_function":
        _add_node(g, address, "compute")
        role = attrs.get("role")
        if isinstance(role, str):
            _add_node(g, role, "principal")
            _add_edge(g, address, role, "lambda execution role")
        for sg_id in _as_list((attrs.get("vpc_config") or {}).get("security_group_ids") if isinstance(attrs.get("vpc_config"), dict) else []):
            if isinstance(sg_id, str):
                _add_node(g, sg_id, "sg")
                _add_edge(g, sg_id, address, f"{sg_id} attached to {address}")

    elif rtype == "aws_ecs_service":
        _add_node(g, address, "compute")
        for sg_id in _as_list(
            (attrs.get("network_configuration") or {}).get("security_groups")
            if isinstance(attrs.get("network_configuration"), dict)
            else []
        ):
            if isinstance(sg_id, str):
                _add_node(g, sg_id, "sg")
                _add_edge(g, sg_id, address, f"{sg_id} attached to {address}")
        task = attrs.get("task_definition")
        if isinstance(task, str):
            _add_node(g, task, "principal")
            _add_edge(g, address, task, "ecs task def")

    elif rtype in (
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    ):
        _add_node(g, address, "principal")
        policy_key = "policy" if rtype != "aws_iam_role" else "assume_role_policy"
        doc = _parse_policy(attrs.get(policy_key))
        for action, resource in _policy_doc_pairs(doc):
            sensitive = _resource_arn_to_address(resource)
            if sensitive is None:
                # Wildcard or "*": link to all sensitive data nodes we know.
                for data_node in [n for n, d in g.nodes(data=True) if d.get("kind") == "data"]:
                    _add_edge(g, address, data_node, f"grant {action}")
            else:
                _add_node(g, sensitive, "data")
                _add_edge(g, address, sensitive, f"grant {action}")

    elif rtype in (
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_policy_attachment",
    ):
        role = attrs.get("role") or attrs.get("user") or attrs.get("group")
        policy_arn = attrs.get("policy_arn")
        if isinstance(role, str):
            principal = f"{rtype}.{role}"
            _add_node(g, principal, "principal")
            if isinstance(policy_arn, str) and (
                _matches_any(policy_arn, DEFAULT_ESCALATION_PATTERNS) is not None
            ):
                # Admin attachment: link the principal to every known data node.
                for data_node in [n for n, d in g.nodes(data=True) if d.get("kind") == "data"]:
                    _add_edge(g, principal, data_node, f"admin via {policy_arn}")

    elif rtype in sensitive_types:
        _add_node(g, address, "data")


def _build_gcp_edges(
    g: nx.DiGraph,
    rc: dict[str, Any],
    state: Literal["before", "after"],
    sensitive_types: frozenset[str],
) -> None:
    rtype = rc.get("type")
    address = rc.get("address") or ""
    if not _resource_present(rc, state):
        return
    attrs = _state_value(rc, state)

    if rtype == "google_compute_firewall":
        _add_node(g, address, "sg")
        ranges = set(attrs.get("source_ranges") or [])
        if ranges & PUBLIC_CIDRS:
            _add_node(g, INTERNET_NODE, "internet")
            _add_edge(g, INTERNET_NODE, address, "gcp-firewall-public")

    elif rtype == "google_compute_instance":
        _add_node(g, address, "compute")
        sa = attrs.get("service_account") or {}
        if isinstance(sa, dict) and isinstance(sa.get("email"), str):
            principal = f"gcp_sa.{sa['email']}"
            _add_node(g, principal, "principal")
            _add_edge(g, address, principal, "gce service account")
        elif isinstance(sa, list):
            for entry in sa:
                if isinstance(entry, dict) and isinstance(entry.get("email"), str):
                    principal = f"gcp_sa.{entry['email']}"
                    _add_node(g, principal, "principal")
                    _add_edge(g, address, principal, "gce service account")

    elif rtype in sensitive_types:
        _add_node(g, address, "data")


def _resource_arn_to_address(resource: str) -> str | None:
    """Map an AWS ARN-shaped Resource string to a synthetic address node.

    Returns None for wildcard / cross-cutting resources (`*`, `arn:...:*`,
    `arn:...*/*`); those are linked at graph-finalization time to every
    sensitive data node.
    """
    if not isinstance(resource, str):
        return None
    if resource == "*":
        return None
    if resource.endswith(":*") or resource.endswith("/*"):
        return None
    # Heuristic: keep last segment that looks like an identifier.
    return f"arn:{resource}"


def build_graph(
    plan: dict[str, Any],
    state: Literal["before", "after"],
    config: ReviewConfig | None = None,
) -> nx.DiGraph:
    cfg = config or default_config()
    sensitive = DEFAULT_SENSITIVE_TYPES | cfg.stateful_types
    g: nx.DiGraph = nx.DiGraph()
    # Add data nodes first so IAM grants can attach to them.
    for rc in plan.get("resource_changes") or []:
        rtype = rc.get("type")
        if rtype in sensitive and _resource_present(rc, state):
            _add_node(g, rc.get("address") or "", "data")
    # Now process all edges.
    for rc in plan.get("resource_changes") or []:
        rtype = rc.get("type") or ""
        if rtype.startswith("aws_"):
            _build_aws_edges(g, rc, state, sensitive)
        elif rtype.startswith("google_"):
            _build_gcp_edges(g, rc, state, sensitive)
    return g


# ---------------- path enumeration ----------------


def _enumerate_paths(
    g: nx.DiGraph,
    *,
    max_depth: int = DEFAULT_MAX_PATH_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> list[list[str]]:
    if INTERNET_NODE not in g:
        return []
    data_nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == "data"]
    out: list[list[str]] = []
    for sink in data_nodes:
        if sink not in g or not nx.has_path(g, INTERNET_NODE, sink):
            continue
        for path in nx.all_simple_paths(
            g, INTERNET_NODE, sink, cutoff=max_depth
        ):
            out.append(path)
            if len(out) >= max_paths:
                return out
    return out


def _path_kinds(g: nx.DiGraph, path: list[str]) -> list[dict[str, str]]:
    return [
        {"address": n, "kind": g.nodes[n].get("kind") or "unknown"}
        for n in path
    ]


def _path_id(path: list[str]) -> tuple[str, ...]:
    return tuple(path)


# ---------------- diff ----------------


def _edges_in_path(path: list[str]) -> set[tuple[str, str]]:
    return {(a, b) for a, b in zip(path, path[1:])}


def _classify_path(
    g_after: nx.DiGraph,
    g_before: nx.DiGraph,
    path: list[str],
    *,
    before_paths: set[tuple[str, ...]],
) -> tuple[bool, list[str]]:
    """Return (is_new, list_of_edges_changed_by_plan)."""
    pid = _path_id(path)
    is_new = pid not in before_paths
    edges_changed: list[str] = []
    for a, b in zip(path, path[1:]):
        if g_before.has_edge(a, b):
            continue
        edges_changed.append(f"{a} -> {b}")
    return is_new, edges_changed


# ---------------- narrative ----------------


def _narrate(
    g: nx.DiGraph, path: list[str], edges_changed: list[str]
) -> str:
    if len(path) < 2:
        return ""
    bits = []
    for src, dst in zip(path, path[1:]):
        reason = g.edges.get((src, dst), {}).get("reason", "")
        connector = f" -> {dst}" if not reason else f" -> {dst} [{reason}]"
        bits.append(connector if bits else f"{src}{connector}")
    body = "".join(bits)
    if edges_changed:
        body += f". Edges introduced by this plan: {', '.join(edges_changed)}."
    return body


# ---------------- severity ----------------


def _severity(is_new: bool, edges_changed: list[str]) -> str:
    if is_new:
        return "blocker"
    if edges_changed:
        return "warn"
    return "info"


# ---------------- entry points ----------------


def analyze_attack_paths_from_json(
    plan: dict[str, Any],
    config: ReviewConfig | None = None,
    *,
    include_preexisting: bool = False,
    max_depth: int = DEFAULT_MAX_PATH_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> AttackPathSummary:
    g_before = build_graph(plan, "before", config=config)
    g_after = build_graph(plan, "after", config=config)

    after_paths = _enumerate_paths(g_after, max_depth=max_depth, max_paths=max_paths)
    before_path_ids = {
        _path_id(p)
        for p in _enumerate_paths(g_before, max_depth=max_depth, max_paths=max_paths)
    }

    paths: list[AttackPath] = []
    widened = 0
    preexisting_unchanged = 0
    for path in after_paths:
        is_new, edges_changed = _classify_path(
            g_after, g_before, path, before_paths=before_path_ids
        )
        if not is_new and not edges_changed:
            preexisting_unchanged += 1
            if not include_preexisting:
                continue
        if not is_new and edges_changed:
            widened += 1
        paths.append(
            AttackPath(
                path=_path_kinds(g_after, path),
                is_new=is_new,
                edges_changed_by_plan=edges_changed,
                severity=_severity(is_new, edges_changed),
                narrative=_narrate(g_after, path, edges_changed),
            )
        )

    summary = {
        "new_paths": sum(1 for p in paths if p.is_new),
        "widened_paths": widened,
        "preexisting_paths_unchanged": preexisting_unchanged,
    }
    return AttackPathSummary(paths=paths, summary=summary)


def analyze_attack_paths_from_plan(
    plan_json_path: str | Path,
    config: ReviewConfig | None = None,
    **kwargs: Any,
) -> AttackPathSummary:
    p = validate_plan_path(plan_json_path)
    if not p.exists():
        raise FileNotFoundError(f"Plan file not found: {p}")
    with p.open() as f:
        plan = json.load(f)
    return analyze_attack_paths_from_json(plan, config=config, **kwargs)
