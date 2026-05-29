"""Semantic IAM-change classifier.

Walks `resource_changes` for IAM-shaped resources across AWS, GCP, and
Azure, diffs before/after, and classifies each change as one or more of:

  - escalation: new admin-equivalent permissions
  - lateral:    new cross-principal or cross-service trust
  - exfil:      new read/decrypt on broad resource scopes
  - tightening: privileges removed (informational only)

Pure functions, no MCP imports. The server module calls
`review_iam_changes_from_plan` and serializes the result.

Pattern sets live as module constants. The YAML config can extend them
via `extra_escalation_patterns`, `extra_lateral_patterns`,
`extra_exfil_patterns`. Patterns are matched case-insensitively. AWS
action patterns may use a trailing `*` glob.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import ReviewConfig, default_config
from .safety import validate_plan_path

# Resource types we walk.

_AWS_IAM_TYPES: frozenset[str] = frozenset(
    {
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_iam_policy",
        "aws_iam_policy_attachment",
        "aws_iam_user_policy",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy",
        "aws_iam_group_policy_attachment",
    }
)

_GCP_IAM_TYPES: frozenset[str] = frozenset(
    {
        "google_project_iam_member",
        "google_project_iam_binding",
        "google_project_iam_policy",
        "google_service_account_iam_member",
        "google_service_account_iam_binding",
        "google_service_account_iam_policy",
        "google_storage_bucket_iam_member",
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_policy",
        "google_folder_iam_member",
        "google_folder_iam_binding",
        "google_organization_iam_member",
        "google_organization_iam_binding",
    }
)

_AZURE_IAM_TYPES: frozenset[str] = frozenset(
    {
        "azurerm_role_assignment",
        "azurerm_role_definition",
    }
)

IAM_RESOURCE_TYPES: frozenset[str] = (
    _AWS_IAM_TYPES | _GCP_IAM_TYPES | _AZURE_IAM_TYPES
)

# Pattern sets. All compared lowercased.

DEFAULT_ESCALATION_PATTERNS: frozenset[str] = frozenset(
    {
        # AWS action wildcards
        "*",
        "*:*",
        "iam:*",
        "iam:passrole",
        "sts:assumerole",
        "organizations:*",
        "kms:*",
        # AWS managed admin policy ARNs
        "arn:aws:iam::aws:policy/administratoraccess",
        "arn:aws:iam::aws:policy/poweruseraccess",
        # GCP primitive admin roles
        "roles/owner",
        "roles/editor",
        # GCP elevated
        "roles/iam.securityadmin",
        "roles/resourcemanager.organizationadmin",
        "roles/iam.organizationroleadmin",
        # Azure
        "owner",
        "contributor",
        "user access administrator",
    }
)

DEFAULT_LATERAL_PATTERNS: frozenset[str] = frozenset(
    {
        # AWS
        "iam:passrole",
        "sts:assumerole",
        "sts:assumerolewithwebidentity",
        "sts:assumerolewithsaml",
        # GCP
        "roles/iam.serviceaccountuser",
        "roles/iam.serviceaccounttokencreator",
        "roles/iam.workloadidentityuser",
        # Azure
        "managed identity operator",
    }
)

DEFAULT_EXFIL_PATTERNS: frozenset[str] = frozenset(
    {
        # AWS - reads on broad scopes
        "s3:getobject",
        "s3:get*",
        "s3:list*",
        "kms:decrypt",
        "kms:generatedatakey*",
        "secretsmanager:getsecretvalue",
        "ssm:getparameter",
        "ssm:getparameters",
        "ssm:getparametersbypath",
        "dynamodb:getitem",
        "dynamodb:scan",
        "dynamodb:query",
        "rds:downloaddbloggile*",
        # GCP read roles
        "roles/storage.objectviewer",
        "roles/secretmanager.secretaccessor",
        "roles/cloudkms.cryptokeydecrypter",
        "roles/bigquery.dataviewer",
        # Azure
        "key vault secrets user",
        "storage blob data reader",
        "reader",
    }
)

# AWS actions where pairing with a Resource wildcard makes the
# classification firmly an exfil signal. Without a resource wildcard
# these are not flagged (broad read on a single ARN is usually fine).
_EXFIL_REQUIRES_WILDCARD_RESOURCE: frozenset[str] = frozenset(
    {
        "s3:getobject",
        "s3:list*",
        "s3:get*",
        "kms:decrypt",
        "kms:generatedatakey*",
        "secretsmanager:getsecretvalue",
        "ssm:getparameter",
        "ssm:getparameters",
        "ssm:getparametersbypath",
        "dynamodb:getitem",
        "dynamodb:scan",
        "dynamodb:query",
    }
)


@dataclass
class IamChange:
    address: str
    type: str
    actions: list[str]
    classifications: list[str]
    added_permissions: list[str]
    removed_permissions: list[str]
    narrative: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IamChangesSummary:
    iam_changes: list[IamChange]
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "iam_changes": [c.to_dict() for c in self.iam_changes],
            "summary": dict(self.summary),
        }


# ---------------- AWS helpers ----------------


def _parse_policy(value: Any) -> dict[str, Any] | None:
    """AWS policy fields are sometimes a JSON string, sometimes a dict."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _statement_action_resource_pairs(
    statement: dict[str, Any],
) -> list[tuple[str, str]]:
    """Extract `(action, resource)` pairs from an AWS policy statement.

    Skips Deny statements (we are flagging granted permissions).
    Pairs every Action with every Resource (cartesian).
    """
    if statement.get("Effect", "Allow") != "Allow":
        return []
    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    if not resources:
        resources = ["*"]  # trust policies omit Resource; treat as wildcard
    out: list[tuple[str, str]] = []
    for a in actions:
        if not isinstance(a, str):
            continue
        for r in resources:
            if not isinstance(r, str):
                continue
            out.append((a, r))
    return out


def _policy_doc_pairs(doc: dict[str, Any] | None) -> set[tuple[str, str]]:
    if doc is None:
        return set()
    statements = _as_list(doc.get("Statement"))
    out: set[tuple[str, str]] = set()
    for s in statements:
        if isinstance(s, dict):
            out.update(_statement_action_resource_pairs(s))
    return out


def _trust_principals(doc: dict[str, Any] | None) -> set[str]:
    """Return the set of trust-policy principal strings (AWS assume_role_policy)."""
    if doc is None:
        return set()
    out: set[str] = set()
    for s in _as_list(doc.get("Statement")):
        if not isinstance(s, dict):
            continue
        if s.get("Effect", "Allow") != "Allow":
            continue
        principal = s.get("Principal") or {}
        if isinstance(principal, str):
            out.add(principal)
            continue
        if isinstance(principal, dict):
            for kind, value in principal.items():
                for v in _as_list(value):
                    if isinstance(v, str):
                        out.add(f"{kind}:{v}")
    return out


# ---------------- pattern matching ----------------


def _matches_any(action: str, patterns: Iterable[str]) -> str | None:
    """Return the matching pattern (lowercased) or None.

    Semantics: we match when the *granted action* equals or subsumes a
    dangerous pattern. Direction matters. `iam:*` grants `iam:passrole`
    (the action subsumes the pattern), so it should match. But
    `iam:GetUser` does not grant `iam:*`, so granting `iam:GetUser`
    should NOT match the `iam:*` escalation pattern.

    Implementation: `fnmatch(pattern, action)` asks whether the literal
    `pattern` string matches the glob `action`. Wildcards live in the
    granted action; dangerous patterns are literal.
    """
    a = action.lower()
    for p in patterns:
        pl = p.lower()
        if "*" in a:
            if fnmatch.fnmatchcase(pl, a):
                return pl
        else:
            if a == pl:
                return pl
    return None


def _classify_aws_pair(
    action: str,
    resource: str,
    *,
    escalation: Iterable[str],
    lateral: Iterable[str],
    exfil: Iterable[str],
) -> list[str]:
    classes: list[str] = []
    if _matches_any(action, escalation) is not None:
        classes.append("escalation")
    if _matches_any(action, lateral) is not None:
        if "escalation" not in classes:
            classes.append("lateral")
    exfil_hit = _matches_any(action, exfil)
    if exfil_hit is not None:
        action_l = action.lower()
        if action_l in _EXFIL_REQUIRES_WILDCARD_RESOURCE:
            if resource.strip() == "*" or resource.endswith(":*") or "/*" in resource:
                classes.append("exfil")
        else:
            classes.append("exfil")
    return classes


def _classify_role(
    role: str,
    *,
    escalation: Iterable[str],
    lateral: Iterable[str],
    exfil: Iterable[str],
) -> list[str]:
    """Classify a GCP / Azure role string (no resource pairing)."""
    classes: list[str] = []
    if _matches_any(role, escalation) is not None:
        classes.append("escalation")
    if _matches_any(role, lateral) is not None and "escalation" not in classes:
        classes.append("lateral")
    if _matches_any(role, exfil) is not None:
        classes.append("exfil")
    return classes


# ---------------- per-type classifiers ----------------


def _aws_inline_policy_change(
    rc: dict[str, Any],
    *,
    escalation: Iterable[str],
    lateral: Iterable[str],
    exfil: Iterable[str],
) -> IamChange | None:
    """Handle an AWS resource whose primary content is an inline policy doc."""
    change = rc.get("change") or {}
    actions = list(change.get("actions") or [])
    if not actions or actions == ["no-op"]:
        return None

    rtype = rc.get("type") or ""
    address = rc.get("address") or ""
    before = change.get("before") or {}
    after = change.get("after") or {}

    if rtype == "aws_iam_role":
        before_doc = _parse_policy(before.get("assume_role_policy"))
        after_doc = _parse_policy(after.get("assume_role_policy"))
        before_principals = _trust_principals(before_doc)
        after_principals = _trust_principals(after_doc)
        added = sorted(after_principals - before_principals)
        removed = sorted(before_principals - after_principals)
        classifications: list[str] = []
        if added:
            classifications.append("lateral")
        if removed and not added:
            classifications.append("tightening")
        if not classifications:
            return None
        narrative = _trust_narrative(address, added, removed)
        return IamChange(
            address=address,
            type=rtype,
            actions=actions,
            classifications=classifications,
            added_permissions=[f"trust:{p}" for p in added],
            removed_permissions=[f"trust:{p}" for p in removed],
            narrative=narrative,
            severity=_severity(classifications),
        )

    # All other inline-policy types.
    policy_key = "policy"
    before_doc = _parse_policy(before.get(policy_key))
    after_doc = _parse_policy(after.get(policy_key))
    before_pairs = _policy_doc_pairs(before_doc)
    after_pairs = _policy_doc_pairs(after_doc)
    added_pairs = sorted(after_pairs - before_pairs)
    removed_pairs = sorted(before_pairs - after_pairs)
    if not added_pairs and not removed_pairs:
        return None

    classifications: list[str] = []
    seen: set[str] = set()
    for action, resource in added_pairs:
        for cls in _classify_aws_pair(
            action, resource, escalation=escalation, lateral=lateral, exfil=exfil
        ):
            if cls not in seen:
                seen.add(cls)
                classifications.append(cls)
    # Surface tightening when any removed permission matched a dangerous
    # pattern, regardless of whether new permissions were also added.
    removed_dangerous = any(
        _classify_aws_pair(
            action, resource, escalation=escalation, lateral=lateral, exfil=exfil
        )
        for action, resource in removed_pairs
    )
    if removed_dangerous and "tightening" not in classifications:
        classifications.append("tightening")
    if not classifications:
        # Permissions changed but none matched any pattern set.
        return None

    narrative = _policy_narrative(address, rtype, added_pairs, removed_pairs)
    return IamChange(
        address=address,
        type=rtype,
        actions=actions,
        classifications=classifications,
        added_permissions=[f"{a} on {r}" for a, r in added_pairs],
        removed_permissions=[f"{a} on {r}" for a, r in removed_pairs],
        narrative=narrative,
        severity=_severity(classifications),
    )


def _aws_policy_attachment(
    rc: dict[str, Any],
    *,
    escalation: Iterable[str],
) -> IamChange | None:
    """Classify an aws_iam_*_policy_attachment by managed-policy ARN."""
    change = rc.get("change") or {}
    actions = list(change.get("actions") or [])
    if not actions or actions == ["no-op"]:
        return None
    rtype = rc.get("type") or ""
    address = rc.get("address") or ""
    before = change.get("before") or {}
    after = change.get("after") or {}

    before_arns: set[str] = set()
    after_arns: set[str] = set()
    for key in ("policy_arn", "policy_arns"):
        before_arns.update(s for s in _as_list(before.get(key)) if isinstance(s, str))
        after_arns.update(s for s in _as_list(after.get(key)) if isinstance(s, str))

    added = sorted(after_arns - before_arns)
    removed = sorted(before_arns - after_arns)
    if not added and not removed:
        return None

    classifications: list[str] = []
    for arn in added:
        if _matches_any(arn, escalation) is not None:
            classifications.append("escalation")
            break
    if removed and not added:
        classifications.append("tightening")
    if not classifications:
        return None

    narrative = (
        f"{address} ({rtype}): attaches "
        f"{', '.join(added)}" if added else
        f"{address} ({rtype}): detaches {', '.join(removed)}"
    )
    return IamChange(
        address=address,
        type=rtype,
        actions=actions,
        classifications=classifications,
        added_permissions=[f"attach:{a}" for a in added],
        removed_permissions=[f"detach:{a}" for a in removed],
        narrative=narrative,
        severity=_severity(classifications),
    )


def _gcp_iam_change(
    rc: dict[str, Any],
    *,
    escalation: Iterable[str],
    lateral: Iterable[str],
    exfil: Iterable[str],
) -> IamChange | None:
    change = rc.get("change") or {}
    actions = list(change.get("actions") or [])
    if not actions or actions == ["no-op"]:
        return None
    rtype = rc.get("type") or ""
    address = rc.get("address") or ""
    before = change.get("before") or {}
    after = change.get("after") or {}

    before_pairs: set[tuple[str, str]] = set()
    after_pairs: set[tuple[str, str]] = set()
    for src, sink in ((before, before_pairs), (after, after_pairs)):
        role = src.get("role")
        if isinstance(role, str):
            members = _as_list(src.get("member") or src.get("members"))
            for m in members:
                if isinstance(m, str):
                    sink.add((role, m))
                else:
                    sink.add((role, "(unknown)"))

    added = sorted(after_pairs - before_pairs)
    removed = sorted(before_pairs - after_pairs)
    if not added and not removed:
        return None

    classifications: list[str] = []
    seen: set[str] = set()
    for role, _member in added:
        for cls in _classify_role(
            role, escalation=escalation, lateral=lateral, exfil=exfil
        ):
            if cls not in seen:
                seen.add(cls)
                classifications.append(cls)
    if removed and not added:
        classifications.append("tightening")
    if not classifications:
        return None

    narrative_bits = [f"{address} ({rtype})"]
    if added:
        narrative_bits.append(
            "adds " + ", ".join(f"{r} to {m}" for r, m in added)
        )
    if removed:
        narrative_bits.append(
            "removes " + ", ".join(f"{r} from {m}" for r, m in removed)
        )
    narrative = ". ".join(narrative_bits) + "."

    return IamChange(
        address=address,
        type=rtype,
        actions=actions,
        classifications=classifications,
        added_permissions=[f"{r} -> {m}" for r, m in added],
        removed_permissions=[f"{r} -> {m}" for r, m in removed],
        narrative=narrative,
        severity=_severity(classifications),
    )


def _azure_iam_change(
    rc: dict[str, Any],
    *,
    escalation: Iterable[str],
    lateral: Iterable[str],
    exfil: Iterable[str],
) -> IamChange | None:
    change = rc.get("change") or {}
    actions = list(change.get("actions") or [])
    if not actions or actions == ["no-op"]:
        return None
    rtype = rc.get("type") or ""
    address = rc.get("address") or ""
    before = change.get("before") or {}
    after = change.get("after") or {}

    def role_name_from(d: dict[str, Any]) -> str | None:
        for key in ("role_definition_name", "role_definition_id"):
            v = d.get(key)
            if isinstance(v, str):
                return v
        return None

    before_role = role_name_from(before)
    after_role = role_name_from(after)
    if before_role == after_role and after_role is None:
        return None
    if before_role == after_role and actions == ["update"]:
        # Scope change, principal change, etc. Treat as info-level only.
        return None

    classifications: list[str] = []
    if after_role:
        classifications.extend(
            _classify_role(
                after_role, escalation=escalation, lateral=lateral, exfil=exfil
            )
        )
    if before_role and not after_role:
        classifications.append("tightening")
    if not classifications:
        return None

    narrative = f"{address} ({rtype}) assigns {after_role or '(none)'}."
    return IamChange(
        address=address,
        type=rtype,
        actions=actions,
        classifications=classifications,
        added_permissions=[after_role] if after_role else [],
        removed_permissions=[before_role] if before_role and not after_role else [],
        narrative=narrative,
        severity=_severity(classifications),
    )


# ---------------- narrative / severity ----------------


def _severity(classifications: list[str]) -> str:
    if "escalation" in classifications or "lateral" in classifications:
        return "blocker"
    if "exfil" in classifications:
        return "warn"
    return "info"


def _trust_narrative(
    address: str, added: list[str], removed: list[str]
) -> str:
    parts = [f"{address} (aws_iam_role) trust policy"]
    if added:
        parts.append("adds principal(s): " + ", ".join(added))
    if removed:
        parts.append("removes principal(s): " + ", ".join(removed))
    return ". ".join(parts) + "."


def _looks_cross_account(principal: str) -> bool:
    """Heuristic: AWS principal references that name another account."""
    if "arn:aws:iam::" not in principal:
        return False
    # Strip the "kind:" prefix added by _trust_principals.
    if ":" in principal:
        principal = principal.split(":", 1)[1]
    try:
        account = principal.split("::", 1)[1].split(":", 1)[0]
    except IndexError:
        return False
    return account.isdigit() and len(account) == 12


def _policy_narrative(
    address: str,
    rtype: str,
    added: list[tuple[str, str]],
    removed: list[tuple[str, str]],
) -> str:
    parts = [f"{address} ({rtype})"]
    if added:
        sample = ", ".join(f"{a} on {r}" for a, r in added[:5])
        more = f" (+{len(added) - 5} more)" if len(added) > 5 else ""
        parts.append("adds " + sample + more)
    if removed:
        sample = ", ".join(f"{a} on {r}" for a, r in removed[:5])
        more = f" (+{len(removed) - 5} more)" if len(removed) > 5 else ""
        parts.append("removes " + sample + more)
    return ". ".join(parts) + "."


# ---------------- entry points ----------------


def review_iam_changes_from_json(
    plan: dict[str, Any], config: ReviewConfig | None = None
) -> IamChangesSummary:
    cfg = config or default_config()
    escalation = DEFAULT_ESCALATION_PATTERNS | cfg.extra_escalation_patterns
    lateral = DEFAULT_LATERAL_PATTERNS | cfg.extra_lateral_patterns
    exfil = DEFAULT_EXFIL_PATTERNS | cfg.extra_exfil_patterns

    iam_changes: list[IamChange] = []
    for rc in plan.get("resource_changes") or []:
        rtype = rc.get("type")
        if rtype not in IAM_RESOURCE_TYPES:
            continue
        change: IamChange | None
        if rtype in _AZURE_IAM_TYPES:
            change = _azure_iam_change(
                rc, escalation=escalation, lateral=lateral, exfil=exfil
            )
        elif rtype in _GCP_IAM_TYPES:
            change = _gcp_iam_change(
                rc, escalation=escalation, lateral=lateral, exfil=exfil
            )
        elif rtype.endswith("policy_attachment"):
            change = _aws_policy_attachment(rc, escalation=escalation)
        else:
            change = _aws_inline_policy_change(
                rc, escalation=escalation, lateral=lateral, exfil=exfil
            )
        if change is not None:
            iam_changes.append(change)

    summary = {
        "escalation_count": sum(
            1 for c in iam_changes if "escalation" in c.classifications
        ),
        "lateral_count": sum(
            1 for c in iam_changes if "lateral" in c.classifications
        ),
        "exfil_count": sum(
            1 for c in iam_changes if "exfil" in c.classifications
        ),
        "tightening_count": sum(
            1 for c in iam_changes if "tightening" in c.classifications
        ),
        "total": len(iam_changes),
    }
    return IamChangesSummary(iam_changes=iam_changes, summary=summary)


def review_iam_changes_from_plan(
    plan_json_path: str | Path,
    config: ReviewConfig | None = None,
) -> IamChangesSummary:
    p = validate_plan_path(plan_json_path)
    if not p.exists():
        raise FileNotFoundError(f"Plan file not found: {p}")
    with p.open() as f:
        plan = json.load(f)
    return review_iam_changes_from_json(plan, config=config)
