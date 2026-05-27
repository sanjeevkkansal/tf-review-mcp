"""Runtime configuration for tf-review-mcp.

Built-in defaults live here. Teams extend them with a `.tf-review.yml`
discovered at runtime (cwd or any parent dir, or `TF_REVIEW_CONFIG`).

Pure functions, no MCP imports. Keep the schema small and the validator
hand-rolled so we don't pull in pydantic for v0.3.1.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Built-in defaults. Kept here so review.py and cost.py both consume one
# source of truth.

_DEFAULT_HIGH_RISK_TYPES: frozenset[str] = frozenset(
    {
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
)

_DEFAULT_STATEFUL_TYPES: frozenset[str] = frozenset(
    {
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
)

_DEFAULT_PUBLIC_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})

_DEFAULT_COST_THRESHOLDS: dict[str, float] = {
    "info_usd": 100.0,
    "warn_usd": 500.0,
    "blocker_usd": 1000.0,
}

# Rule identifiers that can be disabled via `disabled_rules` in the YAML.
KNOWN_RULES: frozenset[str] = frozenset(
    {"high-risk", "stateful-destroy", "public-exposure", "cost-delta"}
)


class ConfigError(ValueError):
    """Raised when a user-provided `.tf-review.yml` fails validation."""


@dataclass(frozen=True)
class ReviewConfig:
    high_risk_types: frozenset[str]
    stateful_types: frozenset[str]
    public_cidrs: frozenset[str]
    cost_thresholds: dict[str, float]
    disabled_rules: frozenset[str]
    source_path: str | None = None  # absolute path to the loaded YAML, or None

    def is_rule_disabled(self, rule: str) -> bool:
        return rule in self.disabled_rules

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # asdict turns frozensets into sets, which json.dumps can't serialize.
        d["high_risk_types"] = sorted(self.high_risk_types)
        d["stateful_types"] = sorted(self.stateful_types)
        d["public_cidrs"] = sorted(self.public_cidrs)
        d["disabled_rules"] = sorted(self.disabled_rules)
        return d


def default_config() -> ReviewConfig:
    return ReviewConfig(
        high_risk_types=_DEFAULT_HIGH_RISK_TYPES,
        stateful_types=_DEFAULT_STATEFUL_TYPES,
        public_cidrs=_DEFAULT_PUBLIC_CIDRS,
        cost_thresholds=dict(_DEFAULT_COST_THRESHOLDS),
        disabled_rules=frozenset(),
        source_path=None,
    )


def _as_str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"`{field_name}` must be a list of strings")
    return value


def _as_float_map(value: Any, field_name: str) -> dict[str, float]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"`{field_name}` must be a mapping")
    out: dict[str, float] = {}
    for k, v in value.items():
        if not isinstance(k, str):
            raise ConfigError(f"`{field_name}` keys must be strings")
        try:
            out[k] = float(v)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"`{field_name}.{k}` must be a number") from exc
    return out


def _config_from_mapping(raw: dict[str, Any], source: Path | None) -> ReviewConfig:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    version = raw.get("version", 1)
    if version != 1:
        raise ConfigError(f"unsupported config version: {version!r} (expected 1)")

    extra_hr = _as_str_list(raw.get("extra_high_risk_types"), "extra_high_risk_types")
    extra_st = _as_str_list(raw.get("extra_stateful_types"), "extra_stateful_types")
    extra_cidrs = _as_str_list(raw.get("extra_public_cidrs"), "extra_public_cidrs")
    disabled = _as_str_list(raw.get("disabled_rules"), "disabled_rules")

    unknown = [r for r in disabled if r not in KNOWN_RULES]
    if unknown:
        raise ConfigError(
            f"unknown rule(s) in `disabled_rules`: {unknown}. "
            f"Known rules: {sorted(KNOWN_RULES)}"
        )

    thresholds = dict(_DEFAULT_COST_THRESHOLDS)
    overrides = _as_float_map(raw.get("cost_thresholds"), "cost_thresholds")
    for k, v in overrides.items():
        if k not in thresholds:
            raise ConfigError(
                f"unknown `cost_thresholds.{k}`. Known keys: {sorted(thresholds)}"
            )
        thresholds[k] = v

    return ReviewConfig(
        high_risk_types=_DEFAULT_HIGH_RISK_TYPES | frozenset(extra_hr),
        stateful_types=_DEFAULT_STATEFUL_TYPES | frozenset(extra_st),
        public_cidrs=_DEFAULT_PUBLIC_CIDRS | frozenset(extra_cidrs),
        cost_thresholds=thresholds,
        disabled_rules=frozenset(disabled),
        source_path=str(source.resolve()) if source else None,
    )


def _discover_config_path(start: Path) -> Path | None:
    """Walk from `start` up to filesystem root looking for `.tf-review.yml`."""
    current = start.resolve()
    while True:
        candidate = current / ".tf-review.yml"
        if candidate.is_file():
            return candidate
        if current.parent == current:
            return None
        current = current.parent


def load_config(start_path: str | Path | None = None) -> ReviewConfig:
    """Discover and load `.tf-review.yml`.

    Precedence:
      1. `TF_REVIEW_CONFIG=/abs/path` env var.
      2. `.tf-review.yml` in `start_path` (or cwd if None).
      3. Walk up parent directories until filesystem root.
      4. Built-in defaults.

    Raises `ConfigError` if YAML is present but malformed. Missing files
    are not an error; they just fall through to defaults.
    """
    env_override = os.environ.get("TF_REVIEW_CONFIG")
    if env_override:
        path = Path(env_override).expanduser()
        if not path.is_file():
            raise ConfigError(
                f"TF_REVIEW_CONFIG points to a missing file: {path}"
            )
        return _load_from_file(path)

    start = Path(start_path).expanduser() if start_path else Path.cwd()
    if start.is_file():
        start = start.parent
    found = _discover_config_path(start)
    if found is None:
        return default_config()
    return _load_from_file(found)


def _load_from_file(path: Path) -> ReviewConfig:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ConfigError(
            "PyYAML is required to load .tf-review.yml. "
            "Install with: pip install 'tf-review-mcp[yaml]'"
        ) from exc

    try:
        with path.open() as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if raw is None:
        # Empty file. Treat as defaults but record the source so introspection
        # still shows where the (empty) config came from.
        return ReviewConfig(
            high_risk_types=_DEFAULT_HIGH_RISK_TYPES,
            stateful_types=_DEFAULT_STATEFUL_TYPES,
            public_cidrs=_DEFAULT_PUBLIC_CIDRS,
            cost_thresholds=dict(_DEFAULT_COST_THRESHOLDS),
            disabled_rules=frozenset(),
            source_path=str(path.resolve()),
        )

    return _config_from_mapping(raw, path)
