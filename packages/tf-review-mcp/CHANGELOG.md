# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [0.4.2] - 2026-05-28

New tool: `analyze_attack_paths`. Graph-based reachability search from
the public internet to sensitive data, with new-vs-widened diff. This
is the flagship v0.4 feature.

### Added
- `analyze_attack_paths(plan_json_path)` MCP tool. Builds a directed
  graph from `resource_changes` (compute, IAM principals, data stores,
  network edges, public ingress), searches for simple paths from a
  synthetic `internet` node to any sensitive resource, diffs against
  the before-state, and surfaces paths that are *new* or *widened*.
- New `attack_paths.py` module (pure functions, no MCP imports).
  Four layers: graph builder, path enumeration (via networkx
  `all_simple_paths`), diff, template-based narrative.
- AWS coverage is comprehensive: public ALB / NLB, CloudFront,
  API Gateway, security group ingress with `0.0.0.0/0` or `::/0`,
  SG attachment to EC2 / Lambda / ECS, instance profiles, IAM
  inline-policy grants resolving to data ARNs, IAM managed-admin
  attachments fanning out to every known data node.
- GCP coverage in v0.4.2 is intentionally light: public firewall
  rules, compute instances with service accounts, sensitive type
  recognition. Cross-network plumbing (transit gateways, VPC peering,
  endpoints) is v0.5 work.
- `DEFAULT_SENSITIVE_TYPES` covers RDS / Aurora / DynamoDB / S3 /
  ElastiCache / Secrets Manager / KMS / SSM Parameter on AWS, Cloud
  SQL / GCS / Secret Manager on GCP, and Key Vault / SQL Server /
  Storage Account on Azure. The set is extended by
  `ReviewConfig.stateful_types` so YAML overrides flow through.
- 11 tests in `test_attack_paths.py` covering new-path detection,
  widened-path detection, preexisting-unchanged suppression (and the
  `include_preexisting=True` knob), no-findings short-circuit, GCP
  node recognition, the disk-reading entry point, sensitive-type
  invariants, and a 500-resource performance benchmark
  (build + search must complete in under 2 seconds).
- 5 fixtures under `tests/fixtures/attack_paths/`.

### Dependencies
- `networkx>=3.0` is now a required runtime dependency. Pure Python,
  no native extensions, ~1MB. Used for `all_simple_paths` and the
  underlying `DiGraph`.

### Notes
- Path depth and total count are bounded at search time (defaults 8
  and 50). Long paths still ship in the JSON but the narrative is
  best read first-and-last-three-hops; the model client can decide
  whether to expand.
- The IAM pattern matcher from v0.4.1 (`_matches_any`,
  `_policy_doc_pairs`) is reused for the principal -> data edge
  builder; no duplicate logic.

## [0.4.1] - 2026-05-28

New tool: `review_iam_changes`. Semantic IAM-change classifier built
on top of v0.4.0's hardened core.

### Added
- `review_iam_changes(plan_json_path)` MCP tool. Walks IAM-shaped
  resources across AWS, GCP, and Azure, diffs before/after, and
  classifies each change as one or more of: `escalation`, `lateral`,
  `exfil`, `tightening`. Returns structured findings with
  `added_permissions`, `removed_permissions`, a deterministic
  template-based `narrative`, and a `severity` derived from the
  classification (escalation/lateral = blocker, exfil-only = warn,
  tightening-only = info).
- New `iam.py` module (pure functions, no MCP imports). Resource
  types covered: 9 AWS (`aws_iam_role`, policy, role/user/group
  inline + attachments), 13 GCP (project / SA / bucket / folder /
  org IAM bindings), 2 Azure (`azurerm_role_assignment`,
  `role_definition`).
- Default pattern sets (`DEFAULT_ESCALATION_PATTERNS`,
  `DEFAULT_LATERAL_PATTERNS`, `DEFAULT_EXFIL_PATTERNS`) covering
  the well-known dangerous actions and managed-policy ARNs.
  Extensible per team via `.tf-review.yml`:
  - `extra_escalation_patterns`
  - `extra_lateral_patterns`
  - `extra_exfil_patterns`
- `iam-review` rule id added to `KNOWN_RULES`; can be disabled via
  `disabled_rules: [iam-review]` in YAML.
- `suggest_review_comments` integrates IAM findings (blocker /
  warn severities only; info-tightening is suppressed there).
- 15 new tests in `test_iam.py` covering each classification, AWS
  inline policies, AWS trust-policy widening, AWS managed-admin
  attachment, GCP bindings, Azure role assignments, multi-class
  cases, no-IAM plans, and `extra_*_patterns` extension.
- 9 fixtures under `tests/fixtures/iam/`.

### Changed
- `ReviewConfig` gains `extra_escalation_patterns`,
  `extra_lateral_patterns`, `extra_exfil_patterns`. The existing
  fields and defaults are unchanged; callers that constructed
  `ReviewConfig` directly may need to add the new (defaulted) args.

### Implementation notes
- Pattern matching is unidirectional: a granted action matches a
  dangerous pattern when the action equals or subsumes the pattern.
  Granting `iam:GetUser` does NOT match the `iam:*` escalation
  pattern; granting `iam:*` does.
- The classifier is rule-based, not LLM-based, by design. Patterns
  are well-known and deterministic; the model's job is to read the
  structured output and write a comment, not to do the
  classification.

## [0.4.0] - 2026-05-28

Hardening release. No tool-contract changes, but every tool now
sanitizes LLM-facing output, and a new host-policy layer gates plan
file reads. Also wires up the new sibling package, `mcp-adversarial`,
and runs its harness against this server as a canary in CI.

### Added
- Every string field in tool output is sanitized via
  `mcp_adversarial.sanitize_for_model`: Unicode Cc/Cf control and
  format chars are stripped, lines that begin with known
  prompt-injection preambles are annotated with `[sus]` (originals
  preserved), and long strings are truncated with a marker. Resource
  addresses additionally go through `sanitize_address_or_marker`;
  traversal addresses are replaced with `[invalid-address]`.
- `safety.py` module exposing `validate_plan_path` and
  `policy_snapshot`. Two new env-driven host knobs:
  - `TF_REVIEW_ALLOWED_DIRS`: colon-separated directory prefix
    allowlist for plan file reads.
  - `TF_REVIEW_MAX_PLAN_BYTES`: max plan file size in bytes
    (default 50 MB).
- `get_active_config` output now includes a `host_policy` block with
  the active values of the two new env knobs.
- `mcp-adversarial` added as a runtime dependency (via uv workspace
  source). `test_adversarial_canary.py` spawns the real server via
  `python -m tf_review_mcp.server` and runs every packaged Terraform
  fixture through the harness on each commit.
- Repo-root `SECURITY.md` describing the trust boundary, the three
  mitigations above, and the threat-model summary.

### Changed
- `review_plan` and `suggest_review_comments` now return structured
  `{"error": ..., "kind": ...}` JSON on `PolicyError` or
  `FileNotFoundError`, matching the `estimate_cost_delta` pattern.
- `review_plan_file` raises `safety.PolicyError` on policy
  violations; `estimate_cost_delta_from_plan` catches it and returns
  the structured-error dict.

### Notes
- The default trust boundary for v1 stdio (developer's machine) is
  unchanged. `TF_REVIEW_ALLOWED_DIRS` is opt-in. The size cap is
  always active to protect against unbounded reads.

## [0.3.1] - 2026-05-21

### Added
- `.tf-review.yml` configuration file. Teams can extend the built-in
  `HIGH_RISK_TYPES`, `STATEFUL_TYPES`, and public-CIDR lists, override
  cost thresholds, and disable specific rules without forking.
- Config discovery: `TF_REVIEW_CONFIG` env var > `.tf-review.yml` in cwd
  > walk-up to filesystem root > built-in defaults.
- `get_active_config` MCP tool. Returns the merged config (defaults +
  YAML overrides) for debugging when expected findings don't appear.
- New `config.py` module with hand-rolled YAML schema validation. Surfaces
  unknown keys, unknown rule ids, and unsupported `version` fields as
  helpful errors rather than stack traces.
- 15 new tests in `tests/test_config.py` plus 2 in `tests/test_cost.py`
  covering threshold overrides and the `cost-delta` disable short-circuit.
- Example config fixture at `tests/fixtures/example_config.yml`.

### Changed
- `review_plan_file` and `review_plan_json` now accept an optional
  `config: ReviewConfig | None` argument. Passing `None` (or omitting
  the argument) preserves the v0.3.0 behavior.
- `estimate_cost_delta_from_plan` accepts the same optional config and
  reads thresholds from it.
- The MCP tools (`review_plan`, `suggest_review_comments`,
  `estimate_cost_delta`) discover the active config on every call so
  edits to `.tf-review.yml` are picked up without a server restart.
- Built-in classification lists moved from `review.py` into `config.py`
  as a single source of truth. The public API is unchanged.

### Added (dependencies)
- `PyYAML>=6.0` is now a required dependency.

## [0.3.0] - 2026-05-21

### Added
- `estimate_cost_delta` MCP tool that wraps the Infracost CLI to return
  a structured monthly cost delta for a Terraform plan: total delta,
  top contributors by absolute delta, currency, infracost version, and
  threshold-based notes.
- New `cost.py` module with `CostSummary` / `CostContributor` dataclasses
  and `estimate_cost_delta_from_plan()` pure function. No MCP imports,
  reusable from CLI or CI.
- Recoverable errors (missing `infracost` binary, non-zero exit, timeout,
  invalid plan JSON) return a structured `{"error": "..."}` dict so the
  model gets actionable text instead of a stack trace.
- Test suite (`tests/test_cost.py`) with mocked `subprocess.run` and
  `shutil.which` so CI runs without Infracost installed.

### Notes
- Cost-delta thresholds (`$100` info, `$500` warn, `$1000` blocker) are
  hardcoded in this release. The upcoming v0.3.1 YAML config will make
  them overridable per team.

## [0.2.0] - 2026-05-21

### Added
- GCP coverage in `HIGH_RISK_TYPES`: `google_compute_firewall`,
  `google_container_node_pool`, `google_dns_managed_zone`,
  `google_dns_record_set`, `google_project_iam_binding`.
- `google_compute_instance` added to `STATEFUL_TYPES` so a replace
  (boot disk + local SSD loss) surfaces as a blocker.
- Diff-aware public-exposure check: `google_compute_firewall` changes
  that add `0.0.0.0/0` or `::/0` to `source_ranges` are flagged as
  `public_exposure_changes` and reported as blockers.
- New `ExposureChange` dataclass and `public_exposure_changes` field on
  `ReviewSummary`.
- GCP test fixture (`tests/fixtures/gcp_plan.json`) and five new tests
  covering firewall widening, GCE instance replace, GCP high-risk types,
  child-resource scoping, and the new note text.

### Changed
- `suggest_review_comments` now emits a `blocker` for each public-exposure
  finding and dedups by resource address so a single resource never gets
  multiple comments.
- README and DESIGN updated to describe the new diff-aware capability
  and the broader provider coverage.

## [0.1.0] - 2026-05-20

### Added
- Initial release.
- `review_plan` and `suggest_review_comments` MCP tools.
- AWS / GCP / Azure high-risk type list (conservative defaults).
- Stateful-destroy detection for RDS, DynamoDB, S3, ElastiCache, Cloud SQL,
  GCS, Azure SQL.
- Fixture-backed unit tests.
- Stdio transport via FastMCP; `tf-review-mcp` console entry point.
