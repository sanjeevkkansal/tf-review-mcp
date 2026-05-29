# tf-review-mcp

[![Status](https://img.shields.io/badge/status-experimental-orange.svg)](#status)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

An MCP server that reviews Terraform plans for blast radius, stateful destroys, and high-risk resource changes. Plug it into Claude Desktop, Cursor, Claude Code, or any MCP client to get structured plan review on demand.

> **Status:** v0.4.2, experimental. Tool contracts may change before 1.0. Issues and PRs welcome.

![tf-review-mcp demo](docs/tf-mcp-demo.gif)

See [DESIGN.md](DESIGN.md) for architecture, threat model, and the existing-tools survey.

## Why

`terraform plan` outputs are long. Risky changes (IAM edits, security-group churn, RDS replacements) get missed in PR reviews. This server parses `terraform show -json` output and surfaces the things a human reviewer actually cares about, so a model can read them and write useful comments instead of summarizing the whole diff.

## What it does

Six tools:

- `review_plan(plan_json_path)` — returns a structured summary: action counts (create/update/delete/replace), high-blast-radius resource changes, stateful destroys, and diff-aware public-exposure findings.
- `suggest_review_comments(plan_json_path)` — returns a list of `{address, severity, comment}` objects ready to drop into a PR review. Severities: `blocker | warn | info`. Includes IAM findings.
- `review_iam_changes(plan_json_path)` — classifies IAM policy changes by privilege impact: `escalation`, `lateral`, `exfil`, `tightening`. Covers AWS, GCP, and Azure IAM-shaped resources.
- `analyze_attack_paths(plan_json_path)` — graph search from public internet to sensitive data (RDS / S3 / KMS / Secrets / Cloud SQL / GCS / Key Vault). Surfaces paths *introduced* or *widened* by this plan. See [Attack-path analysis](#attack-path-analysis) below.
- `estimate_cost_delta(plan_json_path)` — wraps the [Infracost](https://www.infracost.io/) CLI to return the projected monthly cost delta, top cost contributors, and threshold-based notes.
- `get_active_config()` — returns the merged `ReviewConfig` (built-in defaults plus any `.tf-review.yml` overrides). Useful for debugging when an expected finding doesn't appear.

What gets flagged:

- **High-risk types** (warn). Conservative built-in list across AWS, GCP, and Azure: IAM, RDS, KMS, security groups, S3, EKS, GKE, Cloud SQL, GCS, Cloud DNS, GCE firewalls, AKS, Key Vault, etc.
- **Stateful destroys** (blocker). RDS/Cloud SQL/DynamoDB/GCS/S3 deletes or replaces, plus `google_compute_instance` replaces (boot disk + local SSD loss).
- **Public exposure** (blocker). Diff-aware: catches `google_compute_firewall` changes that add `0.0.0.0/0` or `::/0` to `source_ranges`.
- **IAM privilege changes** (blocker / warn / info). Adds `iam:*`, attaching `AdministratorAccess`, granting `roles/owner`, widening `sts:AssumeRole` trust to another account: all classified and severity-ranked. See [IAM review](#iam-review) below.
- **Cost delta** (informational). Total monthly delta plus per-resource top contributors. Notes escalate at `$100`, `$500`, and `$1000` thresholds.

## IAM review

`review_iam_changes` walks IAM-shaped resources across AWS
(`aws_iam_role`, `_policy`, `_role_policy`, `_user_policy`,
`_group_policy`, `_*_policy_attachment`), GCP (`google_*_iam_member`,
`_iam_binding`, `_iam_policy` on projects, service accounts, buckets,
folders, orgs), and Azure (`azurerm_role_assignment`, `_role_definition`),
diffs before/after, and classifies each change:

| Class      | What it means                                                              | Severity |
| ---------- | -------------------------------------------------------------------------- | -------- |
| escalation | New admin-equivalent permissions (`iam:*`, `*:*`, `roles/owner`, `AdministratorAccess`, etc.) | blocker |
| lateral    | New cross-principal or cross-service trust (`sts:AssumeRole` widening, GCP `serviceAccount*`, Azure Managed Identity Operator) | blocker |
| exfil      | New read/decrypt on broad resource scopes (`s3:GetObject` on `*`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `roles/storage.objectViewer` on project) | warn |
| tightening | Privileges removed (informational, not a finding)                          | info |

Sample output for a plan that adds `iam:*` on `*` to an existing policy:

```json
{
  "iam_changes": [
    {
      "address": "aws_iam_policy.admin",
      "type": "aws_iam_policy",
      "actions": ["update"],
      "classifications": ["escalation"],
      "added_permissions": ["iam:* on *"],
      "removed_permissions": [],
      "narrative": "aws_iam_policy.admin (aws_iam_policy). adds iam:* on *.",
      "severity": "blocker"
    }
  ],
  "summary": {"escalation_count": 1, "lateral_count": 0, "exfil_count": 0, "tightening_count": 0, "total": 1}
}
```

Patterns are extensible per team via `.tf-review.yml`:

```yaml
extra_escalation_patterns:
  - "myorg:*"
extra_lateral_patterns:
  - "roles/myorg.crossAccountSetup"
extra_exfil_patterns:
  - "s3:GetBucketPolicy"
```

## Install

```bash
git clone https://github.com/your-user/tf-review-mcp.git
cd tf-review-mcp
pip install -e .
```

Requires Python 3.11+.

### Optional: Infracost for `estimate_cost_delta`

The `estimate_cost_delta` tool shells out to the Infracost CLI. Install it
once and authenticate (the API token is free for individual use):

```bash
brew install infracost
infracost auth login
```

If `infracost` is not on `PATH`, the tool returns a structured error
explaining how to install it. The other tools work without Infracost.

## Generate a plan to review

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
```

## Use it from Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tf-review": {
      "command": "tf-review-mcp"
    }
  }
}
```

Restart Claude Desktop. Then ask: *"Review the plan at /path/to/plan.json and suggest PR comments."*

## Use it from the command line

```bash
python -c "from tf_review_mcp.review import review_plan_file; \
  import json; print(json.dumps(review_plan_file('plan.json').to_dict(), indent=2))"
```

## Sample output

Given a plan that replaces an RDS instance and modifies a security group:

```json
{
  "counts": {"replace": 1, "update": 2, "create": 2},
  "stateful_destroys": [
    {"address": "aws_db_instance.primary", "type": "aws_db_instance", ...}
  ],
  "notes": [
    "1 stateful resource(s) scheduled for destroy/replace. Verify backups and migration plan before applying."
  ]
}
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Configuration

Drop a `.tf-review.yml` at the root of your Terraform repo to extend the
built-in rules without forking. All fields are optional; missing fields
fall back to defaults.

```yaml
version: 1

# Add resource types to the built-in HIGH_RISK_TYPES list (flagged `warn`).
extra_high_risk_types:
  - cloudflare_record
  - vault_policy

# Add resource types to the built-in STATEFUL_TYPES list
# (flagged `blocker` on delete/replace).
extra_stateful_types:
  - mongodbatlas_cluster

# Extra CIDRs treated as "public exposure" for google_compute_firewall.
extra_public_cidrs:
  - "10.0.0.0/8"

# Override the cost-delta thresholds (USD per month).
cost_thresholds:
  info_usd: 50
  warn_usd: 250
  blocker_usd: 1500

# Suppress specific rules entirely. Known rule ids:
#   high-risk, stateful-destroy, public-exposure, cost-delta
disabled_rules:
  - public-exposure
```

Discovery order:

1. `TF_REVIEW_CONFIG=/abs/path/config.yml` (env var override).
2. `.tf-review.yml` in the current working directory.
3. Walk up parent directories until the filesystem root.
4. Built-in defaults.

Call `get_active_config` from the MCP client to see the merged
configuration the server is actually using.

## Security

All tool output is sanitized for safe display to a language model.
Two env knobs gate plan file reads:

- `TF_REVIEW_ALLOWED_DIRS` (colon-separated prefix allowlist; unset = any path).
- `TF_REVIEW_MAX_PLAN_BYTES` (default 50 MB).

This server is tested against
[mcp-adversarial](../mcp-adversarial/), a generic adversarial-input
harness for MCP servers. You can run the same suite against any other
MCP server.

See [../../SECURITY.md](../../SECURITY.md) for the trust boundary,
threat model, and disclosure policy.

## Attack-path analysis

`analyze_attack_paths` builds a directed graph from the plan, searches
for simple paths from a synthetic `internet` node to any sensitive
resource (RDS, S3, DynamoDB, KMS, Secrets Manager, Cloud SQL, GCS,
Key Vault, etc.), and surfaces paths that are *new* or *widened* by
the change.

Edge sources (AWS coverage is the most complete in v0.4.2):

- **Internet -> ingress**: public ALB / NLB, CloudFront, API Gateway,
  security-group rules with `0.0.0.0/0` or `::/0`.
- **Ingress -> compute**: SG attached to EC2, Lambda VPC config, ECS
  service network config.
- **Compute -> principal**: EC2 instance profile, Lambda execution
  role, ECS task role, GCE service account.
- **Principal -> data**: IAM inline-policy `Action` resolved against
  the resource ARN; managed-admin attachments fan out to every known
  data node.

Sample output for a plan that opens an SG to `0.0.0.0/0` on an EC2
instance that already has `s3:GetObject *` on an existing bucket:

```json
{
  "paths": [
    {
      "path": [
        {"address": "internet", "kind": "internet"},
        {"address": "aws_security_group.web", "kind": "sg"},
        {"address": "aws_instance.worker", "kind": "compute"},
        {"address": "aws_iam_instance_profile.worker-profile", "kind": "principal"},
        {"address": "aws_s3_bucket.customer_data", "kind": "data"}
      ],
      "is_new": true,
      "edges_changed_by_plan": ["internet -> aws_security_group.web"],
      "severity": "blocker",
      "narrative": "internet -> aws_security_group.web [sg-allows-public-ingress port=443] -> aws_instance.worker [aws_security_group.web attached to aws_instance.worker] -> aws_iam_instance_profile.worker-profile [instance profile] -> aws_s3_bucket.customer_data [grant s3:GetObject]. Edges introduced by this plan: internet -> aws_security_group.web."
    }
  ],
  "summary": {"new_paths": 1, "widened_paths": 0, "preexisting_paths_unchanged": 0}
}
```

Limits:

- Path depth is capped at 8 hops and total paths at 50 by default. The
  bounds are deliberate; longer paths exist but are noisy.
- Cross-VPC, transit gateway, and VPC-endpoint traversal are not
  modeled in v0.4.2. Same-VPC reachability is implicit.
- GCP coverage in v0.4.2 is light (public firewalls, compute, sensitive
  types). Cross-network and IAM-binding edges arrive in v0.5.

## Roadmap

- Cross-VPC / transit-gateway / VPC-endpoint traversal in
  `analyze_attack_paths`.
- `check_policy` (run OPA/Conftest against the plan).
- More diff-aware checks: `aws_security_group` ingress widening,
  `google_storage_bucket` `force_destroy` toggles, IAM `*` role grants.

## License

MIT.
