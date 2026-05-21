# tf-review-mcp

[![Status](https://img.shields.io/badge/status-experimental-orange.svg)](#status)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

An MCP server that reviews Terraform plans for blast radius, stateful destroys, and high-risk resource changes. Plug it into Claude Desktop, Cursor, Claude Code, or any MCP client to get structured plan review on demand.

> **Status:** v0.2, experimental. Tool contracts may change before 1.0. Issues and PRs welcome.

![tf-review-mcp demo](docs/tf-mcp-demo.gif)

See [DESIGN.md](DESIGN.md) for architecture, threat model, and the existing-tools survey.

## Why

`terraform plan` outputs are long. Risky changes (IAM edits, security-group churn, RDS replacements) get missed in PR reviews. This server parses `terraform show -json` output and surfaces the things a human reviewer actually cares about, so a model can read them and write useful comments instead of summarizing the whole diff.

## What it does

Two tools:

- `review_plan(plan_json_path)` — returns a structured summary: action counts (create/update/delete/replace), high-blast-radius resource changes, stateful destroys, and diff-aware public-exposure findings.
- `suggest_review_comments(plan_json_path)` — returns a list of `{address, severity, comment}` objects ready to drop into a PR review. Severities: `blocker | warn | info`.

What gets flagged:

- **High-risk types** (warn). Conservative built-in list across AWS, GCP, and Azure: IAM, RDS, KMS, security groups, S3, EKS, GKE, Cloud SQL, GCS, Cloud DNS, GCE firewalls, AKS, Key Vault, etc.
- **Stateful destroys** (blocker). RDS/Cloud SQL/DynamoDB/GCS/S3 deletes or replaces, plus `google_compute_instance` replaces (boot disk + local SSD loss).
- **Public exposure** (blocker). Diff-aware: catches `google_compute_firewall` changes that add `0.0.0.0/0` or `::/0` to `source_ranges`.

## Install

```bash
git clone https://github.com/your-user/tf-review-mcp.git
cd tf-review-mcp
pip install -e .
```

Requires Python 3.11+.

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

## Roadmap

- `estimate_cost_delta` (wrap Infracost CLI).
- `check_policy` (run OPA/Conftest against the plan).
- Configurable `HIGH_RISK_TYPES` and exposure rules via a YAML file so teams can codify their own blast-radius rules.
- More diff-aware checks: `aws_security_group` ingress widening, `google_storage_bucket` `force_destroy` toggles, IAM `*` role grants.

## License

MIT.
