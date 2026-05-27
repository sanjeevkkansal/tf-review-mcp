# tf-review-mcp design

## Goal

Give a developer reviewing a Terraform PR an LLM-assisted second pair of eyes that actually understands the plan, not just the diff. The model should be able to ask focused questions ("does this plan destroy anything stateful?", "what IAM changes are in here?", "draft PR comments") and get structured answers backed by the plan JSON, not free-form summarization of a 2000-line wall of text.

## Non-goals

- Replacing `terraform plan` itself. The server consumes plan output; it does not run Terraform.
- Replacing existing policy engines (OPA, Sentinel) or static analyzers (tfsec, Checkov). This server can wrap them; it doesn't reimplement them.
- Multi-tenant SaaS. See [Deployment model](#deployment-model) below.

## Deployment model

**v1: local stdio subprocess.** This is the default and the recommended deployment.

```
  Developer's laptop
  +-----------------------------------------+
  |                                         |
  |  Claude Desktop / Cursor / Continue     |
  |          (any MCP client)               |
  |              |                          |
  |              | stdio (JSON-RPC)         |
  |              v                          |
  |       tf-review-mcp                     |
  |              |                          |
  |              | reads file               |
  |              v                          |
  |        plan.json (local)                |
  |                                         |
  +-----------------------------------------+
```

Properties:

- No network listener. The MCP client spawns the server as a child process and talks to it over stdin/stdout.
- No authentication needed. The trust boundary is the developer's machine.
- Plan JSON never leaves the laptop. The model sees only the structured summary the server returns (resource addresses, types, action buckets), not raw provider config blobs.

**v2 (future, not v1): self-hosted HTTP for CI / shared policy.** Run the server inside the org's network as a long-lived process so a CI job can call `review_plan` against a plan it just generated. This needs:

- HTTP transport instead of stdio.
- Auth (mTLS or an internal token).
- Multi-tenancy for the policy dir (per-repo or per-team rule sets).
- Audit logging.

Worth doing only if a team finds the local v1 useful and wants to enforce the same checks in CI. Not in scope until then.

**What it should never be:** a public hosted endpoint where strangers upload plan files. Plans leak account IDs, IAM relationships, security-group rules, and resource counts. That's a recon goldmine. Don't build that.

## Architecture

```
  src/tf_review_mcp/
  +-- server.py        FastMCP entry point. Tool registration + thin wrappers.
  +-- review.py        Pure functions. Parse plan JSON, classify changes,
  |                    build ReviewSummary. No I/O beyond reading the plan file.
  +-- cost.py          Pure functions. Wraps the Infracost CLI as a subprocess
  |                    and parses its JSON output into a CostSummary.
  +-- config.py        ReviewConfig dataclass + built-in defaults + YAML
  |                    discovery (TF_REVIEW_CONFIG / cwd / walk-up).
  +-- __init__.py
```

The split is intentional. `review.py` has no MCP imports, so it can be:

- Unit-tested without standing up the server.
- Reused from a CLI, a CI script, or a different transport later.
- Audited as a pure data transformation. easy to reason about.

`server.py` is the only file that knows about MCP.

## Tool contracts

### `review_plan(plan_json_path: str) -> str`

Input: path to a file produced by `terraform show -json plan.out`.

Output: JSON string with this shape:

```json
{
  "counts": {"create": 2, "update": 2, "replace": 1, "delete": 0},
  "high_risk_changes": [
    {"address": "...", "type": "...", "actions": [...], "is_high_risk": true, "is_stateful_destroy": false}
  ],
  "stateful_destroys": [...],
  "public_exposure_changes": [
    {"address": "...", "type": "google_compute_firewall", "actions": ["update"], "finding": "source_ranges now includes 0.0.0.0/0 (public exposure)"}
  ],
  "total_changes": 5,
  "terraform_version": "1.9.5",
  "notes": ["..."]
}
```

Classification rules:

- `is_high_risk`: resource type is in a built-in conservative list (IAM, KMS, RDS, security groups, S3, EKS/GKE/AKS clusters, VPC, route53, Cloud DNS, GCE firewalls, etc.).
- `is_stateful_destroy`: resource type is in a tighter stateful subset (RDS, DynamoDB, S3, ElastiCache, Cloud SQL, GCS, Azure SQL, `google_compute_instance`) **and** the action bucket is `delete` or `replace`. `google_compute_instance` is included because GCE replace destroys boot disk and any local-SSD attachments.
- `public_exposure_changes` (diff-aware): a `google_compute_firewall` create/update/replace adds `0.0.0.0/0` or `::/0` to `source_ranges` that didn't have them before, or otherwise widens the range set. Surfaced as a blocker.
- `notes`: human-readable strings the model can quote verbatim in PR comments.

### `suggest_review_comments(plan_json_path: str) -> str`

Returns a JSON list of `{address, severity, comment}`. Severities: `blocker | warn | info`.

The server produces *what to comment on*, not the final wording. The model refines tone, adds context from the surrounding PR, and posts.

### `estimate_cost_delta(plan_json_path: str) -> str`

Input: path to a `terraform show -json` output.

Output: JSON object shaped as:

```json
{
  "total_monthly_cost_delta_usd": 612.40,
  "top_contributors": [
    {"address": "google_sql_database_instance.primary", "monthly_cost_delta_usd": 500.00},
    {"address": "google_compute_instance.worker", "monthly_cost_delta_usd": 112.40}
  ],
  "currency": "USD",
  "infracost_version": "0.10.40",
  "notes": ["Estimated monthly cost increase of $612.40 exceeds $500."]
}
```

Implementation notes:

- Shells out to `infracost breakdown --path <plan> --format json --no-color` with a 60-second timeout.
- Recoverable errors (missing binary, non-zero exit, timeout, bad plan JSON) return `{"error": "...", ...}` instead of raising. The MCP model sees actionable text, not a stack trace.
- Thresholds are hardcoded in v0.3.0 (`$100` info, `$500` warn, `$1000` blocker). The upcoming YAML config makes them per-team.
- The module is pure Python with no MCP imports, so it can be reused from CI or a CLI.

### `get_active_config() -> str`

Returns the merged `ReviewConfig` (built-in defaults + any
`.tf-review.yml` overrides). Includes the `source_path` field so the
caller can tell where the config came from. Returns defaults with an
`error` field when YAML validation fails, so the server never crashes
on a malformed config.

## Configuration

`ReviewConfig` owns all classification lists (`high_risk_types`,
`stateful_types`, `public_cidrs`), the cost-delta thresholds, and the
set of disabled rules. Both `review.py` and `cost.py` consume it as an
optional argument; passing `None` uses the built-in defaults.

Schema is small, hand-validated, versioned (`version: 1`), and extends
defaults rather than replacing them. Unknown keys, unknown rule ids,
and unsupported versions raise `ConfigError`. Empty files are valid and
fall through to defaults.

Discovery order:

1. `TF_REVIEW_CONFIG=/abs/path` env var.
2. `.tf-review.yml` in the current working directory.
3. Walk up parent directories to the filesystem root.
4. Built-in defaults.

The server re-discovers config on each tool call. This keeps edits to
`.tf-review.yml` live without a restart and is cheap (at most a few
`stat` calls).

### Future tools

- `check_policy(plan_json_path, policy_dir)` — shell out to Conftest, return violations.
- `diff_resource(plan_json_path, address)` — return the `before`/`after` for a single resource so the model can drill in without re-parsing the whole plan.

## Security and threat model

| Threat | Mitigation |
|---|---|
| Plan JSON leaks secrets | Server reads from a local path, returns only structured summaries. Raw `before`/`after` blobs are not returned by `review_plan`. |
| Malicious plan JSON triggers parser bug | Parser uses `json.load` (no exec). Dataclass output, no eval. Fuzz-testable. |
| MCP client tricks the server into reading arbitrary files | The path argument is constrained to what the client (and thus the developer) passes in. There is no remote attacker in the v1 threat model. For v2 HTTP mode, this becomes a real concern and needs a path allowlist. |
| Tool prompt injection in resource names | Resource addresses are passed through as data, never executed. The model may see attacker-controlled strings in `address` fields if a malicious actor lands a PR; standard prompt-injection caveats apply, but no privileged action is gated on the model alone. |

## What this is NOT

- Not a policy engine. Use OPA/Conftest for that and wrap it.
- Not a cost estimator. Use Infracost and wrap it.
- Not a linter for HCL source. Use tfsec/Checkov.
- Not an apply gate. The server reports; humans (or CI) decide.

## Existing tools in this space

Categories of overlap, with honest framing:

**Plan-aware policy / analysis (CLI-first, not MCP):**

- HashiCorp Sentinel (TFC/TFE only, commercial).
- Open Policy Agent + Conftest (open source, BYO Rego).
- terraform-compliance (BDD-style, mature).
- Infracost (cost-focused).

**HCL static analysis (source-first, not plan-aware):**

- tfsec, Checkov, terrascan, KICS.

**Workflow orchestration:**

- Atlantis (runs plan in CI, posts to PR; no LLM in the loop).
- Spacelift, env0, Scalr (commercial Terraform PaaS).

**MCP-side:**

- [`hashicorp/terraform-mcp-server`](https://github.com/hashicorp/terraform-mcp-server) — the official HashiCorp MCP server. Scope: Terraform Registry API (provider/module search, doc lookup) and HCP Terraform / Terraform Enterprise workspace management. It does **not** parse plan output, flag risky changes, or generate review comments. Complementary to `tf-review-mcp`, not competitive. The official server helps you *write* Terraform; this one helps you *review* a plan. Install both.
- Various community "wrap the Terraform CLI" MCP experiments exist (run `plan`/`apply` via a tool). Different abstraction layer; they hand the model the raw plan text rather than a structured review.

I have not found a published MCP server scoped specifically to plan review with LLM-friendly structured output as of writing. Worth one more GitHub sweep before publishing in case something shipped recently.

## Why this is differentiated

- **Scope:** plan review specifically, not registry lookup (HashiCorp covers that) and not "wrap the Terraform CLI." Wrapping the CLI is what most community experiments default to, but it's the wrong level of abstraction for review. You want analysis, not RPC.
- **Output shape:** structured JSON the model can quote and reason about, not free-form text it has to re-summarize. Lower hallucination surface.
- **Composability:** the parser is pure functions in `review.py`. Anyone can reuse it from CI without MCP.
- **Honest defaults:** the high-risk list is conservative and visible in the source, not hidden behind a SaaS. Teams fork or PR it.
- **Local-first deployment:** plan JSON never crosses the network. Solves the "I can't paste this into a cloud LLM" problem that blocks LLM-assisted infra review today.

## Roadmap

1. **v0.1 (done):** `review_plan`, `suggest_review_comments`, stdio transport, fixture-backed tests.
2. **v0.2 (done):** GCP coverage (Cloud DNS, GCE firewalls, GKE node pools, IAM bindings), `google_compute_instance` replace as stateful destroy, diff-aware public-exposure check for `google_compute_firewall`.
3. **v0.3.0 (done):** `estimate_cost_delta` (wraps Infracost CLI), structured error handling for missing binary / timeout / non-zero exit.
4. **v0.3.1 (done):** `.tf-review.yml` config file for custom high-risk types, exposure CIDRs, and cost thresholds. New `get_active_config` tool for introspection.
5. **v0.4:** `check_policy` (wrap Conftest), `diff_resource` for drilling in, more diff-aware checks (SG ingress, IAM `*` grants, GCS `force_destroy`).
6. **v0.5:** HTTP transport behind an internal token for CI use.
7. **v1.0:** stable tool contracts, semver guarantees, packaged for pipx/Homebrew.

## Open questions

- Should `review_plan` accept the plan JSON inline (as a string) in addition to a file path? Useful for clients that don't have filesystem access. Trade-off: large payloads over stdio.
- Should the high-risk type list ship as a YAML config from day one? Avoids a v0.2 migration. Counter: YAML configs grow features.
- How to handle modules cleanly? Currently the parser flattens `resource_changes`, which is what Terraform itself does. Module-level rollups might help readability.
