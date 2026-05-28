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

### `review_iam_changes(plan_json_path: str) -> str`

Output: JSON with `iam_changes` (list of `IamChange`) and `summary`
(counts per classification + total). Each `IamChange`:

```json
{
  "address": "aws_iam_policy.admin",
  "type": "aws_iam_policy",
  "actions": ["update"],
  "classifications": ["escalation", "exfil"],
  "added_permissions": ["iam:* on *", "kms:Decrypt on *"],
  "removed_permissions": [],
  "narrative": "aws_iam_policy.admin (aws_iam_policy). adds iam:* on *, kms:Decrypt on *.",
  "severity": "blocker"
}
```

Classifications:

- `escalation`: granted action equals or subsumes a known
  admin-equivalent pattern (`iam:*`, `*:*`, AWS managed admin policy
  ARN, GCP `roles/owner`, Azure `Owner` / `Contributor`).
- `lateral`: granted action matches a cross-principal trust pattern
  (`sts:AssumeRole*`, `iam:PassRole`, GCP `iam.serviceAccount*`,
  Azure Managed Identity Operator), or an AWS trust policy adds a
  new Principal.
- `exfil`: granted action matches a known broad-read pattern
  (`s3:GetObject`, `kms:Decrypt`, `secretsmanager:GetSecretValue`,
  GCP `roles/storage.objectViewer`, etc.) **and**, for AWS,
  is paired with a wildcard resource (`"*"` or `arn:...:*` or
  contains `/*`). Broad-read on a single narrow ARN is usually fine
  and not flagged.
- `tightening`: a previously-granted permission matched any of the
  above patterns and is being removed. Always informational.

Pattern sets live as constants in `iam.py` and can be extended per
team via `.tf-review.yml` (`extra_escalation_patterns`,
`extra_lateral_patterns`, `extra_exfil_patterns`).

#### Why classify, not just flag

`review_plan` already flags "an IAM resource changed." The point of
this tool is to say *what kind* of change it is, so the model client
can write a comment with the right severity and context. Classifying
is rule-based on purpose: the patterns are well-known and
deterministic. Putting a model inside the classification loop would
make every call slow, expensive, and harder to test for regressions.

#### Pattern direction (subtle but load-bearing)

A granted action matches a dangerous pattern when the action equals
or *subsumes* the pattern. Granting `iam:*` matches `iam:PassRole`.
Granting `iam:GetUser` does NOT match `iam:*` (the grant is
narrower than the pattern). The matcher uses `fnmatch(pattern,
action)` so wildcards in the action expand against the literal
pattern, not the other way around. This is the standard
interpretation of "broad grant = bad."

### `analyze_attack_paths(plan_json_path: str) -> str`

Output: JSON with `paths` (list of `AttackPath`) and `summary`
(new / widened / preexisting-unchanged counts).

#### Attack-path model

`networkx.DiGraph` with one synthetic `internet` node plus one node
per relevant resource. Node kinds: `internet`, `ingress`, `sg`,
`compute`, `principal`, `data`, `network`. Edges are directed and
labeled with a short reason string.

What the model captures (v0.4.2):

- Public ingress (`0.0.0.0/0` SG rules; ALB / NLB with
  `scheme=internet-facing`; CloudFront; API Gateway; GCP firewalls).
- Compute attached to security groups (EC2 `vpc_security_group_ids`,
  Lambda VPC config, ECS service network config).
- Principal attached to compute (EC2 instance profile, Lambda
  execution role, ECS task role, GCE service account).
- Principal -> data via IAM grants. Inline-policy Actions are paired
  with Resource ARNs; managed-admin attachments fan out to every
  known data node.

What it does NOT capture (explicit non-goals for v0.4.2):

- Cross-VPC reachability (peering, transit gateways, VPC endpoints).
- DNS-level egress.
- IAM policy `Condition` evaluation. Conditions can narrow a grant
  in practice; we treat the grant as if no condition were set.
- SaaS-CNAPP-level traversal (multi-account assume-role chains).

#### Path search

`nx.all_simple_paths(g, "internet", sink, cutoff=8)` for each `sink`
in the set of data nodes. Total paths capped at 50. The defaults
can be raised via `max_depth` / `max_paths` on the pure-function
entry point. The bounds are intentional; longer paths exist on real
plans but rarely add signal.

#### Diff

Build both before- and after-graphs. A path in the after-graph is:

- `new`       if the node sequence does not appear in the
              before-graph's enumerated paths. Severity `blocker`.
- `widened`   if it does appear, but at least one edge was
              introduced by the plan. Severity `warn`.
- `unchanged` otherwise. Counted in summary but not enumerated in
              `paths` unless `include_preexisting=True`.

#### IAM dependency

The principal-to-data edge builder reuses `iam._policy_doc_pairs`
and `iam._matches_any` from PR #2 to enumerate granted permissions
and recognize admin policy ARNs. The classifier and the graph share
one source of truth for "what is an admin grant?".

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

The trust boundary, mitigations, and disclosure policy live in
[../../SECURITY.md](../../SECURITY.md). This section is the
architectural complement.

| Threat | Mitigation (as of v0.4.0) |
|---|---|
| Plan JSON leaks secrets to the model | Server returns structured summaries, not raw `before`/`after` blobs. The fields we *do* return (addresses, types, action lists, finding strings) go through `sanitize_for_model`. |
| Prompt injection in resource names, tags, descriptions, user_data | All LLM-facing strings flow through `mcp_adversarial.sanitize_for_model`. Known preambles (`system:`, `Ignore previous`, ChatML role tokens) are annotated with `[sus]`. Originals are preserved; the helper does not silently rewrite. |
| Path-traversal addresses | Resource addresses pass through `sanitize_address_or_marker`. Traversal addresses are replaced with `[invalid-address]`. |
| Plan-path traversal / arbitrary file reads | `TF_REVIEW_ALLOWED_DIRS` prefix allowlist (opt-in, env-driven). Unset for v1 stdio default (trust boundary is the dev machine); ready to flip on for the v0.5 HTTP transport. |
| OOM via giant plan file | `TF_REVIEW_MAX_PLAN_BYTES` (default 50 MB, env-overridable). Always active. |
| Malicious plan triggers parser bug | Parser uses `json.load` (no exec). Dataclass output, no eval. Adversarial fixtures exercise pathological nesting, oversize fields, malformed `actions` enums; `test_adversarial_canary.py` runs them on every CI run. |
| Unhandled exception reaches the client | All tools catch `PolicyError` / `FileNotFoundError` and return a structured `{"error": ..., "kind": ...}` JSON object. |
| Regression of any of the above | `test_adversarial_canary.py` spawns the real server and replays every packaged fixture through the harness. |

### Sanitization

`mcp_adversarial.sanitize_for_model(value, max_len=1024)` (the server
uses 1024 as the per-string cap; the library default is 512) does
three things, in order:

1. Strips Unicode general categories `Cc` and `Cf` (control and
   format), keeping tab and newline. RLO / zero-width characters and
   common control bytes (BEL, ESC, DEL, NUL) all go.
2. For each line, lowercases the leading content and checks against a
   small set of known prompt-injection preambles (`system:`,
   `assistant:`, `Ignore previous`, `<|im_start|>`, etc.). On a match,
   prefixes the line with `[sus]`. The original line is preserved
   verbatim after the marker; we never silently rewrite, because
   surprise is worse than wordiness and the model client can decide
   how to react.
3. Truncates the result to `max_len` characters, appending
   `...[truncated]` when truncation happens.

`sanitize_address(addr)` validates a dotted resource address and
rejects NUL bytes, forward/back slashes, and parent-directory tokens
(`..`). `sanitize_address_or_marker(addr)` is the never-raise variant
used at the serialization boundary; on a rejected address it returns
the placeholder `[invalid-address]`.

Both functions live in the `mcp-adversarial` sibling package so any
other MCP server can adopt them without depending on tf-review-mcp.

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
