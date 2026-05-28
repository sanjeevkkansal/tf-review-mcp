# Security policy

This file covers both packages in this workspace: `tf-review-mcp` and
`mcp-adversarial`.

## Supported versions

Security fixes ship on the latest minor release of each package.

| Package          | Supported       |
| ---------------- | --------------- |
| tf-review-mcp    | 0.4.x           |
| mcp-adversarial  | 0.x (pre-1.0)   |

## Reporting a vulnerability

Email `sanjeev@romeprotocol.com` with the subject line
`SECURITY: <package-name> <short title>`. Include a minimal reproduction
and the version you tested against.

Disclosure window is 90 days. We will acknowledge within 5 business days
and aim to ship a fix or mitigation before the window closes. Coordinated
disclosure with credit is the default.

## Trust boundary

`tf-review-mcp` runs as a stdio MCP server, typically launched by a
local client (Claude Desktop, Cursor, Claude Code) on the developer's
machine. The server trusts:

- The user running it (it reads files the user can already read).
- The `.tf-review.yml` config the user chooses to load.

The server does **not** trust:

- The content of the plan JSON it is asked to review. Resource names,
  tags, descriptions, `user_data`, and any other string field that
  flows from a Terraform module into the plan can originate from
  anyone who can land a PR in the consuming repo. Treat all of it as
  attacker-controlled.
- The MCP client. The client only sees what the server returns;
  the server never executes client-supplied code.

## Mitigations in v0.4.0

1. **Output sanitization.** Every string in tool output flows through
   `mcp_adversarial.sanitize_for_model` before serialization. The
   helper strips Unicode Cc/Cf control / format characters (keeping
   tab and newline), marks lines beginning with known prompt-injection
   preambles (`system:`, `Ignore previous`, ChatML role tokens, etc.)
   with a `[sus]` annotation, and truncates to a bounded length.
   Resource addresses additionally pass through `sanitize_address`,
   which rejects path-traversal tokens; an invalid address is replaced
   with the placeholder `[invalid-address]`.

2. **Host-policy gates on plan file reads.** Two environment knobs let
   an operator restrict what the server will read:

   - `TF_REVIEW_ALLOWED_DIRS`: colon-separated allowlist of directory
     prefixes. When set, plan paths must resolve under one of these
     prefixes. Default unset (any readable path).
   - `TF_REVIEW_MAX_PLAN_BYTES`: max plan-file size in bytes. Default
     50 MB. Prevents unbounded reads.

   Violations are returned as structured `{"error": "...", "kind":
   "policy"}` objects rather than raising. `get_active_config` exposes
   the active values via the `host_policy` block.

3. **Adversarial input harness.** `mcp-adversarial` ships a generic
   harness that any MCP server can run against itself. tf-review-mcp's
   `test_adversarial_canary.py` runs the harness on every commit and
   asserts each shipped fixture (prompt-injection in tags, oversize
   names, path traversal in addresses, malformed actions, deeply
   nested JSON, base64-blob `user_data`) is handled with no Python
   traceback, no control-character leakage, and no exfiltration of
   sentinel strings.

## What an MCP client should never auto-execute from server output

This is meant as advice for clients consuming any MCP server, not just
this one. Server output is text returned for human or model
consumption; it is not commands. Specifically, never auto-execute:

- Shell snippets or `curl | bash` blocks embedded in tool output.
- File paths the server suggests writing or reading without the user
  re-confirming the path.
- URLs the server emits, unless the client treats them as references
  rather than fetch targets.
- "ignore previous instructions" preambles or role-token lookalikes.
  `mcp-adversarial` marks these with `[sus]`; clients should surface
  the marker rather than strip it.

A server is a structured oracle. The client decides what to do with
the answer.

## Threat model summary

| Threat                                 | Mitigation                                              |
| -------------------------------------- | ------------------------------------------------------- |
| Prompt injection via plan strings      | `sanitize_for_model` marks known preambles              |
| Control-character leakage              | `sanitize_for_model` strips Cc/Cf chars                 |
| Path traversal in resource addresses   | `sanitize_address` (+ placeholder variant)              |
| Path traversal in plan path argument   | `TF_REVIEW_ALLOWED_DIRS`                                |
| OOM via giant plan file                | `TF_REVIEW_MAX_PLAN_BYTES` (default 50 MB)              |
| Unhandled exceptions reach the client  | Tools catch and return structured `{"error": ...}` dict |
| Regressions of the above               | `test_adversarial_canary.py` runs the harness in CI     |

See [packages/tf-review-mcp/DESIGN.md](packages/tf-review-mcp/DESIGN.md)
for the full architectural threat model.
