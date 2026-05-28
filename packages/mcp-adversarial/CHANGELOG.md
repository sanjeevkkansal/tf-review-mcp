# Changelog

All notable changes to mcp-adversarial are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
package uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-05-28

First public release on PyPI.

### Added
- `sanitize.py`: `sanitize_for_model` (strip Unicode Cc/Cf, mark known
  prompt-injection preambles with a `[sus]` annotation, truncate),
  `sanitize_address` (validate dotted resource addresses, reject
  path-traversal tokens), `sanitize_address_or_marker` (never-raise
  variant).
- `runner.py`: minimal stdio JSON-RPC client (`MCPStdioClient`) and
  `run_harness` driver. The CLI entry point `mcp-adversarial` is
  registered via `[project.scripts]`. Run:

      mcp-adversarial run --server "your-server-cmd" \
                          [--fixtures dir/] \
                          [--report report.json] \
                          [--sentinel STR] [--timeout SECONDS]

- Default fixture set under `src/mcp_adversarial/fixtures/`:
  - `generic/`: injection preambles, control chars, oversize strings,
    path-traversal patterns, RTL/zero-width unicode.
  - `terraform/`: plan-JSON payloads targeting tf-review-mcp's tool
    surface (injection in tags, oversize resource names, traversal in
    addresses, malformed actions, deeply nested JSON, base64 user_data).
- 72 tests covering both `sanitize_*` and the runner end-to-end against
  a minimal stub MCP server.

### Notes
- Tested against tf-review-mcp v0.4.0 as the canary. tf-review-mcp's
  CI runs the full Terraform fixture set against the real server on
  every commit.
- The public API surface (`sanitize_*`, `MCPStdioClient`, `run_harness`,
  `FixtureResult`, `HarnessReport`) is what semver tracks. Internal
  helpers (leading underscore) may change without a major bump.
