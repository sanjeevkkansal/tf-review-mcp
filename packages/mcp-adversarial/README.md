# mcp-adversarial

[![PyPI](https://img.shields.io/pypi/v/mcp-adversarial.svg)](https://pypi.org/project/mcp-adversarial/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-adversarial.svg)](https://pypi.org/project/mcp-adversarial/)
[![License](https://img.shields.io/pypi/l/mcp-adversarial.svg)](https://github.com/sanjeevkkansal/tf-review-mcp/blob/main/packages/tf-review-mcp/LICENSE)

Adversarial input harness for MCP servers. Spawn any MCP server as a
subprocess, replay a set of fixtures against every tool it advertises,
and assert it does not crash, leak control characters into output, or
exfiltrate sentinel strings.

## Install

```bash
pip install mcp-adversarial
```

Or for one-off runs:

```bash
pipx run mcp-adversarial run --server "your-server-cmd"
```

## Quickstart

```bash
mcp-adversarial run --server "your-mcp-server"
```

Output:

```
ran 12 fixtures: 12 passed, 0 failed
  [PASS] generic_injection_preamble (injection) -> review_plan
  [PASS] generic_control_chars (sanitize) -> review_plan
  ...
```

Exit code is non-zero if any fixture fails. Designed to slot directly
into CI.

## How it works

1. **Spawn.** The harness launches your server with `shlex.split` and
   wires stdin / stdout / stderr to PIPE.
2. **Handshake.** It drives the standard MCP JSON-RPC handshake:
   `initialize`, the `notifications/initialized` ack, then
   `tools/list` to see what the server advertises.
3. **Replay.** For each fixture, it calls `tools/call` with the
   fixture's args. Fixtures can pin a specific tool name, or omit the
   tool to fan out across every advertised tool. Plan-shaped fixtures
   can stage temp files via `setup.write_files`; the harness rewrites
   absolute paths in args to the staged location.
4. **Assert.** For each call the harness checks:
   - No Python traceback appears on the server's stderr between calls.
   - No disallowed control characters appear in tool output.
   - No configured sentinel string appears in tool output.

A failure is annotated with the tool name and the specific reason.
Reports can be written to a JSON file via `--report`.

## Fixtures

Two categories ship in the package by default.

`generic/` are MCP-shaped payloads with no tool pinning, so the
harness fans them out across whatever tools the server has:

- `injection_preamble.json`: known prompt-injection preambles
  (`system:`, `Ignore previous`, ChatML role tokens).
- `control_chars.json`: BEL / ESC / DEL / NUL embedded in strings.
- `oversize_string.json`: 8KB strings in common arg slots.
- `path_traversal.json`: `../` / `..\\` / `/etc/passwd` patterns.
- `unicode_format.json`: RTL override + zero-width characters.

`terraform/` are Terraform-plan-shaped payloads scoped to
`tf-review-mcp`'s tool surface. They exist because tf-review-mcp is
this package's first canary; other MCP servers can copy the pattern
without inheriting the schema.

Bring your own fixtures with `--fixtures path/to/dir/`. Each fixture
is one JSON file:

```json
{
  "id": "your-fixture-id",
  "category": "injection",
  "tool": "the_tool_name",
  "args": {"plan_json_path": "/tmp/plan.json"},
  "setup": {"write_files": {"/tmp/plan.json": "<content>"}}
}
```

Omit `tool` to fan out. `setup.write_files` is optional; absolute
path placeholders in `args` are rewritten to the staged location.

## Public API

```python
from mcp_adversarial import (
    sanitize_for_model,         # strip control chars, mark injection lines, truncate
    sanitize_address,           # validate a dotted resource address (raises on traversal)
    sanitize_address_or_marker, # never-raise variant (returns "[invalid-address]")
)
from mcp_adversarial.runner import run_harness, MCPStdioClient
```

`sanitize_for_model` and the address helpers are usable independently
of the harness, e.g. inside your own server's serialization layer.

## Tested against

[tf-review-mcp](https://github.com/sanjeevkkansal/tf-review-mcp) is
the first canary. Its CI runs the full fixture set against the real
server on every commit (see
`packages/tf-review-mcp/tests/test_adversarial_canary.py`).

You can run the same suite against any other MCP server. PRs adding
new canary integrations welcome.

## Roadmap

- A JSON schema for fixture validation in editor / CI.
- More fixture categories: tool-name collision, oversize
  `tools/list` responses, malformed JSON-RPC envelopes.
- A GitHub Action that runs the harness against a server command on
  every PR and posts the report.
- Optional fuzzing mode on top of the static fixtures.

## License

MIT.
