# mcp-adversarial fixtures

Two subdirectories.

- `generic/`: MCP-shaped payloads. Tool name is omitted, so the harness
  replays them against every tool the server advertises. Pass common
  argument names (`path`, `plan_json_path`, `content`). Servers that
  reject the schema with a structured error are fine; the harness only
  fails on crashes, control-character leakage, or sentinel exfiltration.

- `terraform/`: Plan-JSON-shaped payloads scoped to tf-review-mcp's
  tools (`review_plan`, `suggest_review_comments`, `estimate_cost_delta`).
  These exist because tf-review-mcp is the canary server for the
  harness. Other MCP servers can copy the pattern without inheriting
  the schema.

Each fixture is one JSON file with this shape:

```json
{
  "id": "short-stable-identifier",
  "category": "injection | exfil | oversize | traversal | malformed | nesting",
  "tool": "review_plan",
  "args": {"plan_json_path": "/tmp/plan.json"},
  "setup": {"write_files": {"/tmp/plan.json": "<content>"}}
}
```

Omit `tool` to fan out against every advertised tool. `setup.write_files`
materializes files into a tempdir; absolute paths in `args` are rewritten
to the staged location before the call.
