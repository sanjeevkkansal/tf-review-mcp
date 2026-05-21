---
name: Bug report
about: Report a parsing failure, false positive, or false negative on a plan
title: '[bug] '
labels: bug
assignees: ''
---

## What happened

A clear, short description of what you saw vs what you expected.

## Plan input

Please attach (or paste) a minimal `terraform show -json` output that
reproduces the issue. Redact any sensitive values, but **keep the
resource type names, action arrays, and any `source_ranges` /
`before` / `after` fields** that the classifier reads.

If the plan is large, please trim it down to the smallest set of
`resource_changes` that still triggers the bug.

```json
{
  "format_version": "1.2",
  "terraform_version": "...",
  "resource_changes": [
    { "address": "...", "type": "...", "change": { ... } }
  ]
}
```

## What the tool returned

Output of `review_plan` and/or `suggest_review_comments`:

```
(paste here)
```

## What you expected

Describe what the correct output would have been and why.

## Environment

- `tf-review-mcp` version: (`pip show tf-review-mcp`)
- Python version: (`python --version`)
- Terraform version: (`terraform version`)
- MCP client (Claude Desktop / Cursor / Claude Code / other):
