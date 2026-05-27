# tf-review-mcp / mcp-adversarial

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](packages/tf-review-mcp/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](packages/tf-review-mcp/pyproject.toml)

This repository is a `uv` workspace with two packages:

- **[tf-review-mcp](packages/tf-review-mcp/)** is an MCP server that reviews Terraform plans for blast radius, stateful destroys, IAM privilege changes, public exposure, cost delta, and (in v0.4) internet-to-data attack paths. Plug it into Claude Desktop, Cursor, Claude Code, or any MCP client.
- **[mcp-adversarial](packages/mcp-adversarial/)** is a reusable adversarial input harness for MCP servers. It spawns any MCP server as a subprocess, replays fixtures of injection / oversize / traversal payloads against every advertised tool, and asserts the server handles them without leaking unsanitized strings or unhandled exceptions. tf-review-mcp is its first canary.

Both packages ship from this monorepo and release independently. See each package's README and CHANGELOG for details.

## Working in the workspace

```bash
git clone https://github.com/your-user/tf-review-mcp.git
cd tf-review-mcp
uv sync --all-packages
```

`--all-packages` is required: the workspace root has no project deps pointing at the members, so plain `uv sync` would only install whatever the root references. `--all-packages` installs every workspace member editable into `.venv/`.

Run tests per package (pytest lives in each package's `dev` extra):

```bash
uv run --package tf-review-mcp --extra dev pytest packages/tf-review-mcp/tests
uv run --package mcp-adversarial --extra dev pytest packages/mcp-adversarial/tests
```

## License

MIT. See [packages/tf-review-mcp/LICENSE](packages/tf-review-mcp/LICENSE).
