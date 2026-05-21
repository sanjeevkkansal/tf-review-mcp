"""End-to-end smoke test: spawn the MCP server over stdio, list tools, call review_plan.

Run from the repo root after installing the package (`pip install -e .`):

    python scripts/smoke_test.py

By default it locates the `tf-review-mcp` console script on PATH. Override with
the TF_REVIEW_MCP_BIN environment variable if you've installed it elsewhere.
"""

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def find_server_binary() -> str:
    override = os.environ.get("TF_REVIEW_MCP_BIN")
    if override:
        return override
    found = shutil.which("tf-review-mcp")
    if found:
        return found
    # Fall back to the active venv's bin directory if one is set.
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        candidate = Path(venv) / "bin" / "tf-review-mcp"
        if candidate.exists():
            return str(candidate)
    print(
        "ERROR: cannot find tf-review-mcp. Install with `pip install -e .` "
        "or set TF_REVIEW_MCP_BIN to the script path.",
        file=sys.stderr,
    )
    sys.exit(1)


async def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    fixtures = [
        repo_root / "tests" / "fixtures" / "example_plan.json",
        repo_root / "tests" / "fixtures" / "gcp_plan.json",
    ]

    params = StdioServerParameters(
        command=find_server_binary(),
        args=[],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools exposed:")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description.splitlines()[0] if t.description else ''}")

            for fixture in fixtures:
                print(f"\n========== {fixture.name} ==========")
                print("\n--- review_plan ---")
                result = await session.call_tool(
                    "review_plan", {"plan_json_path": str(fixture)}
                )
                payload = result.content[0].text
                parsed = json.loads(payload)
                print(json.dumps(parsed, indent=2))

                print("\n--- suggest_review_comments ---")
                result = await session.call_tool(
                    "suggest_review_comments", {"plan_json_path": str(fixture)}
                )
                print(result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
