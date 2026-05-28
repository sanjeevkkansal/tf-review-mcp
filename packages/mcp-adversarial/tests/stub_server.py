"""Minimal MCP-shaped stdio server used by harness tests.

Implements only what the harness needs:
  - `initialize` -> ack
  - `tools/list` -> three tools (echo / leak / crash)
  - `tools/call` -> behavior depends on tool name

Behaviors selected via env:
  STUB_MODE=clean   -> echo tool returns sanitized arg text
  STUB_MODE=leak    -> echo tool returns text containing the sentinel
  STUB_MODE=control -> echo tool returns text containing a control char
  STUB_MODE=crash   -> echo tool raises (traceback to stderr)
"""

from __future__ import annotations

import json
import os
import sys
import traceback

SENTINEL = "MCP_ADVERSARIAL_EXFIL_SENTINEL"


def _send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _read() -> dict | None:
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line)


def _tools_list() -> list[dict]:
    return [
        {
            "name": "echo",
            "description": "Echo the args back as text.",
            "inputSchema": {"type": "object"},
        },
    ]


def _handle_call(name: str, arguments: dict) -> dict:
    mode = os.environ.get("STUB_MODE", "clean")
    if name != "echo":
        return {"isError": True, "content": [{"type": "text", "text": "no such tool"}]}

    if mode == "crash":
        raise RuntimeError("stub crash for harness test")

    text = json.dumps(arguments)
    if mode == "leak":
        text = text + " " + SENTINEL
    elif mode == "control":
        text = text + " \x07embedded-bell"
    return {"content": [{"type": "text", "text": text}]}


def main() -> int:
    while True:
        try:
            msg = _read()
        except json.JSONDecodeError:
            continue
        if msg is None:
            return 0

        method = msg.get("method")
        rid = msg.get("id")

        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "stub", "version": "0.0.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": _tools_list()}})
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                result = _handle_call(params.get("name"), params.get("arguments") or {})
                _send({"jsonrpc": "2.0", "id": rid, "result": result})
            except Exception:
                traceback.print_exc(file=sys.stderr)
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "error": {"code": -32603, "message": "stub crash"},
                    }
                )
        else:
            if rid is not None:
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "error": {"code": -32601, "message": "method not found"},
                    }
                )


if __name__ == "__main__":
    sys.exit(main())
