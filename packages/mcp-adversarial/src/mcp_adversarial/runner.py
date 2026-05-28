"""Adversarial test harness for MCP servers.

Spawns any MCP server as a subprocess, drives it through the JSON-RPC
initialize / tools-list handshake, replays a set of fixture payloads
against each advertised tool, and asserts:

  - no unhandled exceptions on stderr (Python tracebacks, etc.)
  - no unsanitized control characters in tool output
  - no exfiltration of the configured sentinel strings

Exit code is non-zero if any check fails. Designed to slot into CI for
any MCP server, not just tf-review-mcp.

Fixture shape (one JSON file per fixture):

    {
        "id": "injection_in_tags",
        "category": "injection",
        "tool": "review_plan",
        "args": {"plan_json_path": "/tmp/plan.json"},
        "setup": {
            "write_files": {
                "/tmp/plan.json": "<plan content as string or object>"
            }
        },
        "expect": "no_unhandled_exception"
    }

The `setup.write_files` block lets a fixture stage temp files before the
tool call. Paths must be absolute. The runner deletes them after the
fixture finishes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_SENTINELS: tuple[str, ...] = (
    "MCP_ADVERSARIAL_EXFIL_SENTINEL",
    "SHOULD_NOT_LEAK_TO_OUTPUT",
)

_DISALLOWED_OUTPUT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class FixtureResult:
    fixture_id: str
    tool: str
    category: str
    passed: bool
    reasons: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HarnessReport:
    server_command: str
    fixtures_total: int
    fixtures_passed: int
    fixtures_failed: int
    results: list[FixtureResult]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["results"] = [r.to_dict() for r in self.results]
        return d


class MCPClientError(RuntimeError):
    pass


class MCPStdioClient:
    """Minimal synchronous JSON-RPC client for an MCP stdio server.

    Not a full client. Covers exactly what the harness needs:
    initialize, tools/list, tools/call. One request at a time, line-
    delimited JSON over stdio, with a per-call timeout.
    """

    def __init__(self, command: list[str], timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.command = command
        self.timeout = timeout
        self.proc: subprocess.Popen[str] | None = None
        self._next_id = 0
        self._stderr_chunks: list[str] = []
        self._stderr_thread: threading.Thread | None = None

    def __enter__(self) -> MCPStdioClient:
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()
        self._initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _drain_stderr(self) -> None:
        assert self.proc is not None
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr_chunks.append(line)

    def stderr(self) -> str:
        return "".join(self._stderr_chunks)

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2.0)
        finally:
            self.proc = None

    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _send(self, message: dict[str, Any]) -> None:
        assert self.proc is not None and self.proc.stdin is not None
        payload = json.dumps(message)
        self.proc.stdin.write(payload + "\n")
        self.proc.stdin.flush()

    def _recv(self, expected_id: int | None) -> dict[str, Any]:
        assert self.proc is not None and self.proc.stdout is not None
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPClientError(
                    f"timed out after {self.timeout:.1f}s waiting for response"
                )
            line = self.proc.stdout.readline()
            if not line:
                raise MCPClientError(
                    "server closed stdout unexpectedly; stderr: "
                    + (self.stderr() or "(empty)")
                )
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if expected_id is None:
                return msg
            if msg.get("id") == expected_id:
                return msg

    def request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        rid = self._new_id()
        self._send(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )
        return self._recv(rid)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _initialize(self) -> None:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "mcp-adversarial", "version": "0.0.0"},
                "capabilities": {},
            },
        )
        if "error" in resp:
            raise MCPClientError(f"initialize failed: {resp['error']}")
        self.notify("notifications/initialized", {})

    def list_tools(self) -> list[dict[str, Any]]:
        resp = self.request("tools/list", {})
        if "error" in resp:
            raise MCPClientError(f"tools/list failed: {resp['error']}")
        return list((resp.get("result") or {}).get("tools") or [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )


def _default_fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def load_fixtures(path: Path | None) -> list[dict[str, Any]]:
    """Load fixtures from a directory or fall back to packaged defaults.

    Recurses into subdirectories. Skips files that are not valid JSON.
    """
    root = path or _default_fixtures_dir()
    fixtures: list[dict[str, Any]] = []
    if not root.exists():
        return fixtures
    for jf in sorted(root.rglob("*.json")):
        try:
            fixtures.append(json.loads(jf.read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: skipping {jf}: {exc}", file=sys.stderr)
    return fixtures


def _stage_files(
    setup: dict[str, Any], stage_root: Path
) -> dict[str, str]:
    """Materialize fixture setup.write_files into a temp directory.

    Returns a mapping of placeholder path (as given in the fixture) to
    the absolute on-disk path the file was written to. Substitution of
    placeholders into the fixture args is the caller's job.
    """
    written: dict[str, str] = {}
    for placeholder, content in (setup.get("write_files") or {}).items():
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", placeholder.lstrip("/")) or "f"
        out_path = stage_root / safe_name
        if isinstance(content, (dict, list)):
            out_path.write_text(json.dumps(content))
        else:
            out_path.write_text(str(content))
        written[placeholder] = str(out_path)
    return written


def _substitute_paths(
    args: dict[str, Any], mapping: dict[str, str]
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and v in mapping:
            out[k] = mapping[v]
        else:
            out[k] = v
    return out


def _flatten_tool_text(result: dict[str, Any]) -> str:
    """Extract all text content from a tools/call response payload."""
    content = (result.get("result") or {}).get("content") or []
    chunks: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(item.get("text") or "")
    return "\n".join(chunks)


def _looks_like_python_traceback(s: str) -> bool:
    return "Traceback (most recent call last):" in s


def run_fixture(
    client: MCPStdioClient,
    fixture: dict[str, Any],
    tool_names: list[str],
    sentinels: Iterable[str],
    stage_root: Path,
) -> FixtureResult:
    fid = str(fixture.get("id") or "unnamed")
    category = str(fixture.get("category") or "unknown")
    requested_tool = fixture.get("tool")
    args_template = fixture.get("args") or {}
    setup = fixture.get("setup") or {}

    targets: list[str]
    if requested_tool and requested_tool in tool_names:
        targets = [requested_tool]
    elif requested_tool and requested_tool not in tool_names:
        return FixtureResult(
            fixture_id=fid,
            tool=requested_tool,
            category=category,
            passed=False,
            reasons=[f"server does not advertise tool {requested_tool!r}"],
        )
    else:
        targets = list(tool_names)

    overall_pass = True
    reasons: list[str] = []
    started = time.monotonic()

    file_mapping = _stage_files(setup, stage_root)
    args = _substitute_paths(args_template, file_mapping)

    pre_stderr_len = len(client.stderr())
    for tool in targets:
        try:
            resp = client.call_tool(tool, args)
        except MCPClientError as exc:
            overall_pass = False
            reasons.append(f"{tool}: client error: {exc}")
            continue

        text = _flatten_tool_text(resp)

        if _DISALLOWED_OUTPUT_CONTROL.search(text):
            overall_pass = False
            reasons.append(f"{tool}: output contains disallowed control characters")

        for sentinel in sentinels:
            if sentinel and sentinel in text:
                overall_pass = False
                reasons.append(f"{tool}: output leaked sentinel {sentinel!r}")

        if "error" in resp and not isinstance(resp.get("result"), dict):
            err = resp.get("error") or {}
            if isinstance(err, dict) and err.get("code") in (-32603,):
                overall_pass = False
                reasons.append(f"{tool}: server returned internal error: {err}")

    new_stderr = client.stderr()[pre_stderr_len:]
    if _looks_like_python_traceback(new_stderr):
        overall_pass = False
        reasons.append("server emitted a Python traceback on stderr")

    duration_ms = (time.monotonic() - started) * 1000.0
    return FixtureResult(
        fixture_id=fid,
        tool=requested_tool or ",".join(targets),
        category=category,
        passed=overall_pass,
        reasons=reasons,
        duration_ms=round(duration_ms, 2),
    )


def run_harness(
    server_command: str,
    fixtures_dir: Path | None = None,
    sentinels: Iterable[str] = DEFAULT_SENTINELS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HarnessReport:
    cmd = shlex.split(server_command)
    if not cmd:
        raise MCPClientError("empty server command")

    fixtures = load_fixtures(fixtures_dir)
    results: list[FixtureResult] = []

    with tempfile.TemporaryDirectory(prefix="mcp-adv-") as tmp:
        stage_root = Path(tmp)
        with MCPStdioClient(cmd, timeout=timeout) as client:
            try:
                tools = client.list_tools()
            except MCPClientError as exc:
                raise MCPClientError(f"could not list tools: {exc}") from exc
            tool_names = [t.get("name") for t in tools if t.get("name")]
            for fixture in fixtures:
                results.append(
                    run_fixture(
                        client=client,
                        fixture=fixture,
                        tool_names=tool_names,
                        sentinels=sentinels,
                        stage_root=stage_root,
                    )
                )

    passed = sum(1 for r in results if r.passed)
    return HarnessReport(
        server_command=server_command,
        fixtures_total=len(results),
        fixtures_passed=passed,
        fixtures_failed=len(results) - passed,
        results=results,
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-adversarial",
        description="Adversarial input harness for MCP servers.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the harness against an MCP server")
    run.add_argument(
        "--server",
        required=True,
        help='shell-style command to spawn the MCP server (e.g. "tf-review-mcp")',
    )
    run.add_argument(
        "--fixtures",
        type=Path,
        default=None,
        help="directory of fixture JSON files; defaults to the packaged set",
    )
    run.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write a JSON report to this path",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="per-RPC timeout in seconds",
    )
    run.add_argument(
        "--sentinel",
        action="append",
        default=None,
        help="exfiltration sentinel to check for; can be repeated",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        sentinels = tuple(args.sentinel) if args.sentinel else DEFAULT_SENTINELS
        try:
            report = run_harness(
                server_command=args.server,
                fixtures_dir=args.fixtures,
                sentinels=sentinels,
                timeout=args.timeout,
            )
        except MCPClientError as exc:
            print(f"harness error: {exc}", file=sys.stderr)
            return 2

        print(
            f"ran {report.fixtures_total} fixtures: "
            f"{report.fixtures_passed} passed, {report.fixtures_failed} failed"
        )
        for r in report.results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"  [{mark}] {r.fixture_id} ({r.category}) -> {r.tool}")
            for reason in r.reasons:
                print(f"        {reason}")

        if args.report:
            args.report.write_text(json.dumps(report.to_dict(), indent=2))

        return 0 if report.fixtures_failed == 0 else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
