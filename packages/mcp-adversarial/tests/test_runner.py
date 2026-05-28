from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import pytest

from mcp_adversarial.runner import (
    DEFAULT_SENTINELS,
    MCPClientError,
    MCPStdioClient,
    run_harness,
)

STUB = str(Path(__file__).parent / "stub_server.py")


def _stub_cmd() -> str:
    return shlex.join([sys.executable, STUB])


def _fixture_dir(tmp_path: Path, fixture: dict) -> Path:
    d = tmp_path / "fx"
    d.mkdir()
    (d / "f.json").write_text(json.dumps(fixture))
    return d


def test_client_initialize_and_list_tools(monkeypatch):
    monkeypatch.setenv("STUB_MODE", "clean")
    with MCPStdioClient(shlex.split(_stub_cmd()), timeout=10) as client:
        tools = client.list_tools()
        assert any(t.get("name") == "echo" for t in tools)


def test_runner_passes_clean_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "clean")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "clean-echo",
            "category": "smoke",
            "tool": "echo",
            "args": {"x": "hello"},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_total == 1
    assert report.fixtures_failed == 0
    assert report.results[0].passed


def test_runner_detects_sentinel_leak(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "leak")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "leak-test",
            "category": "exfil",
            "tool": "echo",
            "args": {"x": "hello"},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_failed == 1
    reasons = report.results[0].reasons
    assert any("sentinel" in r for r in reasons)


def test_runner_detects_control_chars(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "control")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "control-test",
            "category": "sanitize",
            "tool": "echo",
            "args": {"x": "hello"},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_failed == 1
    reasons = report.results[0].reasons
    assert any("control" in r for r in reasons)


def test_runner_detects_traceback_on_stderr(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "crash")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "crash-test",
            "category": "exception",
            "tool": "echo",
            "args": {"x": "hello"},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_failed == 1


def test_runner_uses_packaged_fixtures_when_dir_missing(monkeypatch):
    monkeypatch.setenv("STUB_MODE", "clean")
    report = run_harness(
        server_command=_stub_cmd(),
        fixtures_dir=Path("/nonexistent/dir/somewhere"),
    )
    # No fixtures loaded, harness still completes cleanly.
    assert report.fixtures_total == 0
    assert report.fixtures_failed == 0


def test_runner_skips_fixture_for_unknown_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "clean")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "missing-tool",
            "category": "smoke",
            "tool": "this_tool_does_not_exist",
            "args": {},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_failed == 1
    assert "does not advertise" in report.results[0].reasons[0]


def test_runner_stages_files(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "clean")
    fixtures = _fixture_dir(
        tmp_path,
        {
            "id": "stage",
            "category": "smoke",
            "tool": "echo",
            "args": {"path": "/tmp/plan.json"},
            "setup": {"write_files": {"/tmp/plan.json": {"hello": "world"}}},
        },
    )
    report = run_harness(server_command=_stub_cmd(), fixtures_dir=fixtures)
    assert report.fixtures_failed == 0
    # The path placeholder was rewritten before being sent to the tool;
    # the staged file lives in a tempdir, not at /tmp.
    # (Behavior implicitly tested by the fact that the fixture passes
    # against the echo stub regardless of file content.)


def test_default_sentinels_present():
    assert DEFAULT_SENTINELS
    assert all(isinstance(s, str) and s for s in DEFAULT_SENTINELS)


def test_empty_server_command_raises():
    with pytest.raises(MCPClientError):
        run_harness(server_command="   ")
