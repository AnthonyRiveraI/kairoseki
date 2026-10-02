from __future__ import annotations

from kairoseki.session_id import Proc, find_client, is_launcher

PY = r"c:\users\neo\appdata\roaming\uv\tools\kairoseki\scripts\python.exe"
BASE = r"c:\python313\python.exe"


def table(*procs: Proc):  # type: ignore[no-untyped-def]
    by_pid = {p.pid: p for p in procs}
    return by_pid.get


def test_windows_uv_tool_chain_resolves_to_the_client() -> None:
    # the chain reported from a real Windows machine:
    # Claude Code (22324) -> kairoseki.exe (37608) -> python.exe redirector (16852) -> python.exe (22164)
    read = table(
        Proc(22324, 1000, r"C:\Users\Neo\AppData\Local\AnthropicClaude\claude.exe", "100"),
        Proc(37608, 22324, r"C:\Users\Neo\.local\bin\kairoseki.exe", "200"),
        Proc(16852, 37608, PY, "300"),
        Proc(22164, 16852, BASE, "400"),
    )
    client = find_client(read, 22164, {PY, BASE})
    assert client is not None and client.pid == 22324


def test_two_servers_of_one_client_share_it() -> None:
    procs = [Proc(1, 0, "/sbin/init", "1"), Proc(50, 1, "/usr/bin/claude", "10")]
    for base in (100, 200):  # two servers, each with its own launcher chain
        procs += [Proc(base, 50, "/home/u/.local/bin/uvx", "20"), Proc(base + 1, base, "/venv/bin/python", "30")]
    read = table(*procs)
    assert find_client(read, 101, {"/venv/bin/python"}).pid == find_client(read, 201, {"/venv/bin/python"}).pid == 50


def test_other_python_clients_are_not_skipped() -> None:
    read = table(Proc(50, 1, "/usr/bin/python3.12", "10"), Proc(60, 50, "/venv/bin/python", "20"))
    assert find_client(read, 60, {"/venv/bin/python"}).pid == 50


def test_reused_parent_pid_is_not_trusted() -> None:
    # our parent died and its pid now belongs to a newer process: stop at ourselves
    read = table(Proc(60, 50, "/venv/bin/python", "20"), Proc(50, 1, "/usr/bin/claude", "99"))
    assert find_client(read, 60, {"/venv/bin/python"}).pid == 60


def test_launcher_names() -> None:
    assert is_launcher(Proc(1, 0, r"C:\x\kairoseki.exe", ""), set())
    assert is_launcher(Proc(1, 0, "/usr/local/bin/uvx", ""), set())
    assert not is_launcher(Proc(1, 0, "/usr/bin/node", ""), set())


def test_platform_reader_sees_this_process() -> None:
    # runs the real implementation: /proc on Linux, ps on macOS, Toolhelp32 + ctypes on Windows
    import os

    from kairoseki.session_id import _reader

    me = _reader()(os.getpid())
    assert me is not None and me.ppid == os.getppid() and me.exe and me.start


def test_ps_reader_when_available() -> None:
    import os
    import shutil

    import pytest

    from kairoseki.session_id import _ps

    if os.name == "nt" or not shutil.which("ps"):
        pytest.skip("no ps")
    me = _ps(os.getpid())
    assert me is not None and me.ppid == os.getppid() and me.start
