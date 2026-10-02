"""Find the MCP client process that started us, to key the shared session.

All servers of one agent window are started by the same client process, so the client's pid
(plus its start time, to survive pid reuse) is a good session key. But the *direct* parent is
often not the client: launchers sit in between and each server gets its own chain, e.g. on
Windows with ``uv tool install``::

    Claude Code -> kairoseki.exe (launcher) -> python.exe (venv redirector) -> python.exe (us)

So we walk up the process tree and skip ancestors that are part of Kairoseki's own launch
chain: ``kairoseki`` launchers, ``uv``/``uvx``, and processes running our own Python
interpreter. The first other ancestor is the client.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass

_MAX_DEPTH = 16
_LAUNCHER_NAMES = {"kairoseki", "uv", "uvx"}


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    exe: str  # full path when available, otherwise the executable name
    start: str  # creation time, comparable between processes on the same OS ("" if unknown)


def _norm(path: str) -> str:
    with contextlib.suppress(OSError, ValueError):
        path = os.path.realpath(path)
    return os.path.normcase(path)


def _own_interpreters() -> set[str]:
    paths = {sys.executable, getattr(sys, "_base_executable", "") or ""}
    return {_norm(p) for p in paths if p}


def is_launcher(proc: Proc, interpreters: set[str]) -> bool:
    name = os.path.basename(proc.exe.replace("\\", "/")).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name in _LAUNCHER_NAMES or name.startswith("kairoseki"):
        return True
    return _norm(proc.exe) in interpreters


# ---------------------------------------------------------------------------- platform readers


def _linux(pid: int) -> Proc | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
            stat = f.read()
    except OSError:
        return None
    head, _, tail = stat.rpartition(")")
    fields = tail.split()
    if len(fields) < 20:
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = head.partition("(")[2]  # comm: the executable name, when the path is not readable
    return Proc(pid=pid, ppid=int(fields[1]), exe=exe, start=fields[19])


def _ps(pid: int) -> Proc | None:
    """macOS and other POSIX systems without /proc."""
    try:
        out = subprocess.run(
            ["ps", "-o", "ppid=", "-o", "lstart=", "-o", "comm=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    parts = out.split(None, 6)  # ppid, 5 lstart tokens ("Fri Oct  2 17:30:00 2026"), comm
    if len(parts) < 7 or not parts[0].isdigit():
        return None
    return Proc(pid=pid, ppid=int(parts[0]), exe=parts[6], start=" ".join(parts[1:6]))


def _windows_reader() -> Callable[[int], Proc | None]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    table: dict[int, tuple[int, str]] = {}
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if snap and snap != wintypes.HANDLE(-1).value:
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                table[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile)
                ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)

    def read(pid: int) -> Proc | None:
        if pid not in table:
            return None
        ppid, exe = table[pid]
        start = ""
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            try:
                size = wintypes.DWORD(1024)
                buf = ctypes.create_unicode_buffer(size.value)
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    exe = buf.value
                times = [wintypes.FILETIME() for _ in range(4)]
                if kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                    start = str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
            finally:
                kernel32.CloseHandle(handle)
        return Proc(pid=pid, ppid=ppid, exe=exe, start=start)

    return read


def _reader() -> Callable[[int], Proc | None]:
    if os.name == "nt":
        return _windows_reader()
    if os.path.isdir("/proc/self"):
        return _linux
    return _ps


# ---------------------------------------------------------------------------- walk


def find_client(read: Callable[[int], Proc | None], pid: int, interpreters: set[str]) -> Proc | None:
    """Walk up from ``pid`` and return the first ancestor that is not one of our launchers."""
    interpreters = {_norm(i) for i in interpreters}
    current = read(pid)
    for _ in range(_MAX_DEPTH):
        if current is None or current.ppid <= 0 or current.ppid == current.pid:
            return current
        parent = read(current.ppid)
        if parent is None:
            return current
        # a parent created after its child means the real parent died and its pid was reused
        if parent.start.isdigit() and current.start.isdigit() and int(parent.start) > int(current.start):
            return current
        if not is_launcher(parent, interpreters):
            return parent
        current = parent
    return current


def client_session_id() -> str:
    """``proc-<pid>-<start>`` of the MCP client process; falls back to the parent pid."""
    try:
        client = find_client(_reader(), os.getpid(), _own_interpreters())
    except Exception:  # never let process inspection break the proxy
        client = None
    if client is None or client.pid == os.getpid():
        return f"ppid-{os.getppid()}"
    start = "".join(c for c in client.start if c.isalnum())
    return f"proc-{client.pid}" + (f"-{start}" if start else "")
