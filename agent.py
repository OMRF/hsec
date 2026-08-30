"""Session agent: holds the passphrase-derived key in memory only.

Why an agent rather than a cached key file: there is nothing at rest to steal.
The derived key exists only in this process's memory and dies with it, either
on TTL expiry or on `hsec agent stop`. This is the ssh-agent model.

The agent performs the unseal itself and returns plaintext. It never hands out
the derived key, so a pipe client cannot decrypt blobs on its own.

Transport is a Windows named pipe whose DACL is protected and grants access to
exactly one SID: the user who started the agent.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import time
from collections.abc import Callable
from ctypes import wintypes

import store
import tray

# --- Win32 -----------------------------------------------------------------------

_k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_adv = ctypes.WinDLL("advapi32.dll", use_last_error=True)

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_PIPE_CONNECTED = 535
TOKEN_QUERY = 0x0008
TokenUser = 1
SDDL_REVISION_1 = 1


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


# Explicit signatures are mandatory on 64-bit: without them ctypes assumes
# c_int returns and silently truncates HANDLE values, so GetCurrentProcess()
# and CreateNamedPipeW() would hand back garbage handles.
_k32.GetCurrentProcess.argtypes = []
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.LocalFree.argtypes = [ctypes.c_void_p]
_k32.LocalFree.restype = ctypes.c_void_p

_adv.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
]
_adv.OpenProcessToken.restype = wintypes.BOOL
_adv.GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_adv.GetTokenInformation.restype = wintypes.BOOL
_adv.ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
]
_adv.ConvertSidToStringSidW.restype = wintypes.BOOL
_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
]
_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

_k32.CreateNamedPipeW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
]
_k32.CreateNamedPipeW.restype = wintypes.HANDLE
_k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_k32.ConnectNamedPipe.restype = wintypes.BOOL
_k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
_k32.DisconnectNamedPipe.restype = wintypes.BOOL
_k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
_k32.FlushFileBuffers.restype = wintypes.BOOL
_k32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
_k32.ReadFile.restype = wintypes.BOOL
_k32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
_k32.WriteFile.restype = wintypes.BOOL


def current_user_sid() -> str:
    """SID string for the current process token, for the pipe DACL."""
    tok = wintypes.HANDLE()
    if not _adv.OpenProcessToken(
        _k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        need = wintypes.DWORD(0)
        _adv.GetTokenInformation(tok, TokenUser, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(need.value)
        if not _adv.GetTokenInformation(
            tok, TokenUser, buf, need.value, ctypes.byref(need)
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        tu = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        out = wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(tu.User.Sid, ctypes.byref(out)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return out.value
        finally:
            _k32.LocalFree(out)
    finally:
        _k32.CloseHandle(tok)


def pipe_name() -> str:
    # The SID keeps the name unique per user on a shared machine.
    return r"\\.\pipe\hsec-" + current_user_sid()


def _security_attributes() -> SECURITY_ATTRIBUTES:
    """Protected DACL granting GENERIC_ALL to the current user and no one else.

    'P' blocks inherited ACEs, so no parent-container permission can widen
    access to the pipe.
    """
    sddl = f"D:P(A;;GA;;;{current_user_sid()})"
    psd = ctypes.c_void_p()
    if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(psd), None
    ):
        raise OSError(
            ctypes.get_last_error(), "ConvertStringSecurityDescriptor failed"
        )
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = psd
    sa.bInheritHandle = False
    return sa


# --- framing ---------------------------------------------------------------------


def _read_line(handle) -> bytes:
    chunks, buf = [], ctypes.create_string_buffer(4096)
    got = wintypes.DWORD(0)
    while True:
        if not _k32.ReadFile(handle, buf, 4096, ctypes.byref(got), None):
            break
        if got.value == 0:
            break
        chunk = buf.raw[: got.value]
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


def _write_line(handle, data: bytes) -> None:
    payload = data + b"\n"
    written = wintypes.DWORD(0)
    _k32.WriteFile(handle, payload, len(payload), ctypes.byref(written), None)
    _k32.FlushFileBuffers(handle)


# --- server ----------------------------------------------------------------------


class Agent:
    def __init__(self, pass_key: bytes, ttl_seconds: int):
        self.pass_key = bytearray(pass_key)
        self.expires_at = time.time() + ttl_seconds
        self.running = True
        # Run just before the process dies, whichever way it dies. The tray
        # registers its icon teardown here.
        self.shutdown_hooks: list[Callable[[], None]] = []

    def shutdown(self, reason: str) -> None:
        """The single exit path: TTL expiry, `hsec agent stop`, and tray Exit
        all end here.

        os._exit skips atexit, finally and destructors, so anything that must
        happen on the way out has to happen in the hooks, above the call.
        """
        for hook in self.shutdown_hooks:
            try:
                hook()
            except Exception:
                pass
        store.zero(self.pass_key)
        store.audit(reason)
        os._exit(0)

    def handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "ping":
            return {"ok": True, "expires_at": self.expires_at}
        if op == "stop":
            self.running = False
            return {"ok": True}
        if op == "unseal":
            name = req.get("name", "")
            try:
                blob = store.load_blob(name)
                plain = store.unseal(blob, bytes(self.pass_key))
            except Exception as exc:
                store.audit("unseal_failed", name=name, error=str(exc), via="agent")
                return {"ok": False, "error": str(exc)}
            try:
                store.audit("unseal", name=name, via="agent")
                return {"ok": True, "value": store.b64e(bytes(plain))}
            finally:
                store.zero(plain)
        return {"ok": False, "error": f"unknown op {op!r}"}

    def serve(self) -> None:
        name = pipe_name()
        sa = _security_attributes()
        self._start_watchdog()
        store.audit("agent_start", expires_at=self.expires_at)
        while self.running:
            handle = _k32.CreateNamedPipeW(
                name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                ctypes.byref(sa),
            )
            if handle == INVALID_HANDLE_VALUE or handle is None:
                raise OSError(ctypes.get_last_error(), "CreateNamedPipeW failed")
            try:
                connected = _k32.ConnectNamedPipe(handle, None)
                if not connected and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                    continue
                try:
                    req = json.loads(_read_line(handle).decode("utf-8") or "{}")
                except Exception:
                    req = {}
                resp = self.handle(req)
                _write_line(handle, json.dumps(resp).encode("utf-8"))
            finally:
                _k32.FlushFileBuffers(handle)
                _k32.DisconnectNamedPipe(handle)
                _k32.CloseHandle(handle)
        # The stop reply has been written and flushed by now, so the client
        # gets its acknowledgement before we go.
        self.shutdown("agent_stop")

    def _start_watchdog(self) -> None:
        """The serve loop blocks in ConnectNamedPipe, so TTL enforcement lives
        in a daemon thread that terminates the process outright."""

        def tick():
            while self.running:
                if time.time() >= self.expires_at:
                    self.shutdown("agent_expired")
                time.sleep(5)

        threading.Thread(target=tick, daemon=True).start()


# --- client ----------------------------------------------------------------------


def request(payload: dict, timeout: float = 20.0) -> dict | None:
    """Send one request. Returns None when no agent is listening."""
    name = pipe_name()
    deadline = time.time() + timeout
    while True:
        try:
            with open(name, "r+b", buffering=0) as pipe:
                pipe.write(json.dumps(payload).encode("utf-8") + b"\n")
                line = pipe.readline()
            return json.loads(line.decode("utf-8"))
        except FileNotFoundError:
            return None
        except OSError:
            # Pipe busy between instances; retry briefly.
            if time.time() >= deadline:
                return None
            time.sleep(0.05)


def is_running() -> bool:
    resp = request({"op": "ping"}, timeout=2.0)
    return bool(resp and resp.get("ok"))


def status() -> dict | None:
    return request({"op": "ping"}, timeout=2.0)


def stop() -> bool:
    resp = request({"op": "stop"}, timeout=2.0)
    return bool(resp and resp.get("ok"))


def unseal_via_agent(name: str) -> bytearray | None:
    """Ask the agent to unseal. None means no agent; exceptions mean it failed."""
    resp = request({"op": "unseal", "name": name})
    if resp is None:
        return None
    if not resp.get("ok"):
        raise store.StoreError(resp.get("error", "agent refused the request"))
    return bytearray(store.b64d(resp["value"]))


def serve_main() -> int:
    """Entry point for the detached agent process.

    The derived key arrives on stdin rather than argv or the environment, so it
    never appears in any process listing.
    """
    raw = sys.stdin.buffer.readline().strip()
    if not raw:
        print("agent: no key on stdin", file=sys.stderr)
        return 2
    cfg = store.load_config()
    ag = Agent(store.b64d(raw.decode("ascii")), int(cfg["agent_ttl_seconds"]))

    # The tray owns the main thread, because a Win32 message pump has to run on
    # the thread that created the window. When there is no tray -- HSEC_NO_TRAY,
    # or a shell that refused the icon -- the serve loop keeps the main thread
    # and the agent behaves exactly as it did before.
    if not tray.install(ag):
        ag.serve()
        return 0

    def serve_guarded() -> None:
        try:
            ag.serve()
        except Exception as exc:
            # A dead serve loop behind a live icon is the worst of both: the
            # tray says unlocked and nothing answers the pipe. Take the whole
            # process down instead of advertising a session that is gone.
            store.audit("agent_error", error=str(exc))
            ag.shutdown("agent_stop")

    threading.Thread(target=serve_guarded, daemon=True).start()
    tray.run()
    return 0
