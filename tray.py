"""Notification-area icon for the running session agent.

The agent is detached and has no console, so without this there is nothing on
the desktop to tell you it is alive, how long it has left, or how to stop it.
The icon is that handle: hover for the countdown, right-click for the menu.

Pure ctypes against shell32/user32, for the same reason the named pipe and the
TPM calls are: the store carries exactly one dependency and a tray icon is not
worth a second one.

Nothing here may raise into the agent. A tray that fails to start is a cosmetic
loss; an agent that dies with it is a real one. Every entry point catches, and
reports through the audit log because there is no stdout to report to.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import store

# --- Win32 -----------------------------------------------------------------------

_k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_u32 = ctypes.WinDLL("user32.dll", use_last_error=True)
_shell = ctypes.WinDLL("shell32.dll", use_last_error=True)

WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_TIMER = 0x0113
WM_NULL = 0x0000
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B
WM_APP = 0x8000
WM_TRAY = WM_APP + 1

NIM_ADD = 0
NIM_MODIFY = 1
NIM_DELETE = 2
NIF_MESSAGE = 0x01
NIF_ICON = 0x02
NIF_TIP = 0x04

MF_STRING = 0x0000
MF_GRAYED = 0x0001
MF_POPUP = 0x0010
MF_SEPARATOR = 0x0800

TPM_RIGHTBUTTON = 0x0002
TPM_RETURNCMD = 0x0100

IDI_SHIELD = 32518
ERROR_CLASS_ALREADY_EXISTS = 1410
CW_USEDEFAULT = -2147483648

ID_SHOW_LOG = 1
ID_EXIT = 2
TOOLTIP_TIMER = 1
TOOLTIP_INTERVAL_MS = 30_000

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)

# HWND_MESSAGE is (HWND)-3. It has to travel as a pointer, not as an int, or
# the sign extension is wrong on 64-bit and the window becomes a real one.
HWND_MESSAGE = ctypes.cast(ctypes.c_void_p(-3), wintypes.HWND)


def _int_resource(value: int) -> wintypes.LPCWSTR:
    """MAKEINTRESOURCE: a small integer smuggled through an LPCWSTR."""
    return ctypes.cast(ctypes.c_void_p(value), wintypes.LPCWSTR)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", POINT),
    ]


# Explicit signatures, for the reason spelled out in agent.py: without them
# ctypes assumes c_int returns and truncates every HANDLE on 64-bit.
_u32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
_u32.RegisterClassW.restype = wintypes.ATOM
_u32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
]
_u32.CreateWindowExW.restype = wintypes.HWND
_u32.DefWindowProcW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
]
_u32.DefWindowProcW.restype = LRESULT
_u32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
_u32.LoadIconW.restype = wintypes.HICON
_u32.CreatePopupMenu.argtypes = []
_u32.CreatePopupMenu.restype = wintypes.HMENU
_u32.AppendMenuW.argtypes = [
    wintypes.HMENU, wintypes.UINT, ctypes.c_void_p, wintypes.LPCWSTR
]
_u32.AppendMenuW.restype = wintypes.BOOL
_u32.DestroyMenu.argtypes = [wintypes.HMENU]
_u32.DestroyMenu.restype = wintypes.BOOL
_u32.TrackPopupMenu.argtypes = [
    wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, wintypes.HWND, ctypes.c_void_p,
]
_u32.TrackPopupMenu.restype = ctypes.c_int
_u32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
_u32.GetCursorPos.restype = wintypes.BOOL
_u32.SetForegroundWindow.argtypes = [wintypes.HWND]
_u32.SetForegroundWindow.restype = wintypes.BOOL
_u32.PostMessageW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
]
_u32.PostMessageW.restype = wintypes.BOOL
_u32.GetMessageW.argtypes = [
    ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
]
_u32.GetMessageW.restype = ctypes.c_int
_u32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
_u32.TranslateMessage.restype = wintypes.BOOL
_u32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
_u32.DispatchMessageW.restype = LRESULT
_u32.PostQuitMessage.argtypes = [ctypes.c_int]
_u32.PostQuitMessage.restype = None
_u32.SetTimer.argtypes = [
    wintypes.HWND, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p
]
_u32.SetTimer.restype = ctypes.c_void_p
_u32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
_u32.RegisterWindowMessageW.restype = wintypes.UINT
_k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_k32.GetModuleHandleW.restype = wintypes.HMODULE
_shell.Shell_NotifyIconW.argtypes = [
    wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)
]
_shell.Shell_NotifyIconW.restype = wintypes.BOOL


# --- helpers ---------------------------------------------------------------------


def countdown(expires_at: float) -> str:
    left = int(expires_at - time.time())
    if left <= 0:
        return "expired"
    hours, rem = divmod(left, 3600)
    minutes = rem // 60
    if hours:
        return f"unlocked for {hours}h{minutes:02d}m"
    return f"unlocked for {minutes}m"


def pythonw() -> str:
    """The GUI-subsystem interpreter, so a spawned child gets no console.

    Falls back to whatever is running us if the pair is not installed, which
    costs a console window but never a failure to launch.
    """
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate) if candidate.exists() else sys.executable


def spawn_log_window() -> None:
    """Launch the log viewer as its own process.

    Deliberately a process and not a thread: closing the log must not be able to
    take the agent down with it, and the process holding the derived key has no
    business loading a GUI toolkit. The viewer refuses to open twice, so this
    can fire and forget.
    """
    script = Path(__file__).resolve().parent / "hsec.py"
    subprocess.Popen(
        [pythonw(), str(script), "log", "--window"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )


def _secret_items() -> list[str]:
    """Names and env vars from the manifest, which holds no values -- so this
    menu cannot leak one even if the screen is being recorded."""
    warn_days = store.DEFAULT_EXPIRY_WARN_DAYS
    try:
        cfg = store.load_config()
        warn_days = int(cfg.get("expiry_warn_days", warn_days))
    except Exception:
        pass
    try:
        man = store.load_manifest()
    except Exception:
        return []
    items = []
    for name in sorted(man):
        entry = man[name]
        label = f"{name}  ->  {entry.get('env', '?')}"
        iso = entry.get("expires")
        if iso:
            label += f"   [{store.expiry_label(iso, warn_days)}]"
        items.append(label)
    return items


# --- the icon --------------------------------------------------------------------


class Tray:
    def __init__(self, agent):
        self.agent = agent
        self.hwnd = None
        self._nid = None
        self._wndproc = None
        self._class_name = "hsec_tray_wnd"
        self._taskbar_created = _u32.RegisterWindowMessageW("TaskbarCreated")

    # -- lifecycle --

    def install(self) -> None:
        hinst = _k32.GetModuleHandleW(None)

        # Held on the instance, which the module-level _TRAY keeps alive for the
        # life of the process. If this trampoline is collected while Windows
        # still holds the pointer, the next dispatched message jumps into freed
        # memory and takes the agent with it.
        self._wndproc = WNDPROC(self._on_message)

        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = self._class_name
        if not _u32.RegisterClassW(ctypes.byref(wc)):
            # Registered by an earlier attempt in this process: the class is
            # still usable, so only a different error is fatal.
            if ctypes.get_last_error() != ERROR_CLASS_ALREADY_EXISTS:
                raise OSError(ctypes.get_last_error(), "RegisterClassW failed")

        # A message-only window: it never appears anywhere, it only receives.
        self.hwnd = _u32.CreateWindowExW(
            0, self._class_name, "hsec agent", 0,
            CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
            HWND_MESSAGE, None, hinst, None,
        )
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "CreateWindowExW failed")

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = _u32.LoadIconW(None, _int_resource(IDI_SHIELD))
        nid.szTip = self._tip()
        self._nid = nid
        if not _shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            self._nid = None
            raise OSError(
                ctypes.get_last_error(), "Shell_NotifyIconW(NIM_ADD) failed"
            )

        _u32.SetTimer(
            self.hwnd, ctypes.c_void_p(TOOLTIP_TIMER), TOOLTIP_INTERVAL_MS, None
        )

    def remove(self) -> None:
        """Runs from Agent.shutdown, before os._exit. Without it the icon
        lingers as a ghost until the user happens to hover over it."""
        if self._nid is not None:
            _shell.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            self._nid = None

    def run(self) -> None:
        msg = MSG()
        while True:
            got = _u32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if got in (0, -1):
                return
            _u32.TranslateMessage(ctypes.byref(msg))
            _u32.DispatchMessageW(ctypes.byref(msg))

    # -- messages --

    def _tip(self) -> str:
        return f"hsec agent - {countdown(self.agent.expires_at)}"

    def _refresh_tip(self) -> None:
        if self._nid is None:
            return
        self._nid.szTip = self._tip()
        _shell.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))

    def _on_message(self, hwnd, msg, wparam, lparam) -> int:
        try:
            if msg == self._taskbar_created and self._nid is not None:
                # Explorer restarted and dropped every icon. Put ours back.
                _shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self._nid))
                return 0
            if msg == WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._show_menu()
                elif event == WM_LBUTTONDBLCLK:
                    spawn_log_window()
                return 0
            if msg == WM_TIMER and wparam == TOOLTIP_TIMER:
                self._refresh_tip()
                return 0
            if msg == WM_COMMAND:
                self._on_command(wparam & 0xFFFF)
                return 0
            if msg == WM_DESTROY:
                _u32.PostQuitMessage(0)
                return 0
        except Exception as exc:
            # A broken menu must not be able to end the session.
            store.audit("tray_error", error=str(exc))
            return 0
        return _u32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _on_command(self, ident: int) -> None:
        if ident == ID_SHOW_LOG:
            spawn_log_window()
        elif ident == ID_EXIT:
            self.agent.shutdown("agent_stop")

    def _show_menu(self) -> None:
        menu = _u32.CreatePopupMenu()
        submenu = None
        try:
            _u32.AppendMenuW(
                menu, MF_STRING | MF_GRAYED, 0, countdown(self.agent.expires_at)
            )
            _u32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            _u32.AppendMenuW(menu, MF_STRING, ID_SHOW_LOG, "Show log")

            items = _secret_items()
            if items:
                submenu = _u32.CreatePopupMenu()
                for label in items:
                    _u32.AppendMenuW(submenu, MF_STRING | MF_GRAYED, 0, label)
                _u32.AppendMenuW(
                    menu, MF_POPUP, ctypes.c_void_p(submenu), "Secrets"
                )

            _u32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            _u32.AppendMenuW(menu, MF_STRING, ID_EXIT, "Exit (stop agent)")

            pt = POINT()
            _u32.GetCursorPos(ctypes.byref(pt))
            # Both calls are load-bearing and in this order: without the
            # foreground call the menu will not close when you click away, and
            # without the trailing PostMessage it can stay stuck after it does.
            _u32.SetForegroundWindow(self.hwnd)
            chosen = _u32.TrackPopupMenu(
                menu, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y,
                0, self.hwnd, None,
            )
            _u32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
            if chosen:
                self._on_command(int(chosen))
        finally:
            if submenu:
                _u32.DestroyMenu(submenu)
            _u32.DestroyMenu(menu)


# The live Tray, kept alive for the process lifetime so its WNDPROC trampoline
# cannot be collected out from under Windows.
_TRAY: Tray | None = None


def install(agent) -> bool:
    """Add the icon and register the teardown hook. False means run headless."""
    global _TRAY
    if os.environ.get("HSEC_NO_TRAY"):
        return False
    try:
        tray = Tray(agent)
        tray.install()
    except Exception as exc:
        store.audit("tray_failed", error=str(exc))
        return False
    _TRAY = tray
    agent.shutdown_hooks.append(tray.remove)
    return True


def run() -> None:
    if _TRAY is not None:
        _TRAY.run()
