"""Live view of the audit trail, in its own window and its own process.

Opened from the tray icon, or with `hsec log --window`.

It runs as a separate process on purpose. Closing this window must never be
able to stop the agent, and that is a much better guarantee when the two cannot
share a fate than when they share an interpreter. It also keeps Tk out of the
process holding the derived key.

The view is read-only. There is deliberately no way to clear the log from here:
this is the audit trail of a secret store, and a one-click truncate reachable
from a tray menu is the wrong affordance.
"""

from __future__ import annotations

import ctypes
import json
from ctypes import wintypes
from datetime import datetime

import store

TITLE = "hsec - access log"
TAIL_LINES = 500
POLL_MS = 500

_u32 = ctypes.WinDLL("user32.dll", use_last_error=True)
_u32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
_u32.FindWindowW.restype = wintypes.HWND
_u32.SetForegroundWindow.argtypes = [wintypes.HWND]
_u32.SetForegroundWindow.restype = wintypes.BOOL
_u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
_u32.ShowWindow.restype = wintypes.BOOL

SW_RESTORE = 9


def _focus_existing() -> bool:
    """True if a viewer is already up, in which case raise it and let the
    caller exit. Keeps repeated clicks on the tray menu to one window."""
    hwnd = _u32.FindWindowW(None, TITLE)
    if not hwnd:
        return False
    _u32.ShowWindow(hwnd, SW_RESTORE)
    _u32.SetForegroundWindow(hwnd)
    return True


def _format(line: str) -> tuple[str, str]:
    """One log line as (text, tag). Unparseable lines are shown verbatim
    rather than dropped -- a corrupt audit entry is worth seeing."""
    try:
        rec = json.loads(line)
    except Exception:
        return line, "plain"

    event = rec.get("event", "?")
    try:
        stamp = datetime.fromisoformat(rec["ts"]).astimezone().strftime("%H:%M:%S")
    except Exception:
        stamp = str(rec.get("ts", ""))[:19]

    extra = []
    if rec.get("name"):
        extra.append(str(rec["name"]))
    if rec.get("names"):
        extra.append(",".join(rec["names"]))
    if rec.get("command"):
        extra.append(str(rec["command"]))
    if rec.get("exit_code") is not None:
        extra.append(f"rc={rec['exit_code']}")
    if rec.get("redactions"):
        extra.append(f"redacted={rec['redactions']}")
    if rec.get("error"):
        extra.append(str(rec["error"]))

    if event in ("unseal_failed", "tray_failed", "tray_error"):
        tag = "bad"
    elif event.startswith("agent_"):
        tag = "life"
    else:
        tag = "plain"
    return f"{stamp}  {event:<16}{'  '.join(extra)}", tag


class Viewer:
    def __init__(self, root, tk):
        self.tk = tk
        self.root = root
        self.offset = 0
        self.follow = tk.BooleanVar(value=True)

        root.title(TITLE)
        root.geometry("760x420")
        root.minsize(420, 200)

        frame = tk.Frame(root, padx=8, pady=8)
        frame.pack(fill="both", expand=True)

        bar = tk.Frame(frame)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        tk.Checkbutton(bar, text="Follow", variable=self.follow).pack(side="left")
        tk.Label(bar, text=str(store.LOG_PATH), fg="#888", anchor="w").pack(
            side="left", padx=(12, 0)
        )
        tk.Button(bar, text="Close", width=10, command=root.destroy).pack(
            side="right"
        )

        scroll = tk.Scrollbar(frame)
        scroll.pack(side="right", fill="y")
        self.text = tk.Text(
            frame, wrap="none", font=("Consolas", 9), state="disabled",
            yscrollcommand=scroll.set, background="#111418", foreground="#d8dee4",
            insertbackground="#d8dee4", borderwidth=0, highlightthickness=0,
        )
        self.text.pack(side="left", fill="both", expand=True)
        scroll.config(command=self.text.yview)

        self.text.tag_config("bad", foreground="#ff6b6b")
        self.text.tag_config("life", foreground="#7ee787")
        self.text.tag_config("plain", foreground="#d8dee4")

        self._load_tail()
        self._poll()

    def _append(self, lines) -> None:
        self.text.config(state="normal")
        for line in lines:
            if not line.strip():
                continue
            text, tag = _format(line)
            self.text.insert("end", text + "\n", tag)
        self.text.config(state="disabled")
        if self.follow.get():
            self.text.see("end")

    def _load_tail(self) -> None:
        """Only the tail: access.log has no rotation and grows without bound."""
        if not store.LOG_PATH.exists():
            self._append(['{"event": "no audit log yet", "ts": ""}'])
            return
        raw = store.LOG_PATH.read_bytes()
        self.offset = len(raw)
        lines = raw.decode("utf-8", "replace").splitlines()
        self._append(lines[-TAIL_LINES:])

    def _poll(self) -> None:
        try:
            if store.LOG_PATH.exists():
                size = store.LOG_PATH.stat().st_size
                if size < self.offset:
                    # Truncated or replaced underneath us; start over.
                    self.text.config(state="normal")
                    self.text.delete("1.0", "end")
                    self.text.config(state="disabled")
                    self.offset = 0
                    self._load_tail()
                elif size > self.offset:
                    with store.LOG_PATH.open("rb") as fh:
                        fh.seek(self.offset)
                        chunk = fh.read()
                    # Keep a partial trailing line for the next tick rather than
                    # rendering half a record.
                    cut = chunk.rfind(b"\n") + 1
                    if cut:
                        self.offset += cut
                        self._append(
                            chunk[:cut].decode("utf-8", "replace").splitlines()
                        )
        except Exception:
            # A transient read failure must not kill the window.
            pass
        self.root.after(POLL_MS, self._poll)


def main() -> int:
    if _focus_existing():
        return 0
    try:
        import tkinter as tk
    except Exception:
        return 1
    root = tk.Tk()
    Viewer(root, tk)
    root.mainloop()
    return 0
