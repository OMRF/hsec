"""Passphrase prompting.

Claude Code's tool calls run non-interactively with stdin attached to the null
device, so getpass() cannot work there. When there is no usable terminal we put
a dialog on the desktop instead, which does appear because the agent runs in
the user's own interactive session.

The dialog names the secret and the command requesting it. That turns the
prompt into informed consent rather than a reflex click, which matters because
the agent can trigger it.
"""

from __future__ import annotations

import getpass
import sys


def have_tty() -> bool:
    """True only when there is a real interactive terminal on *both* ends.

    Checking stdin alone is not enough. A shell can hand a process a pty-like
    stdin while stdout is redirected to a file or a pipe — which is exactly
    what happens under an agent tool call or a backgrounded command. In that
    case `getpass()` looks available but, on Windows, reads the console
    directly via msvcrt and blocks forever with no timeout.

    The GUI prompt always times out, so when the terminal is anything less
    than unambiguous, prefer it. A hang with no way out is a worse failure
    than an unexpected dialog.
    """
    try:
        return bool(
            sys.stdin is not None
            and sys.stdout is not None
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        )
    except Exception:
        return False


def ask(title: str, detail: str, timeout: float = 90.0) -> str | None:
    """Return the passphrase, or None if canceled or timed out."""
    if have_tty():
        try:
            return getpass.getpass(f"{detail}\nPassphrase: ")
        except (EOFError, KeyboardInterrupt):
            return None
    return _ask_gui(title, detail, timeout)


def _ask_gui(title: str, detail: str, timeout: float) -> str | None:
    try:
        import tkinter as tk
    except Exception:
        return None

    result: dict[str, str | None] = {"value": None}
    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    frame = tk.Frame(root, padx=18, pady=14)
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame, text=detail, justify="left", anchor="w", wraplength=460
    ).pack(fill="x", pady=(0, 10))

    entry = tk.Entry(frame, show="•", width=46)
    entry.pack(fill="x")
    entry.focus_set()

    countdown = tk.Label(frame, text="", anchor="w", fg="#888")
    countdown.pack(fill="x", pady=(6, 0))

    def submit(_event=None):
        result["value"] = entry.get()
        root.destroy()

    def cancel(_event=None):
        result["value"] = None
        root.destroy()

    buttons = tk.Frame(frame)
    buttons.pack(fill="x", pady=(12, 0))
    tk.Button(buttons, text="Cancel", width=10, command=cancel).pack(side="right")
    tk.Button(buttons, text="Unlock", width=10, command=submit).pack(
        side="right", padx=(0, 8)
    )

    root.bind("<Return>", submit)
    root.bind("<Escape>", cancel)

    remaining = {"t": int(timeout)}

    def tick():
        if remaining["t"] <= 0:
            cancel()
            return
        countdown.config(text=f"Times out in {remaining['t']}s")
        remaining["t"] -= 1
        root.after(1000, tick)

    # Pull the dialog to the foreground; it is launched from a background tool
    # call and would otherwise open behind the terminal.
    root.attributes("-topmost", True)
    root.update_idletasks()
    width, height = root.winfo_width(), root.winfo_height()
    x = (root.winfo_screenwidth() - width) // 2
    y = (root.winfo_screenheight() - height) // 3
    root.geometry(f"+{x}+{y}")
    root.lift()
    try:
        entry.focus_force()
    except Exception:
        pass

    tick()
    root.mainloop()
    return result["value"]
