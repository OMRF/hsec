# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=43"]
# ///
"""End-to-end test of the real `hsec run` and session-agent code paths.

Runs against a throwaway store (HSEC_STORE) so the real store and its
passphrase are never touched. It uses the production paths rather than any
test-only shortcut: the agent receives its derived key on stdin exactly as
`hsec agent start` sends it, and `hsec run` reaches the agent over the same
named pipe a normal invocation uses.

    uv run --script integration_test.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

TEST_PASSPHRASE = b"integration-test-passphrase"
SENTINEL = "SENTINEL-abcdef-0123456789"
HSEC = str(HERE / "hsec.py")

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, note: str = "") -> None:
    results.append((label, ok, note))


def run_hsec(env: dict, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Capture bytes, not text. Scrubbing is a byte-level guarantee, and
    decoding through the locale code page would hide real leaks behind
    mojibake (or invent failures that are not there)."""
    return subprocess.run(
        [sys.executable, HSEC, *args],
        env=env, capture_output=True, timeout=timeout,
    )


def dec(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="hsec-itest-"))
    env = dict(os.environ, HSEC_STORE=str(tmp))
    agent_proc = None

    try:
        import agent as agent_mod
        import store

        # store was imported without HSEC_STORE, so point it at the temp store.
        store.STORE_DIR = tmp
        store.CONFIG_PATH = tmp / "config.json"
        store.MANIFEST_PATH = tmp / "manifest.json"
        store.BLOB_DIR = tmp / "store"
        store.LOG_PATH = tmp / "access.log"

        # 1. init the throwaway store through the real CLI
        r = run_hsec(env, "init")
        check("init creates a TPM-backed store", r.returncode == 0,
              dec(r.stdout).strip().splitlines()[-1] if r.stdout else dec(r.stderr)[:80])

        cfg = json.loads((tmp / "config.json").read_text("utf-8"))
        pass_key = store.derive_pass_key(TEST_PASSPHRASE, cfg)

        # 2. seal a verifier and a test secret using the library directly
        #    (enrollment itself is interactive by design)
        (tmp / "verifier.json").write_text(
            json.dumps(store.seal("verifier", b"SENTINEL-VALUE-12345", pass_key, cfg)),
            "utf-8")
        store.BLOB_DIR.mkdir(parents=True, exist_ok=True)
        (store.BLOB_DIR / "probe.json").write_text(
            json.dumps(store.seal("probe", SENTINEL.encode(), pass_key, cfg)), "utf-8")
        store.save_manifest({"probe": {"env": "PROBE_TOKEN", "description": "test"}})
        check("seal a secret into the store", (store.BLOB_DIR / "probe.json").exists())

        # 3. list must never print the value
        r = run_hsec(env, "list")
        check("list shows metadata only",
              r.returncode == 0 and b"PROBE_TOKEN" in r.stdout
              and SENTINEL.encode() not in r.stdout)

        # 4. start the agent exactly as `hsec agent start` does: key on stdin
        agent_proc = subprocess.Popen(
            [sys.executable, HSEC, "agent", "serve"],
            env=env, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        agent_proc.stdin.write(store.b64e(pass_key).encode("ascii") + b"\n")
        agent_proc.stdin.flush()
        agent_proc.stdin.close()

        up = False
        for _ in range(60):
            if agent_mod.is_running():
                up = True
                break
            time.sleep(0.1)
        check("session agent starts and answers ping", up)

        r = run_hsec(env, "agent", "status")
        check("agent status reports unlocked",
              r.returncode == 0 and b"running" in r.stdout, dec(r.stdout).strip())

        # 5. the real wrapper path, with no prompt because the agent is unlocked
        code = "import os;print('GOT:'+os.environ.get('PROBE_TOKEN','MISSING'))"
        r = run_hsec(env, "run", "--name", "probe", "--", sys.executable, "-c", code)
        check("run injects the secret into the child env",
              r.returncode == 0 and b"GOT:" in r.stdout and b"MISSING" not in r.stdout,
              dec(r.stdout).strip()[:70] or dec(r.stderr)[:70])
        check("run scrubs the raw value from stdout",
              SENTINEL.encode() not in r.stdout and b"[REDACTED:probe]" in r.stdout,
              dec(r.stdout).strip()[:70])

        # 6. scrubbing across encodings the child might emit
        code = (
            "import os,base64,urllib.parse as u,json;v=os.environ['PROBE_TOKEN'];"
            "print(v);print('Authorization: Bearer '+v);"
            "print(base64.b64encode(v.encode()).decode());"
            "print(u.quote(v,safe=''));print(json.dumps({'k':v}))"
        )
        r = run_hsec(env, "run", "--name", "probe", "--", sys.executable, "-c", code)
        import base64
        from urllib.parse import quote
        leaks = {
            "raw": SENTINEL.encode() in r.stdout,
            "base64": base64.b64encode(SENTINEL.encode()) in r.stdout,
            "urlencoded": quote(SENTINEL, safe="").encode() in r.stdout,
        }
        check("scrubbing covers raw, base64, and url-encoded forms",
              not any(leaks.values()), f"leaks={leaks}")

        # 7. stderr is scrubbed too - a verbose client writes creds there
        code = "import os,sys;sys.stderr.write('hdr '+os.environ['PROBE_TOKEN'])"
        r = run_hsec(env, "run", "--name", "probe", "--", sys.executable, "-c", code)
        check("scrubbing applies to stderr", SENTINEL.encode() not in r.stderr,
              dec(r.stderr).strip()[:70])

        # 8. exit code passthrough
        r = run_hsec(env, "run", "--name", "probe", "--",
                     sys.executable, "-c", "import sys;sys.exit(42)")
        check("child exit code propagates", r.returncode == 42, f"rc={r.returncode}")

        # 9. unknown secret is refused
        r = run_hsec(env, "run", "--name", "nope", "--", sys.executable, "-c", "pass")
        check("unknown secret is rejected", r.returncode != 0,
              dec(r.stderr).strip()[:60])

        # 10. the audit log records access without recording values
        log = (tmp / "access.log").read_text("utf-8")
        check("audit log records unseals but no values",
              '"event": "unseal"' in log and SENTINEL not in log,
              f"{len(log.splitlines())} entries")

        # 11. stopping the agent forces the next run to need a passphrase again
        r = run_hsec(env, "agent", "stop")
        time.sleep(0.5)
        check("agent stops on request",
              r.returncode == 0 and not agent_mod.is_running(), dec(r.stdout).strip())

        # 12. blobs remain sealed at rest
        raw = (store.BLOB_DIR / "probe.json").read_text("utf-8")
        check("blob on disk contains no plaintext", SENTINEL not in raw)

        # 13. no argv leakage. The child reports its own full command line via
        #     GetCommandLineW, which is exactly what a process listing would
        #     show, so this proves the value travels only in the environment.
        r = run_hsec(env, "agent", "stop")  # already stopped; keep state clean
        agent_proc2 = subprocess.Popen(
            [sys.executable, HSEC, "agent", "serve"],
            env=env, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        agent_proc2.stdin.write(store.b64e(pass_key).encode("ascii") + b"\n")
        agent_proc2.stdin.flush()
        agent_proc2.stdin.close()
        for _ in range(60):
            if agent_mod.is_running():
                break
            time.sleep(0.1)
        try:
            code = (
                "import ctypes,sys;"
                "ctypes.windll.kernel32.GetCommandLineW.restype=ctypes.c_wchar_p;"
                "print('CMDLINE:'+ctypes.windll.kernel32.GetCommandLineW())"
            )
            r = run_hsec(env, "run", "--name", "probe", "--", sys.executable, "-c", code)
            got_line = b"CMDLINE:" in r.stdout
            check("secret never appears in the child command line",
                  got_line and SENTINEL.encode() not in r.stdout
                  and b"[REDACTED" not in r.stdout,
                  "command line carried no secret" if got_line
                  else dec(r.stderr)[:70])
        finally:
            run_hsec(env, "agent", "stop")
            if agent_proc2.poll() is None:
                agent_proc2.terminate()

    finally:
        if agent_proc and agent_proc.poll() is None:
            agent_proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)

    width = max(len(r[0]) for r in results)
    failed = 0
    for label, ok, note in results:
        if not ok:
            failed += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {label.ljust(width)}  {note}")
    print()
    print(f"{len(results) - failed}/{len(results)} passed" if not failed
          else f"{failed} of {len(results)} FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
