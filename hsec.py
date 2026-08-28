# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=43"]
# ///
"""hsec - TPM-sealed secret store for agent API access.

Secrets are sealed under two independent factors: this machine's TPM and a
passphrase. An agent (human or AI) can *use* a secret without *seeing* it:
`hsec run` injects the value into a child process environment and scrubs every
representation of it out of the child's output before returning.

    hsec init                                  create the TPM key and the store
    hsec add <name> --env VAR                  enroll a secret (interactive)
    hsec list                                  names and env vars, never values
    hsec rm <name>                             remove a sealed secret
    hsec run --name a,b -- <command>           run a command with secrets injected
    hsec agent start|status|stop               session agent (prompt once)
    hsec verify                                self-test the security properties
    hsec backup [dir]                          copy the store out of the repo
    hsec log [-n N]                            tail the audit trail
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent  # noqa: E402
import prompt  # noqa: E402
import store  # noqa: E402
import tpm  # noqa: E402

VERIFIER_PATH = store.STORE_DIR / "verifier.json"
VERIFIER_NAME = "verifier"
SENTINEL = b"SENTINEL-VALUE-12345"

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def err(msg: str) -> int:
    print(f"hsec: {msg}", file=sys.stderr)
    return 1


# --- passphrase handling ---------------------------------------------------------


def check_pass_key(pass_key: bytes) -> bool:
    import json

    if not VERIFIER_PATH.exists():
        return True  # nothing enrolled yet
    blob = json.loads(VERIFIER_PATH.read_text("utf-8"))
    try:
        plain = store.unseal(blob, pass_key)
    except store.StoreError:
        return False
    ok = bytes(plain) == SENTINEL
    store.zero(plain)
    return ok


def ask_pass_key(cfg: dict, detail: str) -> bytes | None:
    """Prompt, derive, and confirm against the verifier."""
    phrase = prompt.ask("hsec - unlock secret store", detail)
    if not phrase:
        return None
    pass_key = store.derive_pass_key(phrase.encode("utf-8"), cfg)
    if not check_pass_key(pass_key):
        return None
    return pass_key


# --- commands --------------------------------------------------------------------


def cmd_init(args) -> int:
    store.STORE_DIR.mkdir(parents=True, exist_ok=True)
    store.BLOB_DIR.mkdir(parents=True, exist_ok=True)

    cfg = (
        store.load_config()
        if store.CONFIG_PATH.exists()
        else store.default_config()
    )

    with tpm.Provider(cfg["provider"]) as prov:
        if not prov.is_hardware():
            return err(
                f"{cfg['provider']!r} does not report hardware backing. "
                "Refusing to create a key that would not be TPM-bound."
            )
        rng = prov.rsa_length_range()
        key = prov.open_key(cfg["tpm_key"])
        created = False
        if key is None:
            # Take the largest modulus this TPM actually offers, rather than
            # assuming one. TPM 2.0 only mandates RSA-2048.
            key = prov.create_key(cfg["tpm_key"], bits=tpm.negotiate_key_size(prov))
            created = True
        with key:
            if not key.private_export_is_blocked():
                return err(
                    "the TPM key's private half is exportable. Refusing to "
                    "continue; the machine-binding guarantee would not hold."
                )
            cfg["oaep_hash"] = tpm.negotiate_oaep_hash(key)
            cfg["rsa_bits"] = key.bit_length()
            ceiling = f", TPM max {rng[1]}" if rng else ""
            print(f"TPM key      : {cfg['tpm_key']} ({'created' if created else 'existing'})")
            print(f"provider     : {cfg['provider']} (hardware)")
            print(f"algorithm    : {key.algorithm()} {key.bit_length()} bits{ceiling}")
            print(f"OAEP hash    : {cfg['oaep_hash']} (round-trip verified)")
            print("private export blocked: True")

    store.save_config(cfg)
    if not store.MANIFEST_PATH.exists():
        store.save_manifest({})

    _harden_acl(store.STORE_DIR)
    store.audit("init", tpm_key=cfg["tpm_key"], oaep=cfg["oaep_hash"])
    print(f"\nstore        : {store.STORE_DIR}")
    if not VERIFIER_PATH.exists():
        print("passphrase   : not set (chosen when you enroll the first secret)")
    print("\nIMPORTANT: sealed blobs are unrecoverable if the TPM is cleared,")
    print("the motherboard is replaced, or Windows is reinstalled. Keep every")
    print("secret in your password manager too, and run `hsec backup`.")
    print("\nNext, from your own terminal:")
    print("  hsec add <name> --env <ENV_VAR>")
    return 0


def _write_verifier(pass_key: bytes, cfg: dict) -> None:
    import json

    header = store.seal(VERIFIER_NAME, SENTINEL, pass_key, cfg)
    VERIFIER_PATH.write_text(json.dumps(header, indent=2, sort_keys=True) + "\n", "utf-8")


def _harden_acl(path: Path) -> None:
    """Remove inherited ACEs and grant only the current user.

    Uses icacls rather than PowerShell; no admin rights are needed for objects
    you own.
    """
    sid = agent.current_user_sid()
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
            check=False, capture_output=True, text=True,
        )
    except FileNotFoundError:
        print("hsec: icacls not found; store ACL left at defaults", file=sys.stderr)


def cmd_add(args) -> int:
    cfg = store.load_config()
    name = store.validate_name(args.name)
    env_var = store.validate_env(args.env)
    man = store.load_manifest()

    if store.blob_path(name).exists() and not args.force:
        return err(f"secret {name!r} already exists; pass --force to replace")

    if not prompt.have_tty():
        return err(
            "enrollment must be run from your own terminal, not from an agent "
            "tool call. Open a shell and run: hsec add " + name + " --env " + env_var
        )

    import getpass

    value = getpass.getpass(f"Value for {name} ({env_var}): ")
    again = getpass.getpass("Re-enter value: ")
    if value != again:
        return err("values did not match")
    if len(value) < store.MIN_SECRET_LEN:
        return err(
            f"secret is shorter than {store.MIN_SECRET_LEN} characters. Short "
            "values make output scrubbing destructive, so they are refused."
        )

    first_time = not VERIFIER_PATH.exists()
    if first_time:
        print(
            "\nNo store passphrase set yet. Choose one now; this is the second "
            "factor,\nand the TPM alone cannot decrypt without it."
        )
    phrase = getpass.getpass("Store passphrase: ")
    if first_time:
        if len(phrase) < 10:
            return err("passphrase too short; use at least 10 characters")
        if phrase != getpass.getpass("Re-enter store passphrase: "):
            return err("passphrases did not match")
    pass_key = store.derive_pass_key(phrase.encode("utf-8"), cfg)
    if first_time:
        _write_verifier(pass_key, cfg)
        print("store passphrase set (verifier sealed)")
    elif not check_pass_key(pass_key):
        return err("wrong store passphrase")

    header = store.seal(name, value.encode("utf-8"), pass_key, cfg)
    import json

    store.BLOB_DIR.mkdir(parents=True, exist_ok=True)
    store.blob_path(name).write_text(
        json.dumps(header, indent=2, sort_keys=True) + "\n", "utf-8"
    )
    man[name] = {"env": env_var, "description": args.description or ""}
    store.save_manifest(man)
    _harden_acl(store.STORE_DIR)
    store.audit("add", name=name, env=env_var)
    print(f"sealed {name!r} -> {env_var}")
    print(f"use: hsec run --name {name} -- <command>")
    return 0


def cmd_list(args) -> int:
    # Raises if the store is missing. Without this, a wrong HSEC_STORE or a
    # store that moved would print "no secrets enrolled", which reads as an
    # empty store rather than the wrong one.
    store.load_config()
    man = store.load_manifest()
    if not man:
        print("no secrets enrolled. Add one with: hsec add <name> --env VAR")
        return 0
    width = max(len(n) for n in man)
    print(f"{'NAME'.ljust(width)}  {'ENV VAR'.ljust(24)}  DESCRIPTION")
    for name in sorted(man):
        entry = man[name]
        exists = store.blob_path(name).exists()
        flag = "" if exists else "  [BLOB MISSING]"
        print(
            f"{name.ljust(width)}  {entry['env'].ljust(24)}  "
            f"{entry.get('description', '')}{flag}"
        )
    return 0


def cmd_rm(args) -> int:
    man = store.load_manifest()
    name = store.validate_name(args.name)
    path = store.blob_path(name)
    if not path.exists() and name not in man:
        return err(f"no secret named {name!r}")
    if path.exists():
        path.unlink()
    man.pop(name, None)
    store.save_manifest(man)
    store.audit("rm", name=name)
    print(f"removed {name!r}")
    return 0


# --- the agent-facing wrapper ----------------------------------------------------


def _exec_with_secrets(
    secrets: dict[str, bytes], env_map: dict[str, str], command: list[str]
) -> tuple[int, bytes, bytes, int]:
    """Run `command` with secrets in the environment only, then scrub output.

    The value is never placed on the command line, so it cannot appear in any
    process listing.
    """
    child_env = dict(os.environ)
    for name, value in secrets.items():
        child_env[env_map[name]] = value.decode("utf-8")

    proc = subprocess.run(command, env=child_env, capture_output=True)
    out, hits_o = store.scrub(proc.stdout, secrets)
    errb, hits_e = store.scrub(proc.stderr, secrets)
    return proc.returncode, out, errb, hits_o + hits_e


def cmd_run(args) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return err("no command given. Usage: hsec run --name X -- <command>")

    cfg = store.load_config()
    man = store.load_manifest()
    names = [store.validate_name(n.strip()) for n in args.name.split(",") if n.strip()]
    for n in names:
        if n not in man:
            return err(f"unknown secret {n!r}. Run: hsec list")

    secrets: dict[str, bytearray] = {}
    pass_key: bytes | None = None
    try:
        for n in names:
            got = agent.unseal_via_agent(n)
            if got is None:
                if pass_key is None:
                    detail = (
                        f"Command requesting access:\n  {' '.join(command[:6])}\n\n"
                        f"Secret(s): {', '.join(names)}"
                    )
                    pass_key = ask_pass_key(cfg, detail)
                    if pass_key is None:
                        return err("unlock canceled or wrong passphrase")
                got = store.unseal(store.load_blob(n), pass_key)
                store.audit("unseal", name=n, via="direct")
            secrets[n] = got

        env_map = {n: man[n]["env"] for n in names}
        plain = {n: bytes(v) for n, v in secrets.items()}
        rc, out, errb, hits = _exec_with_secrets(plain, env_map, command)
    except store.StoreError as exc:
        return err(str(exc))
    except FileNotFoundError:
        return err(f"command not found: {command[0]}")
    finally:
        for buf in secrets.values():
            store.zero(buf)

    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(errb)
    sys.stderr.buffer.flush()
    store.audit(
        "run", names=names, command=command[0], exit_code=rc, redactions=hits
    )
    return rc


# --- session agent ---------------------------------------------------------------


def cmd_agent(args) -> int:
    if args.action == "serve":
        return agent.serve_main()

    if args.action == "status":
        st = agent.status()
        if not st:
            print("agent: not running")
            return 1
        left = int(st["expires_at"] - time.time())
        print(f"agent: running, expires in {left // 60}m{left % 60}s")
        return 0

    if args.action == "stop":
        print("agent: stopped" if agent.stop() else "agent: not running")
        return 0

    if args.action == "start":
        if agent.is_running():
            print("agent: already running")
            return 0
        cfg = store.load_config()
        pass_key = ask_pass_key(cfg, "Unlock the hsec store for this session")
        if pass_key is None:
            return err("unlock canceled or wrong passphrase")

        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "agent", "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
        # The key travels on stdin, never argv or the environment.
        proc.stdin.write(store.b64e(pass_key).encode("ascii") + b"\n")
        proc.stdin.flush()
        proc.stdin.close()

        for _ in range(50):
            if agent.is_running():
                ttl = int(cfg["agent_ttl_seconds"]) // 3600
                print(f"agent: started (pid {proc.pid}), unlocked for {ttl}h")
                return 0
            time.sleep(0.1)
        return err("agent failed to start")

    return err(f"unknown agent action {args.action!r}")


# --- verification ----------------------------------------------------------------


def cmd_verify(args) -> int:
    import json

    cfg = store.load_config()
    checks: list[tuple[str, bool, str]] = []

    def check(label, fn):
        try:
            ok, note = fn()
        except Exception as exc:
            ok, note = False, f"{type(exc).__name__}: {exc}"
        checks.append((label, ok, note))

    prov = tpm.Provider(cfg["provider"])
    key = prov.open_key(cfg["tpm_key"])
    if key is None:
        return err(f"TPM key {cfg['tpm_key']!r} not found. Run: hsec init")

    check("1  TPM key is hardware-backed",
          lambda: (key.is_hardware(), f"impl_type=0x{prov.impl_type():08X}"))
    check("2  private key non-exportable",
          lambda: (key.private_export_is_blocked(), "both private blob exports refused"))
    check("3  OAEP round-trip through TPM",
          lambda: (tpm.negotiate_oaep_hash(key) == cfg["oaep_hash"], cfg["oaep_hash"]))

    # Everything below runs in memory with a throwaway passphrase, so the real
    # store is never mutated and no prompt is needed.
    tmp_pass = store.derive_pass_key(b"verify-only-passphrase", cfg)
    blob = store.seal("verify-probe", SENTINEL, tmp_pass, cfg)

    check("4  seal/unseal round-trip",
          lambda: (bytes(store.unseal(blob, tmp_pass)) == SENTINEL, "sentinel matched"))

    def wrong_pass():
        bad = store.derive_pass_key(b"not-the-passphrase", cfg)
        try:
            store.unseal(blob, bad)
            return False, "decrypted with the wrong passphrase"
        except store.StoreError:
            return True, "rejected with authentication failure"

    check("5  wrong passphrase rejected", wrong_pass)

    def corrupt_seed():
        bad = json.loads(json.dumps(blob))
        raw = bytearray(store.b64d(bad["tpm"]["wrapped_seed"]))
        raw[0] ^= 0xFF
        bad["tpm"]["wrapped_seed"] = store.b64e(bytes(raw))
        try:
            store.unseal(bad, tmp_pass)
            return False, "unsealed despite a corrupted TPM wrap"
        except Exception as exc:
            return True, f"failed at the TPM step ({type(exc).__name__})"

    check("6  TPM factor required", corrupt_seed)

    def aad_binding():
        bad = json.loads(json.dumps(blob))
        bad["name"] = "someone-elses-secret"
        try:
            store.unseal(bad, tmp_pass)
            return False, "header tampering went undetected"
        except store.StoreError:
            return True, "renaming the blob breaks authentication"

    check("7  header tampering detected", aad_binding)

    def injection():
        code = "import os;print('present' if os.environ.get('HSEC_VERIFY')else'missing')"
        rc, out, errb, _ = _exec_with_secrets(
            {"probe": SENTINEL}, {"probe": "HSEC_VERIFY"}, [sys.executable, "-c", code]
        )
        return out.strip() == b"present", out.strip().decode() or errb.decode()[:60]

    check("8  env injection reaches the child", injection)

    def scrubbing():
        code = (
            "import os,base64,urllib.parse as u;v=os.environ['HSEC_VERIFY'];"
            "print(v);print('hdr: Bearer '+v);print(base64.b64encode(v.encode()).decode());"
            "print(u.quote(v,safe=''))"
        )
        rc, out, errb, hits = _exec_with_secrets(
            {"probe": SENTINEL}, {"probe": "HSEC_VERIFY"}, [sys.executable, "-c", code]
        )
        leaked = SENTINEL in out or SENTINEL in errb
        b64_leak = store.b64e(SENTINEL).encode() in out
        return (
            not leaked and not b64_leak and hits >= 4,
            f"{hits} redactions, raw leak={leaked}, base64 leak={b64_leak}",
        )

    check("9  output scrubbing catches all encodings", scrubbing)

    def audit_clean():
        if not store.LOG_PATH.exists():
            return True, "no log yet"
        data = store.LOG_PATH.read_bytes()
        return SENTINEL not in data, f"{len(data.splitlines())} entries scanned"

    check("10 audit log contains no secret values", audit_clean)

    key.close()
    prov.close()

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"[{mark}] {label.ljust(width)}  {note}")
    print()
    if failed:
        print(f"{failed} of {len(checks)} checks FAILED")
        return 1
    print(f"all {len(checks)} checks passed")
    print("\nFor the end-to-end path (agent, wrapper, argv leakage), run:")
    print("  uv run --script integration_test.py")
    print(f"\nNot automatable here: cross-machine binding. Copy {store.STORE_DIR}")
    print("to another machine and confirm unseal fails at the TPM step.")
    return 0


# --- housekeeping ----------------------------------------------------------------


def cmd_backup(args) -> int:
    """Copy the store to a second location.

    The store already lives outside the repository, so this is not about git.
    It guards against accidental deletion, which matters because sealed blobs
    are unrecoverable. Copies stay TPM- and passphrase-sealed, so they add no
    exposure - but they are no help against losing the TPM itself, since every
    blob is bound to this machine either way.
    """
    dest_root = Path(args.dest) if args.dest else store.ROOT.parent / ".hsec-backups"
    stamp = store.utcnow().replace(":", "").replace("-", "")
    dest = dest_root / f"hsec-{stamp}"
    if not store.STORE_DIR.exists():
        return err("nothing to back up; store not initialized")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(store.STORE_DIR, dest)
    _harden_acl(dest_root)
    store.audit("backup", dest=str(dest))
    print(f"backed up to {dest}")
    print("Note: this protects against `git clean -xdf` and accidental deletion.")
    print("It does NOT protect against TPM loss - blobs remain machine-bound.")
    return 0


def cmd_log(args) -> int:
    store.load_config()  # same reason as cmd_list: fail loudly on a wrong path
    if not store.LOG_PATH.exists():
        print("no audit log yet")
        return 0
    lines = store.LOG_PATH.read_text("utf-8").splitlines()
    for line in lines[-args.number :]:
        print(line)
    return 0


# --- CLI -------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hsec", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the TPM key and initialize the store")

    a = sub.add_parser("add", help="enroll a secret (interactive, human only)")
    a.add_argument("name")
    a.add_argument("--env", required=True, help="environment variable to inject as")
    a.add_argument("--description", default="")
    a.add_argument("--force", action="store_true", help="replace an existing secret")

    sub.add_parser("list", help="list secret names and env vars")

    r = sub.add_parser("rm", help="remove a sealed secret")
    r.add_argument("name")

    run = sub.add_parser("run", help="run a command with secrets injected")
    run.add_argument("--name", required=True, help="secret name, or comma-separated list")
    run.add_argument("command", nargs=argparse.REMAINDER)

    ag = sub.add_parser("agent", help="session agent")
    ag.add_argument("action", choices=["start", "status", "stop", "serve"])

    sub.add_parser("verify", help="self-test the security properties")

    b = sub.add_parser("backup", help="copy the store outside the repo")
    b.add_argument("dest", nargs="?")

    lg = sub.add_parser("log", help="tail the audit trail")
    lg.add_argument("-n", "--number", type=int, default=20)

    return p


def main() -> int:
    args = build_parser().parse_args()
    handlers = {
        "init": cmd_init, "add": cmd_add, "list": cmd_list, "rm": cmd_rm,
        "run": cmd_run, "agent": cmd_agent, "verify": cmd_verify,
        "backup": cmd_backup, "log": cmd_log,
    }
    try:
        return handlers[args.cmd](args)
    except store.StoreError as exc:
        return err(str(exc))
    except tpm.TpmError as exc:
        return err(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
