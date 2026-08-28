"""Store layout, sealing/unsealing, audit log, and output scrubbing.

Crypto design
-------------
Two independent factors, with the TPM factor gating the passphrase factor so
the passphrase can never be attacked offline:

    seed         = os.urandom(32)
    wrapped_seed = RSA-OAEP(tpm_public_key, seed)     # only this TPM unwraps
    pass_key     = PBKDF2-HMAC-SHA256(passphrase, store_salt, iters)
    aead_key     = HKDF-SHA256(ikm = seed || pass_key, salt = store_salt,
                               info = b"hsec|v1|" + name)
    ciphertext   = AES-256-GCM(aead_key, nonce, plaintext, aad = header)

An attacker holding the blob files cannot even test a passphrase guess without
first extracting `seed` from the TPM, which requires code execution on this
machine. Conversely, TPM access alone yields nothing without the passphrase.

The PBKDF2 salt is deliberately store-wide rather than per-secret. That lets
the session agent derive `pass_key` once and answer many unseal requests, which
is the entire point of "prompt once per session". Per-secret key separation
still holds: every blob has its own random `seed` and its own HKDF `info`.
"""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import tpm

# --- layout ---------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent

# The store lives BESIDE the checkout, never inside it. hsec is a repository
# that gets cloned, pushed, and archived, and a tool's working tree is the
# wrong place for the user's data: `git clean -xdf` deletes ignored
# directories, re-cloning destroys them, and zipping the repo to share it would
# carry the store along. Keeping it one level up makes all three impossible.
#
# HSEC_STORE relocates it, for tests and for keeping more than one store. It
# changes *where* the store lives, never *whether* both factors are required.
_STORE_OVERRIDE = os.environ.get("HSEC_STORE")
STORE_DIR = (
    Path(_STORE_OVERRIDE).resolve() if _STORE_OVERRIDE else ROOT.parent / ".hsec"
)
CONFIG_PATH = STORE_DIR / "config.json"
MANIFEST_PATH = STORE_DIR / "manifest.json"
BLOB_DIR = STORE_DIR / "store"
LOG_PATH = STORE_DIR / "access.log"

BLOB_VERSION = 1
HKDF_INFO_PREFIX = b"hsec|v1|"
DEFAULT_ITERS = 600_000
DEFAULT_TTL_SECONDS = 8 * 60 * 60
MIN_SECRET_LEN = 6

# A name we will happily use as a filename and as an HKDF label.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

_HASHES = {"SHA256": hashes.SHA256, "SHA1": hashes.SHA1}


class StoreError(RuntimeError):
    pass


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- config and manifest --------------------------------------------------------


def default_config() -> dict:
    return {
        "version": 1,
        "provider": tpm.PLATFORM_PROVIDER,
        "tpm_key": "hsec-v1",
        "oaep_hash": "SHA256",
        "kdf_salt": b64e(os.urandom(16)),
        "pbkdf2_iters": DEFAULT_ITERS,
        "agent_ttl_seconds": DEFAULT_TTL_SECONDS,
        "created": utcnow(),
    }


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise StoreError(
            f"store not initialized ({CONFIG_PATH} missing). Run: hsec init"
        )
    return json.loads(CONFIG_PATH.read_text("utf-8"))


def save_config(cfg: dict) -> None:
    _write_json(CONFIG_PATH, cfg)


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        return {}
    return json.loads(MANIFEST_PATH.read_text("utf-8"))


def save_manifest(man: dict) -> None:
    _write_json(MANIFEST_PATH, man)


def _write_json(path: Path, data: dict) -> None:
    """Write atomically so an interrupted write cannot truncate the store."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")
    tmp.replace(path)


def blob_path(name: str) -> Path:
    return BLOB_DIR / f"{name}.json"


def validate_name(name: str) -> str:
    if not NAME_RE.match(name):
        raise StoreError(
            f"invalid secret name {name!r}: use lowercase letters, digits, "
            "dot, dash, underscore; must start alphanumeric; max 64 chars"
        )
    return name


def validate_env(var: str) -> str:
    if not ENV_RE.match(var):
        raise StoreError(f"invalid environment variable name {var!r}")
    return var


# --- key derivation -------------------------------------------------------------


def derive_pass_key(passphrase: bytes, cfg: dict) -> bytes:
    """The expensive half. Cached in memory by the session agent."""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64d(cfg["kdf_salt"]),
        iterations=int(cfg["pbkdf2_iters"]),
    ).derive(passphrase)


def _derive_aead_key(seed: bytes, pass_key: bytes, salt: bytes, name: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO_PREFIX + name.encode("utf-8"),
    ).derive(seed + pass_key)


def _canonical_aad(header: dict) -> bytes:
    """Authenticate every header field except the ciphertext itself, so that
    tampering with the name, the TPM key reference, or the KDF parameters makes
    decryption fail rather than silently changing behavior."""
    shadow = json.loads(json.dumps(header))
    shadow["aead"].pop("ct", None)
    return json.dumps(shadow, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _oaep(hash_name: str) -> padding.OAEP:
    h = _HASHES[hash_name]()
    return padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None)


# --- seal / unseal --------------------------------------------------------------


def seal(name: str, plaintext: bytes, pass_key: bytes, cfg: dict) -> dict:
    validate_name(name)
    with tpm.Provider(cfg["provider"]) as prov:
        key = prov.open_key(cfg["tpm_key"])
        if key is None:
            raise StoreError(
                f"TPM key {cfg['tpm_key']!r} not found in {cfg['provider']!r}. "
                "Run: hsec init"
            )
        with key:
            pub = key.public_key()

    seed = os.urandom(32)
    salt = b64d(cfg["kdf_salt"])
    wrapped = pub.encrypt(seed, _oaep(cfg["oaep_hash"]))
    aead_key = _derive_aead_key(seed, pass_key, salt, name)
    nonce = os.urandom(12)

    header = {
        "v": BLOB_VERSION,
        "name": name,
        "created": utcnow(),
        "kdf": {
            "alg": "pbkdf2-sha256",
            "salt": cfg["kdf_salt"],
            "iters": int(cfg["pbkdf2_iters"]),
        },
        "tpm": {
            "provider": cfg["provider"],
            "key": cfg["tpm_key"],
            "oaep": cfg["oaep_hash"],
            "wrapped_seed": b64e(wrapped),
        },
        "aead": {"alg": "AES-256-GCM", "nonce": b64e(nonce)},
    }
    ct = AESGCM(aead_key).encrypt(nonce, plaintext, _canonical_aad(header))
    header["aead"]["ct"] = b64e(ct)
    return header


def unwrap_seed(blob: dict) -> bytes:
    """Recover the per-blob seed. Requires this physical TPM."""
    t = blob["tpm"]
    with tpm.Provider(t["provider"]) as prov:
        key = prov.open_key(t["key"])
        if key is None:
            raise StoreError(
                f"TPM key {t['key']!r} not found. This blob was sealed on a "
                "different machine or the TPM has been cleared."
            )
        with key:
            return key.decrypt_oaep(b64d(t["wrapped_seed"]), t.get("oaep", "SHA256"))


def unseal(blob: dict, pass_key: bytes) -> bytearray:
    """Return plaintext as a bytearray so callers can zero it after use."""
    seed = unwrap_seed(blob)
    name = blob["name"]
    salt = b64d(blob["kdf"]["salt"])
    aead_key = _derive_aead_key(seed, pass_key, salt, name)
    try:
        plain = AESGCM(aead_key).decrypt(
            b64d(blob["aead"]["nonce"]),
            b64d(blob["aead"]["ct"]),
            _canonical_aad(blob),
        )
    except InvalidTag as exc:
        raise StoreError(
            "authentication failed: wrong passphrase, or the blob header was "
            "tampered with"
        ) from exc
    return bytearray(plain)


def load_blob(name: str) -> dict:
    path = blob_path(validate_name(name))
    if not path.exists():
        raise StoreError(f"no sealed secret named {name!r}. Run: hsec list")
    return json.loads(path.read_text("utf-8"))


def zero(buf: bytearray) -> None:
    """Best effort. Python offers no guarantee that no copy survives, and we
    do not pretend otherwise; this just avoids leaving the obvious copy around."""
    for i in range(len(buf)):
        buf[i] = 0


# --- output scrubbing -----------------------------------------------------------


def secret_variants(value: bytes) -> list[bytes]:
    """Every encoding of the secret we can reasonably expect a child process to
    emit. Verbose HTTP clients, JSON error bodies, and tracebacks all echo
    credentials in transformed shapes, so matching the raw bytes alone is not
    enough."""
    from urllib.parse import quote, quote_plus

    text = value.decode("utf-8", "replace")
    out = [
        value,
        quote(text, safe="").encode(),
        quote_plus(text).encode(),
        base64.b64encode(value),
        base64.b64encode(value).rstrip(b"="),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        json.dumps(text)[1:-1].encode(),
        text.encode("unicode_escape"),
    ]
    seen, uniq = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def scrub(data: bytes, secrets: dict[str, bytes]) -> tuple[bytes, int]:
    """Replace every representation of every secret with a redaction marker.

    This is the control that makes "the agent never sees the value" actually
    true, rather than depending on the agent to avoid careless commands.
    Returns the cleaned bytes and the number of redactions made.
    """
    hits = 0
    for name, value in secrets.items():
        # ASCII deliberately: the marker must render identically whether the
        # consumer's console is UTF-8 or a legacy code page. A UTF-8 marker
        # turns into mojibake under cp1252, which is the last thing you want
        # in the one piece of output that proves redaction happened.
        marker = f"[REDACTED:{name}]".encode("ascii")
        for variant in sorted(secret_variants(value), key=len, reverse=True):
            if variant in data:
                hits += data.count(variant)
                data = data.replace(variant, marker)
    return data, hits


# --- audit ----------------------------------------------------------------------


def audit(event: str, **fields) -> None:
    """Append one line per access. Never contains secret values."""
    record = {"ts": utcnow(), "event": event, "pid": os.getpid(), **fields}
    line = json.dumps(record, sort_keys=True) + "\n"
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line)
