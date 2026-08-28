"""CNG / TPM key storage layer for the hsec secret store.

Talks to ncrypt.dll directly via ctypes so nothing here depends on the
certificate store, CMS, or PowerShell. The RSA private key is created inside
the TPM by the Microsoft Platform Crypto Provider and is non-exportable, so
sealed blobs are cryptographically bound to this physical machine.

Only RSA is used. Elliptic-curve keys are deliberately never generated: a range
of TPM firmware is affected by ADV190024 (TPM-FAIL), a timing side channel in
ECDSA nonce generation that can expose the private key. RSA is unaffected, and
RSA is all this design needs. See README.md.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

# --- provider / algorithm names -------------------------------------------------

PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"
SOFTWARE_PROVIDER = "Microsoft Software Key Storage Provider"
ALG_RSA = "RSA"

BLOB_RSAPUBLIC = "RSAPUBLICBLOB"
BLOB_RSAPRIVATE = "RSAPRIVATEBLOB"
BLOB_RSAFULLPRIVATE = "RSAFULLPRIVATEBLOB"

# --- properties -----------------------------------------------------------------

PROP_LENGTH = "Length"
PROP_LENGTHS = "Lengths"
PROP_EXPORT_POLICY = "Export Policy"
PROP_KEY_USAGE = "Key Usage"
PROP_IMPL_TYPE = "Impl Type"
PROP_ALGORITHM = "Algorithm Name"

# --- flags ----------------------------------------------------------------------

NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001
NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002

NCRYPT_PAD_OAEP_FLAG = 0x00000004
NCRYPT_SILENT_FLAG = 0x00000040
NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080

NCRYPT_IMPL_HARDWARE_FLAG = 0x00000001
NCRYPT_IMPL_SOFTWARE_FLAG = 0x00000002
NCRYPT_IMPL_REMOVABLE_FLAG = 0x00000008
NCRYPT_IMPL_HARDWARE_RNG_FLAG = 0x00000010

BCRYPT_RSAPUBLIC_MAGIC = 0x31415352  # 'RSA1'

# --- status codes we care about -------------------------------------------------

ERROR_SUCCESS = 0x00000000
NTE_EXISTS = 0x8009000F
NTE_BAD_KEYSET = 0x80090016
NTE_NOT_SUPPORTED = 0x80090029
NTE_NOT_FOUND = 0x80090011
NTE_PERM = 0x80090010
NTE_INVALID_PARAMETER = 0x80090027
NTE_BAD_FLAGS = 0x80090009

_STATUS_NAMES = {
    NTE_EXISTS: "NTE_EXISTS (key already exists)",
    NTE_BAD_KEYSET: "NTE_BAD_KEYSET (keyset does not exist)",
    NTE_NOT_SUPPORTED: "NTE_NOT_SUPPORTED",
    NTE_NOT_FOUND: "NTE_NOT_FOUND",
    NTE_PERM: "NTE_PERM (access denied)",
    NTE_INVALID_PARAMETER: "NTE_INVALID_PARAMETER",
    NTE_BAD_FLAGS: "NTE_BAD_FLAGS",
}


class TpmError(RuntimeError):
    """An ncrypt.dll call failed."""

    def __init__(self, fn: str, status: int):
        self.fn = fn
        self.status = status & 0xFFFFFFFF
        detail = _STATUS_NAMES.get(self.status, "")
        suffix = f" {detail}" if detail else ""
        super().__init__(f"{fn} failed: 0x{self.status:08X}{suffix}")


# --- ctypes bindings ------------------------------------------------------------

_nc = ctypes.WinDLL("ncrypt.dll")
_H = ctypes.c_void_p  # NCRYPT_*_HANDLE is ULONG_PTR
_PH = ctypes.POINTER(_H)
_PDW = ctypes.POINTER(wintypes.DWORD)


class NCRYPT_SUPPORTED_LENGTHS(ctypes.Structure):
    _fields_ = [
        ("dwMinLength", wintypes.DWORD),
        ("dwMaxLength", wintypes.DWORD),
        ("dwIncrement", wintypes.DWORD),
        ("dwDefaultLength", wintypes.DWORD),
    ]


class BCRYPT_OAEP_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", wintypes.LPCWSTR),
        ("pbLabel", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbLabel", wintypes.DWORD),
    ]


def _bind(name, argtypes):
    fn = getattr(_nc, name)
    fn.argtypes = argtypes
    fn.restype = ctypes.c_long
    return fn


_open_provider = _bind("NCryptOpenStorageProvider", [_PH, wintypes.LPCWSTR, wintypes.DWORD])
_create_key = _bind(
    "NCryptCreatePersistedKey",
    [_H, _PH, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD],
)
_open_key = _bind(
    "NCryptOpenKey", [_H, _PH, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
)
_set_prop = _bind(
    "NCryptSetProperty",
    [_H, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD],
)
_get_prop = _bind(
    "NCryptGetProperty",
    [_H, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, _PDW, wintypes.DWORD],
)
_finalize = _bind("NCryptFinalizeKey", [_H, wintypes.DWORD])
_export = _bind(
    "NCryptExportKey",
    [_H, _H, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p,
     wintypes.DWORD, _PDW, wintypes.DWORD],
)
_decrypt = _bind(
    "NCryptDecrypt",
    [_H, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
     wintypes.DWORD, _PDW, wintypes.DWORD],
)
_delete_key = _bind("NCryptDeleteKey", [_H, wintypes.DWORD])
_free = _bind("NCryptFreeObject", [_H])


def _check(status: int, fn: str) -> None:
    if status != ERROR_SUCCESS:
        raise TpmError(fn, status)


def _get_dword_prop(handle: _H, prop: str) -> int:
    buf = ctypes.create_string_buffer(4)
    got = wintypes.DWORD(0)
    _check(
        _get_prop(handle, prop, ctypes.cast(buf, ctypes.c_void_p), 4, ctypes.byref(got), 0),
        f"NCryptGetProperty({prop})",
    )
    return int.from_bytes(buf.raw[:4], "little")


def _try_get_dword_prop(handle: _H, prop: str) -> int | None:
    """Like _get_dword_prop but returns None when the provider does not
    expose the property. The Platform Crypto Provider omits several that the
    software KSP supports, and that is not an error."""
    try:
        return _get_dword_prop(handle, prop)
    except TpmError as exc:
        if exc.status == NTE_NOT_SUPPORTED:
            return None
        raise


def _get_str_prop(handle: _H, prop: str) -> str | None:
    need = wintypes.DWORD(0)
    status = _get_prop(handle, prop, None, 0, ctypes.byref(need), 0)
    if status & 0xFFFFFFFF == NTE_NOT_SUPPORTED:
        return None
    _check(status, f"NCryptGetProperty({prop}) size")
    buf = ctypes.create_string_buffer(need.value)
    got = wintypes.DWORD(0)
    _check(
        _get_prop(handle, prop, ctypes.cast(buf, ctypes.c_void_p), need.value,
                  ctypes.byref(got), 0),
        f"NCryptGetProperty({prop})",
    )
    return buf.raw[: got.value].decode("utf-16-le").rstrip(chr(0))


def _set_dword_prop(handle: _H, prop: str, value: int) -> None:
    buf = ctypes.create_string_buffer(value.to_bytes(4, "little"), 4)
    _check(
        _set_prop(handle, prop, ctypes.cast(buf, ctypes.c_void_p), 4, 0),
        f"NCryptSetProperty({prop})",
    )


class Key:
    """A persisted RSA key living inside the TPM."""

    def __init__(self, handle: _H, name: str, provider: "Provider"):
        self._h = handle
        self.name = name
        self.provider = provider
        self.provider_name = provider.name

    # -- introspection ----------------------------------------------------------

    def impl_type(self) -> int | None:
        """Implementation flags. This is a *provider* property; the Platform
        Crypto Provider does not expose it on individual key handles."""
        return self.provider.impl_type()

    def is_hardware(self) -> bool:
        """True when the provider backing this key is hardware.

        Together with private_export_is_blocked(), this is what proves we are
        really on the TPM and not silently on the software KSP, which would
        void the machine-binding guarantee.
        """
        it = self.impl_type()
        return bool(it and it & NCRYPT_IMPL_HARDWARE_FLAG)

    def bit_length(self) -> int:
        return _get_dword_prop(self._h, PROP_LENGTH)

    def algorithm(self) -> str | None:
        return _get_str_prop(self._h, PROP_ALGORITHM)

    def export_policy(self) -> int | None:
        """0 means non-exportable. None means the provider does not expose the
        property, which the TPM does not; rely on private_export_is_blocked()."""
        return _try_get_dword_prop(self._h, PROP_EXPORT_POLICY)

    # -- public key -------------------------------------------------------------

    def public_blob(self) -> bytes:
        need = wintypes.DWORD(0)
        _check(
            _export(self._h, None, BLOB_RSAPUBLIC, None, None, 0, ctypes.byref(need), 0),
            "NCryptExportKey(size)",
        )
        buf = ctypes.create_string_buffer(need.value)
        got = wintypes.DWORD(0)
        _check(
            _export(
                self._h, None, BLOB_RSAPUBLIC, None,
                ctypes.cast(buf, ctypes.c_void_p), need.value, ctypes.byref(got), 0,
            ),
            "NCryptExportKey",
        )
        return buf.raw[: got.value]

    def public_numbers(self) -> tuple[int, int]:
        """Parse BCRYPT_RSAKEY_BLOB into (e, n)."""
        blob = self.public_blob()
        magic, bitlen, cb_exp, cb_mod, cb_p1, cb_p2 = (
            int.from_bytes(blob[i : i + 4], "little") for i in range(0, 24, 4)
        )
        if magic != BCRYPT_RSAPUBLIC_MAGIC:
            raise TpmError(f"public blob magic 0x{magic:08X} != RSA1", 0)
        exp = int.from_bytes(blob[24 : 24 + cb_exp], "big")
        mod = int.from_bytes(blob[24 + cb_exp : 24 + cb_exp + cb_mod], "big")
        return exp, mod

    def public_key(self):
        """Return the public half as a `cryptography` RSAPublicKey."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        e, n = self.public_numbers()
        return rsa.RSAPublicNumbers(e, n).public_key()

    def private_export_is_blocked(self) -> bool:
        """Confirm the private key genuinely cannot leave the TPM.

        Returns True when every private blob export is refused. A False here
        means the key is exportable and the whole design is void.
        """
        for blob_type in (BLOB_RSAPRIVATE, BLOB_RSAFULLPRIVATE):
            need = wintypes.DWORD(0)
            status = _export(self._h, None, blob_type, None, None, 0, ctypes.byref(need), 0)
            if status == ERROR_SUCCESS:
                return False
        return True

    # -- the operation the whole store depends on -------------------------------

    def decrypt_oaep(self, ciphertext: bytes, hash_alg: str = "SHA256") -> bytes:
        pad = BCRYPT_OAEP_PADDING_INFO(hash_alg, None, 0)
        cbuf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
        flags = NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG

        need = wintypes.DWORD(0)
        _check(
            _decrypt(
                self._h, ctypes.cast(cbuf, ctypes.c_void_p), len(ciphertext),
                ctypes.byref(pad), None, 0, ctypes.byref(need), flags,
            ),
            "NCryptDecrypt(size)",
        )
        out = ctypes.create_string_buffer(need.value)
        got = wintypes.DWORD(0)
        _check(
            _decrypt(
                self._h, ctypes.cast(cbuf, ctypes.c_void_p), len(ciphertext),
                ctypes.byref(pad), ctypes.cast(out, ctypes.c_void_p), need.value,
                ctypes.byref(got), flags,
            ),
            "NCryptDecrypt",
        )
        return out.raw[: got.value]

    # -- lifecycle --------------------------------------------------------------

    def delete(self) -> None:
        _check(_delete_key(self._h, 0), "NCryptDeleteKey")
        self._h = None  # handle is freed by NCryptDeleteKey

    def close(self) -> None:
        if self._h:
            _free(self._h)
            self._h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Provider:
    """Handle to a CNG key storage provider."""

    def __init__(self, name: str = PLATFORM_PROVIDER):
        self.name = name
        h = _H()
        _check(_open_provider(ctypes.byref(h), name, 0), "NCryptOpenStorageProvider")
        self._h = h

    def impl_type(self) -> int | None:
        return _try_get_dword_prop(self._h, PROP_IMPL_TYPE)

    def is_hardware(self) -> bool:
        it = self.impl_type()
        return bool(it and it & NCRYPT_IMPL_HARDWARE_FLAG)

    def rsa_length_range(self) -> tuple[int, int, int, int] | None:
        """(min, max, increment, default) RSA modulus sizes this provider
        supports, or None if it does not report them.

        Queried on an unfinalized key handle, which is where CNG exposes the
        property. An unfinalized key is never persisted, so freeing the handle
        leaves nothing behind.
        """
        import os as _os

        probe = "hsec-lengths-probe-" + _os.urandom(4).hex()
        h = _H()
        if _create_key(self._h, ctypes.byref(h), ALG_RSA, probe, 0, 0) != ERROR_SUCCESS:
            return None
        try:
            buf = ctypes.create_string_buffer(ctypes.sizeof(NCRYPT_SUPPORTED_LENGTHS))
            got = wintypes.DWORD(0)
            status = _get_prop(
                h, PROP_LENGTHS, ctypes.cast(buf, ctypes.c_void_p),
                ctypes.sizeof(NCRYPT_SUPPORTED_LENGTHS), ctypes.byref(got), 0,
            )
            if status != ERROR_SUCCESS:
                return None
            s = ctypes.cast(buf, ctypes.POINTER(NCRYPT_SUPPORTED_LENGTHS)).contents
            return (s.dwMinLength, s.dwMaxLength, s.dwIncrement, s.dwDefaultLength)
        finally:
            _free(h)

    def open_key(self, key_name: str) -> Key | None:
        h = _H()
        status = _open_key(self._h, ctypes.byref(h), key_name, 0, NCRYPT_SILENT_FLAG)
        if status & 0xFFFFFFFF in (NTE_BAD_KEYSET, NTE_NOT_FOUND):
            return None
        _check(status, "NCryptOpenKey")
        return Key(h, key_name, self)

    def key_exists(self, key_name: str) -> bool:
        k = self.open_key(key_name)
        if k is None:
            return False
        k.close()
        return True

    def create_key(self, key_name: str, bits: int = 2048, overwrite: bool = False) -> Key:
        """Create a persisted, non-exportable, decrypt-only RSA key.

        RSA is deliberate: elliptic-curve keys are never generated here, because
        some TPM firmware is affected by ADV190024 (TPM-FAIL). See README.md.
        """
        h = _H()
        flags = NCRYPT_OVERWRITE_KEY_FLAG if overwrite else 0
        _check(
            _create_key(self._h, ctypes.byref(h), ALG_RSA, key_name, 0, flags),
            "NCryptCreatePersistedKey",
        )
        key = Key(h, key_name, self)
        try:
            _set_dword_prop(h, PROP_LENGTH, bits)
            # 0 = never allow the private key to be exported, in any form.
            _set_dword_prop(h, PROP_EXPORT_POLICY, 0)
            _set_dword_prop(h, PROP_KEY_USAGE, NCRYPT_ALLOW_DECRYPT_FLAG)
            _check(_finalize(h, NCRYPT_SILENT_FLAG), "NCryptFinalizeKey")
        except Exception:
            key.close()
            raise
        return key

    def close(self) -> None:
        if self._h:
            _free(self._h)
            self._h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def negotiate_key_size(
    prov: Provider, preferred: tuple[int, ...] = (4096, 3072, 2048)
) -> int:
    """Pick the largest RSA modulus this TPM will actually create.

    TPM 2.0 only mandates RSA-2048; 3072 and 4096 are optional and many
    discrete TPMs reject them outright. Rather than hardcoding a size, ask the
    provider for its supported range and take the best candidate that fits, so
    the same code gets 4096 on hardware that offers it.
    """
    rng = prov.rsa_length_range()
    if rng is None:
        return 2048
    lo, hi, inc, default = rng
    for bits in preferred:
        if lo <= bits <= hi and (inc == 0 or (bits - lo) % inc == 0):
            return bits
    return default or 2048


def negotiate_oaep_hash(key: Key, candidates: tuple[str, ...] = ("SHA256", "SHA1")) -> str:
    """Find an OAEP hash this TPM will actually decrypt with.

    Some TPMs restrict the OAEP mask hash. We probe with a real wrap/unwrap
    round-trip rather than trusting a capability flag, and the winner is
    recorded in each sealed blob so old blobs stay readable after a change.
    """
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    pub = key.public_key()
    probe = os.urandom(32)
    algs = {"SHA256": hashes.SHA256, "SHA1": hashes.SHA1}

    for name in candidates:
        h = algs[name]()
        try:
            ct = pub.encrypt(
                probe,
                padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None),
            )
            if key.decrypt_oaep(ct, name) == probe:
                return name
        except Exception:
            continue
    raise TpmError("no usable OAEP hash (tried " + ", ".join(candidates) + ")", 0)
