# hsec

TPM-sealed secret store for agent API access on Windows.

API keys are encrypted at rest under **two independent factors** — the
machine's TPM and a passphrase — and a coding agent can *use* a secret without
ever *seeing* it. `hsec run` injects the value into a child process's
environment and scrubs every representation of it out of the child's output
before returning.

```console
$ hsec run --name github -- gh api /user --verbose
> Authorization: Bearer [REDACTED:github]
{"login":"octocat", ...}
```

The token reached the command. It never reached the transcript.

---

## Read this first: recovery

**Sealed blobs are permanently unrecoverable if the TPM is cleared, the
motherboard is replaced, or Windows is reinstalled.** The RSA private key lives
inside the TPM and cannot be exported or backed up — that is the whole point,
and it is also the risk.

`hsec` is a *convenience and containment* layer, never the system of record.

1. Keep every secret in your password manager as well.
2. Run `hsec backup` after enrolling anything.

---

## Why this exists

Coding agents need credentials to call APIs, and every usual answer leaks them.
A key in `.env`, in a config file, in shell history, or pasted into chat ends up
in a transcript that persists on disk and in a model's context window.

`hsec` separates *using* a credential from *seeing* it. The agent names a
secret; the wrapper does the rest.

---

## Requirements

- Windows with a TPM 2.0 exposed through the **Microsoft Platform Crypto
  Provider** (standard on Windows 10/11 business hardware)
- [`uv`](https://docs.astral.sh/uv/)
- **No administrator rights.** The key is a per-user TPM key

Dependencies are declared inline (PEP 723) and resolved by `uv` on first run.
There is exactly one: `cryptography`. Everything Windows-specific — CNG, the
named pipe and its DACL, the GUI prompt — goes through `ctypes`.

**No PowerShell.** `hsec` talks to CNG directly via `ncrypt.dll`, so there is
no certificate store, no CMS, no `New-SelfSignedCertificate`, and nothing to
code-sign. This matters in environments where script-signing policy makes
`.ps1` files painful to deploy.

---

## Installation

```console
git clone git@github.com:OMRF/hsec.git
cd hsec
./hsec.cmd init
```

`init` creates a non-exportable, decrypt-only RSA key inside the TPM, sets up
the store, and tightens its ACL to your SID alone. It is idempotent, and it
refuses to continue if the provider does not report hardware backing or if the
private key turns out to be exportable.

Expected output:

```
TPM key      : hsec-v1 (created)
provider     : Microsoft Platform Crypto Provider (hardware)
algorithm    : RSA 2048 bits, TPM max 2048
OAEP hash    : SHA256 (round-trip verified)
private export blocked: True

store        : ...\.hsec
```

To put `hsec` on your `PATH`, add the checkout directory to it, or create a
shim pointing at `hsec.cmd`. The examples below assume `hsec` resolves.

### Where the store lives

By default the store is `.hsec`, a sibling of the checkout — deliberately
*outside* the repository. A tool's working tree is the wrong place for user
data: `git clean -xdf` deletes ignored directories, deleting and re-cloning
destroys them, and archiving the repo would carry the store along.

```
<parent>/
  hsec/         this repository
  .hsec/        the store, ACL'd to you alone
  .hsec-backups/
```

`HSEC_STORE` relocates it, for tests and for keeping more than one store. It
changes *where* the store lives, never *whether* both factors are required.

---

## Usage

### Enroll a secret

Run this **from your own terminal** — it refuses to run non-interactively, so
an agent cannot enroll on your behalf:

```console
$ hsec add github --env GITHUB_TOKEN --description "GitHub PAT, repo scope"
Value for github (GITHUB_TOKEN): ********
Re-enter value: ********
Store passphrase: ********
sealed 'github' -> GITHUB_TOKEN
```

The first `add` is where you choose the store passphrase. Values are prompted,
never taken as arguments, so they stay out of shell history and out of any
process listing.

### Unlock for a session

```console
$ hsec agent start
agent: started (pid 24601), unlocked for 8h
```

The agent holds the passphrase-derived key **in memory only** — nothing at rest
to steal — and serves a named pipe whose DACL grants your SID alone. It exits
on TTL expiry or `hsec agent stop`.

### Run commands

```console
hsec run --name github -- gh api /user
hsec run --name github,openai -- python deploy.py
hsec run --name aws -- terraform apply
```

If no agent is running, `hsec run` puts a passphrase dialog on your desktop
naming the secret and the requesting command, then times out.

### Track when a credential expires

Bearer tokens usually expire, and an expired one surfaces as a confusing `401`
from the far end rather than an obvious error. `hsec` records an optional
expiry per secret and warns before you hit that.

If the secret is a JWT, enrollment reads the `exp` claim automatically:

```console
$ hsec add awn-key --env AWN_API_KEY
...
detected JWT expiry: 2027-08-27T03:37:28+00:00
```

Otherwise set it yourself, or attach one to a secret enrolled earlier:

```console
hsec add gh-token --env GITHUB_TOKEN --expires 2027-01-15
hsec expiry gh-token --set 2027-01-15
hsec expiry awn-key --detect     # read the exp claim (needs one unlock)
hsec expiry awn-key --clear
```

`hsec list` then shows the remaining life, flagging anything expired or inside
the warning window:

```
NAME       ENV VAR       EXPIRES               DESCRIPTION
awn-key    AWN_API_KEY   2027-08-27 (363d)     Arctic Wolf PAK
gh-token   GITHUB_TOKEN  2026-09-10 (13d LEFT) GitHub PAT
old-key    LEGACY_TOKEN  2026-01-01 (EXPIRED)  retire me
```

and `hsec run` warns on **stderr** before running, so the warning never
pollutes the command's stdout:

```
hsec: WARNING old-key expired 240 days ago (2026-01-01)
```

The window defaults to 30 days; set `expiry_warn_days` in `config.json` to
change it.

Only the `exp` claim is read from a JWT — no other claim is decoded, logged, or
displayed, so recording an expiry never widens what anyone learns about the
secret. Expiry lives in `manifest.json` and is therefore **not** authenticated,
unlike the sealed blob headers. That is deliberate: it is a reminder, not an
enforcement mechanism, and anyone able to forge it could equally delete the
store. `hsec` never refuses to run on an expired secret; it tells you and
proceeds.

### Everything else

| Command | Purpose |
|---|---|
| `hsec list` | names, env vars, and expiry — never values |
| `hsec expiry <name>` | show, `--set`, `--clear`, or `--detect` an expiry |
| `hsec rm <name>` | remove a sealed secret |
| `hsec log -n 50` | audit trail |
| `hsec backup [dir]` | copy the store to a second location |
| `hsec verify` | self-test the security properties |
| `hsec agent status\|stop` | manage the session agent |

---

## Why RSA, and why 2048

`hsec` uses **RSA only** and never generates elliptic-curve keys. Two reasons,
and the second is the important one.

**RSA is sufficient here.** The TPM key does exactly one job: wrap a 32-byte
random seed. That is a textbook RSA-OAEP key-encapsulation use. ECC would need
ECDH plus a KDF to accomplish the same thing, with no benefit at this size.

**Elliptic curve on a TPM carries avoidable risk.** A broad range of TPM
firmware is affected by [ADV190024][adv] (TPM-FAIL, CVE-2019-11090 and
CVE-2019-16863), a timing side channel in **ECDSA nonce generation** that can
recover the private key from a few hundred signatures. RSA is unaffected.
Since the design gains nothing from ECC, using it would be taking on a known
class of firmware vulnerability for free. If you want to check your own
hardware, `tpmtool getdeviceinformation` reports whether the firmware is
affected.

[adv]: https://msrc.microsoft.com/update-guide/vulnerability/ADV190024

**On key size:** `hsec` does not hardcode 2048. At `init` it asks the provider
for its supported modulus range and takes the largest of 4096, 3072, 2048 that
the hardware will actually create:

```python
negotiate_key_size(prov, preferred=(4096, 3072, 2048))
```

TPM 2.0 only *mandates* RSA-2048; 3072 and 4096 are optional, and many discrete
TPMs reject them outright — `NCryptSetProperty(Length)` fails with
`NTE_INVALID_PARAMETER`. On such a TPM you will get 2048 and `init` will print
the ceiling it found (`TPM max 2048`). On hardware that offers more, the same
code selects 4096 with no change.

RSA-2048 is not the security boundary here in any case. It wraps a 32-byte seed
that is useless without the passphrase-derived half of the key, and the seed
never leaves the TPM in plaintext. The realistic attack is not factoring the
modulus.

---

## How it works

```
seed         = os.urandom(32)
wrapped_seed = RSA-OAEP(tpm_public_key, seed)      # only this TPM unwraps
pass_key     = PBKDF2-HMAC-SHA256(passphrase, store_salt, 600_000)
aead_key     = HKDF-SHA256(ikm = seed || pass_key, salt = store_salt,
                           info = b"hsec|v1|" + name)
ciphertext   = AES-256-GCM(aead_key, nonce, plaintext, aad = header)
```

The TPM factor **gates** the passphrase factor. Someone holding the blob files
cannot even test a passphrase guess without first extracting `seed` from the
TPM, which requires code execution on that machine. Conversely, TPM access
alone yields nothing without the passphrase.

The whole blob header except the ciphertext is authenticated as GCM additional
data, so renaming a blob or editing its KDF parameters makes decryption fail
rather than silently change behavior.

The PBKDF2 salt is store-wide rather than per-secret. That is what lets the
session agent derive the key once and answer many requests — the entire point
of "prompt once per session." Per-secret key separation still holds: each blob
has its own random `seed` and its own HKDF `info`.

### Layout

```
hsec.py               CLI entry point (PEP 723)
hsec.cmd              shim: uv run --script hsec.py
tpm.py                CNG / TPM layer via ctypes
store.py              sealing, unsealing, scrubbing, audit
agent.py              session agent, named pipe + DACL
prompt.py             passphrase prompting (terminal or GUI)
integration_test.py   end-to-end test against a throwaway store
```

Store contents: `config.json` (TPM key name, OAEP hash, KDF salt, agent TTL),
`manifest.json` (name → env var, no values), `verifier.json` (sealed sentinel
used to reject a wrong passphrase), `store/<name>.json` (sealed blobs), and
`access.log`.

Commands other than `init` fail loudly when the store is missing, naming the
path they looked for, so a wrong `HSEC_STORE` reports the wrong path rather
than looking like an empty store.

---

## Threat model

**Protects against:** theft of the blob files, backups, disk images, or
cloud-synced copies. Blobs are useless on any other machine. Also protects
against offline passphrase brute-force, because the TPM gates the passphrase.

**Does not protect against:** an attacker with live code execution as you
*while the session agent is unlocked*. This is the same bar as `ssh-agent` and
is the accepted cost of "prompt once per session." It is bounded by the agent
TTL and every access is logged.

**Output scrubbing is the load-bearing control** for keeping secrets out of an
agent's context. Without it, one `curl -v`, one traceback, or one echoed error
body puts the token in the transcript. `hsec` matches the raw value plus its
URL-encoded, base64, url-safe-base64, JSON-escaped, and backslash-escaped
forms.

Secrets shorter than 6 characters are refused: scrubbing such a value would
mangle unrelated output.

### Known limitations

- Zeroing memory is best-effort. Python strings are immutable and the runtime
  may retain copies; `hsec` holds values in `bytearray` and overwrites them,
  but makes no stronger claim.
- Scrubbing cannot catch a secret the child splits across writes, transforms
  (for example hashes), or re-encodes in a form not listed above.
- A wrapped command that deliberately exfiltrates its own environment is not
  prevented. The audit log records what was accessed and by which command.
- The store's ACL protects against other users, not against an administrator
  or anything running as you.
- Blob size reveals the approximate length of each secret. AES-GCM ciphertext
  matches its plaintext length and `hsec` does not pad, so anyone able to read
  the store learns roughly how long a value is — though not the value, and not
  which service it belongs to beyond what `manifest.json` already says.

To report a security issue, see [SECURITY.md](SECURITY.md). Please do not open
a public issue for a vulnerability.

---

## Verification

```console
hsec verify                          # 10 property checks
uv run --script integration_test.py  # 15 end-to-end checks
```

`verify` proves the TPM key is hardware-backed and non-exportable, that the
OAEP round-trip works, that a wrong passphrase and a corrupted TPM wrap both
fail, that header tampering is detected, and that scrubbing catches every
encoding. It runs in memory against a throwaway passphrase and never mutates
the store.

`integration_test.py` drives the real CLI and the real named-pipe agent against
a temporary store, including a check that the secret never reaches the child's
command line.

The one property neither can check is cross-machine binding. To confirm it by
hand, copy the store to another machine and verify unseal fails at the TPM step.

---

## License

MIT. See [LICENSE](LICENSE).

`SPDX-License-Identifier: MIT`

This software is provided as is, without warranty of any kind. It is a
containment layer for credentials, not a guarantee — read the threat model and
known limitations above before relying on it.
