# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not as public GitHub issues.

Use GitHub's [private vulnerability reporting][pvr] on this repository —
**Security → Report a vulnerability**. That opens an advisory visible only to
the maintainers.

[pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Helpful things to include:

- what you can do that you should not be able to do
- steps to reproduce
- Windows version, TPM manufacturer and firmware version, and the `hsec` commit

This is a small project maintained on a best-effort basis, with no guaranteed
response window. We would much rather hear about something uncertain than not
hear about it. We ask for coordinated disclosure: please give us a reasonable
chance to ship a fix before publishing.

## Supported versions

`main` only. There are no maintained release branches.

## In scope

Broadly, anything that breaks a property the README claims:

- Recovering a sealed secret without **both** the TPM and the passphrase
- Extracting the TPM private key — or getting it created as exportable or
  software-backed while `init` still reports success
- Making `hsec run` emit a secret that scrubbing should have caught
- Getting a secret onto a command line, into the audit log, or into any file
- Reaching the session agent's named pipe as another user, or persuading the
  agent to hand out the derived key rather than a single unsealed value
- Forging or tampering with a blob header in a way that decryption accepts
- Privilege escalation, or code execution triggered by store contents

## Out of scope

These are documented design limits, not vulnerabilities. Each is described in
the README's threat model, and reports about them will be closed as working as
intended:

- **Access while the agent is unlocked.** Anything running as you can ask the
  unlocked agent to unseal a secret. This is the `ssh-agent` model and the
  stated cost of "prompt once per session." It is bounded by the agent TTL and
  recorded in the audit log.
- **A wrapped command exfiltrating its own environment.** `hsec` hands the
  secret to a process you named; it cannot police what that process then does
  with it.
- **Scrubbing missing a transformed value** — a secret the child hashes,
  splits across writes, or re-encodes in a form not listed in the README.
  Scrubbing is a strong mitigation, not a guarantee.
- **Best-effort memory zeroing.** Python may retain copies; `hsec` overwrites
  `bytearray` buffers and deliberately claims nothing stronger.
- **Administrators.** An administrator, or anything already running as you, is
  outside what the store ACL can protect against.
- **Loss of the TPM.** Blobs are unrecoverable by design if the TPM is cleared
  or the machine is replaced. That is the guarantee working, not a bug.

## TPM firmware issues

Vulnerabilities in TPM firmware itself — ADV190024 (TPM-FAIL) and similar — are
vendor issues rather than `hsec` issues. Report those to your TPM vendor or
hardware OEM. `hsec` never generates elliptic-curve keys specifically to avoid
that class of problem; see the README for the reasoning.
