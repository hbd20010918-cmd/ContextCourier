# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | Yes |
| Earlier/unreleased snapshots | No |

## Reporting a vulnerability

Please use GitHub's private **Security → Report a vulnerability** flow for this repository.
Do not open a public Issue for a secret leak, path escape, verification bypass, or archive
resource-exhaustion bug.

Include:

- affected ContextCourier version and operating system;
- the smallest synthetic reproduction you can provide;
- expected versus observed behavior;
- whether any real credential may have been exposed (do not include its value);
- suggested remediation, if known.

We aim to acknowledge reports within 72 hours, provide an initial assessment within seven
days, and coordinate disclosure after a fix is available. These are targets, not guarantees.

## If a credential may have escaped

Revoke or rotate it immediately at its provider. Deleting an archive or applying redaction
after sharing does not invalidate a credential. ContextCourier does not retain or transmit
telemetry that can be used to recover the archive.

## Scope notes

Secret detection is heuristic. A missed unknown token without a bypass of a documented
detector may be a feature request rather than a vulnerability. Path escape, original-value
logging, unsafe defaults, tamper-verification bypass, and a detector that transforms a secret
without removing it are security issues.
