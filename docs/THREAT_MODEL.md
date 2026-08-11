# Threat model

## Assets

- Project source and internal documentation.
- Credentials accidentally present in a working tree.
- Local account paths and identity metadata.
- The integrity of a handoff imported by another AI account or tool.

## Threats in scope

1. A maintainer accidentally shares `.env`, private keys, auth files, cached sessions, or a
   recognizable token embedded in text.
2. A repository contains a symlink or junction that points outside the project.
3. A filename uses traversal, control characters, Unicode normalization collisions, or
   bidirectional controls to confuse the archive or terminal.
4. Files change while a snapshot is being read, producing a mixed handoff.
5. A received archive contains traversal paths, duplicates, extra files, tampered content,
   encryption, unsupported compression, or excessive resource claims.
6. Logs, exceptions, manifests, and test output leak a matched secret even when the packed
   file was redacted.
7. A previous ContextCourier archive is accidentally packed into the next archive.

## Controls

- Git-native file discovery plus privacy-first ignore checks for tracked files.
- Immutable credential-container, key, account-folder, dependency, cache, build, database,
  binary, and generated-archive exclusions.
- Deny-only `.contextcourierignore`; re-inclusion is rejected.
- Bounded policy files, ignore-rule count and match work, Git output, candidate paths, and
  total bytes read even when a candidate is ultimately skipped.
- `lstat`, symlink/junction rejection, resolved-root containment, and pre/post-read stat
  comparison.
- Unicode NFC path normalization, control/bidi rejection, and case-fold collision checks.
- High-confidence token and assignment redaction before any archive write.
- No original-secret value, original-source hash, snippet, project-root absolute path, Git
  remote, or wall-clock timestamp in the manifest.
- Atomic same-directory archive write and cleanup of failed temporary output.
- Stable `--fail-on-secret` refusal mode that writes no archive.
- Git lazy fetching, external protocols, submodule status recursion, inherited Git routing,
  tracing, and pathspec environment switches are disabled for discovery commands.
- Bounded, non-extracting inspection and stored-entry-only SHA-256 verification.
- Tests build synthetic credentials at runtime so repository secret scanners do not learn or
  expose real values.

## Non-goals

ContextCourier does not claim to:

- discover every unknown, encrypted, obfuscated, or custom secret;
- classify source-code licenses or malware;
- authenticate the publisher of an archive;
- control access after an archive is shared;
- securely erase data from storage media;
- migrate private ChatGPT/Codex/Claude/Cursor conversations or account state;
- make a redacted source snapshot safe for public release without human review.
- act as an operating-system sandbox against a privileged local process that can replace
  filesystem objects during a scan.

Future versions may add pluggable detectors and Sigstore attestations. These are not part of
the v1 security contract.

## Safe operating guidance

- Run `ctxcourier scan` and inspect project exclusions before packing.
- Use `--fail-on-secret` for CI and sensitive projects.
- Verify every received archive before reading its source entries.
- Keep the archive private unless the project itself is intended for public release.
- Rotate a credential if you believe it may have been exposed; redaction is not rotation.
