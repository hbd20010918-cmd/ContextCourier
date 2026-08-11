# Roadmap

The roadmap prioritizes verifiable continuity over automatic collection.

## v0.1 — trustworthy handoff core

- [x] Git-native tracked and safe-untracked discovery.
- [x] Immutable sensitive-path and binary exclusions.
- [x] High-confidence text redaction plus `--fail-on-secret`.
- [x] Deterministic stored ZIP and per-entry SHA-256 manifest.
- [x] Bounded `inspect` and strict `verify` commands.
- [x] Cross-agent import prompt, AGENTS.md, CLAUDE.md, and Cursor adapters.
- [x] English and Simplified Chinese account-switching guidance.
- [x] Windows, Linux, and macOS CI matrix.

## v0.2 — better handoff quality

- [ ] Explicit `HANDOFF.md` generator with a human approval gate.
- [ ] Structured task/decision schema that can be rendered into agent-specific files.
- [ ] `--include-profile` presets for docs-only, source, review, and incident handoffs.
- [ ] Token/size estimates without requiring an AI provider.
- [ ] Streaming scanner for very large repositories.
- [ ] Opt-in non-UTF-8 codecs with manifest-declared transcoding.

## v0.3 — extensible trust

- [ ] Detector plugin API and audited rulesets.
- [ ] Optional OSV/SBOM metadata that never uploads the project.
- [ ] Sigstore signing and publisher verification.
- [ ] Machine-readable JSON Schema published with compatibility fixtures.
- [ ] Optional import adapters for additional open coding agents.

## Explicitly out of scope

- Reading undocumented desktop-app databases.
- Copying authentication tokens or subscription state.
- Bypassing account ownership or access control.
- Quietly uploading source code to a hosted service.
