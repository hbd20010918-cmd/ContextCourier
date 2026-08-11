# Changelog

All notable changes to ContextCourier are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-11

### Added

- `init`, `scan`, `pack`, `inspect`, and `verify` commands.
- Git-native tracked/untracked discovery with privacy-first ignored-tracked exclusion.
- Immutable credential, key, account-folder, binary, dependency, cache, and build exclusions.
- Redaction for common token shapes, authorization values, URL credentials, private-key
  blocks, and generic secret assignments.
- `--fail-on-secret`, `--tracked-only`, bounded size/file controls, and JSON output.
- Deterministic, uncompressed ZIP format with canonical metadata and per-entry SHA-256.
- Non-extracting inspection and strict archive integrity verification.
- Generated CONTEXT, redaction report, universal prompt, AGENTS, CLAUDE, and Cursor adapters.
- English and Simplified Chinese account-switching documentation.
- Cross-platform CI and standard-library tests for tampering, traversal, reproducibility,
  secret canaries, configuration, Git privacy, and CLI flows.

[0.1.0]: https://github.com/hbd20010918-cmd/ContextCourier/releases/tag/v0.1.0
