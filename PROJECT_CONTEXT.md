# Project context

## Purpose

ContextCourier helps developers continue a software project after changing AI coding tools,
accounts, or maintainers. It produces an explicit, local, redacted, deterministic, and
verifiable handoff archive.

## Product boundary

- The source of truth is the user's project checkout and its ordinary documentation.
- The tool never needs an AI API, hosted backend, browser session, or account credential.
- It does not read undocumented desktop-app databases or migrate server-side conversations.
- It must never imply that archive integrity proves publisher identity.
- Secret detection reduces accidental exposure but cannot certify public-release safety.

## Architecture

- `src/contextcourier/cli.py`: stable CLI, output, and exit codes.
- `src/contextcourier/gitrepo.py`: repository root, Git-native discovery, snapshot metadata.
- `src/contextcourier/ignore.py`: immutable exclusions and deny-only project rules.
- `src/contextcourier/scanner.py`: path safety, bounds, UTF-8/LF normalization, priority.
- `src/contextcourier/redact.py`: value-only high-confidence secret redaction.
- `src/contextcourier/archive.py`: generated handoff, deterministic ZIP, inspect, verify.
- `tests/`: unit, Git integration, reproducibility, redaction, and malicious archive cases.

## Durable decisions

1. Python 3.11+ standard library only at runtime.
2. Git is recommended for exact ignore semantics; non-Git scanning is a labelled fallback.
3. Archive source text is UTF-8/LF. Undecodable files are skipped, never guessed.
4. ZIP uses `ZIP_STORED`, fixed timestamps and modes, sorted entries, and no directory entries.
5. The manifest hashes every entry except itself and never stores original-secret hashes.
6. `.contextcourierignore` is deny-only; safety rules cannot be bypassed by configuration.
7. The default includes safe untracked work because continuity often depends on unfinished
   files; `--tracked-only` provides the narrower mode.
8. Import adapters are generated inside the archive and never overwrite live project rules.

## Acceptance gate for a release

- Full unit/integration suite passes.
- `compileall` and package build pass.
- Two packs from identical input have identical SHA-256.
- Synthetic canary secrets do not occur in raw archive bytes, output, or manifest.
- The built wheel installs into a clean environment and completes pack/verify smoke tests.
- Public documentation states the conversation/account migration boundary prominently.
