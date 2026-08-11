<p align="center">
  <img src="docs/assets/hero.svg" alt="ContextCourier — carry project context safely across AI accounts" width="100%">
</p>

<p align="center">
  <a href="https://github.com/hbd20010918-cmd/ContextCourier/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hbd20010918-cmd/ContextCourier/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/hbd20010918-cmd/ContextCourier/releases"><img alt="GitHub release" src="https://img.shields.io/github/v/release/hbd20010918-cmd/ContextCourier"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-7c5cff"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-42b883">
  <img alt="zero runtime dependencies" src="https://img.shields.io/badge/runtime%20dependencies-0-59e1ff">
</p>

<p align="center">
  <strong>Local-first · deterministic · secret-aware · vendor-neutral</strong><br>
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="docs/ACCOUNT_SWITCHING.md">Account-switching guide</a> ·
  <a href="docs/FORMAT.md">Format specification</a> ·
  <a href="SECURITY.md">Security</a>
</p>

ContextCourier creates a portable, redacted, verifiable snapshot of a software project.
Use it when you switch ChatGPT/Codex accounts, hand work to another coding agent, or need
an inspectable project brief without uploading your repository to a new service.

It does **not** scrape private app databases or pretend to migrate server-side chat history.
Instead, it carries the part you can safely own and verify: project files, Git state, task
documents, decisions, integrity hashes, and ready-to-use agent instructions.

## Why ContextCourier?

Most repo-to-prompt tools optimize for getting source text into a model. ContextCourier
optimizes for **continuity and trust**:

- **Switch accounts without starting from zero.** Upload one handoff archive and give the
  new account a consistent project snapshot.
- **No API key and no network calls.** Scanning, redaction, packing, and verification run
  entirely on your machine.
- **Secret-aware by default.** Known credential containers, private keys, account folders,
  binaries, dependencies, caches, and build output are excluded. High-confidence tokens in
  text are replaced before the archive is written.
- **Deterministic output.** Stable ordering, canonical UTF-8/LF text, fixed ZIP metadata, and
  `ZIP_STORED` make identical inputs produce identical bytes.
- **Verify before trust.** `MANIFEST.json` records every included entry's size and SHA-256;
  `ctxcourier verify` rejects traversal paths, duplicates, unsupported compression, missing
  entries, and content tampering.
- **Works across agents.** Each pack includes import prompts plus generated `AGENTS.md`,
  `CLAUDE.md`, and Cursor rule adapters.

## Quick start

Python 3.11+ is required and Git is recommended for exact repository/ignore semantics.
There are no runtime Python package dependencies; without Git, ContextCourier uses a
clearly labelled best-effort directory fallback.

```bash
# Install the current GitHub release
python -m pip install "git+https://github.com/hbd20010918-cmd/ContextCourier.git@v0.1.0"

cd your-project

# 1. Add an explicit local policy (optional but recommended)
ctxcourier init

# 2. Preview what will be selected and redacted
ctxcourier scan .

# 3. Create the handoff archive
ctxcourier pack .

# 4. Verify it before importing or sharing
ctxcourier verify your-project.contextcourier.zip
```

Then switch to the new AI account or tool, upload the `.contextcourier.zip` file, and use
the prompt from `adapters/IMPORT_PROMPT.md`:

```text
Treat this ContextCourier archive as a read-only project handoff. Read CONTEXT.md and
MANIFEST.json first. Use files/ as a redacted snapshot, preserve the documented project
state and task intent, and verify assumptions against the live checkout before editing.
Never try to reconstruct values marked CONTEXTCOURIER_REDACTED.
```

See the full [account-switching guide](docs/ACCOUNT_SWITCHING.md).

## What moves — and what does not

| Carried in the archive | Deliberately not migrated |
|---|---|
| Selected project text and working files | Server-side ChatGPT/Codex conversations |
| `README`, `AGENTS.md`, task and decision docs | Account identity, login state, or billing |
| Git branch, commit, and dirty-state flag | Git remotes or embedded credentials |
| Redacted source snapshot | `.env`, private keys, auth databases, app sessions |
| Manifest, hashes, redaction report, adapters | Binary assets, dependencies, caches, builds |

The original account remains the owner of its private tasks. ContextCourier preserves
project continuity without depending on undocumented product internals.

## CLI

```text
ctxcourier init [PATH] [--force] [--json]
ctxcourier scan [PATH] [--tracked-only] [--fail-on-secret] [LIMIT OPTIONS] [--json]
ctxcourier pack [PATH] [-o OUTPUT] [--force] [--tracked-only] [--fail-on-secret]
                [LIMIT OPTIONS] [--json]
ctxcourier inspect ARCHIVE [--json]
ctxcourier verify ARCHIVE [--json]
```

Useful safety controls:

```bash
# Abort instead of writing an archive when any secret match is found
ctxcourier pack . --fail-on-secret

# Exclude all untracked work
ctxcourier pack . --tracked-only

# Tune bounded input limits
ctxcourier scan . --max-file-size 512KiB --max-total-size 10MiB --max-files 2000

# Stable machine-readable output for scripts and CI
ctxcourier verify project.contextcourier.zip --json
```

Exit codes are stable: `0` success, `2` arguments/config, `3` secret-policy refusal,
`4` verification failure, and `5` Git/filesystem/operational failure.

## Archive layout

```text
project.contextcourier.zip
├── CONTEXT.md                    # human-first project handoff
├── MANIFEST.json                 # schema, policy, sizes, SHA-256 hashes
├── REDACTIONS.md                 # detector counts, never original values
├── adapters/
│   ├── AGENTS.md
│   ├── CLAUDE.md
│   ├── cursor-context.mdc
│   └── IMPORT_PROMPT.md
└── files/                        # selected UTF-8/LF, redacted project snapshot
```

The manifest intentionally does not hash itself. It hashes every other archive entry.
The CLI prints the SHA-256 of the finished archive for external comparison. Read the
[format specification](docs/FORMAT.md) for the v1 contract.

## Privacy and security model

ContextCourier applies three layers before writing a pack:

1. Git-native discovery respects `.gitignore`, `.git/info/exclude`, and global Git excludes.
   For privacy, even an already tracked file is excluded if it now matches an ignore rule.
2. Immutable path rules exclude common credential containers and unsafe file types. A
   `.contextcourierignore` rule can exclude more, but cannot re-include anything.
3. High-confidence content detectors redact common OpenAI, GitHub, AWS, Google, Slack,
   Stripe, JWT, authorization-header, URL-credential, private-key, and generic secret forms.

Secret detection is heuristic, not a formal guarantee. Review the archive before sharing,
prefer `--fail-on-secret` in CI, and rotate any credential you believe was exposed. See the
full [threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md).

## Configuration

`ctxcourier init` creates `.contextcourier.toml`:

```toml
[contextcourier]
max_file_size = 1048576
max_total_size = 26214400
max_files = 5000
include_untracked = true
```

It also creates a deny-only `.contextcourierignore`. `!` re-inclusion rules are rejected so
a local exclusion cannot accidentally be undone.

Configurable limits cannot exceed the v1 hard ceilings: 8 MiB per source file, 48 MiB each
for original source bytes and packed bytes, 10,000 selected files, and 100,000 candidate
paths. Verification independently bounds the archive and manifest; see the
[format specification](docs/FORMAT.md).

## Design choices

- Standard-library Python keeps the trusted runtime surface small.
- Git is used for exact ignore semantics; a clearly labelled best-effort fallback exists
  for ordinary directories.
- UTF-8 text is normalized to LF. Unknown encodings and binary data are skipped rather than
  guessed.
- Generated metadata does not collect the project-root absolute path, OS account identity,
  wall-clock time, Git remote URL, or a hash of the original secret-bearing source. Normal
  project text can contain non-secret paths, names, dates, and URLs, so review the pack.
- ZIP entries are stored, not compressed, to support reproducible bytes across platforms.

## Development

```bash
git clone https://github.com/hbd20010918-cmd/ContextCourier.git
cd ContextCourier
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
ctxcourier pack . --fail-on-secret
```

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), review the
[roadmap](docs/ROADMAP.md), and use a synthetic secret fixture—never a real credential.

## Prior art

ContextCourier is a clean-room implementation inspired by the low-friction UX of
[Repomix](https://github.com/yamadashy/repomix),
[Gitingest](https://github.com/coderamp-labs/gitingest),
[code2prompt](https://github.com/mufeedvh/code2prompt), and
[files-to-prompt](https://github.com/simonw/files-to-prompt), plus the security mindset of
[detect-secrets](https://github.com/Yelp/detect-secrets) and
[Secretlint](https://github.com/secretlint/secretlint). No source code or branding was
copied. See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).

## License

[MIT](LICENSE) © 2026 hbd20010918-cmd
