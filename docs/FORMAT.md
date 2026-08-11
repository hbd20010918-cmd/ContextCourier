# ContextCourier archive format v1

Status: stable for ContextCourier `0.1.x`.

## Goals

- Human-readable first contact through `CONTEXT.md`.
- Machine-verifiable integrity through a canonical manifest.
- Generated metadata contains no project-root absolute path, Git remote URL,
  original-secret hash, random identifier, or wall-clock timestamp. Selected project text
  remains project-controlled and may contain ordinary paths, URLs, names, and dates.
- Deterministic bytes for identical normalized inputs, policy, Git state, and tool version.
- Safe inspection of an untrusted archive without extraction.

## Required layout

```text
CONTEXT.md
MANIFEST.json
REDACTIONS.md
adapters/AGENTS.md
adapters/CLAUDE.md
adapters/IMPORT_PROMPT.md
adapters/cursor-context.mdc
files/<normalized project-relative path>  # zero or more source entries
```

ZIP directory entries are not emitted. The six generated handoff entries above are
required even when no source file is selected; `files/` itself is therefore not an archive
entry. `MANIFEST.json` is the only entry not listed in its own `entries` array. Every other
entry must be listed exactly once. Extra, missing, or unknown generated entries make
verification fail.

## Manifest shape

The compact field-shape example below abbreviates hashes and omits the six required
generated-entry records, so it is explanatory rather than a directly verifiable manifest.

```json
{
  "format": "contextcourier",
  "schema_version": 1,
  "tool": {"name": "contextcourier", "version": "0.1.0"},
  "project": {
    "name": "example",
    "git": {
      "available": true,
      "branch": "main",
      "commit": "012345...",
      "dirty": true
    },
    "languages": {"Python": 1},
    "metadata_redactions": {}
  },
  "policy": {
    "archive_compression": "stored",
    "include_untracked": true,
    "max_file_size": 1048576,
    "max_files": 5000,
    "max_total_size": 26214400,
    "secret_policy": "redact",
    "text_encoding": "UTF-8",
    "text_newlines": "LF"
  },
  "entries": [
    {
      "kind": "source",
      "path": "files/src/app.py",
      "source_path": "src/app.py",
      "source_size": 110,
      "size": 128,
      "sha256": "...",
      "redactions": {"GENERIC_SECRET": 1}
    }
  ],
  "totals": {
    "candidate_files": 2,
    "excluded_by_reason": {"binary_extension": 1},
    "packed_bytes": 128,
    "source_bytes": 110,
    "redactions": 1,
    "redactions_by_kind": {"GENERIC_SECRET": 1},
    "source_files": 1
  },
  "warnings": []
}
```

`sha256` hashes the bytes stored in the archive after UTF-8/LF normalization and redaction.
No hash of an original secret-bearing file is stored.

`source_bytes` is the sum of selected files before text normalization and redaction;
`packed_bytes` is the sum after those transformations. Both totals are checked separately
against `policy.max_total_size`. `project.metadata_redactions` counts secret matches removed
from archive-visible project, branch, or path metadata. `totals.redactions_by_kind` and
`totals.redactions` combine those metadata counts with all source-entry `redactions` maps.
`candidate_files` must equal `source_files` plus all `excluded_by_reason` counts.

ContextCourier 0.1.0 writers always emit `project.metadata_redactions` and
`totals.source_bytes`. For compatibility with early schema-v1 packs, readers also accept
either field as absent: missing metadata counts behave as `{}`, while a missing
`source_bytes` disables only that explicit total comparison. Per-entry `source_size` values
are still summed and enforced against `policy.max_total_size`.

## Hard safety ceilings

Policy values may be lower, but neither configuration nor a verified v1 manifest may exceed:

| Resource | Hard ceiling |
|---|---:|
| One original source file | 8 MiB |
| Original selected source bytes | 48 MiB |
| Packed selected source bytes | 48 MiB |
| Selected source files | 10,000 |
| Candidate paths considered by the scanner | 100,000 |
| Finished archive | 64 MiB |
| `MANIFEST.json` | 2 MiB |
| ZIP entries, including `MANIFEST.json` | 10,010 |
| ZIP central directory | 8 MiB |

The scanner enforces the original-source and packed-byte budgets independently. Inspection
and verification also reject Zip64 and multi-disk archives before reading the manifest.

## Path rules

- UTF-8 names normalized to Unicode NFC.
- POSIX `/` separators only.
- No absolute paths, empty components, `.` or `..` components, NUL, backslashes, control
  characters, surrogates, or bidirectional override/isolate characters.
- Two paths that collide after NFC plus Unicode case folding are invalid.
- Symlinks, junctions, submodule directories, devices, sockets, and other non-regular files
  are not packed.

## Deterministic ZIP rules

- Entries sorted by case-folded name, then exact name.
- `ZIP_STORED` only; no data compression.
- For each stored entry, compressed size must equal uncompressed size.
- Entry timestamp fixed to `1980-01-01 00:00:00`.
- `create_system = 3`; the upper 16 external-attribute bits are exactly Unix regular-file
  mode `0100644` (`S_IFREG | 0644`).
- Only the ZIP UTF-8 filename flag may be set; encryption and all other flags are rejected.
- No directory entries, per-entry comments, extra fields, archive comment, or trailing data.
- Generated JSON uses sorted keys, UTF-8, two-space indentation, and a final LF.
- Generated Markdown uses UTF-8 and LF.

The CLI prints the SHA-256 of the finished archive. The outer hash is deliberately not
stored inside the archive.

## Verification contract

`ctxcourier verify` rejects:

- archives larger than 64 MiB or more than 10,010 entries;
- manifests larger than 2 MiB;
- encrypted, compressed, directory, duplicate, unsafe, or normalization-colliding entries;
- unsupported format/schema versions;
- invalid manifest field types, entry sets, sizes, or SHA-256 values;
- incomplete required adapter layout, missing entries, extra entries, and content tampering;
- policy or totals above the hard ceilings, and inconsistent candidate, byte, file, or
  redaction totals.

`ctxcourier inspect` only reads and summarizes the bounded manifest. It always reports
`Integrity: NOT_VERIFIED` and must not be treated as verification.

## Compatibility

- Patch and minor releases may add optional manifest fields.
- A reader must ignore unknown optional keys but must reject an unknown `schema_version`.
- A breaking layout or verification change requires a new integer schema version.
