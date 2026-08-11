# Contributing

Thank you for improving trustworthy AI project handoffs.

## Before opening code

- Search existing Issues and the [roadmap](docs/ROADMAP.md).
- For behavior or format changes, open a focused Issue before a large implementation.
- For a suspected vulnerability or secret leak, follow [SECURITY.md](SECURITY.md) instead of
  opening a public Issue.

## Local setup

```bash
git clone https://github.com/hbd20010918-cmd/ContextCourier.git
cd ContextCourier
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
```

The runtime dependency count must remain zero unless a proposal demonstrates a clear safety
or correctness benefit.

## Pull request checklist

- Keep the change focused and backward-compatible with schema v1 when possible.
- Add tests for success, failure, and privacy boundaries.
- Use only synthetic secret fixtures assembled at runtime; never paste a real or
  scanner-recognizable credential into source.
- Ensure stdout/stderr, exceptions, manifests, and snapshots contain no matched values.
- Run the complete test suite and package smoke test.
- Update `CHANGELOG.md`, format/threat documentation, and compatibility notes when relevant.
- Confirm generated archives are not committed.

## Design principles

1. Explicit handoff beats invisible data collection.
2. A config option may narrow exposure but may never bypass immutable safety rules.
3. `inspect` and `verify` must remain distinct.
4. Archive integrity is not publisher authentication.
5. No claim is stronger than the tests and evidence supporting it.
