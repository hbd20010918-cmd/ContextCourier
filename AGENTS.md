# Agent instructions

These rules apply to AI-assisted changes in this repository.

1. Read `PROJECT_CONTEXT.md`, `TASK_QUEUE.md`, `SECURITY.md`, and the relevant source/tests.
2. Preserve zero Python runtime dependencies unless a reviewed design explicitly changes it.
3. Never add telemetry, uploads, private app-database readers, account-token handling, or
   silent conversation collection.
4. Safety rules are immutable. User configuration may exclude more but cannot re-include a
   credential container, unsafe path, non-regular file, or generated archive.
5. Do not place real or contiguous scanner-recognizable tokens in tests, docs, logs, commits,
   or Issues. Construct synthetic canaries at runtime.
6. `inspect` must never imply integrity; only `verify` may return `VERIFIED`.
7. Every source change requires relevant tests. Run the full unit suite and `compileall`.
8. Update `CHANGELOG.md` for shipped behavior and `TASK_QUEUE.md` for release-gate state.
9. Do not weaken account-migration disclaimers: ContextCourier transfers project context,
   not server-side chat ownership, login state, or subscriptions.
