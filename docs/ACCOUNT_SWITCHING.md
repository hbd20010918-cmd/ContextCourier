# Switching AI accounts without losing project continuity

ContextCourier transfers a safe project handoff. It does not transfer ownership of a
server-side chat, subscription, login session, or account-private task.

## Before signing out of the old account

1. Save important decisions and next steps in ordinary project files. ContextCourier gives
   first priority to `PROJECT_CONTEXT.md`, `TASK_QUEUE.md`, `HANDOFF.md`, `AGENTS.md`,
   `CLAUDE.md`, `README*`, `CHANGELOG*`, and package manifests.
2. From the project root, create policy templates once:

   ```bash
   ctxcourier init
   ```

3. Add any extra private paths to `.contextcourierignore`. This file is deny-only; `!`
   re-inclusion rules are rejected.
4. Preview the pack:

   ```bash
   ctxcourier scan .
   ```

5. Create and verify it:

   ```bash
   ctxcourier pack .
   ctxcourier verify project-name.contextcourier.zip
   ```

6. Review `CONTEXT.md`, `REDACTIONS.md`, and `MANIFEST.json` in the ZIP. If the project is
   especially sensitive, rerun with `--fail-on-secret` and do not share a pack that needs
   content redaction.

## After switching to the new account or tool

1. Open the same live project checkout, if available.
2. Upload the verified `.contextcourier.zip` as project material.
3. Paste `adapters/IMPORT_PROMPT.md`, or use this equivalent prompt:

   ```text
   Treat this ContextCourier archive as a read-only project handoff. Read CONTEXT.md and
   MANIFEST.json first. Use files/ as a redacted snapshot, preserve the documented project
   state and task intent, and verify assumptions against the live checkout before editing.
   Never try to reconstruct values marked CONTEXTCOURIER_REDACTED.
   ```

4. Ask the new agent to summarize the current goal, known decisions, open tasks, Git state,
   and first safe next step before it modifies anything.
5. Compare that summary with the old account's handoff. Correct gaps explicitly.

## Recommended project continuity files

ContextCourier works without special files, but these make handoffs much stronger:

- `PROJECT_CONTEXT.md`: purpose, architecture, constraints, decisions, and current state.
- `TASK_QUEUE.md`: ordered work, owners, acceptance criteria, blockers, and status.
- `CHANGELOG.md`: shipped behavior and compatibility changes.
- `HANDOFF.md`: one-time snapshot of what the next agent should do first.
- `AGENTS.md` or `CLAUDE.md`: durable coding and verification instructions.

Do not put passwords, tokens, private keys, personal account data, or raw chat exports in
these files.

## What to do when the old task says “thread not found”

That message normally means the current account cannot resolve that server-side task ID.
A ContextCourier pack cannot restore the missing remote object. It can give a new task the
project state needed to continue safely, which is why creating the pack before switching is
preferable.
