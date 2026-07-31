# Adversarial review policy (migration)

After **each implementation deliverable** that changes production / spike code under `rust/` (crates, scripts, installer fragments wired to Rust), the parent agent must run **adversarial-review-fix** on that scope before treating the work as done.

## Process

1. Implementation subagent completes a scoped deliverable (domain, storage, secrets, surface, protocols, tunnels, …).
2. Parent launches adversarial-review-fix with:
   - exact paths / crate(s) in scope;
   - acceptance criteria from the migration plan + that subagent’s brief;
   - authority to edit and add regression tests inside the scope only.
3. Require skill gates: 2 clean adversarial cycles + full iterative-review-simplify (3 clean cycles) + verification (`cargo test` / `cargo check` for touched crates).
4. Write / update a ledger under `docs/migration/` (naming below) and add a one-line row to the [README ledger index](README.md#documents) when the review closes.
5. Only then mark the stream complete / merge into the “ready” baseline.

### Concurrency (optional parent note)

When many impl streams finish close together, the parent may queue or fan out adversarial reviews. As a soft ceiling, prefer **at most ~10 concurrent** adversarial-review-fix runs (and other parent subagents combined); above that, serialize or batch. This is a parent scheduling hint, not a hard product rule.

## When to skip

Adversarial-review-fix is **not** required for:

| Kind | Skip when |
|---|---|
| **Tests-only** | Diff is only new/updated tests (or test fixtures) with **no** production / spike source change. |
| **Docs-only** | Diff is only markdown / inventory under `docs/migration/` (or similar) with **no** executable claims that change runtime behavior. Spot-check factual contradictions with [native-surface-broker.md](native-surface-broker.md) still encouraged. |
| **Already-solid audits** | Scope was already closed in a ledger, and this deliverable makes **no** production / spike code change (e.g. README index sync, ledger typo, re-linking). Re-run if prod/spike code in that scope changes again. |

Still run adversarial when a “docs” or “tests” task quietly lands prod/spike edits, or when acceptance criteria / contracts change.

## Ledger naming

- File: `docs/migration/adversarial-ledger-<short-slug>.md`
- Slug: kebab-case, scope-specific (crate or feature), e.g. `adversarial-ledger-vnc-forwarder.md`, `adversarial-ledger-session-tabs.md`
- Prefer one ledger per closed review scope; append a delta slug (`…-delta.md`) only when a follow-up review is intentionally separate
- Index: keep the closed-review table in [README.md](README.md) in sync (do not invent rows for missing files)

## Out of scope for adversarial (unless they contain code)

- Pure inventory markdown with no executable claims that affect runtime (see **Docs-only** above).
- Unrelated .NET production code (do not mutate).
