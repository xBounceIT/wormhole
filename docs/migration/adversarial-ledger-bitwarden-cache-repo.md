# Adversarial ledger — Bitwarden credential cache SQLite repo

**Scope:** `rust/crates/wormhole-storage/src/repos/bitwarden_cache.rs`
(+ registration in `repos/mod.rs`, crate-root re-exports in `lib.rs`,
`wormhole-secrets-win` promoted dev-dep → regular dep in `Cargo.toml`);
integration tests in `tests/storage_tests.rs`.

**Out of scope:** live `bw` CLI spawn / sync; Bitwarden catalog service glue
(`BitwardenCredentialCatalogGlue` already closed in `adversarial-ledger-bitwarden-catalog.md`);
GPUI picker wiring.

**Compared against:** C# `IBitwardenCredentialCacheRepository` /
`BitwardenCredentialCacheRepository` (`Data/Repositories/`), migrations
`0014_bitwarden_credentials.sql` / `0015_bitwarden_credential_cache.sql`,
`BitwardenVirtualCredentialIds.EnsureIds` semantics.
Rust entry type reused: `wormhole_secrets_win::BitwardenCredentialCacheEntry`.

**Authority:** full adversarial-review-fix (parent-verified final battery)  
**Baseline:** wormhole-storage unit **24** / integration **63** green  
**Final:** wormhole-storage unit **24** / integration **71** green (8 new bitwarden registry tests)

**Attack focus:** C# normalization parity (trim / fallback / None vs empty / dedupe
last-wins / ordinal sort), full-sync stale delete incl. empty→delete-all, transaction
rollback on injected SQLite `RAISE` trigger, blank-ItemId drop, fake-vs-sqlite
divergence, timestamp round-trip (`.NET O` lenient parse), secret hygiene.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (24 + 71) |
| `cargo check -p wormhole-storage -p wormhole-secrets-win` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Finding / invariant | Fix |
|---|---|---|---|---|
| Issue cluster | P2 | Normalize | C# `Normalize` last-wins dedupe, ordinals, default-sync-time, Name-fallback verified against each C# branch | Regression tests pin every branch (trim, blank ItemId drop, timestamp defaults, ordinal sort, dedupe order) |
| Issue cluster | P2 | `ReplaceFromFullSyncAsync` | Stale delete semantics (empty → `DELETE FROM BitwardenCredentialCache;` vs `NOT IN`) in one tx, rollback on error | Tests: upsert+stale-delete, empty delete-all, RAISE-trigger rollback (row count unchanged) |
| Issue cluster | P3 | Timestamps | Microsoft.Data.Sqlite space form vs `.NET O`; cast both directions | `format_timestamp_o` writer; `parse_timestamp_o` lenient reader; raw-row round-trip test |
| Issue cluster | P3 | Fake repo | In-memory fake must match SQLite row semantics | `fake_repository_matches_sqlite_semantics` shared-scenario test |

### Simplify delta (post-adversarial)

S-01 rustfmt canonicalization of module layout (whitespace-only) — accepted.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Async API (`async fn`) | Crate convention is synchronous rusqlite repos (all other repos) |
| Move entry type to wormhole-storage | Canonical type already in secrets-win; storage imports it |
| New SQL migration | Schema 0014/0015 already embedded and applied by `MigrationRunner` |

---

## Test command

```powershell
cd rust
cargo test -p wormhole-storage
cargo check -p wormhole-storage -p wormhole-secrets-win
```

**Counts:** 8 new integration tests (`bitwarden_cache_*`); full storage suite **24 + 71**.