# Adversarial ledger — wormhole-ui connection-tree + settings VMs

Scope (ONLY):
- `rust/crates/wormhole-ui/` (`tree`, `settings` modules + related exports/tests)
- `docs/migration/17-tree-settings-vm.md`
- `docs/migration/README.md` (ledger link only)

Out of scope: GPUI chrome, connection-editor / quick-connect (except shared crate compile), C# production app, unrelated `wormhole-vnc` breakage.

Baseline (before review edits): `cargo test -p wormhole-ui` green; `cargo test -p wormhole-ui --features storage` green (no storage-adapter test yet). Context7 MCP unavailable; pins from workspace / `deps-pins.md`.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TSVM-001 | P1 | `settings/store.rs` `JsonFileSettingsStore` | No path confinement — `..` / arbitrary file names allowed | `new("…/../../Windows/settings.json")` would write outside intended root | **Fixed** — `in_directory` / `new` reject `..` and require `settings.json`; `confined_settings_path` |
| TSVM-002 | P1 | `settings/view_model.rs` `persist` | Immediate-persist save failure left mutated in-memory state | Attack: FailStore; UI ahead of disk with no rollback | **Fixed** — `commit` / `persist_or_rollback` restores prior snapshot |
| TSVM-003 | P2 | `JsonFileSettingsStore` | Missing process-local write lock (C# / storage have one) | Concurrent save/load on same path could tear | **Fixed** — `Mutex<()>` around load/migrate/save |
| TSVM-004 | P2 | `SettingsViewModel` `Debug` | Full `AppSettings` dump exposed paths / install-error strings | `format!("{:?}", vm)` included Bitwarden paths and `token=…` error text | **Fixed** — redacted Debug + regression |
| TSVM-005 | P2 | `tree/source.rs` storage feature | `StorageConnectionSource` ungated by regression | `--features storage` compiled but never exercised list→tree | **Fixed** — `storage_tests::storage_source_lists_inserted_nodes` |
| TSVM-006 | P2 | `tree/model.rs` orphans | Missing-parent nodes appended in `HashMap` iteration order | Unstable root order across runs | **Fixed** — stable SortOrder/Name/Uuid sort |
| TSVM-007 | P2 | Search cap / flatten | Cap counted but projection/flatten under-tested for DoS shape | Status text alone ≠ projection bound | **Fixed** — `search_cap_does_not_project_past_limit` (+ existing truncation test) |
| TSVM-008 | P2 | Case-insensitive search | Substring OrdinalIgnoreCase under-tested | Only full-name `LINUX`/`Linux` covered | **Fixed** — `search_substring_case_insensitive_mixed` + `name_matches_query_lower` |
| TSVM-009 | P2 | Expand restore | User-expanded folder outside last projection must survive clear | Nested search auto-expand must not clobber unrelated expand | **Fixed** — regression `clearing_search_restores_user_expanded_folder_not_in_last_projection` |
| TSVM-010 | P3 | Docs | Must not claim GPUI TreeView shipped | Attack on status/out-of-scope wording | **Fixed** — callout in `17-tree-settings-vm.md` + ledger link |
| TSVM-011 | P3 | `JsonFileSettingsStore` `Clone` | Clone minted a fresh write lock → concurrent writers on same path | Post-fix Clone impl | **Fixed** — removed `Clone`; share via `Arc` |
| TSVM-012 | — | Symlink escape past lexical confine | Canonicalize / symlink follow | Lexical `..` rejection only | **Rejected** — residual; same class as other lexical path guards |
| TSVM-013 | — | Atomic replace for `settings.json` | Crash mid-write | C# `WriteAllBytes` same | **Rejected** — parity |
| TSVM-014 | — | Remove `dirty` / `is_dirty` | Always false after rollback setters | Public API kept for future batch edits | **Rejected** — not worth churn |

## Fixes applied

- Path-confined `JsonFileSettingsStore` + write lock; no `Clone`
- Settings VM atomic immediate persist with rollback; redacted Debug
- Tree: stable orphans, search cap flatten bound, case-insensitive substring helper, expand-restore regression
- Storage feature adapter integration test
- Docs: explicit non-claim for GPUI TreeView; README ledger link

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TSVM-001…010 | Fixed; reset |
| Adv-2 | Reverse: Clone/lock → Debug → storage feature → orphan order → cap → restore | TSVM-011 (`Clone`) | Fixed; reset |
| Adv-3 | Forward lanes on post-fix surface | None | Clean (1/2) |
| Adv-4 | Reverse: secrets/Debug, path `..`, persist rollback, feature gate, docs GPUI claim | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `set_bool` → `commit` | Orphan sort without name clones | — | Yes → reset | Fixed |
| Sim-2 | `reapply_current_filter` shared by load/search | Avoid full `search_text` clone when only trim needed | — | Yes → reset | Fixed |
| Sim-3 | Align MemorySettingsStore poison handling with file store | — | Poison → `into_inner` | Yes → reset | Fixed |
| Sim-4 | — | — | Collapse redundant `load_or_default` error arms | Yes → reset | Fixed |
| Sim-5 | Reuse/dead API — reject remove `dirty` | Cap tests overlap — reject merge | Symlink/atomic — reject | None | Clean (1/3) |
| Sim-6 | Same lanes, settings→tree order | No hot-path I/O left | Diff hygiene | None | Clean (2/3) |
| Sim-7 | Same | Same | Docs/API surface ok | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `commit`/`reapply_current_filter`/orphan sort/mutex/`Err(_)` | None | Clean (1/2) |
| Adv-R2 | Reverse on final surface (path, Debug, storage test, expand restore, docs) | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui
cargo test -p wormhole-ui --features storage
```

Result: **pass** — default lib+integration green; `--features storage` includes `storage_source_lists_inserted_nodes`. Pre-existing unused `http_default_port` warning in connection-editor (out of scope). Unrelated `wormhole-vnc` ignored per brief.

## Residual notes

- Lexical path confinement does not follow symlinks (TSVM-012).
- `SettingsViewModel::is_dirty` stays false after successful immediate setters (rollback model); retained for API stability.