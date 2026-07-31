# Adversarial ledger — Tree duplicate connection glue (`wormhole-ui` / `wormhole-storage`)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/tree/duplicate.rs` (+ re-exports in `tree/mod.rs` / crate root)
- `wormhole_domain::ConnectionNode::clone_as_new_identity`
- `wormhole_storage::ConnectionRepository::duplicate_connection` (+ `storage_tests` pin)
- Related unit tests (incl. `--features storage` glue)
- `docs/migration/17-tree-settings-vm.md` duplicate section; `20-connection-editor.md` Duplicate vs editor secret note; `03-storage.md` / `02-domain.md` / feature-matrix / README ledger link
- this ledger

Out of scope: GPUI context-menu chrome; recursive folder duplicate; CredMgr password copy (intentionally never); change-notifier publish inside glue (host); editor `save_validated_editor` Insert path.

**Attack focus:** missing source fail-closed; folder reject; identity clears (fingerprint / inline flag); no secret bodies in SQLite; shared pool id reuse; Fake apply drift (deleted source / kind change / id collision); sort saturation; source load errors; storage mapping.

Baseline (before review edits): implementation + focused tests drafted; first red was Debug assertion matching `use_inline_password` field name.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TD-001 | P2 | `duplicate_connection_storage` | `InvalidArgument` mapped via `contains("connection node")` | Other InvalidArgument strings could mis-map to `NotAConnection` | **Fixed** — exact `FOLDER_MSG` match |
| TD-002 | P2 | `no_password_body_*` test | Asserted `!debug.contains("password:")` | Failed on field name `use_inline_password` | **Fixed** — assert clears + no plaintext payload tokens |
| TD-003 | P2 | `apply_duplicate_memory` | Branched copy/paste paths for id keep vs mint | Drift risk / harder review | **Fixed** — unified rebuild → optional keep advertised id → collision check → append |
| TD-004 | P2 | tests | Kind drift / unicode / advertised id / stacked suffix under-pinned | Attack: source becomes folder; `ラボ`; keep built id after sibling insert | **Fixed** — focused regressions |
| TD-005 | — | Search gate on Duplicate | Reparent gates on `search_active`; Duplicate does not | C# `Duplicate` ignores `IsSearchActive` | **Rejected** — C# parity |
| TD-006 | — | Share `DUPLICATE_NAME_SUFFIX` into storage | Storage hardcodes `" (copy)"` | Avoid ui→storage dep | **Rejected** — intentional literal parity with C# |
| TD-007 | — | Copy CredMgr secret to new Id | Product might want password clone | Explicit non-goal; flag cleared; editor Insert is the secret path | **Rejected** — requirement: no secret copy into SQLite |
| TD-008 | — | Keep `ssh_key_file_name` | Host-scoped? | C# `CloneAsNewIdentity` keeps it | **Rejected** — C# parity |

## Fixes applied

- Domain `clone_as_new_identity` + unit pin
- UI `tree/duplicate.rs` Fake build/apply + storage glue; reuse `reparent::next_sort_order`
- Storage `duplicate_connection` IMMEDIATE tx + `storage_tests` pin
- Exact folder-error mapping; simplified apply; unicode / drift / collision / advertised-id regressions
- Docs: 17 / 20 / 03 / 02 / feature-matrix (+ README ledger row)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → security → integration → tests | TD-001…004 | Fixed; reset |
| Adv-2 | Reverse: C# Duplicate / CloneAsNewIdentity → CredMgr keying → storage error map → apply id keep | None (TD-005…008 rejected) | Clean (1/2) |
| Adv-3 | Forward on post-fix apply + exact FOLDER_MSG + unicode/drift tests | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `next_sort_order` `pub(crate)` from reparent | `duplicate_memory` uses `source.nodes()` | Unified apply; exact FOLDER_MSG | Yes (already in Adv fixes) → treat as reset | Clean path from current |
| Sim-2 | Domain clone shared by UI + storage | No extra `list_all` in memory path | Trailing whitespace in 17 related-docs | Yes → strip trailing spaces; reset | Fixed |
| Sim-3 | No further helpers | No further churn | In-scope only | None | Clean (1/3) |
| Sim-4 | Same | Same | No further churn | None | Clean (2/3) |
| Sim-5 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: unified apply + exact FOLDER_MSG + trailing-ws docs | None | Clean (1/2) |
| Adv-R2 | Reverse: secrets/SQLite, folder reject, missing source, advertised id keep | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib tree::duplicate --no-default-features
cargo test -p wormhole-ui --lib tree::duplicate --features storage
cargo test -p wormhole-storage duplicate_connection
cargo test -p wormhole-domain --lib clone_as_new_identity
cargo test -p wormhole-ui --lib tree::reparent --no-default-features
```

Result: **10** duplicate tests (no-default-features); **11** with `--features storage`; **1** storage integration; **1** domain; **18** reparent smoke — all green.

## Notes

- Folders: Lab fail-closes with `NotAConnection` (C# silently returns) — documented in 17.
- Hosts should publish metadata-only `ConnectionNodeChangeEvent::Create` after successful Fake/storage duplicate (see [02-domain.md](02-domain.md)); glue does not publish.
- Editor Insert remains the only path that stores a new CredMgr inline password for a fresh node Id ([20-connection-editor.md](20-connection-editor.md)).
