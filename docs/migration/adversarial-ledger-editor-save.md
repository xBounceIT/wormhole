# Adversarial ledger — connection editor → storage persist glue

Scope (ONLY):
- `rust/crates/wormhole-ui/src/connection_editor/persist.rs` (`save_validated_editor`, `load_inline_secret`, `--features storage`)
- `ConnectionEditorState` accessor used by rehydrate (`loaded_uses_inline_password`)
- `docs/migration/20-connection-editor.md`, `docs/migration/03-storage.md` (persist call-out)
- Focused regressions: `persist` unit tests + `tests/connection_editor_persist.rs`

Out of scope: GPUI dialog chrome; Bitwarden; HardwarePass / cutover claims; unrelated `wormhole-tunnels` workspace churn (blocks default `session` feature compile mid-edit by other agents — persist verified with `--no-default-features --features storage`).

Baseline (before review edits): `cargo test -p wormhole-ui --features storage` green (135 lib + 5 persist integration); `cargo test -p wormhole-storage` green. Context7 MCP unavailable; pins from workspace / `deps-pins.md`.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| ES-001 | P1 | `persist.rs` (missing API) | Edit after `load_from` without CredMgr rehydrate leaves blank `inline_password` → save **deletes** stored secret | C# `LoadInlineSecretAsync` + dialog LoadAsync; Rust `load_from` clears chrome; blank-inline path deletes | **Fixed** — `load_inline_secret`; regressions `load_inline_secret_then_update_preserves_credmgr_entry`, `edit_after_load_inline_secret_preserves_password_on_rename` |
| ES-002 | P1 | `save_validated_editor` Insert path | CredMgr failure after DB insert left orphan `UseInlinePassword` row; Insert retry hits UNIQUE; chrome already had plaintext | Attack: Fake store fail / oversized password after insert | **Fixed** — compensating `repo.delete` on Insert+Secrets; chrome keeps password; tests `insert_secrets_failure_rolls_back_row_and_keeps_chrome_password`, `insert_oversized_password_fails_closed_without_orphan_row` |
| ES-003 | P2 | `20-connection-editor.md` / `03-storage.md` | Docs omitted rehydrate + Insert rollback contracts | Follow-up wording; table missing `load_inline_secret` | **Fixed** — docs updated; ledger indexed |
| ES-004 | — | Update + CredMgr fail | DB committed, secret apply fails | Same ordering as C# SafeUpdate; chrome retains plaintext for Update retry | **Rejected** — intentional DB-first parity; Insert gets compensating delete only |
| ES-005 | — | Whitespace-only pending | Stores non-empty whitespace in CredMgr | C# `IsNullOrEmpty` same | **Rejected** — parity |
| ES-006 | — | Compensating delete swallows Storage err | Orphan possible if delete also fails | Best-effort; rare | **Rejected** — documented; no safe stronger in-scope API |
| ES-007 | — | Password on SQLite / Debug | Attack: row / `EditorSaveResult` / errors embed secret | Schema has flag only; custom Debug / error strings size-only | **Rejected** — covered by existing + new redaction assertions |
| ES-008 | — | CredMgr key = CredentialId | Saved-cred leave-inline | Delete/store use `node.id`; tests assert credential Id unused | **Rejected** — correct; pinned by tests |
| ES-009 | — | Validation / ephemeral bypass | Skip validate or persist QC | Mode check + validate before writes | **Rejected** — covered |
| ES-010 | — | Id drift insert vs CredMgr | Nil → v4 before `to_connection_node`; apply uses `stored.node.id` | `debug_assert_eq`; round-trips | **Rejected** — no reachable drift |

## Fixes applied

- `load_inline_secret` + `ConnectionEditorState::loaded_uses_inline_password` (C# `_loadedUseInlinePassword` / `LoadInlineSecretAsync`)
- Insert CredMgr failure → best-effort row rollback; chrome plaintext retained for retry
- Docs: rehydrate, partial-failure, build flags; `03-storage` nodes-write call-out
- Regressions: preserve-on-edit, noop load when not inline, secrets fail rollback, oversized reject, missing-row update skips secrets, credential-Id key non-touch

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → atomicity → security → integration → tests | ES-001, ES-002 | Fixed; reset |
| Adv-2 | Reverse: security/logging → partial fail → Id/CredMgr key → empty-vs-delete → ephemeral → docs | ES-003 | Fixed; reset |
| Adv-3 | Security-first reverse on post-fix surface | None (ES-004…010 rejected) | Clean (1/2) |
| Adv-4 | Forward: validation bypass, Id drift, HTTP leftover, update missing row | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Shared test factory / map_err helpers — rejected (locality / taste) | update+get_by_id necessary for timestamps | Dead kind guard in `apply_inline_secret` — keep (C# parity) | None | Clean (1/3) |
| Sim-2 | Same | No extra CredMgr I/O on validate-fail | Extra HTTP chrome-clear assert — nice-to-have only | None | Clean (2/3) |
| Sim-3 | Same | Same | Diff hygiene; no HardwarePass claims | None | Clean (3/3) |

No simplify code edits → no post-simplify adversarial re-loop required. Adv-3/Adv-4 remain the closing adversarial pair on the final implementation.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --features storage
cargo test -p wormhole-storage
```

Result: **pass** — wormhole-ui (no-default + storage): lib **134** + `connection_editor_persist` **6** + validation **17** + settings **5**. wormhole-storage: lib + storage_tests green (**40** integration after concurrent suite growth).

Note: plain `cargo test -p wormhole-ui --features storage` (default `session`) was **blocked** during this review by unrelated in-progress `wormhole-tunnels` compile errors (`openvpn` dual module / fortinet exports). Persist glue does not depend on tunnels; `--no-default-features --features storage` is the accurate gate for this scope.

`git diff --check` on scoped persist / docs paths: clean.
