# Adversarial ledger — Credentials page list/CRUD Fake glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/credentials_page_ui.rs` (+ crate-root re-exports in `lib.rs` / `Cargo.toml` description)
- Composes `credential_picker` filter helpers, `wormhole-storage::credential_glue`, `FakePasswordStore` / `MemoryCredentialSecrets`, optional `BitwardenCredentialCatalogGlue` + `CredentialPasswordResolverGlue`
- Docs: `20-connection-editor.md` (credentials page section), `04-secrets.md` (cross-ref), `feature-matrix.md` (Creds UI row), `README.md` index
- this ledger

**Out of scope:** C# `CredentialDialog` / GPUI grid chrome; Bitwarden sync-if-stale (`bw`); bulk-delete dialog UX; debounce (host-owned); live CredMgr in CI.

**Compared against:** C# `CredentialsViewModel` metadata list + search + multi-select + create/rename/delete ordering  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Rust credentials page VM; feature-matrix Creds UI row **Pending**
- Attack focus: metadata-only list rows; password bodies only in `CredentialSaveDraft` (Debug length-only); filter name/username/domain via picker matcher; load clears selection; last-good on load Err; virtual Bitwarden read-only; name-exists skips virtual; sorted insert/rename; delete row-before-secrets; add rolls back SQLite on CredMgr failure; storage/catalog adapters

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CPg-001 | P1 | `add_credential_profile` | CredMgr failure after insert left orphan metadata row | Editor save glue rolls back | **Fixed** — `repo.delete` on store `Err` + regression |
| CPg-002 | P2 | `CredentialsPageVm::load_from` | Successful load must clear selection | C# `LoadAsync` clears `SelectedCredentials` | **Fixed** — `selected_ids.clear()` + regression |
| CPg-003 | P2 | `CredentialsPageVm` | Last-good on load Err | C# catch keeps prior list | **Fixed** — `?` leaves cache; regression |
| CPg-004 | P2 | `delete_credential_profile_page` | Virtual rows must not delete | C# `IsReadOnly` guard | **Fixed** — `ReadOnly` error + regression |
| CPg-005 | P2 | `credential_name_exists` | Duplicate name check must skip virtual rows | C# `NameExists` | **Fixed** — `!is_virtual_bitwarden` + regression |
| CPg-006 | P2 | `CredentialPageRow` / draft Debug | Must not echo password bodies | Task invariant | **Fixed** — custom Debug (`password_len` only on draft) + regression |
| CPg-007 | P2 | `select` | Unknown id must not inflate selection count | Grid orphan id | **Fixed** — reject unknown + regression |
| CPg-008 | P2 | `filter_credentials_page` | Must delegate to picker matcher (stable order) | C# `MatchesQuery` | **Fixed** — `profile_matches_query` + regression |
| CPg-009 | P2 | docs | Ledger + README + feature-matrix + `20` section | Policy | **Fixed** — this ledger + doc updates |
| CPg-R1 | — | Debounce inside VM | C# 120ms on VM | Host owns debounce (picker/tunnel parity) | **Rejected** |
| CPg-R2 | — | Port `CredentialDialog` GPUI | Explicit lab VM-only scope | **Rejected** |
| CPg-R3 | — | Bitwarden add/edit full reload | C# reload on BW provider change | Lab uses explicit `load_from` by host | **Rejected** — documented |
| CPg-R4 | — | Merge into `credential_picker` | Page needs CRUD + multi-select + full row | Separate module | **Rejected** |
| CPg-R5 | — | Assert `!debug.contains("secret")` | `secret_provider` field name is metadata | Use body-shaped checks only | **Rejected** |

## Fixes applied

- `credentials_page_ui.rs` — `CredentialPageSource` / `FakeCredentialPageStore` / optional `StorageCredentialPageSource` + `CatalogCredentialPageSource`; `CredentialsPageVm`; CRUD glue + `read_password_for_edit`; regressions
- `lib.rs` / `Cargo.toml` — re-exports, crate description
- `docs/migration/20-connection-editor.md` — credentials page behaviour + verification
- `docs/migration/04-secrets.md` — cross-ref
- `docs/migration/feature-matrix.md` — Creds UI row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-credentials-page.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → security (no password in list) → integration (storage/secrets adapters) | CPg-001…009 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → rollback → read-only → name-exists virtual skip | None (CPg-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: multi-select deletable filter, sorted rename selection migrate, catalog virtual merge | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse picker matcher + storage glue + catalog/resolver Fakes | Single module; feature-gated adapters | Add rollback; draft password extract before move | **Fixed** → reset adv |
| Sim-2 | No duplicate filter logic; `toggle_select` thin helper | Mutex Fake pattern from picker/tunnel | Debug assertions avoid enum false positives | None | Clean (1/3) |
| Sim-3 | Stable exports; no GPUI deps | Ledger + verification commands | Unused import trimmed | **Fixed** | Reset |
| Sim-4 | No further extraction | Diff hygiene | None | None | Clean (2/3) |
| Sim-5 | Same | Same | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2 after Sim-1): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --lib credentials_page
cargo test -p wormhole-ui --no-default-features --features storage,secrets --lib credentials_page
```

**Result (final):** `credentials_page` **10** passed without optional features; **16** with `--features storage,secrets`; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/credentials_page_ui.rs rust/crates/wormhole-ui/src/lib.rs rust/crates/wormhole-ui/Cargo.toml docs/migration/adversarial-ledger-credentials-page.md docs/migration/20-connection-editor.md docs/migration/04-secrets.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3** (Sim-3…5 after Sim-1 fix + post-adv re-run).
- No accepted non-blocked findings remain.
- No GPUI chrome / live `bw` / password bodies in list rows.
