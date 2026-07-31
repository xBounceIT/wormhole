# Adversarial ledger — Settings Extensions Bitwarden Fake glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/settings_bitwarden_extensions.rs` (+ crate-root re-exports in `lib.rs` / `Cargo.toml` `secrets` feature)
- `wormhole-secrets-win` ref-impl helpers for catalog/session (`&FakeLocalCredentialCatalog`, `&FakeBitwardenCredentialCache`, `&FakeBitwardenSession`)
- Docs: `17-tree-settings-vm.md`, `04-secrets.md` (cross-ref), `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# Settings Extensions GPUI chrome; live `bw` HTTP / process spawn; WebView2 extension host;
`BitwardenCredentialSyncService` live sync; SQLite cache repo adapter; password resolve at connect.

**Compared against:** C# `SettingsViewModel` Bitwarden bindings + composed `wormhole-secrets-win` Fakes  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Settings → Extensions Rust VM; feature-matrix row **Pending**
- Attack focus: vault enable/disable persist; unlock/lock status; locked vault → fail-closed virtual picker rows
  (local still listed); CLI install summary + pinned install persist atomicity; extension toggle; onboarding
  notice gate via existing helper; Debug omits paths / install/sync error payloads / session keys

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| BS-001 | P1 | `catalog_glue` | `&Fake*` types lacked trait impls — glue would not compile | `cargo build` E0277 | **Fixed** — ref impls in `wormhole-secrets-win` |
| BS-002 | P1 | `apply_cli_install_to_settings` | Settings `apply()` failure ignored after disk install | State atomicity lane | **Fixed** — propagate `SettingsPersist` |
| BS-003 | P2 | `BitwardenSession` trait | Direct `session.status()` without trait in scope | `cargo build` E0599 | **Fixed** — import `BitwardenSession` |
| BS-004 | P2 | `configured_extension_install` | `&self` called `sync_*` requiring `&mut self` | `cargo build` E0596 | **Fixed** — ephemeral settings store from snapshot |
| BS-005 | P2 | tests | `unlock_vault().unwrap()` on non-Result type | `cargo test` E0599 | **Fixed** — assert on `BitwardenUnlockResult` |
| BS-006 | P2 | `debug_omits_*` test | Assert `!dbg.contains("vault")` false positive on `vault_enabled` | Test panic | **Fixed** — assert path substrings only |
| BS-007 | P2 | `Cargo.toml` | `secrets` feature not split from `storage` | Task: lab glue without SQLite | **Fixed** — `secrets` feature + `storage` implies it |
| BS-008 | P2 | docs | Ledger + README + feature-matrix + `17` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| BS-R1 | — | Extension ZIP import on settings glue | Could wire `import_zip` in VM | Lab exposes summaries + configured install only | **Rejected** — install glue already covered in secrets ledger |
| BS-R2 | — | `Arc<FakeBitwardenSession>` | Shared session across harness | Owned session + `session()` accessor suffices | **Rejected** |
| BS-R3 | — | Default-enable `secrets` feature | Would widen compile surface | Opt-in matches `gpui` / `storage` | **Rejected** |
| BS-R4 | — | Duplicate onboarding glue call | VM only exposes `onboarding_notice_visible` bool | Composition via `should_show_*` helper | **Rejected** |
| BS-R5 | — | Log unlock failures | Lab has no logger; UI state carries status text | **Rejected** — host can log `BitwardenUnlockResult` |

## Fixes applied

- `settings_bitwarden_extensions.rs` — `BitwardenSettingsExtensionsGlue` + `BitwardenSettingsUiState` + Fake harness + parity tests
- `wormhole-secrets-win` — `&FakeLocalCredentialCatalog`, `&FakeBitwardenCredentialCache`, `&FakeBitwardenSession` trait impls
- `lib.rs` / `Cargo.toml` — `secrets` feature, re-exports, crate description
- `docs/migration/17-tree-settings-vm.md` — behaviour + API + verification
- `docs/migration/feature-matrix.md` — Settings Extensions row → Lab
- `docs/migration/04-secrets.md` — cross-ref in public API table
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-settings-bitwarden.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → compose Fakes → lock/disable gates → Debug redaction → persist atomicity | BS-001…008 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → locked virtual count → CLI install → onboarding gate | None (BS-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: disable vault locks session, empty password unlock, extension toggle persist | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse catalog/session/cli/extension Fakes from `wormhole-secrets-win`; onboarding via existing helper | No new HTTP / GPUI deps | Settings persist on CLI install fail-closed | None | Clean (1/3) |
| Sim-2 | `with_fake_harness` mirrors `UpdateNotifyGlue::with_fake`; inline snapshot mappers | No extra trait objects beyond settings VM | Ephemeral extension store for read-only configured install | None | Clean (2/3) |
| Sim-3 | No further extraction | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --features secrets settings_bitwarden
cargo test -p wormhole-secrets-win --lib bitwarden
cargo test -p wormhole-ui --features secrets
```

**Result (final):** `settings_bitwarden` **10** passed; `bitwarden` filter **58** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/settings_bitwarden_extensions.rs rust/crates/wormhole-ui/src/lib.rs rust/crates/wormhole-ui/Cargo.toml rust/crates/wormhole-secrets-win/src/bitwarden_credential_catalog.rs rust/crates/wormhole-secrets-win/src/bitwarden_session.rs docs/migration/adversarial-ledger-settings-bitwarden.md docs/migration/17-tree-settings-vm.md docs/migration/README.md docs/migration/feature-matrix.md docs/migration/04-secrets.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live `bw` HTTP / GPUI / CredMgr churn.
