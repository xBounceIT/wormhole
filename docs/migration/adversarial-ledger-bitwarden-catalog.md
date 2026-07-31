# Adversarial ledger — Bitwarden virtual credential catalog (`wormhole-secrets-win`)

**Scope:**
- `rust/crates/wormhole-secrets-win/src/bitwarden_virtual_credential_ids.rs`
- `rust/crates/wormhole-secrets-win/src/bitwarden_credential_catalog.rs`
- Crate-root re-exports in `lib.rs` / `Cargo.toml` description
- Docs: `04-secrets.md`, `03-storage.md`, `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# `BitwardenCredentialSyncService` / live `bw` CLI spawn;
`wormhole-storage` `BitwardenCredentialCache` repository; GPUI picker chrome;
`wormhole-ui::credential_picker` search VM (separate ledger); password resolution at connect.

**Compared against:** C# `BitwardenCredentialCatalogService` + `BitwardenVirtualCredentialIds` +
`BitwardenCredentialCatalogServiceTests`  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Rust catalog module
- Attack focus: SHA-256 → .NET `Guid` layout parity; virtual/link de-dupe per protocol;
  page vs picker projection; vault disabled → local only; locked session → fail-closed empty
  virtuals (local still listed); no passwords in Debug; Fake session must `unlock()` before
  cache merge; demo cache metadata-only

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| BC-001 | P1 | `load_cache_entries` | Locked vault returned `Err` and blocked **local** picker rows | Task: fail-closed empty virtuals; C# still lists saved creds | **Fixed** — locked → `Ok(vec![])`; local merge unchanged |
| BC-002 | P1 | tests / harness | `FakeBitwardenSession::with_session_key` does not unlock until `unlock()` | All merge tests saw `VaultLocked` / empty cache | **Fixed** — `unlocked_session()` test helper |
| BC-003 | P2 | `profiles_for_protocol` | Linked de-dupe used protocol-filtered list, not full local | C# `AddVirtualProfiles(..., local, ...)` | **Fixed** — pass full `local` slice |
| BC-004 | P2 | `dotnet_guid_from_sha256_prefix` | `Uuid::from_fields` d4 needed `&[u8; 8]` ref | `cargo build` E0308 | **Fixed** |
| BC-005 | P2 | `linked_item_ids.contains` | `&str` vs `&String` mismatch on credentials page | `cargo build` E0308 | **Fixed** — trim compare |
| BC-006 | P2 | `#![deny(missing_docs)]` | New public items undocumented | `cargo test` doc lint | **Fixed** — field/variant docs |
| BC-007 | P2 | docs | Ledger + README + feature-matrix + `04` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| BC-R1 | — | `VaultLocked` error enum | Could surface explicit locked error to UI | Lab uses empty cache; simpler contract | **Rejected** — removed unused variant after BC-001 |
| BC-R2 | — | `wormhole-ui` home | Task allowed UI crate | Catalog + session lock belong with secrets | **Rejected** — correct crate |
| BC-R3 | — | SQLite cache repo in scope | Task = Fake glue only | Storage repo still Pending per `03-storage.md` | **Rejected** |
| BC-R4 | — | Merge `bitwarden_virtual_credential_ids` into catalog file | Two small modules | IDs reused by future sync glue | **Rejected** |
| BC-R5 | — | Log locked vault | C# has no lock gate on catalog | Rust lab fail-closed per task | **Rejected** — documented divergence |

## Fixes applied

- `bitwarden_virtual_credential_ids.rs` — SHA-256 ids + `BitwardenCredentialCacheEntry` + C# GUID pins
- `bitwarden_credential_catalog.rs` — glue + Fakes + demo entries + parity tests
- `lib.rs` / `Cargo.toml` — modules, re-exports, `wormhole-domain` + `chrono` + `thiserror` deps
- `docs/migration/04-secrets.md` — catalog section + API table rows
- `docs/migration/03-storage.md` — out-of-scope note updated
- `docs/migration/feature-matrix.md` — virtual catalog row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-bitwarden-catalog.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → C# parity → lock/disable gates → Debug redaction → Fake harness | BC-001…007 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → GUID vectors → linked de-dupe → page projection | None (BC-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: locked local-only, empty cache unlocked, demo Debug scan | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `BitwardenSession` + `BITWARDEN_PASSWORD_FIELD_PATH`; single `load_cache_entries` | No extra trait objects beyond injectable sources | Locked = empty cache documented | None | Clean (1/3) |
| Sim-2 | `enabled_glue` / `unlocked_session` test helpers only | Inline `project` / sort helpers | No GPUI / SQLite churn | None | Clean (2/3) |
| Sim-3 | No further extraction | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib bitwarden
cargo test -p wormhole-secrets-win
```

**Result (final):** `bitwarden` filter **33** passed; full crate **170** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-secrets-win/src/bitwarden_credential_catalog.rs rust/crates/wormhole-secrets-win/src/bitwarden_virtual_credential_ids.rs rust/crates/wormhole-secrets-win/src/lib.rs docs/migration/adversarial-ledger-bitwarden-catalog.md docs/migration/04-secrets.md docs/migration/README.md docs/migration/feature-matrix.md docs/migration/03-storage.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live `bw` CLI / GPUI / CredMgr churn.
