# Adversarial ledger — Tunnel configs page / picker Fake glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/tunnel_configs_ui.rs` (+ crate-root re-exports in `lib.rs` / `Cargo.toml` description)
- Composes existing `connection_editor::TunnelUiState` for tri-state picker writes
- Docs: `07-tunnels-mcp.md` (tunnel configs UI section), `20-connection-editor.md` (cross-ref), `feature-matrix.md` (Tunnels UI row), `README.md` index
- this ledger

**Out of scope:** C# tunnel editor / test dialog GPUI chrome; DPAPI payload read/write (`CredentialService` / `TunnelPayloadStore`); add/edit/delete/test commands on the configs VM; debounce (host-owned); GPUI list/combo bindings.

**Compared against:** C# `TunnelConfigsViewModel` list/filter/select subset + `TunnelPickerViewModel` metadata subset  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Rust tunnel configs page / picker VM; feature-matrix Tunnels UI row **Pending**
- Attack focus: metadata-only list (never DPAPI); configs-page filter name **or** kind display; picker filter name-only; sentinel ids; stale missing-tunnel placeholder; `Enabled=false` trumps vestigial config id; last-good load; Debug omits secrets; `contains("")` footgun; storage adapter maps repo rows only

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TC-001 | P2 | `stale_tunnel_name` | Used `{id:N}` — invalid Rust format | `cargo build` | **Fixed** — `id.simple()` (32-hex, C# `N` parity) |
| TC-002 | P2 | `TunnelConfigRow` timestamps | Needed for editor metadata from storage | `TunnelConfigRepository` rows carry `CreatedAt`/`UpdatedAt` | **Fixed** — optional timestamps on row |
| TC-003 | P2 | `name_contains` | Empty `query_lower` would match all via `contains("")` | Same class as credential-picker CP-005 | **Fixed** — empty guard + regression |
| TC-004 | P2 | `load_from_node` | `TunnelEnabled=false` must clear vestigial config id for display | C# `SelectedTunnel` getter | **Fixed** — delegates to `TunnelUiState::load_from_node` + regression |
| TC-005 | P2 | `select_config` | Unknown id after reload could leave phantom selection | Editor open on deleted row | **Fixed** — reject unknown id; clear on reload miss |
| TC-006 | P2 | tests | Borrow checker on `set_selected_tunnel(Some(picker.inherit_row()))` | `cargo test` E0502 | **Fixed** — clone sentinel rows in tests |
| TC-007 | P2 | `Cargo.toml` | `chrono` needed for storage row mapping | `cargo build` E0432 | **Fixed** — workspace `chrono` dep |
| TC-008 | P2 | docs | Ledger + README + feature-matrix + `07` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| TC-R1 | — | Port full `TunnelConfigsViewModel` CRUD | Add/edit/delete/test + DPAPI | Explicit metadata-only lab scope | **Rejected** |
| TC-R2 | — | Debounce inside `TunnelConfigsVm` | C# 120ms on VM | Host owns debounce (credential-picker parity) | **Rejected** |
| TC-R3 | — | Picker kind substring search | C# `FilterTunnelConfigs` is name-only | Intentional parity | **Rejected** |
| TC-R4 | — | Duplicate `TunnelUiState` in picker | Already in `connection_editor/tunnel.rs` | Compose existing type | **Rejected** |
| TC-R5 | — | `ResolveExact` on configs page | C# picker-only | Picker `resolve_tunnel_for_commit` only | **Rejected** |

## Fixes applied

- `tunnel_configs_ui.rs` — `TunnelConfigSource` / `FakeTunnelConfigList` / optional `StorageTunnelConfigSource`; `TunnelConfigsVm` + `TunnelPickerVm`; filter helpers; regressions
- `lib.rs` / `Cargo.toml` — re-exports, `chrono` dep, crate description
- `docs/migration/07-tunnels-mcp.md` — tunnel configs UI behaviour + verification
- `docs/migration/20-connection-editor.md` — picker cross-ref + adversarial link
- `docs/migration/feature-matrix.md` — Tunnels UI row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-tunnel-configs-ui.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → security (no DPAPI) → integration (storage adapter) | TC-001…008 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → stale placeholder → sentinel ids → last-good load | None (TC-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: picker inherit-off coercion, configs `has_no_matches`, storage metadata test | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `TunnelUiState`; storage `From<TunnelConfig>`; Fake pattern from credential picker | Single module; no GPUI deps | Empty-query guards; Debug contracts | None | Clean (1/3) |
| Sim-2 | Shared `name_contains`; kind display table mirrors C# `KindContains` | No duplicate picker/config filter merge beyond helpers | Sentinel `from_bytes` consts avoid uuid macro feature | None | Clean (2/3) |
| Sim-3 | No further extraction warranted | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --lib tunnel_configs
cargo test -p wormhole-ui --no-default-features --features storage --lib tunnel_configs
```

**Result (final):** `tunnel_configs` **13** passed without `storage`; **14** with `--features storage` (+ `storage_source_lists_metadata_only`); 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/tunnel_configs_ui.rs rust/crates/wormhole-ui/src/lib.rs rust/crates/wormhole-ui/Cargo.toml docs/migration/adversarial-ledger-tunnel-configs-ui.md docs/migration/07-tunnels-mcp.md docs/migration/20-connection-editor.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No DPAPI / GPUI / tunnel CRUD churn.
