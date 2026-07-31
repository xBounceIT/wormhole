# Adversarial ledger — Tunnel editor dialog Fake VM glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/tunnel_editor_dialog.rs` (+ `tunnel_configs_ui.rs` Fake CRUD helpers / re-exports in `lib.rs` / `Cargo.toml`)
- Composes `FakeTunnelConfigList` + optional `FakeTunnelPayloadStore` (`secrets`) + optional `TunnelConfigRepository` (`storage`)
- Docs: `07-tunnels-mcp.md` (editor section), `08-ui.md` cross-ref, `feature-matrix.md` (Tunnels UI row), `README.md` index
- this ledger

**Out of scope:** C# `TunnelDialog.xaml` per-kind panels / import pickers; GPUI chrome; live DPAPI; per-kind required-field validation (WireGuard keys, Fortinet host, etc.); tunnel delete / in-use reference checks.

**Compared against:** C# `TunnelDialog` + `TunnelConfigsViewModel` metadata save + `CredentialService.StoreTunnelConfigAsync` ordering  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: tunnel configs page/picker + test dialog only; feature-matrix listed editor as Pending
- Attack focus: fail-closed empty name / missing kind; optional payload never in `Debug`; two-phase `UpdatedAt` after payload on edit; duplicate name; sentinel row reject; Fake lab composes metadata + secrets Fakes

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TE-001 | P2 | `FakeTunnelEditorLab::Debug` | Must include payload store counts, never bytes | Fake Debug policy | **Fixed** — `payloads` field + regression |
| TE-002 | P2 | `build_draft` / `save_to_lab` | Whitespace-only name must not persist | C# trim before save | **Fixed** — trim in `build_draft` + regression |
| TE-003 | P2 | `save_to_lab` edit | `UpdatedAt` must bump after metadata/payload (pool invalidation) | `07-tunnels-mcp` contract | **Fixed** — interim + bumped rows + regression |
| TE-004 | P2 | `save_tunnel_config_with_payload` | Storage edit must mirror two-phase stamp | `TunnelConfigRepository` docs | **Fixed** — old stamp → payload → bump + regression |
| TE-005 | P2 | `TunnelSaveDraft` / VM `Debug` | Payload bytes must not echo | Security lane | **Fixed** — `payload_len` only + regression |
| TE-006 | P2 | `prepare_edit` | Sentinel / `kind=None` rows invalid | Picker sentinels | **Fixed** — `InvalidRow` + regression |
| TE-007 | P2 | `tunnel_name_exists` | Case-insensitive duplicate on save | C# `NameExists` | **Fixed** — shared helper + regression |
| TE-008 | P2 | `FakeTunnelConfigList` | Lab editor needs insert/update CRUD | Composed Fakes scope | **Fixed** — CRUD on list + editor uses trait `list_all` |
| TE-009 | P2 | docs | Ledger + README + feature-matrix + `07`/`08` | Policy | **Fixed** — this ledger + doc updates |
| TE-R1 | — | Per-kind `CollectMissingRequiredFields` | Full C# validation surface | Host-owned / future draft builders | **Rejected** |
| TE-R2 | — | GPUI `TunnelDialog` chrome | Lab VM-only | **Rejected** |
| TE-R3 | — | Live `DpapiTunnelPayloadStore` in default lab | Fake-only per task | **Rejected** |
| TE-R4 | — | Merge into `wormhole-storage` | UI VM belongs in `wormhole-ui` | **Rejected** |
| TE-R5 | — | Delete tunnel + in-use guard | Configs VM scope | **Rejected** — documented out of scope |

## Fixes applied

- `tunnel_editor_dialog.rs` — `TunnelEditorDialogVm`, `TunnelSaveDraft`, `FakeTunnelEditorLab`, storage save helpers, 12 regressions
- `tunnel_configs_ui.rs` — `FakeTunnelConfigList` CRUD + `tunnel_name_exists`
- `lib.rs` / `Cargo.toml` — `tunnels` re-exports; crate description
- `docs/migration/07-tunnels-mcp.md` — editor behaviour + verification
- `docs/migration/08-ui.md` — cross-ref
- `docs/migration/feature-matrix.md` — Tunnels UI row (editor Lab)
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-tunnel-editor.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary (name/kind) → security (Debug) → state (UpdatedAt) → integration (Fake compose) | TE-001…009 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → duplicate name → payload replace optional → sentinel reject | None (TE-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: storage two-phase stamp → trim name → lab metadata-only create | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `FakeTunnelConfigList` + `tunnel_name_exists`; `TunnelPayloadStore` trait | Single module behind `tunnels` | TE-002 trim; TE-003 UpdatedAt | **Fixed** → reset adv |
| Sim-2 | Storage save delegates to `with_payload` when `secrets` on | No GPUI / live DPAPI | `TunnelConfigSource` import for `list_all` | None | Clean (1/3) |
| Sim-3 | VM `Debug` counts-only; draft `payload_len` | Ledger + verification commands | None | None | Clean (2/3) |
| Sim-4 | No further extraction | Diff hygiene | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2 after Sim-1): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib tunnel_editor
cargo test -p wormhole-ui --lib tunnel_editor --features storage,secrets
cargo test -p wormhole-ui --lib tunnel_configs
```

**Result (final):** `tunnel_editor` **7** passed (default features); **12** with `storage,secrets`; `tunnel_configs` **13** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/tunnel_editor_dialog.rs rust/crates/wormhole-ui/src/tunnel_configs_ui.rs rust/crates/wormhole-ui/src/lib.rs rust/crates/wormhole-ui/Cargo.toml docs/migration/adversarial-ledger-tunnel-editor.md docs/migration/07-tunnels-mcp.md docs/migration/08-ui.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live VPN / GPUI / live DPAPI churn.
