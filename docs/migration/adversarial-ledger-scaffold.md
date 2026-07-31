# Adversarial ledger — kickoff scaffold (surface-lab / surface-win)

**Scope:** `rust/crates/surface-lab/`, `rust/crates/wormhole-surface-win/`, workspace glue
(`rust/Cargo.toml`, `rust/README.md`, `rust/.gitignore`), docs
`01-surface-lab.md`, `gate-checklist.md`, `native-surface-broker.md` (factual),
`deps-pins.md` (RDP owned-overlay consistency).

**Date:** 2026-07-31  
**Gates completed:** 2 consecutive clean adversarial cycles + 3 consecutive clean
iterative-review-simplify cycles (after post-fix adversarial re-check).

---

## Accepted findings → fixed

| ID | Sev | Finding | Fix |
|----|-----|---------|-----|
| A1 | P0 | `--features rdp` failed to compile (broken OLE `#[implement]` / missing modules) | Scoped `rdp` to owned-overlay HWND + CLSID probe + `RdpOcx` CoCreate path that builds on windows 0.61; removed non-building ole_site host |
| A2 | P1 | Stub/docs risked implying RDP uses SetParent / child HWND | Comments, gate 6, checklist, README, broker unregister docs all say owned overlay (`GWLP_HWNDPARENT`) |
| A3 | P1 | Null `OwnerHwnd(0)` lab smoke failed `GWLP_HWNDPARENT` with invalid-handle | Skip `SetWindowLongPtr(GWLP_HWNDPARENT)` when owner is null; still assert `WS_POPUP` !`WS_CHILD` |
| A4 | P1 | Missing regression coverage for stub RDP register / unregister / unknown id | `broker::tests::stub_registers_rdp_without_com_and_unregister_unknown` |
| A5 | P1 | Missing regression that overlay is popup-not-child | `rdp::host::tests::owned_overlay_is_popup_not_child` (feature `rdp`) |
| A6 | P2 | Docs said GPUI deps “commented” / RDP CoCreate fully deferred while features exist | Updated `01-surface-lab.md` + README feature commands; gate 6 documents `--gate06-live` for `RdpOcx` |
| A7 | P3 | `AtomicU64` id counter under exclusive `&mut self` | Simplified to plain `u64` |

## Rejected findings

| ID | Reason |
|----|--------|
| R1 | Merge `HostBounds` + `PhysicalBounds` — different coordinate contracts (screen vs slot) |
| R2 | Remove `SurfaceError::UnsupportedKind` — reserved for future kinds |
| R3 | native-surface-broker §5 spike gate renumbering vs lab gates 1–8 — intentional separate spike map |
| R4 | Saturating `next_id` at `u64::MAX` — unreachable for stub lifespan |
| R5 | Edit wormhole-secrets-win / domain / storage — out of scope (other agents) |

## Invariant status

| Invariant | Status |
|-----------|--------|
| RDP docs/comments = owned overlay, not SetParent/WS_CHILD | Pass |
| Default `cargo check` (no gpui) | Pass (workspace) |
| `cargo test -p wormhole-surface-win` | Pass (5 tests) |
| `cargo test -p wormhole-surface-win --features rdp` | Pass (6 tests) |
| Broker stub does not pretend COM works | Pass (`StubNativeSurfaceBroker` bookkeeping only; `RdpOverlayHost` has no Connect) |
| Feature flags reference real crate features | Pass (`rdp`, `webview`, `gpui`) |
| No secrets in logs/docs | Pass (sentinel stores host/node id only) |

## Verification commands

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo check -p surface-lab -p wormhole-surface-win
cargo check -p surface-lab --features rdp
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
```

## Blockers / residual

- Full MsRdpClient OLE in-place AxHost embedding + reconnect/events still deferred
  (gate-checklist hardware evidence required). `RdpOcx` is a CoCreate/Connect stub only.
- Parallel agents may still touch workspace members; this ledger covers surface scaffold only.
- Do not reintroduce non-compiling `ole_site` `#[implement]` without a green
  `cargo check -p wormhole-surface-win --features rdp`.
