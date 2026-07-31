# Adversarial ledger — RDP owned-overlay COM spike

Scope: `rust/crates/wormhole-surface-win/` RDP modules (`overlay`, `ocx`, `sentinel`, `STA`, `bounds`), `rust/crates/surface-lab/` gate06 + `rdp` feature wiring, `docs/migration/05-rdp-spike.md`  
Baseline: `cargo check` + `cargo test -p wormhole-surface-win` green (5 tests); `--features rdp` green (8 tests) before review  
Design SoT: `docs/migration/native-surface-broker.md`, C# `ConfigureAsOwnedOverlay` / `RdpCrashSentinelService`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| RDP-001 | P1 | `rdp/sentinel.rs` Mark | `remove_file` + `rename` left a no-sentinel window; C# uses atomic `File.Move(..., overwrite: true)` | Crash between delete and rename loses breadcrumb | **Fixed** — Windows `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`; tmp suffix `path + ".tmp"` |
| RDP-002 | P1 | `rdp/dispatch.rs` | BSTR/`VARIANT` not cleared when `Invoke` failed | `put_bstr` / `put_i4` used `?` before `VariantClear`; `get_dispatch` same on invoke err | **Fixed** — clear on all paths |
| RDP-003 | P2 | `rdp/sentinel.rs` tests | Corrupt JSON, orphan keep, overwrite, `.tmp` cleanup, escapes, `LOCALAPPDATA` path, concurrency unpinned | Only roundtrip test existed; C# suite covers these | **Fixed** — regression tests |
| RDP-004 | P2 | `rdp/overlay.rs` | `is_popup_not_child` ignored `WS_EX_TOOLWINDOW` | Attack invariant requires toolwindow; CreateWindowEx set it but diagnostics did not assert | **Fixed** — ex-style check + host tests |
| RDP-005 | P2 | `rdp/ocx.rs` | `RdpOcx` was `Send` — could leave STA via `run_on_sta` return | COM apartment rule; `T: Send` on `run_on_sta` | **Fixed** — `PhantomData<*const ()>` (`!Send`/`!Sync`) |
| RDP-006 | P2 | `rdp/host.rs` / overlay Drop | HWND leak / degenerate bounds / show-hide undertested | No `IsWindow` after drop; no reject of `<1` size in tests | **Fixed** — drop destroys HWND; EMPTY→SEED; reject zero/negative |
| RDP-007 | P3 | docs + sentinel stamp | Docs claimed RFC3339; impl wrote `{secs}Z` | Doc/code mismatch | **Fixed** — docs + comment: unix-secs `Z` breadcrumb |
| RDP-008 | P3 | `rdp/sentinel.rs` | Empty / whitespace `nodeId` accepted | C# uses `Guid`; empty id useless for recovery | **Fixed** — reject on Mark; malformed on read |
| RDP-009 | P3 | `rdp/overlay.rs` | Dead `_unused_cw` / unused imports | Churn only | **Fixed** — removed |
| RDP-010 | — | layout `is_degenerate(8)` skip inside `set_bounds` | C# skips at surface/VM layer, not `SetHostBounds` (`width < 1` only) | Spike matches form API | **Rejected** — session-layer concern |
| RDP-011 | — | STA message pump for full OLE | Connect stub / CoCreate work without pump | Documented deferred AxHost embedding | **Rejected** — deferred (blocked by design) |
| RDP-012 | — | Password / secret logging on Connect stub | `ConnectStubOptions` is server+port only; no ClearTextPassword | Grep + API shape | **Rejected** — clean |
| RDP-013 | — | `SetParent` / `WS_CHILD` path | Only comments forbidding it; styles assert popup+toolwindow | Grep + tests | **Rejected** — invariant held |

## Fixes applied

- `rdp/sentinel.rs` — atomic replace, tmp path parity, empty/whitespace `nodeId`, expanded tests
- `rdp/dispatch.rs` — always `VariantClear` after put/get
- `rdp/ocx.rs` — `RdpOcx` `!Send`; simpler CLSID fallback loop; credential-safety docs
- `rdp/overlay.rs` — assert `WS_EX_TOOLWINDOW`; drop nulls HWND; remove dead helpers
- `rdp/host.rs` / `host_bounds.rs` — HWND-destroy + degenerate bounds tests
- `surface-lab` gate06 — single CLSID probe selection; toolwindow error text
- `docs/migration/05-rdp-spike.md` — sentinel stamp / atomic replace notes

## Gate record

### Adversarial loop (post-fix)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | RDP-001…009 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; whitespace `nodeId` + doc rename wording | RDP-008 widen + doc | Fixed; counter reset |
| Adv-2a | Contract→…→tests (post whitespace) | None | Clean (1/2) |
| Adv-2b | Reverse: tests-as-oracles → secrets → CLSID 11→10→9 → C# Move/overlay parity | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | gate06 double `select_best_rdp_class` | Extra HKCR probes | Stale error text vs toolwindow | **Fixed** gate06 | Reset |
| Sim-fix | — | — | Redundant `i + 1 == len` break in `cocreate_best` | **Fixed** ocx loop | Reset |
| Sim-1 | Probe-never-empty `[0]` vs `unwrap_or_else` — reject taste | No hot-path I/O | `!Send` + VariantClear intact | None | Clean (1/3) |
| Sim-2 | Sentinel test helper already shared | 40-thread stress OK | No SetParent; drop cleanup pinned | None | Clean (2/3) |
| Sim-3 | EMPTY/SEED / `run_on_sta` used consistently | `OnceLock` class register fine | Docs match impl; deferred OLE noted | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta focus: gate06 selection + `cocreate_best` + prior invariants | None | Clean (1/2) |
| Adv-R2 | Reverse: STA/`!Send`, no secrets, overlay styles, sentinel atomicity | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
cargo check -p surface-lab --features rdp
```

Result: **pass** — default check green without `rdp`; 17 unit tests without `rdp` feature (sentinel+bounds); 20 with `--features rdp` (adds overlay HWND tests).

## Deferred (post OLE spike)

Still out of current spike scope (see `05-rdp-spike.md`):

- CredSSP / full `Configure`, RD Gateway, SmartSizing re-assert on resize
- Full `IMsTscAxEvents` beyond Connected / Disconnected / FatalError
- Owner `WM_WINDOWPOSCHANGED` sync-move + resolution debounce (250 ms)
- Broker layout ticks driving a live `RdpOverlayHost`
- Focus target = AxHost child HWND (overlay stand-in today)

**Now in spike:** `IOleClientSite` / `IOleInPlaceSite` + `DoVerb(INPLACEACTIVATE)` into owned overlay HWND; connection-point sink stub; Mark before Connect / Clear on Connected.
