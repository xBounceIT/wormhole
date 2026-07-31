# Surface-lab — how to run & gate → module map

Phase-1 technical gate binary for the Rust/GPUI migration. It does **not** replace
the WinUI 3 app. Domain porting (`InheritanceResolver`) stays blocked until gates
**3–8** pass on real x64 and ARM64 hardware — see [gate-checklist.md](gate-checklist.md).

Toolchain / PATH for agent shells: [toolchain.md](toolchain.md).

**Evidence honesty:** every surface-lab smoke is **`LabOnly`**. Lab status
(`partial` / `implemented` / `scaffold` printed by the binary) is **not** a
gate-checklist pass and must **never** be recorded as `HardwarePass`. Track
status in [gate-evidence-log.md](gate-evidence-log.md) (all rows currently
`LabOnly`; no hardware sign-off).

## Run

From the repo root (PowerShell):

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo run -p surface-lab
# Secrets-free support snapshot (versions, WebView2, sidecars, logs dir) — see 19-diagnostics-soak.md
cargo run -p surface-lab -- --diagnostics
```

`--diagnostics` exits after printing a `wormhole-diagnostics` report (no gate
smokes). Default `cargo run` still prints the gate map, stub broker, pane-layout
skip/smoke, gates 3–8 smokes (feature-gated where noted), then optional GPUI boot.

Optional features (optional deps in `Cargo.toml`; pins in [deps-pins.md](deps-pins.md)):

```powershell
# GPUI chrome (gates 1–2 host path)
cargo check -p surface-lab --features gpui

# WebView2 child HWND via wry 0.56 (gates 3–5, optional gate-7 live focus) — not gpui-wry
cargo check -p surface-lab --features webview
cargo check -p wormhole-surface-win --features webview
cargo run -p surface-lab --features webview

# RDP owned-overlay spike (gate 6; optional gate-7 overlay focus)
cargo check -p surface-lab --features rdp
cargo run -p surface-lab --features rdp
# Live Connect stub (still LabOnly — not HardwarePass)
cargo run -p surface-lab --features rdp -- --gate06-live

# PaneLayoutSink → NativeSurfaceBroker adapter smoke (gate 2 layout tick)
cargo check -p surface-lab --features pane-layout
cargo test -p wormhole-surface-win --features pane-layout
cargo run -p surface-lab --features pane-layout

# Focus + a11y (gates 7–8) — FocusBroker + FocusCycle always; AccessKit needs gpui
cargo run -p surface-lab
cargo test -p wormhole-surface-win focus
cargo test -p wormhole-surface-win focus::cycle
cargo check -p surface-lab --features gpui
$env:SURFACE_LAB_A11Y = "1"
cargo run -p surface-lab --features gpui
# Equivalent CLI: cargo run -p surface-lab --features gpui -- --gate08-a11y
```

Default builds **do not** pull Zed `gpui`, wry, or mstscax COM. The lab prints gate
status, exercises the `wormhole_surface_win` stub broker, and always runs FocusBroker
+ FocusCycle policy smokes (gate 7) plus a11y checklist hooks (gate 8).

Interactive WebView2 smokes (requires Evergreen WebView2 Runtime):

```powershell
$env:SURFACE_LAB_INTERACTIVE = "1"
cargo run -p surface-lab --features webview
```

## Crates

| Path | Role |
|------|------|
| `rust/crates/surface-lab` | Gate lab binary + modules 1–8 |
| `rust/crates/wormhole-surface-win` | `NativeSurfaceBroker` + WebView2/`rdp`/`pane-layout` feature hosts; FocusBroker / FocusCycle |
| `rust/crates/wormhole-diagnostics` | Secrets-free support report behind `--diagnostics` |
| `rust/crates/wormhole-ui` | `PaneLayoutSink` / pane ids (optional via `pane-layout`) |

Design notes for the broker: [native-surface-broker.md](native-surface-broker.md).

## Gate → code module map

| Gate | Criterion (summary) | Evidence | Module |
|---:|---|---|---|
| 1 | Custom title bar / Mica / theme / DPI | LabOnly | `surface-lab::gates::gate01_window` (+ `gpui_host` when featured) |
| 2 | Four resizable panes + DnD (+ optional layout sink) | LabOnly | `surface-lab::gates::gate02_panes` (+ `BrokerPaneLayoutSink` via `pane-layout`) |
| 3 | WebView2 in a pane (**kill switch**) | LabOnly | `surface-lab::gates::gate03_webview2` + `ChildWebViewHost` (`webview` feature) |
| 4 | Menus/tooltips/dialogs above WebView2 (**kill switch**) | LabOnly | `surface-lab::gates::gate04_overlay_ui` + `OverlayStackController` |
| 5 | xterm.js bridge (**kill switch**) | LabOnly | `surface-lab::gates::gate05_xterm` ([14-terminal-bridge.md](14-terminal-bridge.md)) |
| 6 | RDP ActiveX MsRdpClient9 owned overlay (**kill switch**) | LabOnly | `surface-lab::gates::gate06_rdp_activex` + `SurfaceKind::RdpActiveX` (`rdp`; `--gate06-live`) |
| 7 | Focus handoff (**kill switch**) | LabOnly | `surface-lab::gates::gate07_focus` + `FocusBroker` + `FocusCycle` |
| 8 | UIA / keyboard a11y (**kill switch**) | LabOnly | `surface-lab::gates::gate08_a11y` + `gpui_host::try_boot_a11y` |

Design notes: [08-focus-a11y.md](08-focus-a11y.md) (gates 7–8), [08-ui.md](08-ui.md) (pane-layout), [05-rdp-spike.md](05-rdp-spike.md) (gate 6).

Executable pass/fail boxes: [gate-checklist.md](gate-checklist.md). Lab evidence stubs:
[gate-evidence-log.md](gate-evidence-log.md). Printing `TODO` / `scaffold` / `partial` /
`implemented` from the lab is **not** a pass and is **not** `HardwarePass`.

### Gates 1–2 notes (gpui / pane-layout features)

Lab path lives in `surface-lab::gates::gpui_host::lab` (`gpui_platform::application()`, not `Application::new()`). Gate 8 a11y spike is `gpui_host::a11y`.

| Item | Status |
|---|---|
| Custom client-area title bar | Implemented via `TitlebarOptions { appears_transparent: true }` + `WindowControlArea::Drag` / Min / Max / Close |
| Light / dark | In-app System→Light→Dark toggle; reads `Window::appearance()` when System |
| DPI helpers | `logical_bounds_to_physical` / `sanitize_scale_factor` → `PhysicalBounds` + **Log DPI** button; prints hardware checklist; non-finite scale falls back to 96 DPI |
| Mica | `WindowBackgroundAppearance::MicaBackdrop` → `gpui_windows` `DwmSetWindowAttribute(DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW)`. Needs Win11 + translucent fills to be visible; Win10 may no-op |
| 2×2 panes + resize | Horizontal + vertical drag splitters; `h_split` / `v_split` drive **both** visual tile sizes and `PhysicalBounds` via `split_axis_sizes`; ratios clamped 0.15–0.85; unique splitter element IDs; live window bounds during drag |
| DnD | Optional stub: drag pane tab → drop on another pane to swap labels (`pane_order` permutation; OOB/same-slot no-op) |
| `pane-layout` sink | Headless `BrokerPaneLayoutSink` smoke when featured (see below); live GPUI→sink tick still TODO |
| Hardware gate-checklist | **LabOnly** — **not** claimed; still manual on x64/ARM64 at 100/150/200% ([gate-evidence-log.md](gate-evidence-log.md)) |

### Gates 3–5 notes (webview feature)

- Host path is **wry `build_as_child`** under a Win32/`LabOwnerWindow` owner HWND — not `gpui-wry`.
- Each `ChildWebViewHost` gets a **unique** WebView2 user-data folder (proxy/ignore-cert envs never share).
- Gate 4 hides the child via `OverlayStackController::effective_webview_visibility` while chrome is open.
- Gate 5 prefers `Assets/web/terminal.html` via wry custom protocol `http://wormhole.localhost/…` when
  vendor xterm is staged (`scripts/Fetch-WebAssets.ps1` — see [Assets/web/README.md](../../Assets/web/README.md)
  and [14-terminal-bridge.md](14-terminal-bridge.md)). Host→page uses `PostWebMessageAsString` so
  `bridge.js` receives frames. If vendor is missing, falls back to an echo HTML stub with an explicit
  **NOTE**. IPC logs go through `summarize_ipc_for_log` (no raw terminal/clipboard bodies).
- `BrowserProcessExited` is hooked when `ICoreWebView2Environment5` is available (`needs_recreate` / generation token).
- All three remain **LabOnly** kill switches — see [gate-evidence-log.md](gate-evidence-log.md).

### Gate 6 notes (rdp feature)

- Hosting model: **owned overlay** (`GWLP_HWNDPARENT` + `WS_EX_TOOLWINDOW`) — **not** `SetParent` / `WS_CHILD`.
- Default `cargo run -p surface-lab --features rdp`: overlay + OLE in-place + event-sink stub when mstscax is registered.
- `--gate06-live`: Connect stub path. Still **LabOnly** — not a hardware COM/reconnect pass.
- Details: [05-rdp-spike.md](05-rdp-spike.md).

### Gates 7–8 notes (FocusBroker / FocusCycle / a11y)

- Gate 7 always runs (no feature required): `FocusBroker` cold-connect latch, never `SetFocus(NULL)`, AutoReconnected skip, plus **`FocusCycle`** chrome → WebView2 → chrome ring smoke.
- Optional live: `--features webview` (`ChildWebViewHost::request_focus`), `--features rdp` (overlay HWND through broker).
- Gate 8 always prints UIA gap table + keyboard checklist; AccessKit chrome boot is opt-in (`SURFACE_LAB_A11Y=1` or `--gate08-a11y` with `--features gpui`).
- Design: [08-focus-a11y.md](08-focus-a11y.md). Evidence: **LabOnly** in [gate-evidence-log.md](gate-evidence-log.md).

## Broker API (skeleton)

`wormhole_surface_win::NativeSurfaceBroker`:

- `register(owner, WebView2 | RdpActiveX)` → `SurfaceHandle`
- `update_bounds(id, PhysicalBounds + dpi + visibility + ZOrderHint)`
- `unregister` / `list`

`StubNativeSurfaceBroker` records state only — no COM. Real WebView2 attach is
`webview::ChildWebViewHost` behind `--features webview`.

### Pane layout sink (`pane-layout` feature)

`BrokerPaneLayoutSink` implements `wormhole_ui::PaneLayoutSink` and maps
`PaneId` → registered `SurfaceHandle` → `NativeSurfaceBroker::update_bounds`
(`PanePhysicalBounds` → `PhysicalBounds`). Degenerate slots hide; panes omitted
from a tick hide their bound surfaces; `unbind` / rebind hide the previous
surface so no stale visible HWND remains. Lab smoke only — **LabOnly**; **does not**
claim hardware gate-checklist or DPI soak pass (`HardwarePass`).

```powershell
cargo run -p surface-lab --features pane-layout
cargo test -p wormhole-surface-win --features pane-layout
```

See also [08-ui.md](08-ui.md) and [adversarial-ledger-pane-layout.md](adversarial-ledger-pane-layout.md).

### Diagnostics (`--diagnostics`)

```powershell
cargo run -p surface-lab -- --diagnostics
```

Collects a secrets-free support snapshot via `wormhole-diagnostics` (versions,
WebView2 runtime probe, sidecar presence, logs dir) and exits. See
[19-diagnostics-soak.md](19-diagnostics-soak.md). This path is **LabOnly** /
spike support tooling — not a hardware gate pass.
