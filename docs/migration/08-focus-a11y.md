# Focus handoff + accessibility (lab gates 7–8)

**Date:** 2026-07-31  
**Status:** Lab partial — FocusBroker + FocusCycle + Win32 helpers + AccessKit chrome spike  
**C# references:** `Interop/Rdp/RdpHostForm.RequestFocus`, `Views/Sessions/RdpSurfaceHost` `_focusPushed`, `Helpers/Win32Interop.SetFocus`  
**Design parent:** [native-surface-broker.md](native-surface-broker.md)

> **Doc disambiguation:** This file is **lab gates 7–8** (FocusBroker + a11y).  
> [08-ui.md](08-ui.md) is a different stream (`wormhole-ui` shell skeleton) — do not merge or delete either.  
> In [native-surface-broker.md](native-surface-broker.md) §5, the older spike table lists **Focus routing as gate 5**; the executable lab / [gate-checklist.md](gate-checklist.md) renumbered that work to **gate 7** (and UIA/keyboard to **gate 8**). Prefer lab numbering for status; the broker doc still describes the same invariants.

## Gate 7 — FocusBroker

`wormhole_surface_win::FocusBroker` coordinates logical focus among:

| Owner | Native target | Notes |
|-------|---------------|-------|
| `GpuiChrome` | optional main HWND | Owner tracking; GPUI may own input without SetFocus |
| `WebView2` | child controller HWND / wry `focus()` | `ChildWebViewHost::request_focus` |
| `RdpActiveX` | **AxHost child** HWND | Never overlay form alone; never `SetFocus(NULL)` |

### Hard rules (from C#)

1. **Never `SetFocus(NULL)`** — valid Win32 call that detaches keyboard focus from the thread. Helpers reject null before `user32`.
2. **RDP auto-reconnect must not steal focus** — `RdpConnectKind::AutoReconnected` → `FocusAction::Skipped` **by connect kind** (C# `OnSessionAutoReconnected` never calls `TryFocusSession`). Independent of the latch.
3. **Cold-connect one-shot latch** — `rdp_focus_pushed` set only on successful `ColdOrRetry` push; blocks a **second** cold/Retry push in the same lifecycle. Cleared only on terminal `Disconnected` / `Failed` (not transient `Connecting`). Failed / null HWND pushes do **not** burn the latch. Explicit `request_focus(RdpActiveX)` (user click) does **not** set the latch — only `on_rdp_connected(..., ColdOrRetry)` does.

### Cold-connect focus order

Documented in code (`focus/mod.rs`, gate 7 smoke):

1. Shell may programmatically focus the chrome slot (GPUI / former WinUI host).
2. Win32 `SetFocus` on the RDP **AxHost child** HWND (never form alone, never null).
3. Latch `rdp_focus_pushed` so a later **ColdOrRetry** in the same lifecycle skips step 2. Auto-reconnect is skipped by kind (rule 2), not by the latch.

### FocusCycle (Tab / Shift-Tab stub)

`wormhole_surface_win::FocusCycle` is an ordered ring independent of the pane-layout sink:

1. **GPUI chrome sentinel** — always present (first slot); may omit HWND and only update logical owner via `FocusBroker`. Empty / chrome-only rings wrap Next/Prev onto the sentinel (no panic).
2. **Registered `SurfaceHandle`s** — WebView2 / RdpActiveX from `NativeSurfaceBroker::list` (or direct insert). Optional per-surface HWND (AxHost child / WebView2 child) for the produced `FocusRequest`. Null HWNDs are not stored (treated as clear).

`advance(Next|Prev)` / `peek` build `FocusRequest` payloads only — they never call Win32. Callers must pass requests to `FocusBroker::request_focus` (policy + never `SetFocus(NULL)` stay in the broker). Membership: `insert_surface` (idempotent by id; refreshes kind + current), `remove_surface` (current → chrome), `sync_surfaces` / `sync_from_broker` (survivors keep prior ring order; newly seen ids append sorted by id; first populate from an empty ring is id-sorted). Unit tests cover pure cycle logic without HWND; stub-broker sync is `cfg(windows)` because stub `register` is Windows-gated.

Adversarial review: [adversarial-ledger-focus-cycle.md](adversarial-ledger-focus-cycle.md).

```powershell
cargo test -p wormhole-surface-win focus::cycle
```

### Win32 helpers

Always compiled on Windows (default `cargo check` on this target):

- `wormhole_surface_win::set_focus` / `get_focus` (`cfg(windows)`)
- `Win32FocusOps` implements `FocusOps`
- `RecordingFocusOps` for unit tests without live RDP / input queue

`windows` is a non-optional dependency of `wormhole-surface-win` so focus helpers do not require `--features rdp` or `webview`. FocusCycle itself is pure Rust (no Win32).

### Lab

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win focus
cargo test -p wormhole-surface-win focus::cycle
cargo run -p surface-lab
# optional live / AccessKit:
cargo run -p surface-lab --features webview
cargo run -p surface-lab --features rdp
cargo check -p surface-lab --features gpui
# AccessKit window (blocks): cargo run -p surface-lab --features gpui -- --gate08-a11y
```

## Gate 8 — AccessKit + keyboard / UIA

### GPUI chrome (AccessKit)

With `--features gpui` and `SURFACE_LAB_A11Y=1` (or `--gate08-a11y`):

- `gpui_host::try_boot_a11y` — Application role, SpinButton / Button tab stops, Tab / Shift-Tab
- Mirrors Zed `gpui` example `a11y` against pin in [deps-pins.md](deps-pins.md)

### HWND overlay UIA gaps (honest)

| Surface | Local UIA | Gap |
|---------|-----------|-----|
| GPUI chrome | AccessKit → UI Automation | Primary tree for tree/tabs/dialogs |
| WebView2 | Chromium UIA under child HWND | **Not** merged into GPUI AccessKit tree |
| RDP ActiveX overlay | Generic HWND / remote desktop | Local UIA does **not** expose remote controls; same limitation as WinUI today |

Do not invent a fake UIA tree for RDP remote content. Sustainable a11y = full keyboard + AccessKit for chrome; WebView2 uses Edge a11y; RDP documents the remote-desktop gap.

### Checklist hooks

Printed by `gates::gate08_a11y::KEYBOARD_A11Y_CHECKLIST` and mirrored below for hardware sign-off ([gate-checklist.md](gate-checklist.md)):

1. GPUI: Tab / Shift-Tab cycles chrome controls  
2. GPUI: AccessKit roles visible in Inspect.exe / Narrator when AT active  
3. WebView2: focus enters via FocusBroker; in-page Tab stays in Chromium  
4. WebView2: chrome hide/restore (gate 4) does not black-out active surface  
5. RDP: cold-connect lands keys on AxHost child  
6. RDP: AutoReconnected does not steal focus  
7. RDP: local UIA does not claim remote controls (documented gap)  
8. x64 evidence pack  
9. ARM64 evidence pack  

## Feature matrix (compile)

| Command | Expectation |
|---------|-------------|
| `cargo check` | FocusBroker + Win32 helpers + gates 7–8 status |
| `cargo check -p surface-lab --features webview` | + WebView2 `request_focus` smoke path |
| `cargo check -p surface-lab --features rdp` | + overlay `request_focus` / FocusBroker live path |
| `cargo check -p surface-lab --features gpui` | + AccessKit a11y boot (if deps fetch) |

## Status vs pass

Lab **partial** ≠ gate checklist pass. Hardware evidence still required on x64 and ARM64 before treating gates 7–8 as migration green.
