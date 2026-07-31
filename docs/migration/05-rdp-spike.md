# RDP ActiveX owned-overlay spike (Rust)

**Date:** 2026-07-31  
**Status:** Spike under `wormhole-surface-win` feature `rdp`  
**C# references:** `Interop/Rdp/*`, `Services/RdpSessionService.ConfigureAsOwnedOverlay`, `Services/Rdp/RdpCrashSentinelService.cs`, `RdpHostForm.Configure`, `RdpSessionViewModel` tunnel guards  
**Design parent:** [native-surface-broker.md](native-surface-broker.md)

## Mandatory architecture

RDP is an **owned top-level overlay**, not a WinUI/GPUI child:

| Step | Win32 |
|------|--------|
| Window style | `WS_POPUP` (never `WS_CHILD` / `SetParent`) |
| Owner | `SetWindowLongPtr(GWLP_HWNDPARENT, ownerHwnd)` |
| Taskbar / Alt-Tab | OR `WS_EX_TOOLWINDOW` |
| Activatable | Do **not** set `WS_EX_NOACTIVATE` |
| Show / move | `ShowWindow(SW_SHOWNA)` / `SetWindowPos(…, SWP_NOACTIVATE)` |
| Threading | Dedicated **STA** thread + `OleInitialize` + message pump for OCX |

Reparenting into the shell HWND composites the OCX **behind** DirectComposition (airspace).

## What works (this spike)

| Piece | Status |
|-------|--------|
| Owned overlay HWND (`GWLP_HWNDPARENT` + `WS_EX_TOOLWINDOW`) | **Works** |
| CLSID probe MsRdpClient **11 → 10 → 9** | **Works** |
| `OleInitialize` STA + CoCreate | **Works** |
| `IOleClientSite` + `IOleInPlaceSite` site for overlay HWND | **Works** |
| `IOleObject::SetClientSite` + `DoVerb(OLEIVERB_INPLACEACTIVATE)` | **Works** (same STA as overlay) |
| Connection-point sink stub (`OnConnected` / `OnDisconnected` / `OnFatalError`) | **Works** (Advise + IDispatch Invoke) |
| Crash sentinel Mark before Connect / Clear on Connected **and** Disconnected / FatalError | **Works** (`set_on_sentinel_clear`) |
| Connect stub via IDispatch (`Server` / `RDPPort` / `Connect`) | **Works** |
| CredSSP / AdvancedSettings configure (`RdpOcx::configure`) | **Works** (soft-fail CredSSP / Negotiate stubs) |
| Tunnel + gateway / external / strict-auth validation helper | **Works** (`validate_tunnel_rdp_policy` / `validate_rdp_gateway_tunnel_combo` → `Err`) |
| BindLocalForwarder dial-target selection stub | **Works** (`select_rdp_connect_target` / `prepare_rdp_connect_target` — Direct vs LocalForwarder; SOCKS-only rejected; Fake; policy before bind) |
| Layout → `ResolutionDebouncer` → Fake resize glue | **Works** (`RdpResolutionLayoutGlue` / `FakeRdpResizeSurface`; coalesce + min-dim / NaN fail-closed; **no** OCX) |
| Password via `Zeroizing` + clear-after-`ClearTextPassword` put | **Works** (never logged; Debug redacts) |
| CredSSP password wipe ↔ connect-attempt Fake glue | **Works** (`RdpCredSspConnectGlue` / `FakeRdpCredSspSurface`; wipe on success / fail / cancel; **no** OCX) |
| ConnectionProfile display + common redirects → Fake configure | **Works** (`RdpDisplayRedirectGlue` / `FakeRdpPropertySurface`; loud desktop axes fail-closed; TrySet soft-skip; **no** OCX) |
| Brief STA message pump after Connect | **Works** (`pump_messages`) |
| Drop order Unadvise → Close → revoke site → destroy overlay HWND | **Works** (OCX before host) |

## Deliberately deferred

| Piece | Why deferred |
|-------|----------------|
| Audio / performance / bitmap-cache / keyboard-hook Configure surface | Soft-optional polish beyond display + common redirects Fake glue |
| Live OCX apply of display/redirect Fake puts | Fake glue only; wire into `RdpOcx::configure` later |
| RD Gateway (`TransportSettings2`) apply | Rejected when tunnel on; full gateway apply stays app-layer |
| Wire `ResolutionDebouncer` → live `UpdateSessionDisplaySettings` | Layout→debouncer→Fake glue landed; live OCX apply still needs Connected session |
| SmartSizing re-assert on every resize | Non-fatal polish after bounds pipeline |
| Full `IMsTscAxEvents` surface (LoginComplete, AutoReconnect*, …) | Stub covers lifecycle trio only |
| Owner subclass (`WM_WINDOWPOSCHANGED`) sync-move | Broker layout gate |
| Focus on AxHost **child** HWND (vs overlay) | After reliable child HWND discovery |
| Broker layout ticks driving a live `RdpOverlayHost` | Later broker integration |

## Configure (CredSSP / AdvancedSettings)

Parity target: C# `RdpHostForm.Configure` core setters used at connect.

| Property | Where | Loud / soft |
|----------|--------|-------------|
| `Server` | OCX | Loud |
| `UserName` / `Domain` | OCX (if non-empty) | Loud |
| `DesktopWidth` / `DesktopHeight` / `ColorDepth` | OCX | Loud (`ColorDepth` normalised 8/15/16/24/32 else 32) |
| `RDPPort` | `AdvancedSettings9` → `AdvancedSettings2` | Loud |
| `EnableCredSspSupport` | AdvancedSettings | **Soft** — missing name → `ConfigureReport.cred_ssp_soft_missed` + NLA-risk message (OCX default is `false`) |
| `NegotiateSecurityLayer` | AdvancedSettings (optional stub) | **Soft** when `Some(...)` — recorded in `negotiate_applied` |
| `ClearTextPassword` | AdvancedSettings | Loud when password present; buffer is `Zeroizing<String>`, wiped on **every** configure exit (Ok or Err), including validation failures |

### Password wipe ↔ connect lifecycle (Fake glue)

Session-shaped attempts may be **cancelled** before Connect or fail after a configure-shaped
put. Live `RdpOcx::configure` already wipes on every configure exit; the Fake glue
`RdpCredSspConnectGlue` / `RdpCredSspConnectAttempt` pins the same
`WipePasswordOnDrop` helper around a full attempt:

| Exit | Wipe? |
|------|--------|
| Fake configure + Connect Ok | Yes (after put) |
| Validation / Fake configure Err | Yes (leftover via guard) |
| Fake Connect Err (after put) | Yes (put path zeroized; guard empty) |
| Cancel / Drop without `run` | Yes (`Attempt` Drop → `WipePasswordOnDrop`) |

`FakeRdpCredSspSurface` records put **counts** only — never retains the password string.
`Debug` on options / attempt / Fake / glue errors redacts or omits the secret. No live OCX;
OLE / CredSSP configure core is unchanged. Soft CredSSP miss still Fake-Connects (parity with
`RdpOcx::configure_and_connect`); callers must inspect `ConfigureReport::has_cred_ssp_risk()`
before treating the attempt as safe. Explicit `cancel` bumps `cancel_count`; bare Drop without
`run` still wipes but does not bump the counter.

```rust
use wormhole_surface_win::rdp::{RdpConfigureOptions, RdpCredSspConnectGlue};

let mut glue = RdpCredSspConnectGlue::with_fake();
let mut opts = RdpConfigureOptions::new("host", 3389).with_password(secret);
let _report = glue.attempt_connect(&mut opts)?; // wipe on Ok or Err
assert!(opts.password.is_none());
// glue.cancel_attempt(&mut opts); // wipe without Connect
```

### Display + common redirects (Fake configure glue)

Parity target: C# `RdpHostForm.Configure` display / redirection subset (not CredSSP, not
gateway, not audio/performance). Maps `wormhole_domain::ConnectionProfile` onto
`FakeRdpPropertySurface` puts — **no** live OCX / `mstscax`.

| Property | Loud / soft | Notes |
|----------|-------------|--------|
| `DesktopWidth` / `DesktopHeight` | **Loud** | Resolved via `resolve_connect_desktop_size` (`RdpDesktopSizeResolver` parity); then fail-closed by `validate_desktop_axes` (positive, ≤ `MAX_DESKTOP_AXIS` = 16384) |
| `ColorDepth` | **Loud** | `normalise_color_depth` (existing configure helper) |
| `SmartSizing` | Soft (always `true`) | TrySet-style skip when Fake scripts miss |
| `UseMultimon` | Soft | Profile `rdp_use_all_monitors` |
| `RedirectClipboard` / `Printers` / `SmartCards` / `Ports` / `Devices` | Soft | Profile redirect bools |
| `RedirectDrives` | Soft | `""` → off; `"all"` → on; `"C,D"` → on + `DriveCollection` filter |
| `DriveCollection` | Soft | Custom letters only; soft-miss → force `RedirectDrives=false` (least privilege, C# catch path); master soft-miss → skip collection |

`DisplayRedirectReport::redirect_drives_master` is the **final** Fake master enable (`last_applied == "true"`), not raw `redirect_drives` intent — so DriveCollection soft-miss / RedirectDrives soft-miss both report `false`.
Unknown / scripted-missing soft props soft-skip into `DisplayRedirectReport::soft_skips`
(never hard-`Err`). Hostile fixed sizes such as `16385x768` (and full-content surface/fallback over `MAX_DESKTOP_AXIS`) fail closed **before** any put.
Does **not** rewrite CredSSP wipe / OLE configure core.

Adversarial review: [adversarial-ledger-rdp-display-redirect.md](adversarial-ledger-rdp-display-redirect.md).

```rust
use wormhole_domain::ConnectionProfile;
use wormhole_surface_win::rdp::{DesktopSizeContext, RdpDisplayRedirectGlue};

let mut glue = RdpDisplayRedirectGlue::with_fake();
let profile = ConnectionProfile { /* rdp_screen_size, redirects, … */ ..Default::default() };
let report = glue.apply_from_profile(&profile, DesktopSizeContext::with_surface(1024, 768))?;
// report.soft_skips lists TrySet misses; report.desktop_width/height are resolved axes
```

```rust
use wormhole_surface_win::rdp::{
    RdpConfigureOptions, RdpOcx, validate_rdp_gateway_tunnel_combo, validate_tunnel_rdp_policy,
    TunnelRdpPolicy,
};

// Gateway-only (C# `TunnelEnabled && RdpGatewayUsageMethod != 0`):
// 0=Direct Ok; 1=Always / 2=Detect / 3=DefaultRdg / any nonzero → Err(Gateway)
validate_rdp_gateway_tunnel_combo(true, 0)?; // Ok — usage Never
// validate_rdp_gateway_tunnel_combo(true, 3)?; // Err(Gateway) — DefaultRdg
// validate_rdp_gateway_tunnel_combo(false, 1)?; // Ok — tunnel off always allows

// Full session-layer guard — reject AGENTS.md tunnel combos before CoCreate/Connect:
validate_tunnel_rdp_policy(TunnelRdpPolicy {
    tunnel_enabled: true,
    use_external_client: false,
    gateway_usage_method: 0,   // non-zero → Err(Gateway)
    server_authentication: 2,  // 1 = Require → Err(StrictServerAuth)
})?;

let mut opts = RdpConfigureOptions::new("host", 3389)
    .with_password(secret); // never log; wiped after put / any configure exit
opts.enable_cred_ssp = true;
opts.negotiate_security_layer = Some(false);
let report = ocx.configure(&mut opts)?;
assert!(opts.password.is_none());
// report.cred_ssp_soft_missed / soft_failures may list missing CredSSP/Negotiate on old CLSID tiers.
// Do not Connect after hard Err or unacked CredSSP soft miss — OCX may be partially mutated.
```

Input validation (`validate_rdp_configure_options`, also run inside `configure`):

- server: non-empty after trim, ≤1024 chars, no NUL  
- port: non-zero  
- username / domain / password: length caps + no NUL (password errors never echo the secret)  
- desktop width/height: positive and ≤16384  

### Tunnel rejection (parity with AGENTS.md / `RdpSessionViewModel`)

When `tunnel_enabled`, the loopback forwarder cannot safely combine with:

1. **External `mstsc.exe`** — host network bypass  
2. **RD Gateway** (`gateway_usage_method != 0`) — gateway HTTPS bypasses the forwarder  
3. **Strict server authentication** (`server_authentication == 1` / Require) — OCX validates the loopback name  

C# `RdpGatewayUsageMethod` (`ConnectionProfile`): `0=Direct` (never), `1=Always`, `2=Detect`, `3=DefaultRdg`. The Rust helpers reject **any** nonzero `i32` (including negatives / `i32::MAX`), matching C# `!= 0` — not a closed enum match that could false-Ok an unknown value.

C# `RdpServerAuthentication`: `0=NoAuth`, `1=Require`, `2=Warn/prompt` (default). Only `== 1` is rejected with a tunnel (C# `AttachAsync_TunnelEnabled_StrictServerAuthenticationFailsClosed` / `…WarnServerAuthenticationIsAllowed`); every other `i32` — including `0` / `2` / `3` / `-1` / `i32::MAX` / `i32::MIN` — is allowed — matching C# `== 1`, not a closed allow-list that could false-reject Warn/NoAuth.

`validate_rdp_gateway_tunnel_combo(tunnel_enabled, gateway_usage_method)` is the focused C# parity check for (2).  
`validate_tunnel_rdp_policy` covers all three and returns `Err(TunnelRdpConflict::…)` with the same user-facing strings as C# (`TunnelExternalClientUnsupportedMessage` / `TunnelGatewayUnsupportedMessage` / `TunnelStrictServerAuthUnsupportedMessage`). Priority when multiple apply (C# connect-guard order): External → Gateway → Strict (never a false `Ok`). Gateway is checked **before** strict auth; External still wins over Gateway **and** over Strict (even when gateway usage is Direct/`0`). Gateway rejection inside the full policy delegates to `validate_rdp_gateway_tunnel_combo` (same `Gateway` / message identity). External and Strict rejection message identity is pinned to the C# constant text via unit tests (`use_external_client` is the **effective** resolved bool — C# `ShouldUseExternalClientAsync` AAD auto-detect stays deferred; no live mstsc).

These helpers are **pure policy** (no COM, no mstscax, not a hardware / gate-6 lab requirement). Unit tests under `cargo test -p wormhole-surface-win --features rdp` cover them — they are **not** part of the gate-6 OLE/overlay hardware lab.

**Re-audit pin (2026-07-31):** gateway + tunnel reject stub is solid (`configure.rs` + `prepare_rdp_connect_target` before Fake bind). No further glue needed; session wiring stays deferred (no `wormhole-surface-win` dep from `wormhole-session`). See [adversarial-ledger-rdp-gateway.md](adversarial-ledger-rdp-gateway.md) — parent adversarial **SKIP**.

**Re-audit pin (2026-07-31):** external `mstsc.exe` + tunnel reject stub is solid (`validate_tunnel_rdp_policy` External-first + `prepare_rdp_connect_target` before Fake bind / SOCKS). One test-oracle pin added (C# `TunnelExternalClientUnsupportedMessage` byte-match); no production policy change. Session AAD→external resolution stays deferred. See [adversarial-ledger-rdp-external.md](adversarial-ledger-rdp-external.md) — parent adversarial **SKIP**.

**Re-audit pin (2026-07-31, strict server-auth):** `server_authentication == 1` + tunnel → `StrictServerAuth` (C# message identity; non-Require allow vectors; External → Gateway → Strict priority) is solid in the same helpers — docs-only, no glue. See [adversarial-ledger-rdp-strict-auth.md](adversarial-ledger-rdp-strict-auth.md) — parent adversarial **SKIP**.

### BindLocalForwarder target selection (stub)

C# `RdpSessionViewModel.PrepareConnectProfileAsync` routes like VNC: **no tunnel → dial `host:port`**;
**tunnel present → `BindLocalForwarderAsync(host, port)` then dial `127.0.0.1:local`**.
RDP **cannot** speak SOCKS5 — there is no HTTP-style SOCKS preference and no SSH/SFTP-style
SOCKS-required path. Preferring SOCKS for the OCX dial is a mistaken path and fails closed
(`RdpConnectTargetError::SocksNotSupported` / `reject_rdp_socks_only_path`).

Rust parity lives in `wormhole_surface_win::rdp::{select_rdp_connect_target, prepare_rdp_connect_target}` +
`RdpConnectTarget::{Direct,LocalForwarder}` with `FakeTunnelForwarder` for offline unit
tests (records bind host/port; no network). `prepare_rdp_connect_target` runs
`validate_tunnel_rdp_policy` **before** any forwarder bind (and before the SOCKS reject),
matching C# connect-guard order. Live `wormhole-tunnels` bind + OCX Connect stay deferred
(session orchestrator still fails closed on RDP before establish).

These helpers are **pure dial-target selection** (no COM, no mstscax, **not** a hardware /
gate-6 lab requirement). Unit tests under `cargo test -p wormhole-surface-win --features rdp`
cover them — they are **not** part of the gate-6 OLE/overlay hardware lab.

Fail-closed before dial / after bind (no silent Direct fallback when a tunnel is present):

| Condition | Error |
|---|---|
| Empty / whitespace-only / NUL host | `InvalidHost` (no bind attempted) |
| Remote port `0` | `InvalidPort(0)` (no bind attempted) |
| External / gateway / strict policy reject | `Policy(…)` (no bind; before SOCKS check) |
| Mistaken HTTP SOCKS preference | `SocksNotSupported` (no bind) |
| `bind_local_forwarder` returns `Err` | `ForwarderBindFailed` |
| Forwarder local port `0` (incl. hostile `Ok(0)`) | `InvalidForwarderPort(0)` |

`FakeTunnelForwarder` never opens a socket; successful binds return the configured
`local_port`, and failing / zero-port fakes exercise the error rows above.

Adversarial review: [adversarial-ledger-rdp-forwarder.md](adversarial-ledger-rdp-forwarder.md).

```rust
use wormhole_surface_win::rdp::{
    prepare_rdp_connect_target, select_rdp_connect_target, FakeTunnelForwarder,
    RdpConnectTarget, TunnelRdpPolicy,
};

// No tunnel → Direct
let direct = select_rdp_connect_target("dc.local", 3389, None)?;

// Tunnel → LocalForwarder (Fake records real host/port, returns loopback listen port)
let fake = FakeTunnelForwarder::with_local_port(51515);
let fwd = select_rdp_connect_target("dc.local", 3389, Some(&fake))?;
assert!(matches!(fwd, RdpConnectTarget::LocalForwarder { .. }));

// Policy (gateway/external/strict) + optional SOCKS reject before dial/bind:
let policy = TunnelRdpPolicy {
    tunnel_enabled: true,
    use_external_client: false,
    gateway_usage_method: 0,
    server_authentication: 2,
};
let _ = prepare_rdp_connect_target("dc.local", 3389, policy, Some(&fake), false)?;
// prepare_rdp_connect_target(..., http_socks_preferred: true) → Err(SocksNotSupported)
```

## Rust modules

| Module | Role |
|--------|------|
| `wormhole_surface_win::rdp::HostBounds` | Screen physical rect; `EMPTY` / `SEED` / `is_degenerate` (C# parity) |
| `wormhole_surface_win::rdp::ResolutionDebouncer` | Trailing-edge 250 ms coalesce for desktop size (last-wins); `ApplyDesktopSize` hook; fake `MonoTime` / instant mode; **no Connect** |
| `wormhole_surface_win::rdp::RdpResolutionLayoutGlue` | Pane/broker layout size → debouncer → `FakeRdpResizeSurface` (or future OCX hook); `LAYOUT_RESOLUTION_MIN_DIM` = 8; f64 NaN fail-closed |
| `wormhole_surface_win::rdp::RdpCrashSentinel` | `%LOCALAPPDATA%\Wormhole\rdp-in-flight.json` Mark / Clear / TryReadOrphan |
| `rdp::clsid` (`rdp` feature) | Probe HKCR for MsRdpClient **11 → 10 → 9** CLSIDs |
| `rdp::configure` | `RdpConfigureOptions`, CredSSP soft stubs, `validate_rdp_gateway_tunnel_combo`, `validate_tunnel_rdp_policy` |
| `rdp::credssp_connect_glue` | `RdpCredSspConnectGlue` / `FakeRdpCredSspSurface` — password wipe on success / fail / cancel (Fake; no OCX) |
| `rdp::display_redirect_glue` | `RdpDisplayRedirectGlue` / `FakeRdpPropertySurface` — ConnectionProfile display + common redirects → Fake puts; TrySet soft-skip; desktop axes fail-closed |
| `rdp::target` | `select_rdp_connect_target` / `prepare_rdp_connect_target` — Direct vs LocalForwarder; SOCKS-only reject; `FakeTunnelForwarder` |
| `rdp::dispatch` | IDispatch put/get + soft missing-member mapping |
| `rdp::site` | `IOleClientSite` + `IOleInPlaceSite` bound to overlay HWND |
| `rdp::events` | `IMsTscAxEvents` IDispatch sink (Connected / Disconnected / FatalError) |
| `rdp::ocx::RdpOcx` | CoCreate + in-place activate + Advise + `configure` / Connect stub |
| `rdp::host::RdpOverlayHost` | Owned overlay HWND; `activate_ocx` on same STA |
| `surface-lab::gates::gate06_rdp_activex` | Lab exercises + run docs |

### Resolution debounce (pure logic)

Parity target: C# `RdpSurfaceHost` (`ResolutionDebounceMs = 250`, `_resolutionTimer` stop on Unloaded).

| Rule | Behavior |
|------|----------|
| Default delay | `RESOLUTION_DEBOUNCE_DEFAULT` = **250 ms** (`Default` / `with_default_delay`) |
| Last-wins | Each `push` replaces pending size and restarts the quiet deadline |
| Degenerate | `width == 0` or `height == 0` → skip (no schedule); negative `HostBounds` axes clamp to 0 then skip; integer axes only (no NaN) |
| Emit paths | `poll` after deadline, `flush` early, or `instant()` (`Duration::ZERO`) emit-on-push |
| Dedup | Identical to `last_emitted` suppressed until `reset_last_emitted` (Connected / AutoReconnected) |
| Cancel-on-drop | `Drop` / `cancel` discard pending — **never** flush (avoids Apply / `last_emitted` commit after teardown) |
| Connect | **Never** — hook is `ApplyDesktopSize` only; live `UpdateSessionDisplaySettings` wiring stays deferred |

Fake `MonoTime` drives unit tests (flush vs poll races, overdue drop). Layout min-size skips (C# `IsDegenerate(8)`) stay at the caller / `ApplyLayout` layer, not inside the debouncer — implemented by `RdpResolutionLayoutGlue` (`LAYOUT_RESOLUTION_MIN_DIM` = 8), which wires layout ticks into the debouncer and applies through `FakeRdpResizeSurface` (no OCX).

### Layout → debouncer → Fake resize glue

Parity target: C# `ApplyLayout` → `ScheduleResolutionRefresh` → `ApplyResolution` → `UpdateRemoteResolution` (without Connect / OCX).

| Rule | Behavior |
|------|----------|
| Min dim | `LAYOUT_RESOLUTION_MIN_DIM` = **8** (C# `IsDegenerate()` default); seed `1×1` and sub-8 skip |
| Fail-closed | Zero / sub-min / f64 NaN / ±∞ / negative → no schedule; **do not** cancel existing pending |
| Last-wins | Rapid `on_layout_*` coalesces through `ResolutionDebouncer` (deadline restarts) |
| Sink | `FakeRdpResizeSurface` records applies; production swaps `ApplyDesktopSize` for live OCX later |
| Connected reset | `on_connected_reset` clears last-emitted (C# `_lastNegotiated*`) so the same size can re-apply |
| Cancel-on-drop | Dropping glue / debouncer discards pending — never applies to the Fake |
| Connect / OCX | **Never** in this module |

CLSIDs (same as C# `AxMsRdpClient9.cs`):

- 11: `1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8`
- 10: `A0C63C30-F08D-4AB4-907C-34905D770C7D`
- 9:  `8B918B82-7985-4C24-89DF-C33AD2BBFBCD`

## Feature gate

- Default `cargo check` / `cargo run -p surface-lab` does **not** enable `rdp`.
- `mstscax` is **never** a link-time dependency — `CoCreateInstance` loads it at runtime.
- Missing OCX → runtime `Error` (acceptable for the lab).
- Uses `windows` **0.61.3** + `windows-core` **0.61.2** for `#[implement]`.
- `zeroize` **1.9.0** is pulled only with `--features rdp` (password wipe).
- `wormhole-domain` is pulled only with `--features rdp` (ConnectionProfile display/redirect Fake glue).

```toml
# wormhole-surface-win
rdp = ["dep:zeroize", "dep:wormhole-domain"]   # windows / windows-core always linked; flag gates COM/OLE modules

# surface-lab
rdp = ["wormhole-surface-win/rdp"]
```

## How to run

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust

# Always: skeleton + sentinel unit tests (no COM)
cargo check
cargo test -p wormhole-surface-win
cargo run -p surface-lab

# Gate 6 spike (OLE + overlay + configure)
cargo check -p wormhole-surface-win --features rdp
cargo test -p wormhole-surface-win --features rdp
cargo check -p surface-lab --features rdp
cargo run -p surface-lab --features rdp

# Optional: Connect stub against a lab server
$env:WORMHOLE_RDP_LAB_SERVER = "127.0.0.1"
$env:WORMHOLE_RDP_LAB_PORT = "3389"
cargo run -p surface-lab --features rdp -- --gate06-live
```

Gate 6 always exercises (with `--features rdp`):

1. `NativeSurfaceBroker` `SurfaceKind::RdpActiveX` registration  
2. Crash sentinel Mark → TryReadOrphan → Clear (temp path)  
3. STA overlay spawn + OLE in-place activate + event Advise  
4. Mark before Connect path; Clear on Connected / Disconnected / FatalError (and teardown); drop OCX before overlay HWND

`--gate06-live` additionally calls the Connect stub and pumps messages briefly.
Full login / gateway apply remain deferred. Resolution debounce **logic** (`ResolutionDebouncer`, cancel-on-drop, instant/fake-clock tests) is unit-covered without COM; layout→debouncer→`FakeRdpResizeSurface` glue (`RdpResolutionLayoutGlue`) is also unit-covered without COM. Live wiring to `UpdateSessionDisplaySettings` stays deferred. CredSSP configure + password-wipe↔connect Fake glue + display/redirect Fake glue + tunnel policy + BindLocalForwarder dial-target selection are unit-covered under `--features rdp`.

## Crash sentinel semantics (high level)

Matches C# `IRdpCrashSentinelService`:

1. **Mark** before OCX handshake touches the danger zone (tmp + atomic replace).  
2. **Clear** on Connected / Disconnected / FatalError (via `RdpEventState::set_on_sentinel_clear`) and on orderly teardown.  
3. **TryReadOrphan** at next launch **without** deleting; clear only after recovery action succeeds.  
4. Malformed JSON → delete + treat as no orphan.

OLE teardown: drop `RdpOcx` (Unadvise → `Close` → `SetClientSite(None)`) **before** destroying the overlay HWND. `run_on_sta` pairs `OleInitialize` / `OleUninitialize` with an RAII guard.

Payload shape (camelCase): `{ "nodeId", "host", "startedAtUtc" }`.
`startedAtUtc` is a unix-epoch seconds breadcrumb with a `Z` suffix (not a full calendar RFC3339 stamp).
Mark uses tmp + atomic replace (`MoveFileEx` overwrite on Windows), matching C# `File.Move(..., overwrite: true)`.
Empty / whitespace-only `nodeId` is rejected on Mark and treated as malformed on read.

## Compile / runtime expectations

| Command | Expect |
|---------|--------|
| `cargo check` | OK without `rdp` / without mstscax |
| `cargo check -p wormhole-surface-win --features rdp` | OK on Windows MSVC; needs `windows 0.61.3` |
| `cargo test -p wormhole-surface-win --features rdp` | OK — includes tunnel policy + configure soft-put + display/redirect Fake glue unit tests |
| `cargo check -p surface-lab --features rdp` | OK on Windows MSVC |
| `cargo run -p surface-lab --features rdp` | Overlay + OLE activate when mstscax registered; else prints runtime error and continues |
| `--gate06-live` | Connect may fail without a reachable RDP server / credentials — still proves API wiring |
