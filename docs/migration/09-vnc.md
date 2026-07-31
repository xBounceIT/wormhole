# VNC / RFB library spike — `wormhole-vnc`



**Status:** Raw pixel buffer + damage tracking + bounded input queue + session↔fb/input glue stub + client↔server clipboard cut-text glue stub + password-only auth glue stub + BindLocalForwarder target stub; live engine deferred behind feature  

**Date:** 2026-07-31  

**Context7 MCP:** unavailable; versions from crates.io / docs.rs.



## Parity target (C# today)



Wormhole v1 VNC (`ProtocolType.Vnc = 6`) uses `Community.MarcusW.VncClient` with:



- Auth: **no-auth** + **classic VNC password** only (`PasswordProviderAuthenticationHandler`)

- Tunnel: `BindLocalForwarderAsync` (same loopback bridge as RDP — no SOCKS)

- UI: WinUI framebuffer + pointer/keyboard mapping



## Crate audit (2026-07-31)



| Crate | Pin researched | Async | No-auth + VncAuth | Notes |

|---|---|---|---|---|

| **[`vnc-rs`](https://crates.io/crates/vnc-rs)** (lib `vnc`) | **0.5.3** | Tokio | **Yes** — `set_auth_method`; callback unused when server is None | Preferred engine. Separates protocol engine from OS UI; encodings Raw/CopyRect/Zrle/Tight |

| [`vnc`](https://crates.io/crates/vnc) (whitequark) | 0.4.0 | Sync / threads | Yes (classic client) | Coupled to `std::net::TcpStream` / threads — poorer fit for tunnel-forwarded async sockets |

| `vnc-client` | 1.0.0 | — | Unknown | Thin / stale; skip |



### Decision



**Prefer `vnc-rs` `=0.5.3`** when wiring a live client (`wormhole-vnc` feature `engine`).



Default builds **do not** pull `vnc-rs`. They ship RFB subset types + a decode/input stub surface so GPUI/app composition can compile without the engine:



- `RfbSecurityType::{None, VncAuth}` (wire values 1 / 2)

- `VncPassword` (8-**byte** classic DES limit; redacted `Debug`; no `Display`)

- **Auth glue** (`auth_glue`): no-auth vs classic VNC password select (`select_vnc_auth` / `provide_vnc_auth_input` / `FakeVncPasswordProvider`). Username/domain on `VncAuthFields` are **ignored** (C# editor hides them for VNC; `CredentialsAuthenticationInput` → `UnsupportedCredentialsAuth`). Missing / **empty** password when VncAuth required → `PasswordRequired` (fail-closed); provider cancel → `AuthCancelled`. `Debug` redacts password on fields / selection / Fake. No live RFB challenge.

- `RawPixelBuffer` — contiguous BGRA/RGBA store with **damage-rect merge** (overlapping + edge-adjacent)

- Decode stub: **Raw encoding only** via `RawPixelBuffer::blit_raw` / `apply_raw_rect` (Zrle/Tight deferred)

- `InputEventQueue` — bounded pointer/key enqueue (`DEFAULT_INPUT_QUEUE_CAPACITY = 256`); **drop policy:** full → `VncError::InputQueueFull` (queue unchanged; no silent drop / no unbounded growth). Capacity `0` is coerced to `1`.

- `FramebufferSink` / `VncInputSink` traits; `VncSession` wires buffer + queue (no TCP). Session / options `Debug` redacts nested password.

- **Session glue** (`session_glue`): pointer/key → existing `InputEventQueue` via `push_pointer_to_session` / `push_key_to_session`; Raw FB rect → `apply_framebuffer_rect` + `FramebufferDirtyNotify` (`FakeFramebufferDirtyNotify` for Lab). Fail-closed when not `Connected` (`NotConnected` — Idle / Negotiating / Closed; input after `close()` cleared); full queue → `InputQueueFull` (queue unchanged); apply errors (`InvalidFramebufferUpdate`) skip dirty notify (no partial invalidate; prior notifies retained). Orchestrator still `UnsupportedProtocol` before tunnel establish — glue does **not** open RFB.

- **Clipboard glue** (`clipboard_glue`): outbound host text → Fake `VncSession` ClientCutText queue (`send_clipboard_to_session`); inbound ServerCutText → local buffer (`apply_server_cut_text`). Soft **1 MiB UTF-8** cap (parity with terminal paste); empty / oversize fail-closed (no send / buffer unchanged); not `Connected` → `NotConnected`; `close()` clears outbound queue + local buffer. `CutTextPayload` / session `Debug` expose lengths only (secrets-adjacent — same posture as terminal paste). C# `HandleServerClipboardUpdate` is still a no-op; no OS clipboard / GPUI.

- OOB Raw blits **reject** (`InvalidFramebufferUpdate`) rather than clamping into the store; damage unions that cannot fit in `u16` expand to full-plane over-damage (never truncate to empty).

- `select_vnc_connect_target` / `VncConnectTarget::{Direct,LocalForwarder}` — tunnel dial selection stub (see below)



This mirrors the SSH spike's transport-hook style: types first, live I/O behind a feature.



### BindLocalForwarder target selection (stub)



C# `VncSessionService.ConnectAsync` routes like RDP: **no tunnel → dial `host:port`**;
**tunnel present → `BindLocalForwarderAsync(host, port)` then dial `127.0.0.1:local`**.
VNC **cannot** speak SOCKS5 — there is no HTTP-style SOCKS preference and no SFTP-style
SOCKS-required path. SOCKS on the lease is ignored; the RFB client always opens its own
TCP socket to the loopback forwarder when tunneled.



Rust parity lives in `wormhole_vnc::select_vnc_connect_target` +
`VncConnectTarget::{Direct,LocalForwarder}` with `FakeTunnelForwarder` for offline unit
tests (records bind host/port; no network). Live `wormhole-tunnels` bind + RFB connect
stay deferred (session orchestrator still fails closed on VNC before establish).



Fail-closed before dial / after bind (no silent Direct fallback when a tunnel is present):



| Condition | Error |
|---|---|
| Empty / whitespace-only / NUL host | `InvalidHost` (no bind attempted) |
| Remote port `0` | `InvalidPort(0)` (no bind attempted) |
| `bind_local_forwarder` returns `Err` | `ForwarderBindFailed` |
| Forwarder local port `0` | `InvalidForwarderPort(0)` |

`FakeTunnelForwarder` never opens a socket; successful binds return the configured
`local_port`, and failing / zero-port fakes exercise the error rows above.

Adversarial review: [adversarial-ledger-vnc-forwarder.md](adversarial-ledger-vnc-forwarder.md).



## Feature flags



| Feature | Default | Effect |

|---|---|---|

| *(none)* | — | Protocol types + password-only auth glue + Raw buffer/damage + input queue + session stub + fb/input glue + clipboard cut-text glue + forwarder target selection |

| `engine` | **off** | Pulls `vnc-rs` + tokio; exposes `VncRsEngineMarker` (presence-only; no live TCP yet) |



## Non-goals (this spike)



- Live TCP / RFB session I/O (feature `engine` is presence-only; **no** live RFB/UI parity claim)

- Live `wormhole-tunnels` `bind_local_forwarder` wiring (selection stub + Fake only)

- Orchestrator VNC connect (still `UnsupportedProtocol` / `StubVncConnector` — see [16-session-orchestrator.md](16-session-orchestrator.md))

- Hardware gate pass for VNC surfaces

- Zrle / Tight / CopyRect decode

- Advanced security types (TLS, VeNCrypt, MS Logon, …)

- GPUI pixel blit

- OS clipboard sync / live ClientCutText wire I/O (Lab Fake queue + local buffer only)



## Verification



```powershell

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

cd rust

cargo test -p wormhole-vnc

cargo test -p wormhole-vnc --features engine

```

