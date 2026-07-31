# Terminal bridge — wormhole-terminal ↔ WebView2 / xterm.js

**Status:** LabOnly / Partial — codec + session trait + output backpressure +
host clipboard paste helpers + paste→session write glue stub green; auto-sudo
prompt **detector** + session **glue stub** (`FakeTerminalSession` inject) live
in `wormhole-ssh`. Full pump orchestration still C# (`TerminalBridge`);
surface-lab gate 5 posts `f:` / `d:` but does **not** claim WebView2 paste
assembly or product SSH-tab parity.  
**Date:** 2026-07-31  
**Assets:** [Assets/web/README.md](../../Assets/web/README.md)  
**Ledgers:** [adversarial-ledger-terminal-bridge.md](adversarial-ledger-terminal-bridge.md)
(codec / gate 5),
[adversarial-ledger-clipboard-auto-sudo.md](adversarial-ledger-clipboard-auto-sudo.md)
(HostClipboard + auto-sudo detector),
[adversarial-ledger-terminal-paste.md](adversarial-ledger-terminal-paste.md)
(chunking / Debug redaction),
[adversarial-ledger-clipboard-paste.md](adversarial-ledger-clipboard-paste.md)
(paste → session write glue)

> **Honest LabOnly:** unit-tested wire types, clipboard helpers, and
> Fake-backed paste→session write glue ≠ a Rust `TerminalBridge` pump, ≠
> gate-checklist hardware pass, ≠ shipping SSH tab. Gate 5 `STATUS` is
> `Partial` when `--features webview` is on; note text still says clipboard
> paste assembly is lab-partial.

## Wire protocol

Must stay in sync across:

| Layer | Path |
|---|---|
| C# codec | `Interop/Terminal/TerminalBridgeMessages.cs` |
| C# pump | `Interop/Terminal/TerminalBridge.cs` |
| Page | `Assets/web/bridge.js` + `terminal.html` |
| Rust codec | `rust/crates/wormhole-terminal` |

### Host → page

| Frame | Meaning |
|---|---|
| `d:<stream>:<frame>:<b64>` | Live output |
| `q:<stream>:<frame>:<b64>` | Side-effect-free replay |
| `f:<stream>` | Ordered focus barrier |
| `k:<stream>` | Neutral parser barrier |
| `x:<stream>` | Immediate retirement boundary |
| `clear:` / `clear:<stream>` | Ordered reset (incl. scrollback) |
| `paste-drain:<id>` | Release JS paste gate |
| `paste-begin:<id>:<force>:<bytes>` | Start clipboard paste |
| `paste-chunk:<id>:<b64>` | Paste body chunk |
| `paste-end:<id>` / `paste-cancel:<id>` | Finish / cancel paste |

### Page → host

| Frame | Meaning |
|---|---|
| `ready:COLSxROWS` | One-shot usable layout handshake |
| `a:<stream>:<frame>` | Output frame parsed (ACK credit) |
| `b:<stream>:<u\|p>:<b64>` | User / parser input |
| `r:<stream>:<cols>x<rows>` | Geometry after ready / focus |
| `focus:<stream>` / `barrier:<stream>` | Focus / parser barrier complete |
| `p:<id>:<0\|1>` | Paste request |
| `c:<b64>` | Selection copy candidate |
| `error:…` / `fatal:…` | Init / protocol / write / clear / barrier failures |
| `z:collapsed-fit:…` | Safe layout diagnostic |

Size caps and watermarks mirror `TerminalBridge`:

- `MAX_OUTPUT_FRAME_BYTES` = 128 KiB  
- `HIGH_WATERMARK_BYTES` / `LOW_WATERMARK_BYTES` = 512 / 128 KiB (hysteresis)  
- clipboard / selection / wire caps as in `wormhole_terminal::messages`

## Rust crate surface (`wormhole-terminal`)

- `encode_message` / `decode_message` / `classify_sessionless_replay_message`
- `try_parse_scoped_geometry` (C# `TryParseScopedGeometry` + usable mins)
- `OutputBackpressure` → `BackpressureAction::{Pause,Resume}` for
  `TerminalSession::pause_reading` / `resume_reading` (`high > low` required)
- Golden vectors ported from `Wormhole.Tests/Interop/Terminal/TerminalBridgeMessagesTests.cs`
- **Host clipboard** (`HostClipboard` + `FakeClipboard`; paste assembly via
  `build_paste_transaction` / `read_paste_text`). Win32
  `CF_UNICODETEXT` stub: `Win32Clipboard` behind feature `clipboard-win`
  (`cfg(windows)` only; default build has no Win32 backend). Paste runs only
  on page `PasteRequest` (`p:`) — the host never auto-sends clipboard into the
  session. Never log clipboard bodies — `FakeClipboard` / `ClipboardHook`
  `Debug` show UTF-8 length only; error strings carry op/size, not paste text.
  Chunk size mirrors C# `ClipboardPasteChunkCharacters` (16 KiB Unicode
  scalars); `utf8_char_chunks` keeps `\r\n` together (C# CRLF guard; scalars
  already keep surrogate pairs). Soft limit: exact
  `MAX_CLIPBOARD_PASTE_UTF8_BYTES` (1 MiB) is allowed; oversize →
  `ClipboardError::TooLarge` (no frames emitted; Win32 reads fail-closed — no
  silent truncation). Empty clipboard text → `ClipboardError::Empty` (C#
  `IsNullOrEmpty` skip); empty `build_paste_transaction` is still wire-legal
  (`paste-begin:…:0` + `paste-end`, no chunks). `max_chars == 0` yields no
  chunks. Write-path failures free the `HGLOBAL` when `SetClipboardData` does
  not take ownership.

- **Paste → session glue** (`paste_request_to_session` / `FakeTerminalSession`):
  page `PasteRequest` id+force → `read_paste_text` → `build_paste_transaction`
  chunk bounds → each `PasteChunk` body written via `TerminalSession::write`.
  Empty / oversize fail closed (no writes). Closing session at entry fails
  closed **before** clipboard read (Fake one-shot remains retryable). Mid-flight
  close between chunks fails closed (partial chunk writes may already have
  landed; `FakeTerminalSession::close_after_n_writes` pins this). Unexpected
  non begin/chunk/end frames → `PasteSessionError::UnexpectedFrame` (body-free;
  no further writes). Lab / unit path only — does **not** post `paste-drain` /
  `paste-begin` / `paste-chunk` / `paste-end` to WebView2 (that stays C#
  `TerminalBridge`). `PasteToSessionResult` and `FakeTerminalSession` `Debug`
  expose sizes/ids only.

**Not yet in Rust:** the live pump that drains `p:` / writes `c:`, applies
backpressure to a real session, and drives paste-drain/begin/chunk/end over
WebView2 — that remains C# `TerminalBridge` until surface cutover. Gate 5 does
not exercise paste assembly. The session-write glue above is a Fake-backed stub
for chunk-bound paste delivery tests, not product bridge parity.

## Auto-sudo detector + session glue (`wormhole-ssh`)

Related but **not** in `wormhole-terminal` (clipboard paste stays separate —
host never auto-sends clipboard into the session; Auto sudo injects the **saved
connection password** only at an echo-off sudo prompt):

| Layer | API |
|---|---|
| Detector | `wormhole_ssh::auto_sudo` — classify bounded UTF-8 tail (`TAIL_CAPACITY` = 512); never accepts/stores/sends/logs a password |
| Glue stub | `AutoSudoSessionGlue` + `FakeTerminalSession` — first output → `ELEVATION_COMMAND`; prompt → out-of-band password inject (`\r`); timeout → no send; sync write `Err` fail-closed (secret cleared). `Debug` redacts secrets |

No GPUI / live shell wiring yet. See [06-ssh-spike.md](06-ssh-spike.md),
[adversarial-ledger-clipboard-auto-sudo.md](adversarial-ledger-clipboard-auto-sudo.md), and
[adversarial-ledger-auto-sudo-session-glue.md](adversarial-ledger-auto-sudo-session-glue.md).

## surface-lab gate 5

`gate05_xterm::STATUS` = `Partial` with `--features webview` (else Blocked).
`NOTE`: Assets/web `terminal.html` via `wormhole.localhost` when vendor staged;
else echo stub — run `scripts/Fetch-WebAssets.ps1`; **clipboard paste assembly
still lab-partial**.

With `--features webview`:

1. Resolve `Assets/web` (cwd via `ChildWebViewHost::find_assets_web`, else crate
   manifest → repo root); require leaf path `Assets/web` after canonicalize
   (`is_assets_web_layout`).
2. If `xterm_vendor_ready` → navigate `http://wormhole.localhost/terminal.html`
   (wry custom protocol; **virtual host only** + path traversal rejected), wait
   briefly for `ready:`, and post `f:` / `d:` via `PostWebMessageAsString`.
3. Else if `assets_web_ready` without vendor → echo HTML stub + console **NOTE**
   pointing at `scripts/Fetch-WebAssets.ps1`.
4. Else (Assets/web not found) → same echo stub + NOTE.

IPC logs always go through `summarize_ipc_for_log` (redacts `d`/`b`/`c`/`paste*`
bodies — do not regress). Smoke result string still records
`paste/clipboard assembly still lab-partial`. `BrowserProcessExited` sets
`needs_recreate` when the environment exposes it. Interactive linger:
`SURFACE_LAB_INTERACTIVE=1`.

## Stage vendor

```powershell
powershell -NoProfile -File scripts\Fetch-WebAssets.ps1
```

`Assets/web/vendor/` is gitignored; CI / local MSBuild fetch the same pins.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-terminal
cargo test -p wormhole-terminal --features clipboard-win
cargo test -p wormhole-ssh
# Auto-sudo detector + FakeTerminalSession glue tests are always on.
cargo test -p wormhole-surface-win --features webview --lib
cargo check -p surface-lab --features webview
# Optional interactive (Evergreen WebView2 Runtime; vendor via Fetch-WebAssets.ps1):
# $env:SURFACE_LAB_INTERACTIVE = "1"
# cargo run -p surface-lab --features webview
```

LabOnly evidence only — not [gate-checklist.md](gate-checklist.md) hardware pass.
