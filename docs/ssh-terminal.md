# SSH terminal presentation

SSH uses `@xterm/xterm` with the WebGL, Fit and Unicode 11 addons. Chromium's
default renderer is the fallback when WebGL initialization fails or its context
is lost. React attaches the terminal container and controls connection states;
it does not retain output bytes, rebuild terminal cells or drive screen updates.
The xterm instance survives page and tab switches and is disposed when its
session is removed. Scrollback is limited to 5,000 lines.

Go continues to own SSH, credentials, host-key trust, VPN leases, auto-sudo,
bracketed clipboard paste and MCP replay/presentation filtering. Electron opts
SSH sessions into `terminal_stream`. Go sends filtered ANSI bytes in base64
packets of at most 16 KiB; SSH presentation bypasses the Go cell emulator.
Serial terminals and clients that do not opt into streaming retain their existing
cell protocol.

Each stream has at most 16 unacknowledged packets. The owning renderer acknowledges
after xterm parses a packet, rather than when IPC merely delivers it. Remote readers
pause outside the terminal state mutex, so paste/resize cannot block acknowledgment
processing. The bounded Go queue reserves capacity for the existing bounded MCP
filters to flush long quoted commands. Queue exhaustion closes the affected session
with an explicit error instead of silently dropping terminal bytes.

Electron validates packet size, encoding, sequence and reset geometry. It retains
unacknowledged packets while locked and replays them on unlock; acknowledgments
require the same authorized owner window. The renderer deduplicates replayed packets.
Reconnect starts with a reset packet, while resize retains xterm's history and sends
the new PTY size to Go. Closing a remote shell drains parsed output before closing,
with a bounded timeout. Shutdown wakes readers waiting for presentation capacity.

Keyboard text uses UTF-8; legacy mouse reports preserve binary bytes. Terminal
queries are answered even before the React surface mounts or while its tab is
hidden and authorized. Locked surfaces do not forward replies through the UI's
input failure handler. Native menu and Linux primary-selection paste also pass
through Go's paste validation and escape sanitization. Ctrl+C copies a selection
and otherwise reaches SSH as an interrupt.

Go coalesces pending SSH input in order, bounded to 4 MiB of queued bytes plus
one in-flight write. Bursts of small terminal-query replies do not consume a
separate queue slot per reply. Enqueueing remains nonblocking if the remote peer
stops reading. Queue overflow and remote input write failures are logged at Error
level with a session identifier and byte counts; input contents are never logged.
Input queue overflow closes the affected session, discards pending input and
clears its automatic-reconnect state. Electron receives cleanup before the final
error so terminal ownership and VPN leases are released while Reconnect remains
available to the user.

Ctrl/Cmd+V and right-click use native clipboard paste through Go. Copy-on-select
preserves the selection, and unrelated React updates do not steal focus.

## Verification

`npm run test:terminal-clipboard` includes stream validation/ownership tests and a
real Chromium harness for xterm and the production React SSH surface. The harness
checks ANSI styles/true color, split UTF-8, CJK widths, alternate screens, keyboard
and binary mouse input, clipboard behavior, history bounds, hidden tabs, resets,
focus, WebGL context loss and software fallback. It measures the application
terminal code with V8 block coverage and enforces 80%. Third-party xterm code is
excluded from that percentage.

Go tests cover byte fidelity, credits, bounded queues, blocked readers, MCP replay,
initial reset ordering, shutdown, and an actual local SSH server in both legacy and
streaming modes. `npm run test:coverage` enforces the existing Node and aggregate Go
coverage gates. Electron entrypoint adapters are exercised by source-extracted
runtime tests; their delegated stream module is measured directly by Node coverage.

Build and static gates remain `npm run build`, `npm run typecheck`, `npm run lint`
and `npm run format:check`. Responsiveness against a particular remote server or
PuTTY still requires measurement using the same server and network path.
