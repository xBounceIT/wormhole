# Embedded FreeRDP surface

On macOS, RDP is rendered inside the existing connection tab. A windowless
FreeRDP adapter supplies RGBA tiles to the React canvas through the Go
controller and Electron preload. The Windows ActiveX and Linux X11 paths are
unchanged.

The adapter creates no SDL, Cocoa, or X11 window. Go continues to resolve
profiles and credentials, acquire VPN routes, supervise the process, and
release the tunnel on teardown. Passwords enter the adapter only through its
private stdin pipe. Stdout contains only a bounded binary display protocol;
native diagnostics are discarded by Go.

Each paint consists of tiles of at most 128 x 128 pixels, followed by a paint
boundary with a sequence number. The adapter matches the canvas acknowledgement before sending
another paint. While waiting it retains only a dirty flag and the current
FreeRDP framebuffer. Hide releases held input; show repaints the current
desktop. Old lifecycle IDs cannot send input into a replacement connection.

The remote display follows the canvas dimensions when the server supports
RDP display control. The canvas scales the negotiated desktop otherwise.
Native fullscreen and multimonitor window options do not escape the tab.
Unrecognized certificates are confirmed with a Wormhole-owned dialog and can
be accepted for the current connection only. Locking the workspace cancels a
pending trust decision and terminates that handshake, including reconnect retries. Strict certificate profiles cannot override validation. Text clipboard redirection remains in the native
adapter, without exposing clipboard contents in renderer state.

## Building the display adapter

FreeRDP provisioning is separate. `npm run build:rdp-canvas` reuses the
already configured FreeRDP source builds under
`obj/macos-freerdp/{x64,arm64}-osx`, adds the adapter target, and stages one
universal `dist-electron/wormhole-freerdp-host` binary. The macOS package
prehook runs this step; it does not download or install FreeRDP. Development
can point `WORMHOLE_FREERDP_HOST` at an adapter built against an installed
FreeRDP 3.33 SDK with the standalone CMake project under
`tools/wormhole-freerdp-host`.

## Verification

`tests/rdp-canvas.test.ts` covers pixel/input validation, scaling, keyboard
mapping, queue ordering, overload, and failure recovery using Node coverage.
`tests/rdp-canvas-surface.test.ts` exercises the real mounted RDP surface in
Electron, including pixels, input, stale events, tab hiding, lock and retry,
and measures V8 coverage. Backend tests exercise binary framing, malformed
data, input validation and actual child process startup/exit with Go coverage.

The native FreeRDP callbacks require platform integration verification against
a real RDP server. Node/Go coverage does not instrument external FreeRDP or
the platform-dependent display callbacks; they are excluded from those
percentages. The standalone native wire tests measure the bounded C parser
separately. A successful synthetic canvas test is not a real macOS RDP login.
