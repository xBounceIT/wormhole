# Wormhole terminal WebView assets

Checked in:

- `terminal.html` — xterm host page (CSP + `#terminal` container)
- `bridge.js` — WebView2 ↔ native wire protocol (must stay in sync with
  `Interop/Terminal/TerminalBridgeMessages.cs` and `wormhole-terminal`)

**Not** checked in (gitignored): `vendor/` — xterm.js + fit addon binaries.

## Stage vendor (required for surface-lab gate 5 UI)

From the repo root (PowerShell):

```powershell
powershell -NoProfile -File scripts\Fetch-WebAssets.ps1
```

This downloads pinned `@xterm/xterm@6.0.0` and `@xterm/addon-fit@0.11.0` into
`Assets/web/vendor/` and verifies SHA-256 (see the script for hashes / mirrors).

MSBuild already invokes the same script when building the WinUI app. Rust
`surface-lab --features webview` gate 5 looks for:

- `vendor/xterm/xterm.js`
- `vendor/xterm/xterm.css`
- `vendor/addon-fit/addon-fit.js`
- `bridge.js` + `terminal.html`

If vendor is missing, gate 5 falls back to an echo IPC stub and prints a clear
`NOTE` pointing at this script. Protocol codec tests in `wormhole-terminal` do
not need the vendor bundle.
