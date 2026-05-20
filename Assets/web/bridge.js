// Wormhole terminal bridge — scaffold placeholder.
//
// When xterm.js is wired up in the SSH feature PR, this script should:
//   1. Instantiate a Terminal and FitAddon attached to #terminal.
//   2. Forward term.onData -> chrome.webview.postMessage("d:" + utf8data)
//   3. Forward FitAddon resize -> chrome.webview.postMessage("r:" + cols + "x" + rows)
//   4. Listen for chrome.webview.addEventListener("message", e => term.write(base64Decode(e.data.slice(2))))
//
// See Interop/Terminal/TerminalBridge.cs for the .NET side of the channel.
