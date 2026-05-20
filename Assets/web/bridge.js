// Wormhole terminal bridge.
//
// Wire format (must stay in sync with Interop/Terminal/TerminalBridge.cs):
//   C# -> JS: "d:" + base64(shell-output-bytes)   (arbitrary bytes including ANSI escapes)
//   JS -> C#: "d:" + utf8(typed-input)            (user keystrokes; C# does Encoding.UTF8.GetBytes)
//   JS -> C#: "r:COLSxROWS"                        (geometry on fit / window resize)
//   JS -> C#: "ready"                              (one-shot handshake after first fit)

(function () {
  "use strict";

  function base64ToUint8Array(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function post(msg) {
    if (window.chrome && window.chrome.webview) {
      window.chrome.webview.postMessage(msg);
    }
  }

  function init() {
    const container = document.getElementById("terminal");
    if (!container || !window.Terminal) {
      console.error("xterm.js bundle missing or #terminal container not found.");
      return;
    }

    const term = new window.Terminal({
      fontFamily: '"Cascadia Mono", "Consolas", monospace',
      fontSize: 14,
      cursorBlink: true,
      allowProposedApi: true,
      theme: {
        background: "#0c0c0c",
        foreground: "#e0e0e0",
        cursor: "#e0e0e0",
      },
    });

    const FitAddonCtor =
      (window.FitAddon && window.FitAddon.FitAddon) ||
      (window.addonFit && window.addonFit.FitAddon);
    const fit = FitAddonCtor ? new FitAddonCtor() : null;
    if (fit) term.loadAddon(fit);

    term.open(container);
    if (fit) fit.fit();
    term.focus();

    term.onData(function (data) {
      post("d:" + data);
    });

    if (window.chrome && window.chrome.webview) {
      window.chrome.webview.addEventListener("message", function (e) {
        const msg = typeof e.data === "string" ? e.data : "";
        if (!msg.startsWith("d:")) return;
        try {
          term.write(base64ToUint8Array(msg.slice(2)));
        } catch (err) {
          console.error("Failed to decode shell output:", err);
        }
      });
    }

    function reportSize() {
      if (fit) {
        try { fit.fit(); } catch (_) { /* container hidden during resize */ }
      }
      post("r:" + term.cols + "x" + term.rows);
    }

    let resizeTimer = 0;
    window.addEventListener("resize", function () {
      if (resizeTimer) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(reportSize, 50);
    });

    // Send the initial geometry, then the ready handshake. Order matters: the C# side
    // attaches the bridge on "ready" and uses the latest geometry to size the PTY.
    reportSize();
    post("ready");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
