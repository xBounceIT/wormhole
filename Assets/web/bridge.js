// Wormhole terminal bridge.
//
// Wire format (must stay in sync with Interop/Terminal/TerminalBridge.cs):
//   C# -> JS: "d:" + base64(shell-output-bytes)   (arbitrary bytes including ANSI escapes)
//   C# -> JS: "f:"                                (focus the terminal)
//   C# -> JS: "clear:"                            (full xterm.js reset incl. scrollback)
//   C# -> JS: "paste:" + base64(utf8(text))       (clipboard text in reply to a "p:" request)
//   JS -> C#: "d:" + utf8(typed-input)            (user keystrokes; C# does Encoding.UTF8.GetBytes)
//   JS -> C#: "b:" + base64(raw-input-bytes)      (non-UTF-8 terminal input)
//   JS -> C#: "r:COLSxROWS"                      (geometry after ready)
//   JS -> C#: "c:" + base64(utf8(selection))     (selection changed; C# decides whether to copy)
//   JS -> C#: "p:"                               (right-click paste request)
//   JS -> C#: "ready:COLSxROWS"                  (one-shot handshake after usable layout)
//   JS -> C#: "error:" + message                 (terminal initialization failure)
//   JS -> C#: "z:collapsed-fit:..."              (safe layout diagnostic)

(function () {
  "use strict";

  const READY_TIMEOUT_MS = 10000;
  const FIT_RETRY_DELAYS_MS = [0, 50, 150, 500, 1000, 2000, 4000, 7000, 9500];
  const MIN_USABLE_COLUMNS = 20;
  const MIN_USABLE_ROWS = 8;

  function base64ToUint8Array(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  // btoa only accepts Latin-1 — round-trip through UTF-8 so non-ASCII selections
  // (accented chars, CJK, emoji) survive the trip to C#. The encode/decode loops
  // avoid String.fromCharCode.apply (stack overflow on large selections) and the
  // deprecated escape/unescape globals.
  function utf8ToBase64(text) {
    const bytes = new TextEncoder().encode(text);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin);
  }

  function base64ToUtf8(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }

  function post(msg) {
    try {
      if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage(msg);
      }
    } catch (err) {
      console.error("Failed to post terminal message:", err);
    }
  }

  function fail(message, err) {
    if (err) {
      console.error(message, err);
    } else {
      console.error(message);
    }
    post("error:" + message);
  }

  function init() {
    const container = document.getElementById("terminal");
    if (!container || !window.Terminal) {
      fail("xterm.js bundle missing or #terminal container not found.");
      return;
    }

    const FitAddonCtor =
      (window.FitAddon && window.FitAddon.FitAddon) ||
      (window.addonFit && window.addonFit.FitAddon);
    if (!FitAddonCtor) {
      fail("xterm.js fit addon is missing.");
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

    const fit = new FitAddonCtor();
    term.loadAddon(fit);
    term.open(container);

    term.onData(function (data) {
      post("d:" + data);
    });

    // term.onBinary fires for non-UTF-8 input (notably legacy X10/X11 mouse reports).
    // The payload is a binary string, each charCodeAt is a byte 0..255, which btoa can
    // base64-encode directly. The host decodes "b:" as raw bytes (no UTF-8 round-trip).
    if (typeof term.onBinary === "function") {
      term.onBinary(function (data) {
        try {
          post("b:" + btoa(data));
        } catch (err) {
          console.error("Failed to encode binary input:", err);
        }
      });
    }

    // xterm fires onSelectionChange on every pixel of a mouse drag, so debounce on the
    // trailing edge — otherwise a single drag would hammer the Windows clipboard dozens of
    // times and pollute clipboard-history apps. Mirrors the 50ms resize debounce below.
    // Empty selections (deselect click) are dropped so toggling off doesn't leave stale text.
    if (typeof term.onSelectionChange === "function") {
      let selectionTimer = 0;
      term.onSelectionChange(function () {
        if (selectionTimer) window.clearTimeout(selectionTimer);
        selectionTimer = window.setTimeout(function () {
          try {
            if (!term.hasSelection()) return;
            const sel = term.getSelection();
            if (!sel) return;
            post("c:" + utf8ToBase64(sel));
          } catch (err) {
            console.error("Failed to report selection:", err);
          }
        }, 50);
      });
    }

    // Right-click pastes unconditionally; preventDefault keeps WebView2's chrome menu
    // from showing in Debug builds (it's already disabled in Release).
    container.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      post("p:");
    });

    let readySent = false;
    let readyTimer = 0;
    let resizeTimer = 0;
    let lastReportedGeometry = "";
    let lastIgnoredGeometry = "";

    function dimensionsText(dimensions) {
      return dimensions.cols + "x" + dimensions.rows;
    }

    function hasUsableDimensions(dimensions) {
      return container.clientWidth > 0 &&
        container.clientHeight > 0 &&
        dimensions &&
        dimensions.cols >= MIN_USABLE_COLUMNS &&
        dimensions.rows >= MIN_USABLE_ROWS;
    }

    function proposedDimensions() {
      try {
        return fit.proposeDimensions();
      } catch (_) {
        return null;
      }
    }

    function fitNow(reportResize) {
      const dimensions = proposedDimensions();
      if (!hasUsableDimensions(dimensions)) {
        if (dimensions) {
          const ignored = dimensionsText(dimensions) + ":" + container.clientWidth + "x" + container.clientHeight;
          if (readySent && ignored !== lastIgnoredGeometry) {
            lastIgnoredGeometry = ignored;
            post("z:collapsed-fit:" + ignored);
          }
        }
        return;
      }

      try {
        if (term.cols !== dimensions.cols || term.rows !== dimensions.rows) {
          term.resize(dimensions.cols, dimensions.rows);
        }
      } catch (_) {
        return;
      }

      const fitted = dimensionsText(dimensions);

      if (!readySent) {
        readySent = true;
        lastReportedGeometry = fitted;
        if (readyTimer) {
          window.clearTimeout(readyTimer);
          readyTimer = 0;
        }
        post("ready:" + fitted);
        return;
      }

      if (reportResize && fitted !== lastReportedGeometry) {
        lastReportedGeometry = fitted;
        post("r:" + fitted);
      }
    }

    function scheduleFit(delay, reportResize) {
      const run = function () {
        window.requestAnimationFrame(function () {
          fitNow(reportResize);
        });
      };

      if (delay <= 0) {
        run();
      } else {
        window.setTimeout(run, delay);
      }
    }

    if (window.chrome && window.chrome.webview) {
      window.chrome.webview.addEventListener("message", function (e) {
        const msg = typeof e.data === "string" ? e.data : "";
        if (msg === "f:" || msg.startsWith("f:")) {
          term.focus();
          scheduleFit(0, true);
          scheduleFit(100, true);
          scheduleFit(300, true);
          window.setTimeout(function () { term.focus(); }, 50);
          window.setTimeout(function () { term.focus(); }, 250);
          return;
        }
        if (msg === "clear:" || msg.startsWith("clear:")) {
          try {
            term.reset();
          } catch (err) {
            console.error("Failed to reset terminal:", err);
          }
          return;
        }
        if (msg.startsWith("d:")) {
          try {
            term.write(base64ToUint8Array(msg.slice(2)));
          } catch (err) {
            console.error("Failed to decode shell output:", err);
          }
          return;
        }
        if (msg.startsWith("paste:")) {
          try {
            // term.paste applies bracketed-paste mode when the shell enabled it, so
            // multi-line pastes are safe; it also normalizes CRLF to LF.
            term.paste(base64ToUtf8(msg.slice(6)));
          } catch (err) {
            console.error("Failed to apply paste:", err);
          }
        }
      });
    }

    if (window.ResizeObserver) {
      const observer = new ResizeObserver(function () {
        if (resizeTimer) window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(function () {
          scheduleFit(0, true);
          scheduleFit(150, true);
        }, 50);
      });
      observer.observe(container);
    }

    window.addEventListener("resize", function () {
      if (resizeTimer) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(function () {
        scheduleFit(0, true);
      }, 50);
    });

    // Full-screen TUI apps (nano, vim, less, htop) switch to the alternate screen
    // buffer and back. The #terminal container's pixel size doesn't change across
    // that switch, so neither the ResizeObserver nor window.resize fires — if the
    // grid drifted while the alt buffer was active, nothing re-fits on exit and the
    // restored shell repaints into a stale sub-rectangle of the canvas. Re-fit on
    // every buffer switch to snap cols/rows (and the remote PTY via "r:") back to
    // the real canvas size; the delayed second fit covers a transient layout settle.
    if (term.buffer && typeof term.buffer.onBufferChange === "function") {
      term.buffer.onBufferChange(function () {
        scheduleFit(0, true);
        scheduleFit(50, true);
      });
    }

    readyTimer = window.setTimeout(function () {
      if (!readySent) {
        fail("Terminal did not receive a usable layout size.");
      }
    }, READY_TIMEOUT_MS);

    FIT_RETRY_DELAYS_MS.forEach(function (delay) {
      scheduleFit(delay, false);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
