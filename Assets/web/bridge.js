// Wormhole terminal bridge.
//
// Wire format (must stay in sync with Interop/Terminal/TerminalBridge.cs):
//   C# -> JS: "d:" + base64(shell-output-bytes)   (arbitrary bytes including ANSI escapes)
//   C# -> JS: "f:"                                (focus and repaint the terminal)
//   C# -> JS: "clear:"                            (full xterm.js reset incl. scrollback)
//   C# -> JS: "paste:" + base64(utf8(text))       (clipboard text in reply to a "p:" request)
//   JS -> C#: "b:" + base64(raw-input-bytes)      (user keystrokes / binary terminal input)
//   JS -> C#: "a:N"                              (flow-control ack: xterm parsed N output bytes)
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

    // Keep the default xterm.js renderer. The WebGL addon is faster under floods, but
    // in WebView2 it can desynchronize its render model / color atlas after commands
    // with heavy ANSI color output (for example docker compose logs), leaving later
    // text painted in stale colors. PuTTY-like correctness beats GPU throughput here.

    function postInputBytes(data) {
      post("b:" + utf8ToBase64(data));
    }

    function refreshVisibleRows(rebuildAtlas) {
      try {
        if (rebuildAtlas && typeof term.clearTextureAtlas === "function") {
          term.clearTextureAtlas();
        }
        term.refresh(0, term.rows - 1);
      } catch (err) {
        console.warn("Terminal repaint failed:", err);
      }
    }

    function scheduleControlKeyRepaint() {
      window.setTimeout(function () { refreshVisibleRows(false); }, 25);
      window.setTimeout(function () { refreshVisibleRows(true); }, 120);
    }

    function scheduleHostFocusRepaint() {
      window.requestAnimationFrame(function () { refreshVisibleRows(false); });
      window.setTimeout(function () { refreshVisibleRows(false); }, 50);
      window.setTimeout(function () { refreshVisibleRows(true); }, 150);
      window.setTimeout(function () { refreshVisibleRows(false); }, 300);
    }

    term.onData(function (data) {
      postInputBytes(data);
      // CTRL+L is form feed. The remote shell/readline clears the screen in response;
      // repaint after the remote has had a short chance to echo its clear sequence so
      // the visible grid cannot lag the parser state. This does not alter terminal
      // state or swallow the key.
      if (data.indexOf("\x0c") >= 0) {
        scheduleControlKeyRepaint();
      }
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

    // --- Renderer self-heal -------------------------------------------------
    // After a high-throughput burst (e.g. a tcpdump flood), schedule a pure display-layer
    // repaint once output settles and periodically while it keeps streaming. This does
    // not write to the terminal, so cursor, parser, color attributes, and scrollback are
    // untouched; it simply asks xterm to redraw visible rows from its buffer.
    var SELF_HEAL_MIN_BURST_BYTES = 4096; // ignore interactive echo; only large coalesced bursts arm it
    var SELF_HEAL_SETTLE_MS = 180;        // repaint this long after the last burst chunk
    var SELF_HEAL_MAX_MS = 1000;          // ...but at least this often while output keeps streaming
    var selfHealSettleTimer = 0;
    var selfHealMaxTimer = 0;

    function selfHealRenderer(rebuildAtlas) {
      // A visible-row refresh is cheap enough to run periodically while output is still flowing.
      refreshVisibleRows(rebuildAtlas);
    }

    function clearSelfHealTimers() {
      if (selfHealSettleTimer) { window.clearTimeout(selfHealSettleTimer); selfHealSettleTimer = 0; }
      if (selfHealMaxTimer) { window.clearTimeout(selfHealMaxTimer); selfHealMaxTimer = 0; }
    }

    function scheduleSelfHeal() {
      // Trailing edge: fires once output goes quiet — exactly when the user starts editing. Output
      // has stopped, so do the full atlas-rebuild repaint.
      if (selfHealSettleTimer) window.clearTimeout(selfHealSettleTimer);
      selfHealSettleTimer = window.setTimeout(function () {
        clearSelfHealTimers();
        selfHealRenderer(true);
      }, SELF_HEAL_SETTLE_MS);
      // Max-wait: a continuously streaming flood never goes quiet, so guarantee a periodic repaint —
      // a cheap refresh only (no atlas churn) since output is still in flight.
      if (!selfHealMaxTimer) {
        selfHealMaxTimer = window.setTimeout(function () {
          selfHealMaxTimer = 0;
          selfHealRenderer(false);
        }, SELF_HEAL_MAX_MS);
      }
    }

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

    function fitNow(reportResize, forceReport) {
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

      let resized = false;
      try {
        if (term.cols !== dimensions.cols || term.rows !== dimensions.rows) {
          term.resize(dimensions.cols, dimensions.rows);
          resized = true;
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

      if (resized) {
        refreshVisibleRows(false);
        window.setTimeout(function () { refreshVisibleRows(true); }, 50);
      }

      if (reportResize && (forceReport || fitted !== lastReportedGeometry)) {
        lastReportedGeometry = fitted;
        post("r:" + fitted);
      }
    }

    function scheduleFit(delay, reportResize, forceReport) {
      const run = function () {
        window.requestAnimationFrame(function () {
          fitNow(reportResize, forceReport);
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
          // Force-report even when the grid has not changed. Resize messages emitted
          // while SSH is still connecting can be lost before TerminalBridge subscribes;
          // the first focus request after bridge creation must therefore resync the
          // remote PTY even if JS thinks it already reported this geometry.
          scheduleFit(0, true, true);
          scheduleFit(100, true, true);
          scheduleFit(300, true, true);
          // A WebView2 surface can come back from a TabView hide/show with xterm's
          // buffer intact but its canvas compositor black. Repaint only the display
          // layer so reactivating a tab restores pixels without replaying scrollback.
          scheduleHostFocusRepaint();
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
          let outBytes;
          try {
            outBytes = base64ToUint8Array(msg.slice(2));
          } catch (err) {
            console.error("Failed to decode shell output:", err);
            return;
          }
          try {
            // Pass a callback so xterm reports how many bytes it has parsed: that drives the C#
            // flow-control window (the "a:" ack), which pauses the SSH read pump when xterm falls
            // behind so a torrential producer can't overrun xterm's internal write buffer. Keep in
            // sync with TerminalBridge's "a:" handler / TerminalFlowController.
            term.write(outBytes, function () {
              post("a:" + outBytes.length);
            });
          } catch (err) {
            // term.write throws only if xterm's write buffer blew past its hard ~50MB discard
            // limit — flow control should prevent that, but if it ever happens the chunk is
            // dropped and the parser may be left mid-sequence. Surface it distinctly (not the
            // misleading "decode failed"), return the flow-control credit so the read pump can't
            // deadlock, and force a repaint. We deliberately do NOT term.reset() here: that wipes
            // scrollback on every hiccup — a worse regression than a one-off repaint.
            console.warn("xterm write discarded (buffer overflow); repainting to recover.", err);
            post("a:" + outBytes.length);
            selfHealRenderer(true);
          }
          // A large coalesced chunk means a burst is in progress; arm the post-burst self-heal so
          // the renderer is repainted once it settles (or periodically if it never does).
          if (outBytes.length >= SELF_HEAL_MIN_BURST_BYTES) {
            scheduleSelfHeal();
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
        scheduleFit(0, true, true);
        scheduleFit(50, true, true);
        window.setTimeout(function () { refreshVisibleRows(true); }, 75);
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
