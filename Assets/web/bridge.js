// Wormhole terminal bridge.
//
// Wire format (must stay in sync with Interop/Terminal/TerminalBridge.cs):
//   C# -> JS: "d:" + base64(shell-output-bytes)   (arbitrary bytes including ANSI escapes)
//   C# -> JS: "f:"                                (focus the terminal)
//   JS -> C#: "d:" + utf8(typed-input)            (user keystrokes; C# does Encoding.UTF8.GetBytes)
//   JS -> C#: "b:" + base64(raw-input-bytes)      (non-UTF-8 terminal input)
//   JS -> C#: "r:COLSxROWS"                      (geometry after ready)
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
        if (!msg.startsWith("d:")) return;
        try {
          term.write(base64ToUint8Array(msg.slice(2)));
        } catch (err) {
          console.error("Failed to decode shell output:", err);
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
