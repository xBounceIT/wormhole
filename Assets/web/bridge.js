// Wormhole terminal bridge.
//
// Wire format (must stay in sync with Interop/Terminal/TerminalBridge.cs):
//   C# -> JS: "d:STREAM_ID:FRAME_ID:" + base64(live-output-bytes)
//   C# -> JS: "q:STREAM_ID:FRAME_ID:" + base64(side-effect-free-replay-bytes)
//   C# -> JS: "f:STREAM_ID"                       (ordered focus barrier)
//   C# -> JS: "k:STREAM_ID"                       (neutral parser barrier; no focus/input)
//   C# -> JS: "x:STREAM_ID"                       (immediate scoped retirement boundary)
//   C# -> JS: "clear:" or "clear:STREAM_ID"       (ordered full reset incl. scrollback)
//   C# -> JS: "paste-drain:ID", then paste-begin/chunk/end (one bounded paste)
//   JS -> C#: "p:ID:FORCE"                       (right-click paste request)
//   JS -> C#: "b:STREAM_ID:ORIGIN:" + base64(raw-input-bytes), ORIGIN=u|p
//   JS -> C#: "a:STREAM_ID:FRAME_ID"              (frame parsed by xterm)
//   JS -> C#: "focus:STREAM_ID"                   (replay parsed; focus/input safe)
//   JS -> C#: "barrier:STREAM_ID"                 (neutral parser barrier complete)
//   JS -> C#: "r:STREAM_ID:COLSxROWS"            (stream-scoped geometry after ready)
//   JS -> C#: "c:" + base64(utf8(selection))     (selection changed; C# decides whether to copy)
//   JS -> C#: "ready:COLSxROWS"                  (one-shot handshake after usable layout)
//   JS -> C#: "error:" + message                 (terminal initialization failure)
//   JS -> C#: "fatal:protocol"                   (malformed output frame; reset required)
//   JS -> C#: "fatal:write:STREAM_ID:FRAME_ID"   (xterm rejected an output frame)
//   JS -> C#: "fatal:clear" or "fatal:clear:STREAM_ID" (xterm reset failed)
//   JS -> C#: "fatal:barrier:STREAM_ID"           (neutral parser barrier failed)
//   JS -> C#: "z:collapsed-fit:..."              (safe layout diagnostic)

(function () {
  "use strict";

  const READY_TIMEOUT_MS = 10000;
  const FIT_RETRY_DELAYS_MS = [0, 50, 150, 500, 1000, 2000, 4000, 7000, 9500];
  const FOCUS_FIT_RETRY_DELAYS_MS = [0, 50, 150, 500, 1000, 2000];
  const MIN_USABLE_COLUMNS = 20;
  const MIN_USABLE_ROWS = 8;
  const MAX_SIGNED_INT64_TEXT = "9223372036854775807";
  const MAX_CLIPBOARD_PASTE_BYTES = 1024 * 1024;
  const MAX_CLIPBOARD_PASTE_CHUNKS = 128;
  const MAX_SELECTION_UTF8_BYTES = 4 * 1024 * 1024;
  const MAX_DEFERRED_INPUT_FRAME_CHARS = 128 * 1024;
  const PASTE_REQUEST_TIMEOUT_MS = 50000;
  const MAX_RETIRED_STREAM_IDS = 64;
  const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

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
  function utf8ToBase64(text, maximumBytes) {
    const bytes = new TextEncoder().encode(text);
    if (maximumBytes && bytes.length > maximumBytes) return null;
    let bin = "";
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin);
  }

  function inputToBase64(data) {
    for (let i = 0; i < data.length; i++) {
      if (data.charCodeAt(i) > 0x7f) {
        return utf8ToBase64(data);
      }
    }
    return btoa(data);
  }

  function post(msg) {
    try {
      if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage(msg);
        return true;
      }
    } catch (err) {
      console.error("Failed to post terminal message:", err);
    }
    return false;
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
      scrollback: 10000,
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

    const MAX_PENDING_PASTE_REQUESTS = 8;
    const MAX_PENDING_EXACT_INPUT_MARKERS = 64;
    const ASYNC_INPUT_MARKER_TIMEOUT_MS = 1000;
    const PASTE_GATE_TIMEOUT_MS = 15000;
    const pendingPasteRequests = [];
    const pendingExactInputMarkers = [];
    let activePasteRequest = null;
    let activePasteGateHeld = false;
    let pasteRequestTimer = 0;
    let applyingHostPaste = false;
    let deferredInputFrameCharacters = 0;
    let replayInputSuppressed = false;
    let terminalUserInputEnabled = false;
    let activeParserStreamId = null;
    let focusedInputStreamId = null;
    let activeResizeStreamId = null;
    let claimedStreamId = null;
    const retiredStreamIds = new Set();
    const retiredStreamOrder = [];
    let resizeOperationGeneration = 0;
    let synchronousDomUserInputDepth = 0;

    function freezePostReadyAutoFit() {
      activeResizeStreamId = null;
      resizeOperationGeneration = resizeOperationGeneration >= Number.MAX_SAFE_INTEGER
        ? 1
        : resizeOperationGeneration + 1;
      if (resizeTimer) {
        window.clearTimeout(resizeTimer);
        resizeTimer = 0;
      }
    }

    function blurTerminalWithoutInput() {
      terminalUserInputEnabled = false;
      const previousSuppression = replayInputSuppressed;
      replayInputSuppressed = true;
      try { term.blur(); } catch (_) { }
      replayInputSuppressed = previousSuppression;
    }

    function removeQueuedPasteOperations(keepInput) {
      for (let i = outputOperations.length - 1; i >= 0; i--) {
        const operation = outputOperations[i];
        if (operation.kind === "pasteRequest" || operation.kind === "pasteApply") {
          outputOperations.splice(i, 1);
        } else if (!keepInput && operation.kind === "input") {
          deferredInputFrameCharacters -= operation.frame.length;
          outputOperations.splice(i, 1);
        } else if (!keepInput && operation.kind === "inputBatch") {
          deferredInputFrameCharacters -= operation.frameCharacters;
          outputOperations.splice(i, 1);
        }
      }
      if (deferredInputFrameCharacters < 0) deferredInputFrameCharacters = 0;
    }

    function resetPasteRequestTimer() {
      if (pasteRequestTimer) {
        window.clearTimeout(pasteRequestTimer);
        pasteRequestTimer = 0;
      }
    }

    function resetActivePasteRequest() {
      resetPasteAssembly();
      resetPasteRequestTimer();
      activePasteRequest = null;
      activePasteGateHeld = false;
    }

    function enqueueRequestInput(request) {
      if (request.deferredInputFrames.length === 0) return;
      // Keep a cancelled request as one queue operation. A stalled clipboard request can
      // legally accumulate thousands of one-byte key/mouse reports; one operation per frame
      // would recurse through the synchronous drain and could overflow the WebView stack.
      outputOperations.push({
        kind: "inputBatch",
        frames: request.deferredInputFrames,
        frameCharacters: request.deferredInputFrameCharacters,
      });
    }

    function postRequestInputNow(request) {
      for (let i = 0; i < request.deferredInputFrames.length; i++) {
        const frame = request.deferredInputFrames[i];
        deferredInputFrameCharacters -= frame.length;
        if (!postProtocolMessage(frame, "forwarding deferred terminal input")) break;
      }
      if (deferredInputFrameCharacters < 0) deferredInputFrameCharacters = 0;
    }

    function dropRequestInput(request) {
      deferredInputFrameCharacters -= request.deferredInputFrameCharacters;
      if (deferredInputFrameCharacters < 0) deferredInputFrameCharacters = 0;
    }

    function scheduleNextPasteRequest() {
      if (activePasteRequest || pendingPasteRequests.length === 0) return;
      const next = pendingPasteRequests[0];
      if (next.scheduled) return;
      next.scheduled = true;
      outputOperations.push(next);
    }

    function completeActivePasteRequest(requestId, flushInput, finishCurrentOperation) {
      if (!activePasteRequest ||
          requestId === null ||
          requestId !== activePasteRequest.requestId) {
        return false;
      }

      const completed = activePasteRequest;
      const pendingIndex = pendingPasteRequests.indexOf(completed);
      if (pendingIndex >= 0) pendingPasteRequests.splice(pendingIndex, 1);
      resetActivePasteRequest();
      if (flushInput) {
        if (finishCurrentOperation) {
          postRequestInputNow(completed);
        } else {
          enqueueRequestInput(completed);
        }
      } else {
        dropRequestInput(completed);
      }
      scheduleNextPasteRequest();
      if (finishCurrentOperation) {
        finishOutputOperation();
      } else {
        drainOutputOperations();
      }
      return true;
    }

    function cancelAllPasteRequests(flushInput) {
      const requests = pendingPasteRequests.slice();
      const releaseHeldGate = activePasteGateHeld;
      pendingPasteRequests.length = 0;
      pendingExactInputMarkers.length = 0;
      synchronousDomUserInputDepth = 0;
      removeQueuedPasteOperations(flushInput);
      resetActivePasteRequest();
      if (flushInput) {
        for (let i = 0; i < requests.length; i++) enqueueRequestInput(requests[i]);
      } else {
        deferredInputFrameCharacters = 0;
      }
      if (releaseHeldGate) outputWriteActive = false;
    }

    function postInputFrame(encodedPayload, isUserInput) {
      if (replayInputSuppressed) return;
      if (isUserInput && !terminalUserInputEnabled) return;
      const streamId = isUserInput ? focusedInputStreamId : activeParserStreamId;
      if (!streamId) return;

      // Input carries both the stream and its independently classified origin. A retiring native
      // bridge drains parser DA/DSR/CPR replies but must reject human/paste/focus input even when
      // a late DOM event still carries the old stream.
      const origin = isUserInput ? "u" : "p";
      const frame = "b:" + streamId + ":" + origin + ":" + encodedPayload;
      // Protocol replies generated while parsing backend output must remain immediate. Genuine
      // keyboard/IME/mouse input is marked independently and held behind the user's paste gesture.
      if (isUserInput && pendingPasteRequests.length > 0 && !applyingHostPaste) {
        if (deferredInputFrameCharacters + frame.length >
            MAX_DEFERRED_INPUT_FRAME_CHARS) {
          console.warn("Cancelled a stalled paste transaction to preserve terminal input.");
          cancelAllPasteRequests(true);
          outputOperations.push({ kind: "input", frame: frame });
          deferredInputFrameCharacters += frame.length;
          drainOutputOperations();
          return;
        }
        const request = pendingPasteRequests[pendingPasteRequests.length - 1];
        request.deferredInputFrames.push(frame);
        request.deferredInputFrameCharacters += frame.length;
        deferredInputFrameCharacters += frame.length;
        return;
      }
      postProtocolMessage(frame, "forwarding terminal input");
    }

    function postInputBytes(data, isUserInput) {
      postInputFrame(inputToBase64(data), isUserInput);
    }

    function removeExactInputMarker(marker) {
      const index = pendingExactInputMarkers.indexOf(marker);
      if (index >= 0) pendingExactInputMarkers.splice(index, 1);
    }

    function enqueueExactInputMarker(data) {
      if (typeof data !== "string" || !data) return null;
      if (pendingExactInputMarkers.length >= MAX_PENDING_EXACT_INPUT_MARKERS) {
        pendingExactInputMarkers.shift();
      }
      const marker = { data: data };
      pendingExactInputMarkers.push(marker);
      return marker;
    }

    function consumeExactInputMarker(data) {
      // Prefer the newest match. A compositionend marker can coexist briefly with the
      // input event that commits it; the synchronous input must consume its own marker
      // and leave the older marker for xterm's deferred composition callback.
      for (let i = pendingExactInputMarkers.length - 1; i >= 0; i--) {
        if (pendingExactInputMarkers[i].data === data) {
          pendingExactInputMarkers.splice(i, 1);
          return true;
        }
      }
      return false;
    }

    function queueMicrotaskSafe(callback) {
      if (typeof window.queueMicrotask === "function") {
        window.queueMicrotask(callback);
      } else {
        Promise.resolve().then(callback);
      }
    }

    function markSynchronousDomUserInput() {
      synchronousDomUserInputDepth++;
      // Mouse and focus reports are emitted synchronously by xterm from the DOM event.
      // A microtask expires the scope before another WebView/backend task can run.
      queueMicrotaskSafe(function () {
        if (synchronousDomUserInputDepth > 0) synchronousDomUserInputDepth--;
      });
    }

    const exactDomInputMarkers = new WeakMap();

    function captureExactDomInput(event) {
      const data = event && typeof event.data === "string" ? event.data : "";
      const marker = enqueueExactInputMarker(data);
      if (marker) exactDomInputMarkers.set(event, marker);
    }

    function finishSynchronousDomInput(event) {
      const marker = exactDomInputMarkers.get(event);
      if (!marker) return;
      exactDomInputMarkers.delete(event);
      removeExactInputMarker(marker);
    }

    function finishAsynchronousDomInput(event) {
      const marker = exactDomInputMarkers.get(event);
      if (!marker) return;
      exactDomInputMarkers.delete(event);
      // xterm 6 commits IME composition through a zero-delay callback. Keep the exact
      // text marker long enough for that callback, then discard it if no data was emitted.
      window.setTimeout(function () {
        removeExactInputMarker(marker);
      }, ASYNC_INPUT_MARKER_TIMEOUT_MS);
    }

    function refreshVisibleRows() {
      // DEC mode 2026 deliberately hides intermediate TUI paints until the application ends
      // its synchronized update. A manual refresh here would expose the partial nano/vim frame.
      if (term.modes && term.modes.synchronizedOutputMode) return;
      try {
        term.refresh(0, term.rows - 1);
      } catch (err) {
        console.warn("Terminal repaint failed:", err);
      }
    }

    function scheduleControlKeyRepaint() {
      window.setTimeout(refreshVisibleRows, 25);
      window.setTimeout(refreshVisibleRows, 120);
    }

    function scheduleHostFocusRepaint() {
      window.requestAnimationFrame(refreshVisibleRows);
      window.setTimeout(refreshVisibleRows, 50);
      window.setTimeout(refreshVisibleRows, 150);
      window.setTimeout(refreshVisibleRows, 300);
    }

    // onKey exposes the exact string that the following onData event will send. This is
    // the stable public API distinction between a human key and DA/DSR/CPR replies that
    // xterm itself emits while an asynchronous write is in progress.
    if (typeof term.onKey === "function") {
      term.onKey(function (event) {
        const marker = enqueueExactInputMarker(event.key);
        if (marker) {
          // onKey and its corresponding onData are synchronous. Do not leave a stale
          // marker behind if an embedding/custom handler suppresses the data event.
          queueMicrotaskSafe(function () { removeExactInputMarker(marker); });
        }
      });
    }

    function installDomUserInputMarkers(target, eventNames) {
      if (!target || typeof target.addEventListener !== "function") return;
      for (let i = 0; i < eventNames.length; i++) {
        target.addEventListener(eventNames[i], markSynchronousDomUserInput, true);
      }
    }

    // Ancestor capture runs before xterm's textarea listeners. Correlate virtual-keyboard
    // and IME commits by their exact data, while mouse/focus reports only need the current
    // synchronous DOM task. This never holds an unrelated backend DA/DSR reply.
    container.addEventListener("input", captureExactDomInput, true);
    container.addEventListener("input", finishSynchronousDomInput, false);
    container.addEventListener("compositionend", captureExactDomInput, true);
    container.addEventListener("compositionend", finishAsynchronousDomInput, false);
    installDomUserInputMarkers(
      container,
      ["mousedown", "mouseup", "mousemove", "wheel", "focus", "focusin", "blur"]);

    term.onData(function (data) {
      const isUserInput =
        applyingHostPaste ||
        consumeExactInputMarker(data) || synchronousDomUserInputDepth > 0;
      postInputBytes(data, isUserInput);
      // CTRL+L is form feed. The remote shell/readline clears the screen in response;
      // repaint after the remote has had a short chance to echo its clear sequence so
      // the visible grid cannot lag the parser state. This does not alter terminal
      // state or swallow the key.
      if (data.indexOf("\x0c") >= 0) {
        scheduleControlKeyRepaint();
      }
    });

    // term.onBinary fires for non-UTF-8 input (notably legacy X10/X11 mouse reports).
    // It is always genuine local mouse input; backend-generated terminal replies use onData.
    if (typeof term.onBinary === "function") {
      term.onBinary(function (data) {
        try {
          postInputFrame(btoa(data), true);
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
            const encoded = utf8ToBase64(sel, MAX_SELECTION_UTF8_BYTES);
            if (encoded === null) {
              console.warn("Selection is too large for automatic clipboard transfer.");
              return;
            }
            post("c:" + encoded);
          } catch (err) {
            console.error("Failed to report selection:", err);
          }
        }, 50);
      });
    }

    // When a full-screen program enables mouse tracking, xterm already reports right-click
    // through its terminal-input path. Shift+right-click remains an explicit paste override.
    // The mode is checked again when the ordered paste executes, closing the race where the
    // enabling escape sequence was queued but had not yet reached xterm at click time.
    let nextPasteRequestId = 1;

    function requestClipboardPaste(forcePaste) {
      if (!terminalUserInputEnabled) return;
      if (pendingPasteRequests.length >= MAX_PENDING_PASTE_REQUESTS) {
        console.warn("Ignored terminal paste because the bounded paste queue is full.");
        return;
      }

      const request = {
        kind: "pasteRequest",
        requestId: String(nextPasteRequestId++),
        force: forcePaste,
        scheduled: false,
        deferredInputFrames: [],
        deferredInputFrameCharacters: 0,
      };
      if (nextPasteRequestId > Number.MAX_SAFE_INTEGER) nextPasteRequestId = 1;
      pendingPasteRequests.push(request);
      scheduleNextPasteRequest();
      drainOutputOperations();
    }

    container.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      const forcePaste = e.shiftKey;
      const mouseTrackingMode = term.modes && term.modes.mouseTrackingMode;
      if (!forcePaste && mouseTrackingMode && mouseTrackingMode !== "none") return;
      requestClipboardPaste(forcePaste);
    });

    // Capture xterm's native textarea paste before its handler can emit an unbounded onData
    // payload. Ctrl+V is an explicit paste action, so it behaves like the Shift override.
    container.addEventListener("paste", function (e) {
      e.preventDefault();
      e.stopPropagation();
      requestClipboardPaste(true);
    }, true);

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

    function selfHealRenderer() {
      // A visible-row refresh is cheap enough to run periodically while output is still flowing.
      refreshVisibleRows();
    }

    function clearSelfHealTimers() {
      if (selfHealSettleTimer) { window.clearTimeout(selfHealSettleTimer); selfHealSettleTimer = 0; }
      if (selfHealMaxTimer) { window.clearTimeout(selfHealMaxTimer); selfHealMaxTimer = 0; }
    }

    function scheduleSelfHeal() {
      // Trailing edge: fires once output goes quiet — exactly when the user starts editing.
      if (selfHealSettleTimer) window.clearTimeout(selfHealSettleTimer);
      selfHealSettleTimer = window.setTimeout(function () {
        clearSelfHealTimers();
        selfHealRenderer();
      }, SELF_HEAL_SETTLE_MS);
      // Max-wait: a continuously streaming flood never goes quiet, so guarantee a periodic repaint —
      // a cheap refresh only (no atlas churn) since output is still in flight.
      if (!selfHealMaxTimer) {
        selfHealMaxTimer = window.setTimeout(function () {
          selfHealMaxTimer = 0;
          selfHealRenderer();
        }, SELF_HEAL_MAX_MS);
      }
    }

    function isCanonicalPositiveInt64(value) {
      if (!/^[1-9][0-9]*$/.test(value)) return false;
      if (value.length !== MAX_SIGNED_INT64_TEXT.length) {
        return value.length < MAX_SIGNED_INT64_TEXT.length;
      }
      return value <= MAX_SIGNED_INT64_TEXT;
    }

    function parseOutputFrame(message, kind) {
      const streamSeparator = message.indexOf(":", 2);
      const frameSeparator = streamSeparator < 0 ? -1 : message.indexOf(":", streamSeparator + 1);
      if (streamSeparator <= 2 || frameSeparator <= streamSeparator + 1) {
        throw new Error("Output frame is missing an identifier.");
      }

      const streamId = message.slice(2, streamSeparator);
      const frameId = message.slice(streamSeparator + 1, frameSeparator);
      const payload = message.slice(frameSeparator + 1);
      if (!isCanonicalPositiveInt64(streamId) || !isCanonicalPositiveInt64(frameId)) {
        throw new Error("Output frame identifiers must be canonical positive Int64 values.");
      }
      if (!payload || payload.length % 4 !== 0 || !CANONICAL_BASE64.test(payload)) {
        throw new Error("Output frame payload is not canonical base64.");
      }

      return {
        kind: kind,
        streamId: streamId,
        frameId: frameId,
        bytes: base64ToUint8Array(payload),
      };
    }

    // Keep one application-level queue in front of xterm's async write queue. In
    // particular, a clear is an ordered barrier: all earlier frames finish parsing,
    // the reset runs, and only then can a later frame be submitted to xterm.
    const outputOperations = [];
    const emptyWriteBarrier = new Uint8Array(0);
    let outputWriteActive = false;
    let outputDrainActive = false;
    let outputFailed = false;
    let focusOperationGeneration = 0;
    let activeFocusOperation = null;

    function invalidateFocusOperations() {
      focusOperationGeneration = focusOperationGeneration >= Number.MAX_SAFE_INTEGER
        ? 1
        : focusOperationGeneration + 1;
      for (let i = outputOperations.length - 1; i >= 0; i--) {
        if (outputOperations[i].kind === "focus") outputOperations.splice(i, 1);
      }
      if (activeFocusOperation) {
        activeFocusOperation = null;
        // Focus retries do not own an xterm write. Releasing this latch lets an ordered
        // clear or replacement focus proceed; stale callbacks are rejected by generation.
        outputWriteActive = false;
      }
      return focusOperationGeneration;
    }

    function isActiveFocusOperation(operation) {
      return activeFocusOperation === operation &&
        operation.generation === focusOperationGeneration &&
        !outputFailed;
    }

    function failOutput(fatalMessage, diagnostic, err) {
      if (err) {
        console.error(diagnostic, err);
      } else {
        console.error(diagnostic);
      }
      if (outputFailed) return;

      invalidateFocusOperations();
      cancelAllPasteRequests(false);
      claimedStreamId = null;
      focusedInputStreamId = null;
      freezePostReadyAutoFit();
      blurTerminalWithoutInput();
      outputFailed = true;
      outputOperations.length = 0;
      clearSelfHealTimers();
      post(fatalMessage);
    }

    function postProtocolMessage(message, diagnostic) {
      if (outputFailed) return false;
      if (post(message)) return true;
      failOutput(
        "fatal:protocol",
        "Failed to post a protocol-critical terminal message while " + diagnostic + ".");
      return false;
    }

    function finishOutputOperation() {
      outputWriteActive = false;
      // xterm normally completes writes asynchronously, but input/paste operations and
      // test/custom renderers may complete synchronously. Let the active drain loop advance
      // them iteratively instead of growing the JavaScript call stack.
      if (!outputDrainActive) drainOutputOperations();
    }

    function writeDataOperation(operation) {
      const isReplay = operation.kind === "replay";
      if (!isReplay) {
        activeParserStreamId = operation.streamId;
      }

      if (isReplay) {
        // A full raw replay is a display reconstruction, not new remote output. xterm may
        // answer historical DA/DSR/CPR requests while parsing it, so suppress every generated
        // input byte and restore parser replies before the next live frame. Human input stays
        // disabled until an ordered focus barrier explicitly re-enables it.
        blurTerminalWithoutInput();
        replayInputSuppressed = true;
      }

      try {
        term.write(operation.bytes, function () {
          if (isReplay) {
            replayInputSuppressed = false;
          } else {
            if (activeParserStreamId === operation.streamId) {
              activeParserStreamId = null;
            }
            const acknowledged = postProtocolMessage(
              "a:" + operation.streamId + ":" + operation.frameId,
              "acknowledging parsed terminal output");
            if (acknowledged && operation.bytes.length >= SELF_HEAL_MIN_BURST_BYTES) {
              scheduleSelfHeal();
            }
          }
          finishOutputOperation();
        });
      } catch (err) {
        if (!isReplay && activeParserStreamId === operation.streamId) {
          activeParserStreamId = null;
        }
        replayInputSuppressed = false;
        outputWriteActive = false;
        failOutput(
          "fatal:write:" + operation.streamId + ":" + operation.frameId,
          "xterm rejected terminal output; waiting for an ordered reset.",
          err);
      }
    }

    function writeInputOperation(operation) {
      deferredInputFrameCharacters -= operation.frame.length;
      if (deferredInputFrameCharacters < 0) deferredInputFrameCharacters = 0;
      postProtocolMessage(operation.frame, "forwarding ordered terminal input");
      finishOutputOperation();
    }

    function writeInputBatchOperation(operation) {
      for (let i = 0; i < operation.frames.length; i++) {
        const frame = operation.frames[i];
        deferredInputFrameCharacters -= frame.length;
        if (!postProtocolMessage(frame, "forwarding batched terminal input")) break;
      }
      if (deferredInputFrameCharacters < 0) deferredInputFrameCharacters = 0;
      finishOutputOperation();
    }

    function startActivePasteTimer(timeout, diagnostic) {
      resetPasteRequestTimer();
      const requestId = activePasteRequest && activePasteRequest.requestId;
      pasteRequestTimer = window.setTimeout(function () {
        if (!activePasteRequest || activePasteRequest.requestId !== requestId) return;
        console.error(diagnostic);
        completeActivePasteRequest(requestId, true, activePasteGateHeld);
      }, timeout);
    }

    function writePasteRequestOperation(operation) {
      activePasteRequest = operation;
      activePasteGateHeld = true;
      const mouseTrackingMode = term.modes && term.modes.mouseTrackingMode;
      if (!operation.force && mouseTrackingMode && mouseTrackingMode !== "none") {
        completeActivePasteRequest(operation.requestId, true, true);
        return;
      }

      startActivePasteTimer(
        PASTE_GATE_TIMEOUT_MS,
        "Timed out starting the ordered clipboard paste barrier.");
      postProtocolMessage(
        "p:" + operation.requestId + ":" + (operation.force ? "1" : "0"),
        "requesting an ordered clipboard paste");
    }

    function releaseActivePasteGate(requestId) {
      if (!activePasteRequest ||
          activePasteRequest.requestId !== requestId ||
          !activePasteGateHeld) {
        console.warn("Ignored stale or malformed paste-drain frame.");
        return;
      }

      activePasteGateHeld = false;
      startActivePasteTimer(
        PASTE_REQUEST_TIMEOUT_MS,
        "Timed out waiting for clipboard paste data.");
      // The host captured its native-pump watermark before sending paste-drain. Releasing
      // the JS gate lets every older d: frame reach xterm and ACK without deadlocking.
      finishOutputOperation();
    }

    function writePasteApplyOperation(operation) {
      if (!activePasteRequest ||
          activePasteRequest.requestId !== operation.requestId) {
        finishOutputOperation();
        return;
      }

      applyingHostPaste = true;
      try {
        // The host waited for its pre-gesture watermark to parse, and this apply operation
        // sits behind every WebView output message delivered before the clipboard response.
        term.paste(operation.text);
      } catch (err) {
        console.error("Failed to apply paste:", err);
      } finally {
        applyingHostPaste = false;
        completeActivePasteRequest(operation.requestId, true, true);
      }
    }

    function scheduleFocusFit(operation) {
      window.setTimeout(function () {
        window.requestAnimationFrame(function () {
          if (operation.generation !== focusOperationGeneration || outputFailed) return;
          fitNow(true, false, operation.streamId);
        });
      }, 150);
    }

    function writeFocusOperation(operation) {
      if (operation.generation !== focusOperationGeneration) {
        finishOutputOperation();
        return;
      }
      activeFocusOperation = operation;
      let attempt = 0;

      const tryCompleteFocus = function () {
        const delay = FOCUS_FIT_RETRY_DELAYS_MS[attempt++];
        const run = function () {
          window.requestAnimationFrame(function () {
            // A clear, fatal boundary, or replacement f: invalidates the generation and
            // releases the queue latch. This stale callback must not focus, emit DEC input,
            // acknowledge its old stream, or disturb whatever operation is active now.
            if (!isActiveFocusOperation(operation)) return;

            try {
              // Fit and report the PTY geometry before focus can emit a DEC focus reply.
              // The host processes resize -> focus input -> focus ACK in one control FIFO.
              if (!fitNow(true, true, operation.streamId)) {
                if (attempt < FOCUS_FIT_RETRY_DELAYS_MS.length) {
                  tryCompleteFocus();
                  return;
                }
                throw new Error("Terminal viewport stayed unusable during focus.");
              }

              activeResizeStreamId = operation.streamId;
              focusedInputStreamId = operation.streamId;
              terminalUserInputEnabled = true;
              term.focus();
              refreshVisibleRows();
              scheduleFocusFit(operation);
              scheduleHostFocusRepaint();
              postProtocolMessage(
                "focus:" + operation.streamId,
                "acknowledging terminal focus");
              activeFocusOperation = null;
              finishOutputOperation();
            } catch (err) {
              failOutput("fatal:protocol", "Failed to complete terminal focus barrier.", err);
            }
          });
        };

        if (delay <= 0) {
          run();
        } else {
          window.setTimeout(run, delay);
        }
      };

      tryCompleteFocus();
    }

    function writeClearOperation(operation) {
      const fatalMessage = operation.streamId
        ? "fatal:clear:" + operation.streamId
        : "fatal:clear";
      try {
        term.write(emptyWriteBarrier, function () {
          try {
            clearSelfHealTimers();
            blurTerminalWithoutInput();
            term.reset();
          } catch (err) {
            outputWriteActive = false;
            failOutput(fatalMessage, "Failed to reset terminal at the output barrier.", err);
            return;
          }
          finishOutputOperation();
        });
      } catch (err) {
        outputWriteActive = false;
        failOutput(fatalMessage, "Failed to enqueue the terminal reset barrier.", err);
      }
    }

    function writeParserBarrierOperation(operation) {
      try {
        term.write(emptyWriteBarrier, function () {
          postProtocolMessage(
            "barrier:" + operation.streamId,
            "acknowledging the terminal parser barrier");
          finishOutputOperation();
        });
      } catch (err) {
        outputWriteActive = false;
        failOutput(
          "fatal:barrier:" + operation.streamId,
          "Failed to enqueue the terminal parser barrier.",
          err);
      }
    }

    function drainOutputOperations() {
      if (outputDrainActive || outputWriteActive || outputFailed) return;

      outputDrainActive = true;
      try {
        while (!outputWriteActive && !outputFailed && outputOperations.length > 0) {
          const operation = outputOperations.shift();
          outputWriteActive = true;
          if (operation.kind === "clear") {
            writeClearOperation(operation);
          } else if (operation.kind === "pasteRequest") {
            writePasteRequestOperation(operation);
          } else if (operation.kind === "pasteApply") {
            writePasteApplyOperation(operation);
          } else if (operation.kind === "input") {
            writeInputOperation(operation);
          } else if (operation.kind === "inputBatch") {
            writeInputBatchOperation(operation);
          } else if (operation.kind === "focus") {
            writeFocusOperation(operation);
          } else if (operation.kind === "parserBarrier") {
            writeParserBarrierOperation(operation);
          } else {
            writeDataOperation(operation);
          }
        }
      } finally {
        outputDrainActive = false;
      }
    }

    function enqueueOutputFrame(frame) {
      if (outputFailed) return;
      outputOperations.push(frame);
      drainOutputOperations();
    }


    function enqueueParserBarrier(streamId) {
      if (outputFailed) return;
      outputOperations.push({
        kind: "parserBarrier",
        streamId: streamId,
      });
      drainOutputOperations();
    }

    function beginTerminalRetirement(streamId) {
      rememberRetiredStream(streamId);
      // f: claims ownership on receipt, before it reaches the ordered queue. A late x: from the
      // prior bridge must not cancel a replacement focus that is waiting behind an xterm write.
      if (claimedStreamId && claimedStreamId !== streamId) return;
      // Freeze at the geometry already shared with the PTY. A new fit here could overtake d:
      // frames produced for the old dimensions; a resize posted before x: instead drains before k:.
      // Retirement is an immediate human-input boundary, separate from the later ordered k:
      // parser proof. Releasing an active paste gate lets older and not-yet-posted d: frames
      // drain without waiting for the 15-second page timeout; their replies keep origin p.
      claimedStreamId = null;
      focusedInputStreamId = null;
      freezePostReadyAutoFit();
      terminalUserInputEnabled = false;
      invalidateFocusOperations();
      cancelAllPasteRequests(false);
      drainOutputOperations();
    }

    function enqueueFocus(streamId) {
      if (outputFailed || retiredStreamIds.has(streamId)) return;
      // Claim synchronously, even if the ordered focus must wait behind an active xterm write.
      claimedStreamId = streamId;
      // A new focus is the only operation allowed to claim post-ready resize ownership.
      freezePostReadyAutoFit();
      const generation = invalidateFocusOperations();
      outputOperations.push({
        kind: "focus",
        streamId: streamId,
        generation: generation,
      });
      drainOutputOperations();
    }

    function rememberRetiredStream(streamId) {
      if (retiredStreamIds.has(streamId)) return;
      retiredStreamIds.add(streamId);
      retiredStreamOrder.push(streamId);
      if (retiredStreamOrder.length > MAX_RETIRED_STREAM_IDS) {
        retiredStreamIds.delete(retiredStreamOrder.shift());
      }
    }
    let pendingPasteAssembly = null;
    let pasteAssemblyTimer = 0;

    function resetPasteAssembly() {
      if (pasteAssemblyTimer) {
        window.clearTimeout(pasteAssemblyTimer);
        pasteAssemblyTimer = 0;
      }
      pendingPasteAssembly = null;
    }

    function rejectCurrentPasteAssembly(message, err) {
      if (err) {
        console.error(message, err);
      } else {
        console.error(message);
      }
      if (activePasteRequest) {
        completeActivePasteRequest(
          activePasteRequest.requestId,
          true,
          activePasteGateHeld);
      }
    }

    function beginPasteAssembly(message) {
      const fields = message.split(":");
      if (fields.length !== 4 ||
          fields[0] !== "paste-begin" ||
          !isCanonicalPositiveInt64(fields[1])) {
        console.error("Ignored malformed paste-begin frame.");
        return;
      }

      const requestId = fields[1];
      if (!activePasteRequest || requestId !== activePasteRequest.requestId) {
        console.warn("Ignored stale paste-begin frame.");
        return;
      }
      if ((fields[2] !== "0" && fields[2] !== "1") ||
          (fields[2] === "1") !== activePasteRequest.force ||
          !/^[1-9][0-9]*$/.test(fields[3])) {
        rejectCurrentPasteAssembly("Rejected malformed paste-begin frame.");
        return;
      }

      const expectedBytes = Number(fields[3]);
      if (!Number.isSafeInteger(expectedBytes) ||
          expectedBytes > MAX_CLIPBOARD_PASTE_BYTES) {
        rejectCurrentPasteAssembly("Rejected oversized paste transaction.");
        return;
      }

      resetPasteAssembly();
      pendingPasteAssembly = {
        requestId: requestId,
        force: fields[2] === "1",
        expectedBytes: expectedBytes,
        receivedBytes: 0,
        chunks: [],
      };
      pasteAssemblyTimer = window.setTimeout(function () {
        if (pendingPasteAssembly &&
            pendingPasteAssembly.requestId === requestId) {
          rejectCurrentPasteAssembly("Discarded incomplete paste transaction.");
        }
      }, 10000);
    }

    function appendPasteChunk(message) {
      const prefix = "paste-chunk:";
      const separator = message.indexOf(":", prefix.length);
      if (separator <= prefix.length ||
          message.indexOf(":", separator + 1) >= 0) {
        console.error("Ignored malformed paste chunk.");
        return;
      }

      const requestId = message.slice(prefix.length, separator);
      const payload = message.slice(separator + 1);
      if (!isCanonicalPositiveInt64(requestId)) {
        console.error("Ignored paste chunk with malformed request id.");
        return;
      }
      if (!activePasteRequest || requestId !== activePasteRequest.requestId) {
        console.warn("Ignored stale paste chunk.");
        return;
      }
      if (!pendingPasteAssembly ||
          requestId !== pendingPasteAssembly.requestId) {
        rejectCurrentPasteAssembly("Rejected paste chunk without its begin frame.");
        return;
      }
      if (pendingPasteAssembly.chunks.length >= MAX_CLIPBOARD_PASTE_CHUNKS ||
          !payload ||
          payload.length % 4 !== 0 ||
          !CANONICAL_BASE64.test(payload)) {
        rejectCurrentPasteAssembly("Rejected malformed paste chunk.");
        return;
      }

      try {
        const bytes = base64ToUint8Array(payload);
        if (pendingPasteAssembly.receivedBytes + bytes.length >
            pendingPasteAssembly.expectedBytes) {
          rejectCurrentPasteAssembly("Paste transaction exceeded its declared byte count.");
          return;
        }
        pendingPasteAssembly.chunks.push(bytes);
        pendingPasteAssembly.receivedBytes += bytes.length;
      } catch (err) {
        rejectCurrentPasteAssembly("Failed to decode paste chunk.", err);
      }
    }

    function finishPasteAssembly(message) {
      const requestId = message.slice("paste-end:".length);
      if (!isCanonicalPositiveInt64(requestId)) {
        console.error("Ignored malformed paste-end frame.");
        return;
      }
      if (!activePasteRequest || requestId !== activePasteRequest.requestId) {
        console.warn("Ignored stale paste-end frame.");
        return;
      }

      const assembly = pendingPasteAssembly;
      if (!assembly ||
          requestId !== assembly.requestId ||
          assembly.receivedBytes !== assembly.expectedBytes) {
        rejectCurrentPasteAssembly("Rejected incomplete paste transaction.");
        return;
      }

      try {
        const bytes = new Uint8Array(assembly.expectedBytes);
        let offset = 0;
        for (let i = 0; i < assembly.chunks.length; i++) {
          bytes.set(assembly.chunks[i], offset);
          offset += assembly.chunks[i].length;
        }
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        resetPasteAssembly();
        outputOperations.push({
          kind: "pasteApply",
          requestId: requestId,
          text: text,
        });
        drainOutputOperations();
      } catch (err) {
        rejectCurrentPasteAssembly("Failed to assemble terminal paste.", err);
      }
    }

    function enqueueClearBarrier(streamId) {
      // A session reset is also an input boundary: clipboard work, focus retries, and keys
      // belonging to the retired session must never leak into the replacement shell.
      // Disable immediately on message receipt; the ordered clear operation performs the blur.
      claimedStreamId = null;
      focusedInputStreamId = null;
      freezePostReadyAutoFit();
      terminalUserInputEnabled = false;
      invalidateFocusOperations();
      cancelAllPasteRequests(false);
      // A host-requested clear is the explicit recovery boundary after a fatal write
      // or protocol error. Preserve any valid write already inside xterm, then reset.
      if (outputFailed) {
        outputFailed = false;
        outputOperations.length = 0;
      }
      outputOperations.push({ kind: "clear", streamId: streamId || null });
      drainOutputOperations();
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

    function fitNow(reportResize, forceReport, explicitStreamId) {
      const dimensions = proposedDimensions();
      if (!hasUsableDimensions(dimensions)) {
        if (dimensions) {
          const ignored = dimensionsText(dimensions) + ":" + container.clientWidth + "x" + container.clientHeight;
          if (readySent && ignored !== lastIgnoredGeometry) {
            lastIgnoredGeometry = ignored;
            post("z:collapsed-fit:" + ignored);
          }
        }
        return false;
      }

      // Once ready, only the stream established by an ordered f: operation may resize xterm.
      // x:/clear null this owner immediately, freezing observer/timer fits during detach.
      const resizeStreamId = explicitStreamId || activeResizeStreamId;
      if (readySent && !resizeStreamId) return false;

      let resized = false;
      try {
        if (term.cols !== dimensions.cols || term.rows !== dimensions.rows) {
          term.resize(dimensions.cols, dimensions.rows);
          resized = true;
        }
      } catch (_) {
        return false;
      }

      const fitted = dimensionsText(dimensions);

      if (!readySent) {
        if (!post("ready:" + fitted)) return false;
        readySent = true;
        lastReportedGeometry = fitted;
        if (readyTimer) {
          window.clearTimeout(readyTimer);
          readyTimer = 0;
        }
        return true;
      }

      if (resized) {
        refreshVisibleRows();
        window.setTimeout(refreshVisibleRows, 50);
      }

      // Every real post-handshake xterm resize must reach the PTY, including fits
      // scheduled by startup retries. A forced report is only for host reattachment.
      if (resized || (reportResize && (forceReport || fitted !== lastReportedGeometry))) {
        if (!postProtocolMessage(
            "r:" + resizeStreamId + ":" + fitted,
            "reporting terminal geometry")) {
          return false;
        }
        lastReportedGeometry = fitted;
      }
      return true;
    }

    function scheduleFit(delay, reportResize, forceReport) {
      const generation = resizeOperationGeneration;
      const run = function () {
        window.requestAnimationFrame(function () {
          if (generation !== resizeOperationGeneration) return;
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
        if (msg.startsWith("x:")) {
          const streamId = msg.slice(2);
          if (!isCanonicalPositiveInt64(streamId)) {
            failOutput("fatal:protocol", "Rejected malformed terminal retirement boundary.");
            return;
          }
          beginTerminalRetirement(streamId);
          return;
        }
        if (msg.startsWith("k:")) {
          const streamId = msg.slice(2);
          if (!isCanonicalPositiveInt64(streamId)) {
            failOutput("fatal:protocol", "Rejected malformed terminal parser barrier.");
            return;
          }
          enqueueParserBarrier(streamId);
          return;
        }
        if (msg.startsWith("f:")) {
          const streamId = msg.slice(2);
          if (!isCanonicalPositiveInt64(streamId)) {
            failOutput("fatal:protocol", "Rejected malformed terminal focus barrier.");
            return;
          }
          if (retiredStreamIds.has(streamId)) return;
          if (outputFailed) {
            // Fatal page state can predate this bridge (for example a reset failed before
            // the network connection completed). Repeat the signal so the new owner fails
            // immediately instead of waiting for its focus watchdog.
            post("fatal:protocol");
            return;
          }
          // A focus barrier belongs to the currently attaching bridge. Abort clipboard
          // work left by a retired bridge so it cannot hold replay/live output for 50 seconds.
          cancelAllPasteRequests(false);
          enqueueFocus(streamId);
          return;
        }
        if (msg === "clear:") {
          enqueueClearBarrier(null);
          return;
        }
        if (msg.startsWith("clear:")) {
          const streamId = msg.slice("clear:".length);
          if (!isCanonicalPositiveInt64(streamId)) {
            failOutput("fatal:protocol", "Rejected malformed scoped terminal reset.");
            return;
          }
          enqueueClearBarrier(streamId);
          return;
        }
        if (msg.startsWith("d:") || msg.startsWith("q:")) {
          if (outputFailed) return;
          try {
            enqueueOutputFrame(parseOutputFrame(
              msg,
              msg.startsWith("q:") ? "replay" : "data"));
          } catch (err) {
            failOutput("fatal:protocol", "Rejected malformed terminal output frame.", err);
          }
          return;
        }
        if (msg.startsWith("paste-drain:")) {
          const requestId = msg.slice("paste-drain:".length);
          if (isCanonicalPositiveInt64(requestId)) {
            releaseActivePasteGate(requestId);
          } else {
            console.warn("Ignored malformed paste-drain frame.");
          }
          return;
        }
        if (msg.startsWith("paste-begin:")) {
          beginPasteAssembly(msg);
          return;
        }
        if (msg.startsWith("paste-chunk:")) {
          appendPasteChunk(msg);
          return;
        }
        if (msg.startsWith("paste-end:")) {
          finishPasteAssembly(msg);
          return;
        }
        if (msg.startsWith("paste-cancel:")) {
          const requestId = msg.slice("paste-cancel:".length);
          if (isCanonicalPositiveInt64(requestId) &&
              activePasteRequest &&
              requestId === activePasteRequest.requestId) {
            completeActivePasteRequest(requestId, true, activePasteGateHeld);
          } else {
            console.warn("Ignored stale or malformed paste-cancel frame.");
          }
          return;
        }
      });
    }

    if (window.ResizeObserver) {
      const observer = new ResizeObserver(function () {
        if (resizeTimer) window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(function () {
          resizeTimer = 0;
          scheduleFit(0, true);
          scheduleFit(150, true);
        }, 50);
      });
      observer.observe(container);
    }

    window.addEventListener("resize", function () {
      if (resizeTimer) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(function () {
        resizeTimer = 0;
        scheduleFit(0, true);
      }, 50);
    });

    // Full-screen TUI apps (nano, vim, less, htop) switch to the alternate screen
    // buffer and back without changing the container. Re-fit once so a real geometry
    // change reaches the PTY, but do not manufacture duplicate SIGWINCH reports.
    if (term.buffer && typeof term.buffer.onBufferChange === "function") {
      term.buffer.onBufferChange(function () {
        scheduleFit(0, true, false);
        window.setTimeout(refreshVisibleRows, 75);
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
