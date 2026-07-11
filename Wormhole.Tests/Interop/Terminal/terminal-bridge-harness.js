"use strict";

const fs = require("fs");
const vm = require("vm");

const bridgePath = process.argv[2];
const scenario = process.argv[3];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function equal(actual, expected, message) {
  if (actual !== expected) {
    fail(message + ": expected " + JSON.stringify(expected) + ", got " + JSON.stringify(actual));
  }
}

function deepEqual(actual, expected, message) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    fail(message + ": expected " + expectedJson + ", got " + actualJson);
  }
}

function encodeFrame(kind, streamId, frameId, bytes) {
  return kind + ":" + streamId + ":" + frameId + ":" + Buffer.from(bytes).toString("base64");
}

function decodeInputFrame(frame) {
  assert(frame.startsWith("b:"), "Expected a binary input frame, got " + frame);
  const streamSeparator = frame.indexOf(":", 2);
  const originSeparator = frame.indexOf(":", streamSeparator + 1);
  assert(
    streamSeparator > 2 && originSeparator === streamSeparator + 2,
    "Expected a stream/origin-scoped binary input frame, got " + frame);
  const origin = frame.slice(streamSeparator + 1, originSeparator);
  assert(origin === "u" || origin === "p", "Unexpected terminal input origin " + origin);
  return {
    streamId: Number(frame.slice(2, streamSeparator)),
    origin: origin,
    data: Buffer.from(frame.slice(originSeparator + 1), "base64").toString("utf8"),
  };
}

function decodeInput(frame) {
  return decodeInputFrame(frame).data;
}

class DeterministicTimers {
  constructor() {
    this.nextId = 1;
    this.entries = [];
  }

  setTimeout(callback, delay = 0) {
    const entry = { id: this.nextId++, callback, delay, cancelled: false };
    this.entries.push(entry);
    return entry.id;
  }

  clearTimeout(id) {
    const entry = this.entries.find(item => item.id === id);
    if (entry) entry.cancelled = true;
  }

  clear() {
    this.entries.length = 0;
  }

  runNext() {
    const index = this.entries.findIndex(entry => !entry.cancelled);
    if (index < 0) fail("No deterministic timer was available to run.");
    const [entry] = this.entries.splice(index, 1);
    entry.callback();
  }

  runNextDelay(delay) {
    const index = this.entries.findIndex(entry => !entry.cancelled && entry.delay === delay);
    if (index < 0) fail("No deterministic timer with delay " + delay + " was available to run.");
    const [entry] = this.entries.splice(index, 1);
    entry.callback();
  }

  runAll(limit = 100) {
    for (let i = 0; i < limit; i++) {
      const index = this.entries.findIndex(entry => !entry.cancelled);
      if (index < 0) return;
      const [entry] = this.entries.splice(index, 1);
      entry.callback();
    }
    fail("Deterministic timer queue did not settle.");
  }
}

class DeterministicMicrotasks {
  constructor() {
    this.entries = [];
  }

  queue(callback) {
    this.entries.push(callback);
  }

  runAll(limit = 100) {
    for (let i = 0; i < limit && this.entries.length > 0; i++) {
      this.entries.shift()();
    }
    if (this.entries.length > 0) fail("Deterministic microtask queue did not settle.");
  }
}

class FakeElement {
  constructor(microtasks) {
    this.clientWidth = 800;
    this.clientHeight = 600;
    this.listeners = new Map();
    this.microtasks = microtasks;
  }

  addEventListener(name, callback, options = false) {
    if (!this.listeners.has(name)) this.listeners.set(name, []);
    const capture = options === true || Boolean(options && options.capture);
    this.listeners.get(name).push({ callback, capture });
  }

  dispatch(name, overrides = {}) {
    const event = {
      type: name,
      data: null,
      inputType: "",
      preventDefault() {},
      stopPropagation() {},
      shiftKey: false,
      ...overrides,
    };
    const listeners = this.listeners.get(name) || [];
    for (const listener of listeners) {
      if (listener.capture) listener.callback(event);
    }
    for (const listener of listeners) {
      if (!listener.capture) listener.callback(event);
    }
    this.microtasks.runAll();
  }
}

function createHarness(options = {}) {
  const bridgeSource = fs.readFileSync(bridgePath, "utf8");
  const timers = new DeterministicTimers();
  const microtasks = new DeterministicMicrotasks();
  const container = new FakeElement(microtasks);
  const posted = [];
  const postAttempts = [];
  const postFailures = (options.failPostPrefixes || []).slice();
  const webMessageListeners = [];
  const terminalEvents = [];
  const windowListeners = new Map();
  const state = {
    dimensions: { cols: 80, rows: 24 },
    deferWriteCallbacks: false,
    deferParserReplies: false,
    terminal: null,
  };

  class FakeFitAddon {
    proposeDimensions() {
      return state.dimensions;
    }
  }

  class FakeTerminal {
    constructor() {
      this.cols = 80;
      this.rows = 24;
      this.modes = {
        synchronizedOutputMode: false,
        mouseTrackingMode: "none",
      };
      this.writtenChunks = [];
      this.pendingWriteCallbacks = [];
      this.pendingParserReplies = [];
      this.dataHandlers = [];
      this.keyHandlers = [];
      this.binaryHandlers = [];
      this.bufferChangeHandlers = [];
      this.focusCount = 0;
      this.resetCount = 0;
      this.refreshCount = 0;
      this.isAlternate = false;
      this.seenAlternateEnter = false;
      this.seenAlternateExit = false;
      this.parserBytes = Buffer.alloc(0);
      this.buffer = {
        onBufferChange: callback => this.bufferChangeHandlers.push(callback),
      };
      // Model xterm 6's input origins closely enough to exercise the bridge's capture
      // ordering: direct input is synchronous, while compositionend commits on a timer.
      container.addEventListener("input", event => {
        if (event.inputType === "insertText" && event.data) this.emitData(event.data);
      });
      container.addEventListener("compositionend", event => {
        const data = event.data;
        timers.setTimeout(() => {
          if (data) this.emitData(data);
        }, 0);
      });
      // xterm 6 emits DEC focus reports synchronously from its textarea focus/blur
      // listeners when mode 1004 is enabled. Chromium sends focus before focusin.
      container.addEventListener("focus", () => this.emitData("\x1b[I"));
      container.addEventListener("blur", () => this.emitData("\x1b[O"));
      state.terminal = this;
    }

    loadAddon() {}
    open() {}
    onData(callback) { this.dataHandlers.push(callback); }
    onKey(callback) { this.keyHandlers.push(callback); }
    onBinary(callback) { this.binaryHandlers.push(callback); }
    onSelectionChange() {}
    hasSelection() { return false; }
    getSelection() { return ""; }
    refresh() { this.refreshCount++; }
    blur() {
      terminalEvents.push("blur");
      container.dispatch("blur");
    }

    resize(cols, rows) {
      this.cols = cols;
      this.rows = rows;
      terminalEvents.push("resize:" + cols + "x" + rows);
    }

    focus() {
      this.focusCount++;
      terminalEvents.push("focus");
      container.dispatch("focus");
    }

    reset() {
      this.resetCount++;
      terminalEvents.push("reset");
      this.parserBytes = Buffer.alloc(0);
      this.isAlternate = false;
    }

    paste(text) {
      terminalEvents.push("paste:" + text);
      this.emitData(text);
    }

    emitData(data) {
      for (const callback of this.dataHandlers) callback(data);
    }

    emitUserData(data) {
      for (const callback of this.keyHandlers) callback({ key: data });
      this.emitData(data);
      microtasks.runAll();
    }

    write(bytes, callback) {
      const copy = Buffer.from(bytes);
      this.writtenChunks.push(copy);
      this.parserBytes = Buffer.concat([this.parserBytes, copy]);
      const parserText = this.parserBytes.toString("latin1");

      if (!this.seenAlternateEnter && parserText.includes("\x1b[?1049h")) {
        this.seenAlternateEnter = true;
        this.isAlternate = true;
        terminalEvents.push("alternate:enter");
        for (const handler of this.bufferChangeHandlers) handler();
      }
      if (!this.seenAlternateExit && parserText.includes("\x1b[?1049l")) {
        this.seenAlternateExit = true;
        this.isAlternate = false;
        terminalEvents.push("alternate:exit");
        for (const handler of this.bufferChangeHandlers) handler();
      }

      // Model xterm-generated replies emitted through onData while parsing backend output.
      if (copy.includes(Buffer.from("\x1b[6n", "latin1"))) {
        const reply = () => this.emitData("\x1b[24;80R");
        if (state.deferParserReplies) {
          this.pendingParserReplies.push(reply);
        } else {
          reply();
        }
      }

      if (state.deferWriteCallbacks) {
        this.pendingWriteCallbacks.push(callback);
      } else {
        callback();
      }
    }

    completeNextParserReply() {
      const reply = this.pendingParserReplies.shift();
      if (!reply) fail("No pending xterm parser reply was available.");
      reply();
    }

    completeNextWrite() {
      const callback = this.pendingWriteCallbacks.shift();
      if (!callback) fail("No pending xterm write callback was available.");
      callback();
    }
  }

  const webview = {
    postMessage(message) {
      postAttempts.push(message);
      const failureIndex = postFailures.findIndex(prefix => message.startsWith(prefix));
      if (failureIndex >= 0) {
        postFailures.splice(failureIndex, 1);
        throw new Error("Injected WebView post failure for " + message);
      }
      posted.push(message);
    },
    failNextPost(prefix) { postFailures.push(prefix); },
    addEventListener(name, callback) {
      if (name === "message") webMessageListeners.push(callback);
    },
    dispatch(message) {
      for (const callback of webMessageListeners) callback({ data: message });
    },
  };

  const document = {
    readyState: "complete",
    getElementById(id) { return id === "terminal" ? container : null; },
    addEventListener() {},
  };

  const fakeWindow = {
    Terminal: FakeTerminal,
    FitAddon: { FitAddon: FakeFitAddon },
    chrome: { webview },
    setTimeout: timers.setTimeout.bind(timers),
    clearTimeout: timers.clearTimeout.bind(timers),
    requestAnimationFrame(callback) { callback(); },
    queueMicrotask(callback) { microtasks.queue(callback); },
    addEventListener(name, callback) {
      if (!windowListeners.has(name)) windowListeners.set(name, []);
      windowListeners.get(name).push(callback);
    },
  };
  fakeWindow.window = fakeWindow;
  fakeWindow.document = document;

  class FakeResizeObserver {
    constructor(callback) { this.callback = callback; }
    observe() {}
  }

  const harnessConsole = options.suppressConsoleErrors
    ? { error() {}, warn() {}, log() {} }
    : console;
  const context = vm.createContext({
    window: fakeWindow,
    document,
    ResizeObserver: FakeResizeObserver,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    console: harnessConsole,
    atob: value => Buffer.from(value, "base64").toString("latin1"),
    btoa: value => Buffer.from(value, "latin1").toString("base64"),
  });
  new vm.Script(bridgeSource, { filename: bridgePath }).runInContext(context);

  assert(state.terminal, "bridge.js did not construct the fake xterm terminal.");
  if (options.allowPendingReady) {
    assert(!posted.includes("ready:80x24"), "The injected ready failure was committed.");
  } else {
    assert(posted.includes("ready:80x24"), "bridge.js did not complete its initial usable fit.");
    timers.clear();
    posted.length = 0;
    terminalEvents.length = 0;
  }

  return {
    container,
    microtasks,
    posted,
    postAttempts,
    state,
    term: state.terminal,
    terminalEvents,
    timers,
    webview,
    dispatchWindow(name) {
      const listeners = windowListeners.get(name) || [];
      for (const callback of listeners) callback({ type: name });
      microtasks.runAll();
    },
  };
}

function enableTerminalInput(harness, streamId) {
  harness.webview.dispatch("f:" + streamId);
  harness.posted.length = 0;
  harness.terminalEvents.length = 0;
  harness.timers.clear();
}

function fragmentedOutputScenario() {
  const harness = createHarness();
  const bytes = Buffer.from(
    "\x1b[?1049h\x1b[31mnano: café 😀\x1b[0m\r\nline two\x1b[?1049l",
    "utf8");
  const emojiOffset = bytes.indexOf(Buffer.from("😀", "utf8"));
  const chunks = [
    bytes.subarray(0, 5),
    bytes.subarray(5, emojiOffset + 2),
    bytes.subarray(emojiOffset + 2, bytes.length - 4),
    bytes.subarray(bytes.length - 4),
  ];

  chunks.forEach((chunk, index) => {
    harness.webview.dispatch(encodeFrame("d", 11, index + 1, chunk));
  });

  const written = Buffer.concat(harness.term.writtenChunks);
  assert(written.equals(bytes), "Fragmented terminal bytes did not reach xterm in exact FIFO order.");
  equal(
    new TextDecoder("utf-8", { fatal: true }).decode(written),
    bytes.toString("utf8"),
    "Fragmented UTF-8 did not reconstruct exactly");
  assert(harness.term.seenAlternateEnter, "Fragmented alternate-screen enter was not observed.");
  assert(harness.term.seenAlternateExit, "Fragmented alternate-screen exit was not observed.");
  assert(!harness.term.isAlternate, "Terminal remained in the alternate buffer after the exit frame.");
  deepEqual(
    harness.posted.filter(message => message.startsWith("a:")),
    ["a:11:1", "a:11:2", "a:11:3", "a:11:4"],
    "Output acknowledgements were not FIFO");
}

function alternateScreenExitOrderingScenario() {
  const harness = createHarness();
  harness.state.deferWriteCallbacks = true;
  const repaint = Buffer.from(
    "\x1b[?1049h\x1b[Hnano header\r\nline 1\r\nline 2\r\nline 42",
    "latin1");
  const exitAndPrompt = Buffer.from(
    "\x1b[?1049l\r\nroot@host:~# ",
    "latin1");

  harness.webview.dispatch(encodeFrame("d", 12, 1, repaint));
  harness.webview.dispatch(encodeFrame("d", 12, 2, exitAndPrompt));

  equal(
    harness.term.writtenChunks.length,
    1,
    "The alternate-screen exit was submitted before the repaint finished parsing.");
  assert(
    harness.term.isAlternate,
    "nano's alternate screen was not active while its repaint callback was pending.");
  assert(
    !harness.posted.includes("a:12:2"),
    "The shell prompt was acknowledged before nano's repaint.");

  harness.term.completeNextWrite();
  equal(
    harness.term.writtenChunks.length,
    2,
    "The ordered shell-exit frame was not submitted after nano's repaint.");
  assert(
    !harness.term.isAlternate,
    "The terminal did not leave nano's alternate buffer in FIFO order.");
  assert(
    Buffer.concat(harness.term.writtenChunks).equals(
      Buffer.concat([repaint, exitAndPrompt])),
    "Nano repaint and shell-exit bytes were reordered or lost.");

  harness.term.completeNextWrite();
  deepEqual(
    harness.posted.filter(message => message.startsWith("a:")),
    ["a:12:1", "a:12:2"],
    "Nano repaint and shell-exit acknowledgements were not FIFO.");
}
function replaySideEffectsScenario() {
  const harness = createHarness();
  const query = Buffer.from("history\x1b[6n", "latin1");

  harness.webview.dispatch(encodeFrame("q", 21, 1, query));
  assert(
    !harness.posted.some(message => message.startsWith("b:")),
    "A full replay forwarded a historical xterm-generated reply.");
  assert(
    !harness.posted.some(message => message.startsWith("a:")),
    "A side-effect-free replay unexpectedly consumed live-output credit.");

  harness.webview.dispatch(encodeFrame("d", 21, 2, query));
  const inputFrames = harness.posted.filter(message => message.startsWith("b:"));
  equal(inputFrames.length, 1, "Live terminal query should forward exactly one generated reply");
  equal(decodeInput(inputFrames[0]), "\x1b[24;80R", "Live terminal query reply was corrupted");
  assert(harness.posted.includes("a:21:2"), "Live output was not acknowledged after parsing.");
}

function asyncParserReplyStreamScopeScenario() {
  const harness = createHarness();
  harness.state.deferWriteCallbacks = true;
  harness.state.deferParserReplies = true;

  harness.webview.dispatch(
    encodeFrame("d", 91, 1, Buffer.from("\x1b[6n", "latin1")));
  harness.webview.dispatch("clear:92");

  // xterm 6 parses writes asynchronously. The old reply may be posted after the native clear
  // request was delivered, but it must retain the old output stream so a replacement bridge
  // can reject it instead of writing it into the new session.
  harness.term.completeNextParserReply();
  const oldReply = harness.posted
    .filter(message => message.startsWith("b:"))
    .map(decodeInputFrame);
  deepEqual(
    oldReply,
    [{ streamId: 91, origin: "p", data: "\x1b[24;80R" }],
    "An asynchronous old-session parser reply lost its stream identity.");

  harness.term.completeNextWrite();
  harness.term.completeNextWrite();

  harness.state.deferParserReplies = false;
  harness.webview.dispatch(
    encodeFrame("d", 93, 1, Buffer.from("\x1b[6n", "latin1")));
  const replies = harness.posted
    .filter(message => message.startsWith("b:"))
    .map(decodeInputFrame);
  deepEqual(
    replies,
    [
      { streamId: 91, origin: "p", data: "\x1b[24;80R" },
      { streamId: 93, origin: "p", data: "\x1b[24;80R" },
    ],
    "The replacement parser reply did not use its live stream identity.");
}

function retirementPasteGateScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 101);

  // Hold human input and a subsequently posted native frame behind a real clipboard request.
  // Retirement must release this gate without waiting for the page's stalled-paste timeout.
  harness.container.dispatch("paste");
  assert(harness.posted.includes("p:1:1"), "Paste request did not acquire its output gate.");
  harness.term.emitUserData("stale-human-input");
  assert(
    !harness.posted.some(message =>
      message.startsWith("b:") && decodeInput(message) === "stale-human-input"),
    "Human input escaped before retirement cancelled the paste gate.");

  harness.state.deferWriteCallbacks = true;
  harness.state.deferParserReplies = true;
  harness.webview.dispatch(
    encodeFrame("d", 101, 1, Buffer.from("\x1b[6n", "latin1")));
  assert(
    !harness.posted.includes("a:101:1"),
    "Native output escaped the active paste gate before retirement.");

  // x: is only the immediate human-input boundary. It must release and restart the queued
  // output drain, but it cannot post the parser barrier before the native flush completes.
  harness.webview.dispatch("x:101");
  assert(
    !harness.posted.includes("barrier:101"),
    "The immediate retirement boundary posted the parser barrier before native flush.");
  harness.term.completeNextParserReply();
  harness.term.completeNextWrite();
  assert(
    harness.posted.includes("a:101:1"),
    "Retirement did not restart and acknowledge output queued behind the paste gate.");

  // C# posts k: only after the sealed native prefix has flushed and ACKed.
  harness.webview.dispatch("k:101");
  assert(
    !harness.posted.includes("barrier:101"),
    "The ordered parser barrier completed before its xterm write callback.");
  harness.term.completeNextWrite();
  assert(
    harness.posted.includes("barrier:101"),
    "The parser barrier did not complete after the sealed output and parser reply drained.");

  harness.term.emitUserData("post-retirement-input");
  harness.container.dispatch("paste");

  const inputs = harness.posted
    .filter(message => message.startsWith("b:"))
    .map(decodeInputFrame);
  deepEqual(
    inputs,
    [{ streamId: 101, origin: "p", data: "\x1b[24;80R" }],
    "Retirement did not preserve parser input while dropping every human frame.");
  equal(
    harness.posted.filter(message => message.startsWith("p:")).length,
    1,
    "Retirement allowed a new clipboard request after disabling human input.");
}

function pasteGateAndClearScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 31);
  harness.state.deferWriteCallbacks = true;
  harness.webview.dispatch(encodeFrame("d", 31, 1, Buffer.from("before-paste", "utf8")));

  harness.container.dispatch("paste");
  harness.term.emitUserData("key-after-paste");
  assert(
    !harness.posted.some(message => message.startsWith("p:")),
    "Paste request overtook an earlier xterm write.");

  harness.term.completeNextWrite();
  const firstAck = harness.posted.indexOf("a:31:1");
  const firstRequest = harness.posted.indexOf("p:1:1");
  assert(
    firstAck >= 0 && firstRequest > firstAck,
    "Paste request was not ordered behind earlier output acknowledgement.");

  harness.webview.dispatch("paste-drain:1");
  harness.container.dispatch("paste");
  equal(
    harness.posted.filter(message => message.startsWith("p:")).length,
    1,
    "Overlapping paste gesture should remain queued behind the active request");
  harness.term.emitUserData("old-session-input");

  const firstPaste = Buffer.from("first", "utf8");
  harness.webview.dispatch("paste-begin:1:1:" + firstPaste.length);
  harness.webview.dispatch("paste-chunk:1:" + firstPaste.toString("base64"));
  harness.webview.dispatch("paste-end:1");

  assert(
    harness.posted.includes("p:2:1"),
    "Second paste gesture was dropped instead of starting after the first completed.");
  const firstPasteInputIndex = harness.posted.findIndex(
    message => message.startsWith("b:") && decodeInput(message) === "first");
  const deferredKeyIndex = harness.posted.findIndex(
    message => message.startsWith("b:") && decodeInput(message) === "key-after-paste");
  assert(firstPasteInputIndex >= 0, "First ordered paste was not emitted as terminal input.");
  assert(
    deferredKeyIndex > firstPasteInputIndex,
    "A human key overtook the paste while the earlier xterm write callback was pending.");
  assert(
    !harness.posted.some(
      message => message.startsWith("b:") && decodeInput(message) === "old-session-input"),
    "Input deferred behind the second paste escaped before the session boundary.");

  harness.webview.dispatch("clear:");
  harness.term.completeNextWrite();
  harness.webview.dispatch("f:32");
  harness.term.emitUserData("new-session-input");

  assert(harness.term.resetCount === 1, "clear: did not reset xterm at its ordered barrier.");
  assert(
    !harness.posted.some(
      message => message.startsWith("b:") && decodeInput(message) === "old-session-input"),
    "clear: flushed input belonging to the retired session.");
  assert(
    harness.posted.some(
      message => message.startsWith("b:") && decodeInput(message) === "new-session-input"),
    "Input remained blocked after clear: cancelled the stale paste transaction.");
}

function synchronizedOutputScenario() {
  const harness = createHarness();
  harness.term.modes.synchronizedOutputMode = true;

  harness.webview.dispatch(
    encodeFrame("d", 51, 1, Buffer.alloc(4096, "x")));
  for (const handler of harness.term.bufferChangeHandlers) handler();
  harness.term.emitUserData("\x0c");
  harness.timers.runAll();

  equal(
    harness.term.refreshCount,
    0,
    "Manual repaint exposed a partial DEC synchronized-output frame");

  harness.term.modes.synchronizedOutputMode = false;
  for (const handler of harness.term.bufferChangeHandlers) handler();
  harness.timers.runAll();
  assert(
    harness.term.refreshCount > 0,
    "Renderer repaint did not resume after synchronized output ended.");
}

function focusClearRebindScenario() {
  const harness = createHarness();
  harness.container.clientWidth = 0;
  harness.container.clientHeight = 0;
  harness.state.dimensions = { cols: 0, rows: 0 };
  harness.webview.dispatch("f:61");

  equal(harness.term.focusCount, 0, "Old focus unexpectedly completed while collapsed");
  harness.webview.dispatch("clear:");
  equal(harness.term.resetCount, 1, "clear: did not reset after cancelling old focus");
  harness.webview.dispatch("f:62");

  harness.container.clientWidth = 1000;
  harness.container.clientHeight = 700;
  harness.state.dimensions = { cols: 120, rows: 40 };
  harness.timers.runAll();

  assert(!harness.posted.includes("focus:61"), "A stale focus retry acknowledged its retired stream.");
  assert(harness.posted.includes("focus:62"), "Replacement focus did not complete.");
  equal(harness.term.focusCount, 1, "A stale focus retry focused the terminal after clear:");
  equal(
    harness.posted.filter(
      message => message.startsWith("b:") && decodeInput(message) === "\x1b[I").length,
    1,
    "A stale focus retry emitted DEC focus input into the replacement session");
}

function clearInputGateScenario() {
  const harness = createHarness();
  harness.webview.dispatch("f:81");
  const postedBeforeClear = harness.posted.length;

  harness.webview.dispatch("clear:");
  const blurEvent = harness.terminalEvents.lastIndexOf("blur");
  const resetEvent = harness.terminalEvents.lastIndexOf("reset");
  assert(blurEvent >= 0 && resetEvent > blurEvent, "clear: reset xterm before removing focus.");

  harness.term.emitUserData("held-key");
  harness.container.dispatch("contextmenu", { shiftKey: true });
  harness.webview.dispatch(encodeFrame("d", 82, 1, Buffer.from("\x1b[6n", "latin1")));

  let gatedMessages = harness.posted.slice(postedBeforeClear);
  let gatedInput = gatedMessages
    .filter(message => message.startsWith("b:"))
    .map(decodeInput);
  deepEqual(
    gatedInput,
    ["\x1b[24;80R"],
    "Clear boundary dropped a parser reply or leaked blur/held-key input.");
  assert(
    !gatedMessages.some(message => message.startsWith("p:")),
    "Clipboard input escaped while the terminal input gate was closed.");

  harness.webview.dispatch("f:83");
  harness.term.emitUserData("next-key");
  gatedMessages = harness.posted.slice(postedBeforeClear);
  gatedInput = gatedMessages
    .filter(message => message.startsWith("b:"))
    .map(decodeInput);
  deepEqual(
    gatedInput,
    ["\x1b[24;80R", "\x1b[I", "next-key"],
    "Ordered focus did not re-enable input after parser replies.");
}

function imePasteOrderingScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 71);
  harness.container.dispatch("paste");
  assert(harness.posted.includes("p:1:1"), "Paste request was not emitted.");
  harness.webview.dispatch("paste-drain:1");

  harness.container.dispatch("compositionend", { data: "漢" });
  const query = Buffer.from("\x1b[6n", "latin1");
  harness.webview.dispatch(encodeFrame("d", 71, 1, query));

  const beforeComposition = harness.posted.filter(message => message.startsWith("b:"));
  equal(beforeComposition.length, 1, "Backend reply was deferred behind an unrelated IME marker");
  equal(decodeInput(beforeComposition[0]), "\x1b[24;80R", "Backend reply was corrupted");

  harness.timers.runNextDelay(0);
  assert(
    !harness.posted.some(message => message.startsWith("b:") && decodeInput(message) === "漢"),
    "Asynchronous IME input overtook its pending paste");

  const paste = Buffer.from("clip", "utf8");
  harness.webview.dispatch("paste-begin:1:1:" + paste.length);
  harness.webview.dispatch("paste-chunk:1:" + paste.toString("base64"));
  harness.webview.dispatch("paste-end:1");

  const orderedInput = harness.posted
    .filter(message => message.startsWith("b:"))
    .map(decodeInput);
  deepEqual(
    orderedInput,
    ["\x1b[24;80R", "clip", "漢"],
    "IME, paste, and backend reply did not preserve their independent ordering");
}

function pasteCancellationStressScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 72);
  harness.container.dispatch("paste");
  harness.webview.dispatch("paste-drain:1");

  const frameCount = 4000;
  for (let i = 0; i < frameCount; i++) harness.term.emitUserData("x");
  assert(
    !harness.posted.some(message => message.startsWith("b:")),
    "Input escaped before the pending paste was cancelled.");

  // This used to recurse once per held frame and overflow the WebView JavaScript stack.
  harness.webview.dispatch("paste-cancel:1");
  const inputFrames = harness.posted.filter(message => message.startsWith("b:"));
  equal(inputFrames.length, frameCount, "Paste cancellation lost deferred input frames");
  assert(
    inputFrames.every(message => decodeInput(message) === "x"),
    "Paste cancellation corrupted deferred input frames.");
}

function focusCyclePasteOrderingScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 73);
  harness.container.dispatch("paste");
  harness.webview.dispatch("paste-drain:1");

  // Browser order is focus -> focusin. xterm emits ESC[I from its focus listener,
  // so the earlier event itself must be captured while the paste transaction is pending.
  harness.container.dispatch("blur");
  harness.container.dispatch("focus");
  harness.container.dispatch("focusin");
  assert(
    !harness.posted.some(message =>
      message.startsWith("b:") &&
      ["\x1b[O", "\x1b[I"].includes(decodeInput(message))),
    "A DEC focus report overtook the earlier pending paste.");

  const paste = Buffer.from("clip", "utf8");
  harness.webview.dispatch("paste-begin:1:1:" + paste.length);
  harness.webview.dispatch("paste-chunk:1:" + paste.toString("base64"));
  harness.webview.dispatch("paste-end:1");

  const orderedInput = harness.posted
    .filter(message => message.startsWith("b:"))
    .map(decodeInput);
  deepEqual(
    orderedInput,
    ["clip", "\x1b[O", "\x1b[I"],
    "Paste and DEC focus reports did not preserve browser event order");
}

function neutralParserBarrierScenario() {
  const harness = createHarness();
  harness.state.deferWriteCallbacks = true;
  const postedBefore = harness.posted.length;
  const query = Buffer.from("\x1b[6n", "latin1");

  harness.webview.dispatch("clear:91");
  harness.webview.dispatch(encodeFrame("q", 91, 1, query));
  harness.webview.dispatch("k:91");

  assert(!harness.posted.includes("barrier:91"), "Parser barrier ACK overtook xterm writes.");
  harness.term.completeNextWrite(); // ordered clear
  harness.term.completeNextWrite(); // side-effect-free replay
  assert(!harness.posted.includes("barrier:91"), "Parser barrier ACK overtook its empty write.");
  harness.term.completeNextWrite(); // neutral parser barrier

  const postedDuringReplay = harness.posted.slice(postedBefore);
  assert(postedDuringReplay.includes("barrier:91"), "Parser barrier did not acknowledge completion.");
  equal(harness.term.focusCount, 0, "Neutral parser barrier focused the terminal");
  assert(
    !postedDuringReplay.some(message => message.startsWith("r:")),
    "Neutral parser barrier reported a resize.");
  assert(
    !postedDuringReplay.some(message => message.startsWith("b:")),
    "Replay or parser barrier leaked generated terminal input.");
}
function retirementResizeReattachScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 71);
  harness.state.deferWriteCallbacks = true;

  // Hold old-stream output inside xterm while a real observer fit is reported for that stream.
  harness.webview.dispatch(
    encodeFrame("d", 71, 1, Buffer.from("old-geometry-output", "utf8")));
  harness.state.dimensions = { cols: 100, rows: 30 };
  harness.dispatchWindow("resize");
  harness.timers.runNextDelay(50);
  const oldResizeIndex = harness.posted.indexOf("r:71:100x30");
  assert(oldResizeIndex >= 0, "Pre-retirement resize was not scoped to the old stream.");

  // x: freezes without fitting. The already-posted r: remains ahead of k:'s parser proof.
  harness.webview.dispatch("x:71");
  harness.term.completeNextWrite();
  harness.webview.dispatch("k:71");
  harness.term.completeNextWrite();
  const oldBarrierIndex = harness.posted.indexOf("barrier:71");
  assert(oldBarrierIndex > oldResizeIndex, "Retirement barrier overtook the scoped resize.");

  // Both a pre-x scheduled fit and a new observer fit after x must be inert while focus is null.
  harness.state.dimensions = { cols: 120, rows: 40 };
  harness.timers.runAll();
  harness.dispatchWindow("resize");
  harness.timers.runNextDelay(50);
  equal(harness.term.cols, 100, "A retired fit changed xterm columns before reattach.");
  equal(harness.term.rows, 30, "A retired fit changed xterm rows before reattach.");
  assert(
    !harness.posted.includes("r:71:120x40"),
    "A post-retirement fit leaked through the old stream.");

  // Detached output is parsed at the frozen geometry. Explicit f:new then fits/reports before focus.
  const detachedWriteIndex = harness.term.writtenChunks.length;
  harness.webview.dispatch(
    encodeFrame("d", 72, 1, Buffer.from("detached-output", "utf8")));
  equal(harness.term.cols, 100, "Detached output was submitted after an unowned resize.");
  harness.term.completeNextWrite();
  assert(
    harness.term.writtenChunks[detachedWriteIndex].equals(Buffer.from("detached-output", "utf8")),
    "Detached output was not parsed before replacement focus.");

  harness.webview.dispatch("f:72");
  const newResizeIndex = harness.posted.indexOf("r:72:120x40");
  const newFocusInputIndex = harness.posted.findIndex(message =>
    message.startsWith("b:72:u:") && decodeInput(message) === "\x1b[I");
  const newFocusAckIndex = harness.posted.indexOf("focus:72");
  assert(newResizeIndex > oldBarrierIndex, "Replacement geometry report was not stream scoped.");
  assert(newFocusInputIndex > newResizeIndex, "Replacement focus input overtook resize.");
  assert(newFocusAckIndex > newFocusInputIndex, "Replacement focus ACK overtook resize/input.");
  assert(
    !harness.posted.some(message => /^r:[0-9]+x[0-9]+$/.test(message)),
    "A post-ready resize escaped without a stream id.");
}

function staleRetirementCannotCancelClaimedFocusScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 201);
  harness.state.deferWriteCallbacks = true;
  const focusCountBefore = harness.term.focusCount;
  harness.webview.dispatch(
    encodeFrame("d", 201, 1, Buffer.from("pending-old-write", "utf8")));

  // f:new claims the page immediately but waits behind the old xterm write. A late x:old must
  // not invalidate/remove that queued focus operation.
  harness.webview.dispatch("f:202");
  harness.webview.dispatch("x:201");
  harness.term.completeNextWrite();

  assert(harness.posted.includes("focus:202"), "A stale x: cancelled the claimed replacement focus.");
  assert(
    harness.posted.some(message => message.startsWith("r:202:")),
    "Claimed replacement focus did not publish scoped geometry.");
  equal(
    harness.term.focusCount,
    focusCountBefore + 1,
    "Replacement focus did not survive stale retirement.");
}

function protocolPostFailureScenario() {
  const ready = createHarness({
    failPostPrefixes: ["ready:"],
    allowPendingReady: true,
    suppressConsoleErrors: true,
  });
  equal(
    ready.postAttempts.filter(message => message.startsWith("ready:")).length,
    1,
    "Initial ready post was not attempted exactly once.");
  ready.timers.runNextDelay(50);
  assert(ready.posted.includes("ready:80x24"), "A failed ready post was not retried.");
  equal(
    ready.postAttempts.filter(message => message.startsWith("ready:")).length,
    2,
    "Ready state committed before the successful retry.");

  const parserInput = createHarness({ suppressConsoleErrors: true });
  parserInput.webview.failNextPost("b:");
  parserInput.webview.dispatch(
    encodeFrame("d", 301, 1, Buffer.from("[6n", "latin1")));
  parserInput.webview.dispatch("k:301");
  assert(parserInput.posted.includes("fatal:protocol"), "Parser-input post failure was not fatal.");
  assert(
    !parserInput.posted.some(message =>
      message.startsWith("b:") || message === "a:301:1" || message === "barrier:301"),
    "A failed parser reply still allowed ACK or retirement proof.");

  const outputAck = createHarness({ suppressConsoleErrors: true });
  outputAck.webview.failNextPost("a:");
  outputAck.webview.dispatch(
    encodeFrame("d", 302, 1, Buffer.from("first", "utf8")));
  outputAck.webview.dispatch(
    encodeFrame("d", 302, 2, Buffer.from("must-not-parse", "utf8")));
  assert(outputAck.posted.includes("fatal:protocol"), "Output ACK post failure was not fatal.");
  equal(outputAck.term.writtenChunks.length, 1, "Output continued after an ACK post failure.");

  const geometry = createHarness({ suppressConsoleErrors: true });
  geometry.state.dimensions = { cols: 120, rows: 40 };
  geometry.webview.failNextPost("r:");
  geometry.webview.dispatch("f:303");
  assert(geometry.posted.includes("fatal:protocol"), "Geometry post failure was not fatal.");
  equal(geometry.term.focusCount, 0, "Focus continued after geometry could not reach the host.");
  assert(!geometry.posted.includes("focus:303"), "Focus ACK escaped after geometry failure.");

  const focus = createHarness({ suppressConsoleErrors: true });
  focus.webview.failNextPost("focus:");
  focus.webview.dispatch("f:304");
  assert(focus.posted.includes("fatal:protocol"), "Focus ACK post failure was not fatal.");
  assert(!focus.posted.includes("focus:304"), "Failed focus ACK was treated as delivered.");
  const inputCountAfterFocusFailure =
    focus.posted.filter(message => message.startsWith("b:")).length;
  focus.term.emitUserData("must-be-disabled");
  equal(
    focus.posted.filter(message => message.startsWith("b:")).length,
    inputCountAfterFocusFailure,
    "Human input remained enabled after focus ACK failure.");

  const barrier = createHarness({ suppressConsoleErrors: true });
  barrier.webview.failNextPost("barrier:");
  barrier.webview.dispatch("k:305");
  assert(barrier.posted.includes("fatal:protocol"), "Barrier ACK post failure was not fatal.");
  assert(!barrier.posted.includes("barrier:305"), "Failed parser barrier was treated as complete.");

  const pasteRequest = createHarness({ suppressConsoleErrors: true });
  enableTerminalInput(pasteRequest, 306);
  pasteRequest.state.deferWriteCallbacks = true;
  pasteRequest.webview.dispatch(
    encodeFrame("d", 306, 1, Buffer.from("before-paste", "utf8")));
  pasteRequest.webview.failNextPost("p:");
  pasteRequest.container.dispatch("paste");
  pasteRequest.term.emitUserData("must-be-dropped");
  pasteRequest.term.completeNextWrite();
  assert(
    pasteRequest.posted.includes("fatal:protocol"),
    "Paste-request post failure was not fatal.");
  assert(
    !pasteRequest.posted.some(message =>
      message.startsWith("b:") && decodeInput(message) === "must-be-dropped"),
    "Input deferred behind a failed paste request leaked to the host.");

  pasteRequest.webview.dispatch("paste-drain:1");
  pasteRequest.webview.dispatch("paste-begin:1:1:4");
  pasteRequest.webview.dispatch("paste-chunk:1:Y2xpcA==");
  pasteRequest.webview.dispatch("paste-end:1");
  pasteRequest.term.emitUserData("must-stay-disabled");
  assert(
    !pasteRequest.posted.some(message => message.startsWith("b:")),
    "Stale paste frames or human input escaped after a paste-request failure.");

  pasteRequest.webview.dispatch("clear:306");
  pasteRequest.term.completeNextWrite();
  equal(pasteRequest.term.resetCount, 1, "Failed paste request stranded the output gate.");
  pasteRequest.webview.dispatch("f:307");
  pasteRequest.term.emitUserData("new-session-input");
  deepEqual(
    pasteRequest.posted
      .filter(message => message.startsWith("b:"))
      .map(decodeInput),
    ["\x1b[I", "new-session-input"],
    "Paste failure recovery leaked deferred input or left the input gate blocked");

  const batch = createHarness({ suppressConsoleErrors: true });
  enableTerminalInput(batch, 308);
  batch.container.dispatch("paste");
  batch.webview.dispatch("paste-drain:1");
  batch.term.emitUserData("one");
  batch.term.emitUserData("two");
  const attemptsBeforeBatch = batch.postAttempts.length;
  batch.webview.failNextPost("b:");
  batch.webview.dispatch("paste-cancel:1");
  equal(
    batch.postAttempts.slice(attemptsBeforeBatch)
      .filter(message => message.startsWith("b:")).length,
    1,
    "Batched input continued after its first failed post.");
  assert(batch.posted.includes("fatal:protocol"), "Batched input failure was not fatal.");
}

function lateFocusAfterRetirementScenario() {
  const harness = createHarness();
  enableTerminalInput(harness, 401);
  harness.webview.dispatch("x:401");
  harness.webview.dispatch("k:401");
  assert(harness.posted.includes("barrier:401"), "Retirement barrier did not complete.");

  const focusCount = harness.term.focusCount;
  const inputCount = harness.posted.filter(message => message.startsWith("b:")).length;
  harness.state.dimensions = { cols: 120, rows: 40 };
  harness.webview.dispatch("f:401");
  equal(harness.term.focusCount, focusCount, "Late focus reclaimed its retired stream.");
  equal(harness.term.cols, 80, "Late focus resized xterm after retirement.");
  equal(
    harness.posted.filter(message => message.startsWith("b:")).length,
    inputCount,
    "Late focus re-enabled retired-stream input.");
  assert(!harness.posted.includes("focus:401"), "Late focus acknowledged a retired stream.");
  assert(!harness.posted.includes("fatal:protocol"), "Late retired focus poisoned the page.");

  harness.webview.dispatch("f:402");
  equal(harness.term.focusCount, focusCount + 1, "A new stream could not claim the page.");
  assert(harness.posted.includes("r:402:120x40"), "New stream did not report geometry.");
  assert(harness.posted.includes("focus:402"), "New stream did not acknowledge focus.");

  // A retired f: must be rejected before it can cancel clipboard/input state owned by B.
  harness.container.dispatch("paste");
  assert(harness.posted.includes("p:1:1"), "New stream did not start its paste transaction.");
  harness.term.emitUserData("held-behind-paste");
  assert(
    !harness.posted.some(message =>
      message.startsWith("b:") && decodeInput(message) === "held-behind-paste"),
    "Input escaped before the pending paste completed.");

  harness.webview.dispatch("f:401");
  harness.webview.dispatch("paste-drain:1");
  const paste = Buffer.from("clip", "utf8");
  harness.webview.dispatch("paste-begin:1:1:" + paste.length);
  harness.webview.dispatch("paste-chunk:1:" + paste.toString("base64"));
  harness.webview.dispatch("paste-end:1");

  deepEqual(
    harness.posted
      .filter(message => message.startsWith("b:"))
      .map(decodeInput)
      .slice(-2),
    ["clip", "held-behind-paste"],
    "Late retired focus cancelled the active stream's paste or deferred input.");
}

function focusAfterFitScenario() {
  const harness = createHarness();
  harness.container.clientWidth = 0;
  harness.container.clientHeight = 0;
  harness.state.dimensions = { cols: 0, rows: 0 };
  harness.webview.dispatch("f:41");

  equal(harness.term.focusCount, 0, "Focus occurred while the terminal viewport was unusable");
  assert(!harness.posted.includes("focus:41"), "Focus ACK occurred before a usable fit");

  harness.container.clientWidth = 1000;
  harness.container.clientHeight = 700;
  harness.state.dimensions = { cols: 120, rows: 40 };
  harness.timers.runNext();

  const resizeEvent = harness.terminalEvents.indexOf("resize:120x40");
  const focusEvent = harness.terminalEvents.indexOf("focus");
  assert(resizeEvent >= 0 && focusEvent > resizeEvent, "xterm focus occurred before resize.");

  const resizeMessage = harness.posted.indexOf("r:41:120x40");
  const focusInput = harness.posted.findIndex(
    message => message.startsWith("b:") && decodeInput(message) === "\x1b[I");
  const focusAck = harness.posted.indexOf("focus:41");
  assert(resizeMessage >= 0, "Usable focus fit did not report the new PTY geometry.");
  assert(focusInput > resizeMessage, "DEC focus input overtook the geometry report.");
  assert(focusAck > focusInput, "Focus ACK overtook the DEC focus input.");
}

const scenarios = {
  "fragmented-output": fragmentedOutputScenario,
  "alternate-screen-exit-ordering": alternateScreenExitOrderingScenario,
  "replay-side-effects": replaySideEffectsScenario,
  "async-parser-reply-stream-scope": asyncParserReplyStreamScopeScenario,
  "retirement-paste-gate": retirementPasteGateScenario,
  "retirement-resize-reattach": retirementResizeReattachScenario,
  "stale-retirement-claimed-focus": staleRetirementCannotCancelClaimedFocusScenario,
  "protocol-post-failures": protocolPostFailureScenario,
  "late-focus-after-retirement": lateFocusAfterRetirementScenario,
  "paste-gate-and-clear": pasteGateAndClearScenario,
  "synchronized-output": synchronizedOutputScenario,
  "focus-after-fit": focusAfterFitScenario,
  "neutral-parser-barrier": neutralParserBarrierScenario,
  "focus-clear-rebind": focusClearRebindScenario,
  "clear-input-gate": clearInputGateScenario,
  "ime-paste-ordering": imePasteOrderingScenario,
  "paste-cancellation-stress": pasteCancellationStressScenario,
  "focus-cycle-paste-ordering": focusCyclePasteOrderingScenario,
};

if (!bridgePath || !scenario || !scenarios[scenario]) {
  fail(
    "Usage: node terminal-bridge-harness.js <bridge.js> <" +
    Object.keys(scenarios).join("|") + ">");
}

scenarios[scenario]();
process.stdout.write("PASS " + scenario + "\n");
