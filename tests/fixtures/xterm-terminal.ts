import assert from 'node:assert/strict';
import { XtermSession, sshTerminal, retainSshTerminals } from '../../src/xterm-terminal';
import { WebglAddon } from '@xterm/addon-webgl';
import * as React from 'react';
import { createRoot } from 'react-dom/client';
import {
  ContextMenuOverlayProvider,
  useContextMenuOverlayOpen,
} from '../../src/components/ui/context-menu';
// Compiled from the production App component by the Chromium harness.
import { SshXtermSurface } from 'virtual:ssh-surface';

const sleep = (delay = 30) => new Promise((resolve) => setTimeout(resolve, delay));

async function assertPainted(runtime: XtermSession, text: string): Promise<void> {
  const rows = runtime.terminal.element!.querySelector('.xterm-rows')!;
  for (let retry = 0; retry < 100 && !rows.textContent!.includes(text); retry++) await sleep(10);
  assert.ok(rows.textContent!.includes(text), 'fallback did not paint terminal text');
}

async function run() {
  window.confirm = () => {
    throw new Error('Native confirmation must not be used');
  };
  window.open = () => {
    throw new Error('Renderer navigation must not be used');
  };
  const activateLink = (runtime: XtermSession, url: string) => {
    const event = new MouseEvent('click', { cancelable: true });
    runtime.terminal.options.linkHandler!.activate(event, url, {
      start: { x: 1, y: 1 },
      end: { x: 1, y: 1 },
    });
    assert.ok(event.defaultPrevented);
  };
  const acknowledgments: number[] = [];
  const startupReplies: string[] = [];
  window.wormhole = {
    acknowledgeSshTerminal: (_id: string, sequence: number) => acknowledgments.push(sequence),
    sendSshInput: async (_id: string, data: string) => {
      startupReplies.push(atob(data));
    },
  } as typeof window.wormhole;
  let sequence = 0;
  const send = async (runtime: XtermSession, text: string | Uint8Array, reset = false) => {
    const bytes = typeof text === 'string' ? new TextEncoder().encode(text) : text;
    const number = ++sequence;
    runtime.receive({
      type: 'terminal-output',
      sessionId: 'test',
      data: btoa(String.fromCharCode(...bytes)),
      sequence: number,
      reset,
      columns: reset ? 80 : 0,
      rows: reset ? 24 : 0,
    });
    for (let retry = 0; retry < 100 && !acknowledgments.includes(number); retry++) await sleep(5);
    assert.ok(acknowledgments.includes(number), 'xterm did not acknowledge parsed output');
    return number;
  };
  const surface = document.createElement('div');
  surface.style.cssText = 'width:800px;height:400px';
  document.body.append(surface);
  const inputs: string[] = [],
    copied: string[] = [],
    sizes: number[][] = [];
  let pasteResult = true;
  let pasteCount = 0;
  let completePaste: ((result: boolean) => void) | undefined;
  const links: string[] = [];
  const actions = {
    active: true,
    autoCopy: true,
    input: (data: string) => inputs.push(data),
    resize: (cols: number, rows: number) => sizes.push([cols, rows]),
    copy: (text: string) => copied.push(text),
    openLink: (url: string) => links.push(url),
    paste: async () => {
      pasteCount++;
      return completePaste
        ? new Promise<boolean>((resolve) => {
            completePaste = resolve;
          })
        : pasteResult;
    },
  };
  const runtime = sshTerminal('test');
  activateLink(runtime, 'https://example.com');
  assert.equal(links.length, 0, 'unmounted terminal opened a link');
  assert.equal(sshTerminal('test'), runtime);
  await send(runtime, '', true);
  await send(runtime, '\x1b[6n');
  assert.ok(startupReplies[0]?.startsWith('\x1b['));
  runtime.configure(actions);
  runtime.attach(surface);
  runtime.attach(surface);
  runtime.focus();
  activateLink(runtime, 'https://example.com');
  activateLink(runtime, 'https://example.com/' + 'a'.repeat(8192));
  assert.deepEqual(links, ['https://example.com/']);
  assert.equal(document.activeElement, runtime.terminal.textarea);
  assert.ok(surface.querySelector('.xterm'));
  assert.ok(sizes.length > 0);
  assert.equal(runtime.terminal.options.scrollback, 5000);
  runtime.terminal.resize(200, 24);
  await send(runtime, '\x1b[?1000h');
  const screen = runtime.terminal.element!.querySelector('.xterm-screen')!;
  const rect = screen.getBoundingClientRect();
  screen.dispatchEvent(
    new MouseEvent('mousedown', {
      bubbles: true,
      button: 0,
      buttons: 1,
      clientX: rect.left + (rect.width * 130) / 200,
      clientY: rect.top + 10,
    }),
  );
  assert.ok(
    startupReplies.some(
      (reply) => reply.startsWith('\x1b[M') && [...reply].some((char) => char.charCodeAt(0) > 127),
    ),
    'legacy mouse bytes were lost',
  );
  await send(runtime, '\x1b[?1000l');
  runtime.fit();

  await send(runtime, '\x1b[1;3;4;38;2;12;34;56mA\x1b[0m');
  const cell = runtime.terminal.buffer.active.getLine(0)!.getCell(0)!;
  assert.ok(cell.isBold());
  assert.ok(cell.isItalic());
  assert.ok(cell.isUnderline());
  assert.equal(cell.getFgColor(), 0x0c2238);
  const utf8 = new TextEncoder().encode('日本語');
  await send(runtime, utf8.slice(0, 2));
  await send(runtime, utf8.slice(2));
  assert.ok(runtime.terminal.buffer.active.getLine(0)!.translateToString(true).includes('日本語'));
  assert.equal(runtime.terminal.buffer.active.getLine(0)!.getCell(1)!.getWidth(), 2);
  await send(runtime, '\x1b[?1049h\x1b[Heditor');
  assert.equal(runtime.terminal.buffer.active.type, 'alternate');
  await send(runtime, '\x1b[?1049l');
  assert.equal(runtime.terminal.buffer.active.type, 'normal');
  assert.ok(runtime.terminal.buffer.active.getLine(0)!.translateToString(true).includes('日本語'));
  runtime.terminal.select(0, 0, 1);
  surface
    .querySelector('.xterm')!
    .dispatchEvent(new MouseEvent('mouseup', { bubbles: true, button: 0 }));
  assert.deepEqual(copied, ['A']);

  const key = (key: string, options: KeyboardEventInit = {}) =>
    runtime.terminal.textarea!.dispatchEvent(
      new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...options }),
    );
  key('c', { ctrlKey: true, keyCode: 67 });
  key('c', { ctrlKey: true, keyCode: 67, repeat: true });
  assert.equal(copied.length, 2);
  assert.equal(inputs.includes('\x03'), false);
  runtime.terminal.textarea!.dispatchEvent(
    new KeyboardEvent('keyup', { key: 'c', ctrlKey: true, bubbles: true }),
  );
  runtime.terminal.clearSelection();
  key('c', { ctrlKey: true, keyCode: 67 });
  assert.equal(inputs.at(-1), '\x03');
  key('c', { ctrlKey: true, shiftKey: true, keyCode: 67 });
  runtime.terminal.textarea!.dispatchEvent(new KeyboardEvent('keyup', { key: 'c', bubbles: true }));
  key('v', { ctrlKey: true, keyCode: 86 });
  await sleep();
  assert.equal(pasteCount, 1);
  runtime.terminal.select(0, 0, 1);
  surface
    .querySelector('.xterm')!
    .dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  await sleep();
  assert.equal(pasteCount, 2);
  assert.equal(runtime.terminal.hasSelection(), false);
  pasteResult = false;
  runtime.terminal.select(0, 0, 1);
  key('v', { ctrlKey: true, keyCode: 86 });
  await sleep();
  assert.equal(runtime.terminal.hasSelection(), true);
  runtime.terminal.textarea!.dispatchEvent(
    new KeyboardEvent('keyup', { key: 'v', ctrlKey: true, bubbles: true }),
  );
  completePaste = () => {};
  key('v', { metaKey: true, keyCode: 86 });
  runtime.terminal.select(0, 0, 3);
  completePaste!(true);
  await sleep();
  assert.equal(runtime.terminal.getSelection(), 'A日');
  completePaste = undefined;
  runtime.configure({
    ...actions,
    paste: async () => {
      throw new Error('clipboard unavailable');
    },
  });
  key('v', { ctrlKey: true });
  await sleep();

  runtime.configure({ ...actions, active: false, autoCopy: false });
  activateLink(runtime, 'https://example.com/hidden');
  assert.equal(links.length, 1, 'inactive terminal opened a link');
  runtime.focus();
  runtime.fit();
  key('v', { ctrlKey: true });
  surface
    .querySelector('.xterm')!
    .dispatchEvent(new MouseEvent('mouseup', { bubbles: true, button: 0 }));
  surface.querySelector('.xterm')!.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
  await send(runtime, '\x1b[6n');
  assert.ok(inputs.at(-1)?.startsWith('\x1b['), 'hidden sessions must answer terminal queries');
  // A reconnect starts a fresh PTY at the reset geometry even in a hidden tab.
  await send(runtime, '', true);
  assert.equal(runtime.terminal.cols, 80, 'hidden reconnect retained the previous PTY width');
  assert.equal(runtime.terminal.rows, 24);
  runtime.detach();
  await send(runtime, '\r\nhidden output');
  runtime.configure(actions);
  runtime.attach(surface);
  assert.ok(
    runtime.terminal.buffer.active.getLine(1)!.translateToString(true).includes('hidden output'),
  );
  const number = await send(runtime, 'once');
  runtime.receive({
    type: 'terminal-output',
    sessionId: 'test',
    data: btoa('once'),
    sequence: number,
    reset: false,
    columns: 0,
    rows: 0,
  });
  assert.ok(runtime.terminal.buffer.active.getLine(1)!.translateToString(true).endsWith('once'));
  assert.equal(
    runtime.terminal.buffer.active.getLine(1)!.translateToString(true).endsWith('onceonce'),
    false,
  );

  // Queue bursts and duplicate delivery while a prior write is still parsing.
  const burst: number[] = [];
  for (let index = 0; index < 16; index++) {
    const packet = {
      type: 'terminal-output' as const,
      sessionId: 'test',
      data: btoa('line\r\n'.repeat(100)),
      sequence: ++sequence,
      reset: false,
      columns: 0,
      rows: 0,
    };
    runtime.receive(packet);
    runtime.receive(packet);
    burst.push(packet.sequence);
  }
  while (!acknowledgments.includes(burst.at(-1)!)) await sleep();
  await send(runtime, 'line\r\n'.repeat(6000));
  assert.ok(runtime.terminal.buffer.active.length <= 5000 + runtime.terminal.rows);
  await send(runtime, '', true);
  assert.equal(runtime.terminal.buffer.active.getLine(0)!.translateToString(true), '');
  surface.style.width = '20000px';
  runtime.fit();
  assert.equal(runtime.terminal.cols, 500);
  surface.style.width = '0px';
  runtime.fit();
  surface.style.width = '800px';
  runtime.fit();

  let addon: WebglAddon | undefined;
  const fallback = new XtermSession('fallback', () => {
    throw new Error('WebGL unavailable');
  });
  fallback.configure(actions);
  fallback.attach(surface);
  await send(fallback, 'fallback');
  assert.equal(fallback.terminal.buffer.active.getLine(0)!.translateToString(true), 'fallback');
  await assertPainted(fallback, 'fallback');
  fallback.dispose();
  const contextLoss = new XtermSession('context', () => {
    addon = new WebglAddon();
    return addon;
  });
  contextLoss.configure(actions);
  contextLoss.attach(surface);
  const canvas = contextLoss.terminal.element!.querySelector('canvas');
  const gl = canvas?.getContext('webgl2');
  if (gl) {
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    await sleep(100);
  }
  await send(contextLoss, 'after context loss');
  assert.equal(
    contextLoss.terminal.buffer.active.getLine(0)!.translateToString(true),
    'after context loss',
  );
  if (gl?.isContextLost()) await assertPainted(contextLoss, 'after context loss');
  contextLoss.dispose();
  runtime.receive({
    type: 'terminal-output',
    sessionId: 'test',
    data: btoa('dispose pending'),
    sequence: ++sequence,
    reset: false,
    columns: 0,
    rows: 0,
  });
  retainSshTerminals(new Set());
  runtime.receive({
    type: 'terminal-output',
    sessionId: 'test',
    data: '',
    sequence: ++sequence,
    reset: false,
    columns: 0,
    rows: 0,
  });
  await sleep();
  const replacement = sshTerminal('test');
  assert.notEqual(replacement, runtime);
  retainSshTerminals(new Set(['test']));
  retainSshTerminals(new Set());
  assert.ok(addon || !gl);
  // Mount the production React surface, including lifecycle and focus behavior.
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const mounted = document.createElement('div');
  mounted.style.cssText = 'width:800px;height:400px';
  document.body.append(mounted);
  const root = createRoot(mounted);
  window.copyTerminalTest = (text: string) => copied.push(text);
  window.wormhole = {
    ...window.wormhole,
    resizeSshSession: async (_id: string, cols: number, rows: number) => {
      sizes.push([cols, rows]);
    },
    pasteClipboardToSsh: async () => ({ pasted: false }),
  } as typeof window.wormhole;
  const nativePastes: string[] = [];
  const receiveInput = (_id: string, data: string, paste = false) => {
    if (paste) nativePastes.push(data);
    else inputs.push(data);
  };
  let props = {
    session: { id: 'ui', backendSessionId: 'component', status: 'connected' },
    isActive: true,
    isAuthorized: true,
    autoCopyOnSelect: false,
    onInput: receiveInput,
    onReconnect: () => {},
    onTrustHostKey: () => {},
  };
  const render = async () => {
    await React.act(async () => {
      root.render(
        React.createElement(
          ContextMenuOverlayProvider,
          null,
          React.createElement(OverlayProbe),
          React.createElement(SshXtermSurface, props),
        ),
      );
    });
  };
  function OverlayProbe() {
    return React.createElement(
      'output',
      { id: 'native-overlay-probe' },
      String(useContextMenuOverlayOpen()),
    );
  }
  await render();
  const componentRuntime = sshTerminal('component');
  assert.ok(mounted.querySelector('.xterm'));
  componentRuntime.terminal.input('user input', true);
  assert.equal(inputs.at(-1), 'user input');
  const nativePaste = new DataTransfer();
  nativePaste.setData('text/plain', '\x1b[201~echo injected\r');
  const inputCountBeforePaste = inputs.length;
  componentRuntime.terminal.textarea!.dispatchEvent(
    new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: nativePaste }),
  );
  await sleep();
  assert.equal(inputs.length, inputCountBeforePaste, 'native paste bypassed the Go clipboard flow');
  assert.deepEqual(nativePastes, ['\x1b[201~echo injected\r']);
  componentRuntime.terminal.select(0, 0, 1);
  mounted.querySelector('.xterm')!.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
  await sleep();
  const otherInput = document.createElement('input');
  document.body.append(otherInput);
  otherInput.focus();
  props = { ...props, onInput: (id, data, paste) => receiveInput(id, data, paste) };
  await render();
  assert.equal(document.activeElement, otherInput, 'background state updates stole focus');
  props = { ...props, isActive: false, isAuthorized: false };
  await render();
  assert.ok(componentRuntime.terminal.textarea!.readOnly);
  componentRuntime.terminal.textarea!.dispatchEvent(
    new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: nativePaste }),
  );
  assert.equal(nativePastes.length, 1, 'locked native paste was forwarded');
  const inputsBeforeLock = inputs.length;
  await send(componentRuntime, '\x1b[6n');
  assert.equal(
    inputs.length,
    inputsBeforeLock,
    'a locked terminal sent input through the UI handler',
  );
  props = { ...props, isActive: true, isAuthorized: true };
  await render();
  assert.equal(document.activeElement, componentRuntime.terminal.textarea);

  const destination = 'https://auth.openai.com/codex/device';
  const openedLinks: string[] = [];
  let browserFailure = false;
  let finishOpen: (() => void) | undefined;
  window.wormhole!.openTerminalLink = async (url: string) => {
    openedLinks.push(url);
    if (browserFailure) throw new Error('Sensitive diagnostic must not appear');
    if (finishOpen)
      await new Promise<void>((resolve) => {
        finishOpen = resolve;
      });
  };
  const requestLink = async (url = destination) => {
    await React.act(async () => {
      activateLink(componentRuntime, url);
    });
    await React.act(async () => {
      await sleep(100);
    });
  };
  const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
  const button = (label: string) => {
    const element = [...dialog()!.querySelectorAll('button')].find(
      (item) => item.textContent === label,
    );
    assert.ok(element, 'Missing terminal link button: ' + label);
    return element;
  };
  const click = async (label: string) => {
    await React.act(async () => {
      button(label).click();
    });
    await React.act(async () => {
      await sleep(100);
    });
  };
  const escape = async () => {
    await React.act(async () => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });
    await React.act(async () => {
      await sleep(100);
    });
  };
  // Exercise OSC 8 parsing and xterm's real mouse link provider rather than
  // relying solely on calls to the options callback used by boundary tests.
  componentRuntime.terminal.clearSelection();
  await send(componentRuntime, `\x1b[2J\x1b[H\x1b]8;;${destination}\x07Open link\x1b]8;;\x07`);
  mounted.scrollIntoView();
  const linkScreen = componentRuntime.terminal.element!.querySelector('.xterm-screen')!;
  const linkRect = linkScreen.getBoundingClientRect();
  const linkPoint = {
    bubbles: true,
    cancelable: true,
    clientX: linkRect.left + (1.5 * linkRect.width) / componentRuntime.terminal.cols,
    clientY: linkRect.top + (0.5 * linkRect.height) / componentRuntime.terminal.rows,
    button: 0,
  };
  linkScreen.dispatchEvent(new MouseEvent('mousemove', linkPoint));
  await sleep();
  assert.ok(linkScreen.classList.contains('xterm-cursor-pointer'), 'OSC 8 link was not detected');
  await React.act(async () => {
    linkScreen.dispatchEvent(new MouseEvent('mousedown', { ...linkPoint, buttons: 1 }));
    linkScreen.dispatchEvent(new MouseEvent('mouseup', linkPoint));
  });
  await React.act(async () => {
    await sleep(100);
  });
  assert.ok(dialog()!.textContent!.includes('Open terminal link?'));
  assert.ok(dialog()!.textContent!.includes(destination));
  assert.equal(document.querySelector('#native-overlay-probe')!.textContent, 'true');
  assert.equal(document.activeElement, button('Cancel'), 'Cancel must be the initial focus');
  assert.equal(openedLinks.length, 0, 'link opened without confirmation');
  await requestLink('https://example.com/replacement');
  assert.ok(
    dialog()!.textContent!.includes(destination),
    'second link replaced a pending confirmation',
  );
  await click('Cancel');
  assert.equal(dialog(), null);
  assert.equal(document.querySelector('#native-overlay-probe')!.textContent, 'false');
  assert.equal(document.activeElement, componentRuntime.terminal.textarea);
  const unicodeDestination = 'https://例え.テスト/\u202elogin';
  await requestLink(unicodeDestination);
  assert.equal(
    dialog()!.querySelector('p.font-mono')!.textContent,
    new URL(unicodeDestination).href,
  );
  await click('Cancel');
  for (const rejected of [
    'javascript:alert(1)',
    'https://user:password@example.com',
    'https://example.com/' + 'é'.repeat(1500),
  ]) {
    await requestLink(rejected);
    assert.equal(dialog(), null, 'invalid or credential-bearing destination entered dialog state');
  }
  await requestLink();
  await escape();
  assert.equal(dialog(), null);
  await requestLink();
  await click('Close');
  assert.equal(dialog(), null);

  browserFailure = true;
  await requestLink();
  await click('Open in browser');
  assert.ok(
    dialog()!.querySelector('[role="alert"]')!.textContent!.includes("couldn't open this link"),
  );
  assert.equal(dialog()!.textContent!.includes('Sensitive diagnostic'), false);
  assert.equal(button('Open in browser').disabled, false);
  browserFailure = false;
  await click('Open in browser');
  assert.equal(dialog(), null);
  assert.deepEqual(openedLinks, [destination, destination]);

  await requestLink();
  const bridge = window.wormhole;
  window.wormhole = undefined;
  await click('Open in browser');
  assert.ok(dialog()!.querySelector('[role="alert"]'));
  window.wormhole = bridge;
  await click('Cancel');

  finishOpen = () => {};
  await requestLink();
  await click('Open in browser');
  assert.ok(button('Opening…').disabled);
  assert.equal(button('Close').disabled, false);
  await click('Opening…');
  await escape();
  assert.equal(dialog(), null, 'pending browser launch trapped the user in its dialog');
  assert.equal(openedLinks.length, 3, 'busy activation opened a second browser');
  await React.act(async () => {
    finishOpen!();
  });
  await sleep();
  assert.equal(dialog(), null);

  // Locking/switching tabs dismisses the request and prevents stale completion
  // from closing a newer confirmation after returning to this terminal.
  finishOpen = () => {};
  await requestLink();
  await click('Open in browser');
  const finishStaleOpen = finishOpen;
  props = { ...props, isAuthorized: false };
  await render();
  assert.equal(dialog(), null);
  assert.equal(document.querySelector('#native-overlay-probe')!.textContent, 'false');
  await requestLink();
  assert.equal(dialog(), null, 'locked terminal showed a link request');
  props = { ...props, isAuthorized: true };
  await render();
  assert.equal(dialog(), null, 'old request reappeared on unlock');
  await requestLink('https://example.com/new');
  await React.act(async () => {
    finishStaleOpen!();
  });
  assert.ok(dialog()!.textContent!.includes('https://example.com/new'));
  await click('Cancel');
  finishOpen = undefined;
  await requestLink();
  props = { ...props, isActive: false };
  await render();
  assert.equal(dialog(), null);
  props = { ...props, isActive: true };
  await render();
  assert.equal(dialog(), null);
  await requestLink();
  for (const status of ['connecting', 'failed', 'disconnected']) {
    props = { ...props, session: { ...props.session, status } };
    await render();
    assert.ok(mounted.textContent!.includes('state ' + status));
    assert.equal(mounted.querySelector('.xterm'), null);
  }
  props = {
    ...props,
    session: { ...props.session, backendSessionId: undefined, status: 'connected' },
  };
  await render();
  props = { ...props, session: { ...props.session, backendSessionId: 'component' } };
  await render();
  componentRuntime.terminal.resize(30, 10);
  await React.act(async () => {
    root.unmount();
  });
  retainSshTerminals(new Set());
  console.log(
    'xterm ANSI, Unicode, input, clipboard, hidden sessions, bounded history, reconnect, WebGL/fallback passed',
  );
}

(window as unknown as { runTerminalTests: () => Promise<void> }).runTerminalTests = run;
