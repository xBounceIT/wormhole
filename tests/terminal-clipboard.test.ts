import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { transformWithOxc } from 'vite';
import { encodeTerminalClipboardText, isEncodedSshInput } from '../electron/terminal-clipboard.ts';
import { writeClipboardText } from '../src/clipboard.ts';
import {
  clearTerminalSelectionIfUnchanged,
  copyTerminalSelection,
  normalizeTerminalPasteText,
  shouldAutoCopyTerminalSelection,
  shouldUseTerminalClipboardShortcut,
  terminalCopyChordAfterKeyDown,
  terminalCopyChordAfterKeyUp,
} from '../src/terminal-clipboard.ts';
import { terminalControlKeyData } from '../src/terminal-keyboard.ts';
import {
  nextTerminalViewportResetSequence,
  scrollTerminalToBottom,
  terminalScrollEventKeepsBottomPin,
  terminalVisibleScrollback,
} from '../src/terminal-frame.ts';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const require = createRequire(import.meta.url);
const electronExecutable = require('electron') as string;
const execFileAsync = promisify(execFile);

type TerminalConnectionStateProps = {
  session: {
    id: string;
    status: 'connecting' | 'failed' | 'disconnected';
    host?: string;
    error?: string;
    hostKeyMismatch?: { expected: string; received: string };
    tunnelProgress?: object;
  };
  isSerial: boolean;
  onReconnect: (sessionId: string) => void;
  onTrustHostKey?: (sessionId: string, mismatch: object) => void;
};

// Execute the production JSX without loading App's unrelated native session lifecycles.
const connectionStateStart = appSource.indexOf('function SshTerminalConnectionState');
const connectionStateEnd = appSource.indexOf('function SshTerminalSurface', connectionStateStart);
assert.ok(connectionStateStart >= 0 && connectionStateEnd > connectionStateStart);
const connectionStateTransform = await transformWithOxc(
  appSource.slice(connectionStateStart, connectionStateEnd),
  'terminal-connection-state.tsx',
  { jsx: { runtime: 'classic' } },
);
const renderConnectionState = runInNewContext(
  `${connectionStateTransform.code}\nSshTerminalConnectionState;`,
  {
    React,
    Button: 'button',
    LoaderCircle: 'loading-icon',
    AlertCircle: 'error-icon',
    Terminal: 'terminal-icon',
    RefreshCcw: 'reconnect-icon',
    ConnectionStepper: 'connection-stepper',
  },
) as (props: TerminalConnectionStateProps) => React.ReactElement<Record<string, unknown>>;

function connectionStateElements(
  node: React.ReactNode,
): React.ReactElement<Record<string, unknown>>[] {
  if (!React.isValidElement<Record<string, unknown>>(node)) return [];
  return [
    node,
    ...React.Children.toArray(node.props.children as React.ReactNode).flatMap(
      connectionStateElements,
    ),
  ];
}

test('terminal connection states preserve SSH and serial copy, status icons, and reconnect', () => {
  for (const isSerial of [false, true]) {
    for (const status of ['connecting', 'failed', 'disconnected'] as const) {
      const reconnects: string[] = [];
      const element = renderConnectionState({
        session: { id: 'terminal-1', status },
        isSerial,
        onReconnect: (id) => reconnects.push(id),
      });
      const markup = renderToStaticMarkup(element);
      const protocol = isSerial ? 'Serial' : 'SSH';
      const expectedTitle =
        status === 'connecting'
          ? isSerial
            ? 'Opening serial port'
            : 'Connecting to SSH'
          : `${protocol} ${status === 'failed' ? 'connection failed' : 'session closed'}`;
      const expectedMessage =
        status === 'connecting'
          ? isSerial
            ? 'Opening the local serial line.'
            : 'Opening a secure shell session.'
          : isSerial
            ? 'The serial port closed the session.'
            : 'The remote host closed the connection.';
      assert.ok(markup.includes(expectedTitle), expectedTitle);
      assert.ok(markup.includes(expectedMessage), expectedMessage);
      assert.ok(markup.includes(isSerial ? 'Serial terminal' : 'Secure shell'));
      assert.ok(markup.includes('inherited target'));
      const elements = connectionStateElements(element);
      const icon =
        status === 'connecting'
          ? 'loading-icon'
          : status === 'failed'
            ? 'error-icon'
            : 'terminal-icon';
      assert.ok(elements.some((child) => child.type === icon));
      const reconnect = elements.find((child) => child.type === 'button');
      if (status === 'connecting') {
        assert.equal(reconnect, undefined);
        assert.ok(
          markup.includes(isSerial ? 'Opening local serial line' : 'Negotiating secure session'),
        );
      } else {
        assert.equal(typeof reconnect?.props.onClick, 'function');
        (reconnect!.props.onClick as () => void)();
        assert.deepEqual(reconnects, ['terminal-1']);
      }
    }
  }
});

test('terminal errors retain escaped diagnostics and only failed SSH can trust a changed host key', () => {
  const mismatch = { expected: 'SHA256:saved', received: 'SHA256:presented' };
  const trusted: unknown[][] = [];
  const props: TerminalConnectionStateProps = {
    session: {
      id: 'terminal-2',
      status: 'failed',
      host: 'server.example',
      error: '<remote failure>',
      hostKeyMismatch: mismatch,
    },
    isSerial: false,
    onReconnect: () => assert.fail('trust must retain its separate reconnect lifecycle'),
    onTrustHostKey: (...args) => trusted.push(args),
  };
  const element = renderConnectionState(props);
  const markup = renderToStaticMarkup(element);
  assert.ok(
    markup.includes('The server identity changed. Verify the new fingerprint before trusting it.'),
  );
  assert.ok(markup.includes('SHA256:saved') && markup.includes('SHA256:presented'));
  assert.ok(markup.includes('server.example'));
  assert.ok(markup.includes('Trust new key &amp; reconnect'));
  assert.ok(!markup.includes('&lt;remote failure&gt;'));
  const trust = connectionStateElements(element).find((child) => child.type === 'button');
  (trust!.props.onClick as () => void)();
  assert.equal(trusted.length, 1);
  assert.equal(trusted[0][0], 'terminal-2');
  assert.equal(trusted[0][1], mismatch);
  const optionalTrust = renderConnectionState({ ...props, onTrustHostKey: undefined });
  const optionalButton = connectionStateElements(optionalTrust).find(
    (child) => child.type === 'button',
  );
  assert.doesNotThrow(() => (optionalButton!.props.onClick as () => void)());

  for (const override of [
    { isSerial: true },
    { session: { ...props.session, status: 'connecting' as const } },
    { session: { ...props.session, status: 'disconnected' as const } },
    { session: { ...props.session, hostKeyMismatch: undefined } },
  ]) {
    const ordinaryMarkup = renderToStaticMarkup(renderConnectionState({ ...props, ...override }));
    assert.ok(!ordinaryMarkup.includes('Host key changed'));
    assert.ok(ordinaryMarkup.includes('&lt;remote failure&gt;'));
  }
});

test('only connecting SSH renders the tunnel progress stepper', () => {
  const tunnelProgress = { phase: 'connecting', message: 'Opening VPN' };
  for (const isSerial of [false, true]) {
    for (const status of ['connecting', 'failed', 'disconnected'] as const) {
      const element = renderConnectionState({
        session: { id: 'terminal-3', status, tunnelProgress },
        isSerial,
        onReconnect: () => undefined,
      });
      const stepper = connectionStateElements(element).find(
        (child) => child.type === 'connection-stepper',
      );
      if (!isSerial && status === 'connecting') {
        assert.equal(stepper?.props.tunnelProgress, tunnelProgress);
        assert.equal(
          connectionStateElements(element).some((child) => child.type === 'button'),
          false,
        );
      } else {
        assert.equal(stepper, undefined);
      }
    }
  }
});

test('terminal state content keeps its parent surface, focus, and protocol resize lifecycle', () => {
  const surfaceSource = appSource.slice(
    connectionStateEnd,
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'", connectionStateEnd),
  );
  const stateRender = surfaceSource.slice(
    surfaceSource.indexOf("if (session.status !== 'connected')"),
    surfaceSource.indexOf("aria-label={isSerial ? 'Live serial terminal'"),
  );
  assert.match(stateRender, /return \(\s*<div[\s\S]*ref=\{surfaceRef\}/);
  assert.match(
    stateRender,
    /aria-label=\{isSerial \? 'Serial connection state' : 'SSH connection state'\}/,
  );
  const content = stateRender.match(/<SshTerminalConnectionState[\s\S]*?\/>/)?.[0] ?? '';
  for (const prop of ['session', 'isSerial', 'onReconnect', 'onTrustHostKey']) {
    assert.ok(content.includes(`${prop}={${prop}}`), `${prop} stays connected to the parent`);
  }
  assert.equal(surfaceSource.match(/ref=\{surfaceRef\}/g)?.length, 2);
  assert.match(surfaceSource, /const focus = \(\) => surface\.focus\(\{ preventScroll: true \}\);/);
  assert.match(
    surfaceSource,
    /const frame = requestAnimationFrame\(focus\);\s*return \(\) => cancelAnimationFrame\(frame\);/,
  );
  assert.match(
    surfaceSource,
    /isSerial\s*\? window\.wormhole\?\.resizeSerialSession\(backendSessionId, columns, rows\)\s*: window\.wormhole\?\.resizeSshSession\(backendSessionId, columns, rows\)/,
  );
});

test('terminal paste events preserve the SSH block and retain serial newline handling', () => {
  const terminalSource = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  const handler = terminalSource.match(/onPaste=\{\(event\) => \{([\s\S]*?)\n      \}\}/)?.[1];
  assert.ok(handler);
  const paste = new Function(
    'event',
    'onInput',
    'session',
    'isSerial',
    'normalizeTerminalPasteText',
    'terminalSelection',
    handler,
  );
  for (const isSerial of [false, true]) {
    const calls: unknown[][] = [];
    let prevented = false;
    const text = 'sudo first\r\nsudo second\nlast';
    const event = {
      clipboardData: { getData: () => text },
      preventDefault: () => {
        prevented = true;
      },
    };
    paste(
      event,
      (...args: unknown[]) => calls.push(args),
      { id: 'session' },
      isSerial,
      normalizeTerminalPasteText,
      () => undefined,
    );
    assert.equal(prevented, true);
    assert.deepEqual(calls, [
      ['session', isSerial ? 'sudo first\rsudo second\rlast' : text, !isSerial],
    ]);
    event.clipboardData.getData = () => '';
    paste(
      event,
      (...args: unknown[]) => calls.push(args),
      { id: 'session' },
      isSerial,
      normalizeTerminalPasteText,
      () => undefined,
    );
    assert.equal(calls.length, 1);
  }
});

test('SSH clipboard IPC forwards paste identity to Go and validates its type', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8').replace(
    /\r\n/g,
    '\n',
  );
  const handlersSource = main.slice(
    main.indexOf("  ipcMain.handle(\n    'ssh:input'"),
    main.indexOf("  ipcMain.handle(\n    'ssh:resize'"),
  );
  assert.ok(handlersSource.includes('ssh:paste-clipboard'));
  const transpile = stripTypeScriptTypes;
  const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
  const calls: unknown[][] = [];
  let clipboardText = 'first\r\nsecond';
  let authorized = true;
  new Function(
    'ipcMain',
    'isSshSessionId',
    'isSshInput',
    'serializeAuthOperation',
    'requireWorkspaceAuth',
    'sshBackend',
    'encodeTerminalClipboardText',
    'clipboard',
    transpile(handlersSource),
  )(
    {
      handle: (name: string, handler: (...args: unknown[]) => Promise<unknown>) =>
        handlers.set(name, handler),
    },
    (id: unknown) => id === 'session',
    isEncodedSshInput,
    (operation: () => Promise<unknown>) => operation(),
    async () => {
      if (!authorized) throw new Error('locked');
    },
    { sendInput: (...args: unknown[]) => calls.push(args) },
    encodeTerminalClipboardText,
    { readText: () => clipboardText },
  );
  const input = handlers.get('ssh:input')!;
  const clipboard = handlers.get('ssh:paste-clipboard')!;
  await input(null, 'session', 'DQ==');
  await input(null, 'session', 'YQ==', true);
  assert.deepEqual(await clipboard(null, 'session'), { pasted: true });
  assert.deepEqual(calls, [
    ['session', 'DQ==', false],
    ['session', 'YQ==', true],
    ['session', Buffer.from(clipboardText).toString('base64'), true],
  ]);
  clipboardText = '\r\n'.repeat(1024 * 1024);
  const largePaste = Buffer.from(clipboardText).toString('base64');
  await input(null, 'session', largePaste, true);
  assert.deepEqual(await clipboard(null, 'session'), { pasted: true });
  assert.equal(calls.length, 5);
  for (const call of calls.slice(3)) {
    assert.equal(call[1], largePaste);
    assert.equal(call[2], true);
  }
  await assert.rejects(input(null, 'session', largePaste), /invalid/);
  clipboardText = '';
  assert.deepEqual(await clipboard(null, 'session'), { pasted: false });
  await assert.rejects(input(null, 'session', 'YQ==', 'true'), /invalid/);
  await assert.rejects(input(null, 'session', 'bad'), /invalid/);
  await assert.rejects(input(null, 'invalid', 'YQ==', true), /invalid/);
  await assert.rejects(clipboard(null, 'invalid'), /invalid/);
  authorized = false;
  await assert.rejects(clipboard(null, 'session'), /locked/);
  await assert.rejects(input(null, 'session', 'YQ==', true), /locked/);
  assert.equal(calls.length, 5);

  const backendSource = main.slice(main.indexOf('class NativeSshBackend'));
  const method = backendSource.match(/  sendInput\([^]*?\n  \}/)?.[0];
  assert.ok(method);
  const backend = new Function('return ' + transpile(`(new class { ${method} })`))();
  const messages: unknown[] = [];
  backend.write = (message: unknown) => messages.push(message);
  backend.sendInput('session', 'YQ==', true);
  backend.sendInput('session', 'DQ==');
  assert.deepEqual(messages, [
    { type: 'input', session_id: 'session', data: 'YQ==', paste: true },
    { type: 'input', session_id: 'session', data: 'DQ==', paste: false },
  ]);
});

const shortcut = (
  key: string,
  overrides: Partial<Parameters<typeof shouldUseTerminalClipboardShortcut>[0]> = {},
) => ({
  key,
  ctrlKey: true,
  metaKey: false,
  altKey: false,
  ...overrides,
});

test('paste shortcuts stay in Chromium instead of becoming SSH control input', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('v'), false), true);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('V'), false), true);
  assert.equal(
    shouldUseTerminalClipboardShortcut(shortcut('v', { ctrlKey: false, metaKey: true }), false),
    true,
  );
});

test('copy uses the clipboard only when terminal text is selected', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('c'), true), true);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('c'), false), false);
});

test('copy key repeats stay in Chromium until the copied chord is released', () => {
  const copyKey = shortcut('c');
  let copyChordActive = false;

  assert.equal(shouldUseTerminalClipboardShortcut(copyKey, true, copyChordActive), true);
  copyChordActive = terminalCopyChordAfterKeyDown(copyKey, true, copyChordActive);
  assert.equal(copyChordActive, true);

  assert.equal(shouldUseTerminalClipboardShortcut(copyKey, false, copyChordActive), true);
  assert.equal(
    shouldUseTerminalClipboardShortcut(shortcut('c', { ctrlKey: false }), false, copyChordActive),
    true,
  );
  assert.equal(terminalCopyChordAfterKeyUp({ key: 'Control' }, copyChordActive), true);

  copyChordActive = terminalCopyChordAfterKeyUp({ key: 'C' }, copyChordActive);
  assert.equal(copyChordActive, false);
  assert.equal(shouldUseTerminalClipboardShortcut(copyKey, false, copyChordActive), false);
});

test('non-copy shortcuts never start the retained copy chord', () => {
  assert.equal(terminalCopyChordAfterKeyDown(shortcut('v'), true, false), false);
  assert.equal(terminalCopyChordAfterKeyDown(shortcut('c'), false, false), false);
  assert.equal(terminalCopyChordAfterKeyDown(shortcut('c', { altKey: true }), true, false), false);
});

test('copying terminal text writes plain text and preserves the selection', () => {
  const calls: string[] = [];
  const clipboardData = {
    setData(format: string, text: string) {
      calls.push(`${format}:${text}`);
    },
  };

  assert.equal(copyTerminalSelection('selected command', clipboardData), true);
  assert.deepEqual(calls, ['text/plain:selected command']);

  calls.length = 0;
  assert.equal(copyTerminalSelection('', clipboardData), false);
  assert.deepEqual(calls, []);
});

test('unrelated and alt-modified shortcuts remain terminal input', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('x'), true), false);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('v', { altKey: true }), true), false);
});

test('Ctrl+K remains terminal input and encodes its remote control character', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('k'), false), false);
  assert.equal(terminalControlKeyData('k'), '\u000b');
  assert.equal(terminalControlKeyData('K'), '\u000b');
});

test('terminal control-key encoding preserves letters, punctuation, and invalid keys', () => {
  assert.equal(terminalControlKeyData(' '), '\u0000');
  assert.equal(terminalControlKeyData('a'), '\u0001');
  assert.equal(terminalControlKeyData('Z'), '\u001a');
  assert.deepEqual(['@', '[', '\\', ']', '^', '_'].map(terminalControlKeyData), [
    '\u0000',
    '\u001b',
    '\u001c',
    '\u001d',
    '\u001e',
    '\u001f',
  ]);
  assert.equal(terminalControlKeyData('1'), undefined);
  assert.equal(terminalControlKeyData('Enter'), undefined);
});

test('auto-copy only handles selection gestures from the primary mouse button', () => {
  assert.equal(shouldAutoCopyTerminalSelection(true, 0), true);
  assert.equal(shouldAutoCopyTerminalSelection(true, 1), false);
  assert.equal(shouldAutoCopyTerminalSelection(true, 2), false);
  assert.equal(shouldAutoCopyTerminalSelection(false, 0), false);
});

test('right-click paste encodes Unicode text for the SSH wire protocol', () => {
  const text = 'printf "caffè ☕"\r\nprintf "done"\n';
  const normalized = 'printf "caffè ☕"\rprintf "done"\r';
  const encoded = encodeTerminalClipboardText(text);
  assert.equal(normalizeTerminalPasteText(text), normalized);
  assert.equal(encoded, Buffer.from(text, 'utf8').toString('base64'));
  assert.equal(isEncodedSshInput(encoded), true);
});

test('right-click paste ignores an empty clipboard and rejects oversized text', () => {
  assert.equal(encodeTerminalClipboardText(''), undefined);
  assert.doesNotThrow(() => encodeTerminalClipboardText('a'.repeat(1024 * 1024)));
  assert.throws(() => encodeTerminalClipboardText('a'.repeat(2 * 1024 * 1024 + 1)), /too large/i);
});

test('SSH input validation rejects malformed and oversized base64', () => {
  assert.equal(isEncodedSshInput('not base64'), false);
  assert.equal(isEncodedSshInput('YQ='), false);
  assert.equal(isEncodedSshInput(Buffer.alloc(1024 * 1024).toString('base64')), true);
  assert.equal(isEncodedSshInput(Buffer.alloc(1024 * 1024 + 1).toString('base64')), false);
  const maximumCrLfPaste = encodeTerminalClipboardText('\r\n'.repeat(1024 * 1024));
  assert.equal(isEncodedSshInput(maximumCrLfPaste), false);
  assert.equal(isEncodedSshInput(maximumCrLfPaste, true), true);
  assert.equal(isEncodedSshInput('YQ=', true), false);
  assert.equal(
    isEncodedSshInput(Buffer.alloc(2 * 1024 * 1024 + 1).toString('base64'), true),
    false,
  );
});

test('clipboard writes fall back after the async API rejects', async () => {
  const calls: string[] = [];
  await writeClipboardText(
    'selected text',
    async () => {
      calls.push('async');
      throw new Error('permission denied');
    },
    () => {
      calls.push('fallback');
      return true;
    },
  );
  assert.deepEqual(calls, ['async', 'fallback']);
});

test('successful async clipboard writes do not invoke the fallback', async () => {
  let fallbackCalled = false;
  await writeClipboardText(
    'selected text',
    async () => undefined,
    () => {
      fallbackCalled = true;
      return true;
    },
  );
  assert.equal(fallbackCalled, false);
});

test('clipboard writes fail when neither implementation is available', async () => {
  await assert.rejects(
    writeClipboardText('selected text', undefined, () => false),
    /unavailable/i,
  );
});

test('normal terminal frames expose their retained scrollback', () => {
  const scrollback = [{ text: 'previous output' }];

  assert.equal(terminalVisibleScrollback({ alternateScreen: false, scrollback }), scrollback);
});

test('alternate-screen applications hide retained scrollback', () => {
  assert.equal(
    terminalVisibleScrollback({
      alternateScreen: true,
      scrollback: [{ text: 'previous output' }],
    }),
    undefined,
  );
});

test('terminal viewport reset survives later frames that React can batch into one render', () => {
  assert.equal(
    nextTerminalViewportResetSequence(undefined, {
      sequence: 11,
      viewportReset: false,
    }),
    undefined,
  );
  const resetSequence = nextTerminalViewportResetSequence(undefined, {
    sequence: 12,
    viewportReset: true,
  });

  assert.equal(
    nextTerminalViewportResetSequence(resetSequence, {
      sequence: 13,
      viewportReset: false,
    }),
    12,
  );
  assert.equal(
    nextTerminalViewportResetSequence(resetSequence, {
      sequence: 14,
      viewportReset: true,
    }),
    14,
  );
});

test('terminal output stays pinned after content grows ahead of an automatic scroll event', () => {
  assert.equal(terminalScrollEventKeepsBottomPin(360, false, 360), true);
  assert.equal(terminalScrollEventKeepsBottomPin(360.5, false, 360), true);
});

test('terminal scroll events still release the bottom pin after manual scrolling', () => {
  assert.equal(terminalScrollEventKeepsBottomPin(180, false, 360), false);
  assert.equal(terminalScrollEventKeepsBottomPin(180, false, undefined), false);
  assert.equal(terminalScrollEventKeepsBottomPin(360, true, undefined), true);
});

test('automatic terminal scrolling tracks the applied offset and clamps short content', () => {
  const short = { scrollHeight: 100, clientHeight: 200, scrollTop: 50 };
  assert.equal(scrollTerminalToBottom(short), 0);
  let applied = 0;
  const rounded = {
    scrollHeight: 1000,
    clientHeight: 200,
    get scrollTop() {
      return applied;
    },
    set scrollTop(value: number) {
      applied = value - 0.5;
    },
  };
  assert.equal(scrollTerminalToBottom(rounded), 799.5);
});

test('live scroll handler catches the final output and preserves the pin across delayed events', () => {
  const surfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );
  const handler = surfaceSource
    .slice(
      surfaceSource.indexOf('onScroll={(event) => {') + 'onScroll={'.length,
      surfaceSource.indexOf('\n      ref={surfaceRef}', surfaceSource.indexOf('onScroll=')),
    )
    .trim()
    .slice(0, -1);
  const stickToBottomRef = { current: true };
  const automaticScrollTopRef: { current: number | undefined } = { current: 360 };
  const onScroll = runInNewContext(`(${handler})`, {
    stickToBottomRef,
    automaticScrollTopRef,
    terminalScrollEventKeepsBottomPin,
    scrollTerminalToBottom,
    terminalIsAtBottom: (surface: {
      scrollHeight: number;
      clientHeight: number;
      scrollTop: number;
    }) => surface.scrollHeight - surface.clientHeight - surface.scrollTop <= 18,
  });
  const surface = { scrollHeight: 900, clientHeight: 180, scrollTop: 360 };
  // The last output arrived after the browser queued the automatic scroll event.
  onScroll({ currentTarget: surface });
  assert.equal(surface.scrollTop, 720);
  assert.equal(automaticScrollTopRef.current, 720);
  for (let frame = 0; frame < 100; frame++) {
    surface.scrollHeight += 180;
    onScroll({ currentTarget: surface });
    assert.equal(surface.scrollTop, surface.scrollHeight - surface.clientHeight);
    assert.equal(stickToBottomRef.current, true);
  }
  // Reading earlier output must release the pin and preserve the user's position.
  surface.scrollTop -= 180;
  const manualPosition = surface.scrollTop;
  onScroll({ currentTarget: surface });
  assert.equal(stickToBottomRef.current, false);
  assert.equal(automaticScrollTopRef.current, undefined);
  surface.scrollHeight += 180;
  onScroll({ currentTarget: surface });
  assert.equal(surface.scrollTop, manualPosition);
  surface.scrollTop = surface.scrollHeight - surface.clientHeight;
  onScroll({ currentTarget: surface });
  assert.equal(stickToBottomRef.current, true);
});

test('horizontal terminal wheel scrolling preserves following while vertical scrolling can release it', () => {
  const start = appSource.indexOf('const handleWheel = (event: WheelEvent) => {');
  const source = appSource.slice(
    start,
    appSource.indexOf("surface.addEventListener('wheel'", start),
  );
  const surface = {
    scrollTop: 360,
    scrollLeft: 0,
    scrollHeight: 900,
    clientHeight: 180,
    scrollWidth: 1000,
    clientWidth: 500,
  };
  const automaticScrollTopRef = { current: 360 };
  const stickToBottomRef = { current: true };
  const handleWheel = runInNewContext(
    stripTypeScriptTypes(`${source}\nhandleWheel`, { mode: 'strip' }),
    {
      surface,
      automaticScrollTopRef,
      stickToBottomRef,
      terminalWheelDelta: (_surface: unknown, delta: number) => delta,
      terminalIsAtBottom: () =>
        surface.scrollHeight - surface.scrollTop - surface.clientHeight <= 18,
    },
  );
  const event = { deltaMode: 0, preventDefault() {}, stopPropagation() {} };
  handleWheel({ ...event, deltaX: 100, deltaY: 0 });
  assert.equal(surface.scrollLeft, 100);
  assert.equal(automaticScrollTopRef.current, 360);
  assert.equal(stickToBottomRef.current, true);
  handleWheel({ ...event, deltaX: 0, deltaY: -180 });
  assert.equal(surface.scrollTop, 180);
  assert.equal(automaticScrollTopRef.current, undefined);
  assert.equal(stickToBottomRef.current, false);
  handleWheel({ ...event, deltaX: 0, deltaY: 10000 });
  assert.equal(surface.scrollTop, 720);
  assert.equal(stickToBottomRef.current, true);
});

test('live terminal wires automatic scroll tracking into frame and user scroll handling', () => {
  const frameApplicationSource = appSource.slice(
    appSource.indexOf('function applySshTerminalFrame'),
    appSource.indexOf('const navItems'),
  );
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );

  assert.match(
    frameApplicationSource,
    /viewportResetSequence: nextTerminalViewportResetSequence\(\s*previous\?\.viewportResetSequence,\s*incoming,/,
  );
  assert.match(
    terminalSurfaceSource,
    /useLayoutEffect\(\(\) => \{[\s\S]*stickToBottomRef\.current = true;[\s\S]*automaticScrollTopRef\.current = undefined;[\s\S]*handledViewportResetSequenceRef\.current = undefined;[\s\S]*session\.backendSessionId, session\.status/,
  );
  assert.match(
    terminalSurfaceSource,
    /viewportResetSequence !== handledViewportResetSequenceRef\.current[\s\S]*stickToBottomRef\.current = true;[\s\S]*handledViewportResetSequenceRef\.current = viewportResetSequence;/,
  );
  assert.match(
    terminalSurfaceSource,
    /automaticScrollTopRef\.current = scrollTerminalToBottom\(surface\);/,
  );
  assert.match(
    terminalSurfaceSource,
    /onScroll=\{\(event\) => \{[\s\S]*terminalScrollEventKeepsBottomPin\([\s\S]*automaticScrollTopRef\.current,[\s\S]*\? scrollTerminalToBottom\(surface\)/,
  );
  assert.match(
    terminalSurfaceSource,
    /if \(deltaY !== 0\) \{\s*automaticScrollTopRef\.current = undefined;\s*surface\.scrollTop = nextScrollTop;/,
  );
});

test('live terminal preserves its DOM selection after a copy event', () => {
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );
  const copyHandlerSource = terminalSurfaceSource.slice(
    terminalSurfaceSource.indexOf('onCopy='),
    terminalSurfaceSource.indexOf('onPaste='),
  );

  assert.match(
    copyHandlerSource,
    /copyTerminalSelection\([\s\S]*terminalSelectionText\(event\.currentTarget\),[\s\S]*event\.clipboardData,[\s\S]*event\.preventDefault\(\);/,
  );
});

test('live terminal retains the copy chord until key release and clears it on focus loss', () => {
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );
  const keyboardHandlerSource = terminalSurfaceSource.slice(
    terminalSurfaceSource.indexOf('onKeyDown='),
    terminalSurfaceSource.indexOf('onCopy='),
  );

  assert.match(
    keyboardHandlerSource,
    /shouldUseTerminalClipboardShortcut\([\s\S]*terminalCopyChordActiveRef\.current[\s\S]*terminalCopyChordAfterKeyDown\([\s\S]*if \(useClipboard\) return;/,
  );
  assert.match(
    keyboardHandlerSource,
    /onKeyUp=\{[\s\S]*terminalCopyChordAfterKeyUp\([\s\S]*onBlur=\{[\s\S]*terminalCopyChordActiveRef\.current = false;/,
  );
  assert.match(
    terminalSurfaceSource,
    /window\.addEventListener\('blur', resetCopyChord\);[\s\S]*document\.addEventListener\('visibilitychange', resetCopyChordWhenHidden\);[\s\S]*window\.removeEventListener\('blur', resetCopyChord\);[\s\S]*document\.removeEventListener\('visibilitychange', resetCopyChordWhenHidden\);/,
  );
});

test('auto-copy preserves the selection after success or failure', async () => {
  const source = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  const handler = source.match(/onMouseUp=\{\(event\) => \{([\s\S]*?)\n      \}\}/)![1];
  const run = new Function(
    'event',
    'autoCopyOnSelect',
    'shouldAutoCopyTerminalSelection',
    'terminalSelection',
    'copyTextToClipboard',
    handler,
  );
  for (const fails of [false, true]) {
    const copied: string[] = [];
    run(
      { button: 0, currentTarget: {} },
      true,
      shouldAutoCopyTerminalSelection,
      () => ({
        toString: () => 'selected',
        removeAllRanges: () => assert.fail('selection must persist'),
      }),
      async (text: string) => {
        copied.push(text);
        if (fails) throw new Error('denied');
      },
    );
    await Promise.resolve();
    assert.deepEqual(copied, ['selected']);
  }
});

test('styled runs remain inline and preserve spaces when Chromium copies a terminal row', () => {
  const terminalGridSource = appSource.slice(
    appSource.indexOf('const TerminalScrollback'),
    appSource.indexOf('function terminalCsiWithModifier'),
  );

  // Both live rows and scrollback must opt into the shared selection handler.
  assert.equal(terminalGridSource.match(/data-terminal-row/g)?.length, 2);
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );
  assert.match(terminalSurfaceSource, /onMouseDown={selectTerminalDoubleClick}/);
  assert.equal(terminalGridSource.match(/inline-block overflow-hidden align-top/g)?.length, 2);
  assert.equal(
    terminalGridSource.match(/className="h-\[18px\] min-w-max whitespace-pre"/g)?.length,
    2,
  );
  assert.doesNotMatch(terminalGridSource, /className=(?:"|{`)[^"`]*block flex-none/);
});

test('mounted SSH and serial terminals follow long output and preserve manual scroll in Chromium', async () => {
  const start = appSource.indexOf('const terminalFontSize');
  const end = appSource.indexOf("type SftpPaneKind = 'local' | 'remote'", start);
  assert.ok(start >= 0 && end > start);
  const helpers = readFileSync(
    new URL('../src/terminal-frame.ts', import.meta.url),
    'utf8',
  ).replaceAll('export function', 'function');
  const fixture = readFileSync(new URL('./fixtures/terminal-scroll.tsx', import.meta.url), 'utf8');
  const selectionSource = readFileSync(
    new URL('../src/terminal-selection.ts', import.meta.url),
    'utf8',
  ).replaceAll('export function', 'function');
  const transformed = await transformWithOxc(
    helpers + selectionSource + appSource.slice(start, end) + fixture,
    'terminal-scroll.tsx',
    {
      jsx: { runtime: 'classic' },
    },
  );
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { memo, useRef, useEffect, useLayoutEffect } = React;
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-terminal-scroll-'));
  const harnessPath = join(directory, 'scroll.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow } = require('electron');
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, webPreferences: {
          nodeIntegration: true, contextIsolation: false, backgroundThrottling: false, offscreen: true,
        } });
        try {
          await window.loadURL('data:text/html,' + encodeURIComponent('<style>.terminal-scrollbar{height:180px;width:500px;overflow:auto}.min-w-max{min-width:max-content}.whitespace-pre{white-space:pre}.inline-block{display:inline-block}.overflow-hidden{overflow:hidden}.align-top{vertical-align:top}</style><div id="root"></div>'));
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        } finally { window.destroy(); }
        app.quit();
      }).catch((error) => { console.error(error); app.exit(1); });
    `,
    );
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    await execFileAsync(
      needsDisplay ? 'xvfb-run' : electronExecutable,
      needsDisplay
        ? ['--auto-servernum', electronExecutable, '--no-sandbox', harnessPath]
        : [harnessPath],
      { env: environment, timeout: 30_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});

test('Chromium preserves clipboard highlights, outside clicks, and double-click word selection', async () => {
  const surfaceSource = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  const copyHandler = surfaceSource.match(/onCopy=\{\(event\) => \{([\s\S]*?)\n      \}\}/)![1];
  const pointerStart = surfaceSource.lastIndexOf(
    '  useEffect(() => {',
    surfaceSource.indexOf('const clearOnOutsidePointer'),
  );
  const pointerEnd = surfaceSource.indexOf('}, [isActive, session.status]);', pointerStart);
  const browserSetup = stripTypeScriptTypes(
    appSource.slice(
      appSource.indexOf('function terminalSelection('),
      appSource.indexOf('function SshTerminalConnectionState'),
    ) +
      copyTerminalSelection.toString() +
      `
const terminal = document.getElementById('terminal');
    terminal.addEventListener('copy', (event) => {${copyHandler}});
    const surfaceRef = {current: terminal};
    const isActive = true;
    const session = {status: 'connected'};
    const cleanup = (() => {${surfaceSource.slice(pointerStart + '  useEffect(() => {'.length, pointerEnd)}})();`,
  );

  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'wormhole-terminal-clipboard-'));
  const harnessPath = join(temporaryDirectory, 'selection.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    const selectionSource = stripTypeScriptTypes(
      readFileSync(new URL('../src/terminal-selection.ts', import.meta.url), 'utf8'),
    ).replace('export function', 'function');
    const doubleClickChecks =
      selectionSource +
      `
      terminal.innerHTML = '<div data-terminal-row style="white-space:pre;font:13px/18px monospace;height:18px"><span style="display:inline-block;height:18px;overflow:hidden;vertical-align:top">log: ti</span><span style="display:inline-block;height:18px;overflow:hidden;vertical-align:top;color:red">me    </span></div>';
      const row = terminal.firstElementChild;
      const first = row.firstElementChild.firstChild;
      const second = row.lastElementChild.firstChild;
      const selectAt = (node, offset) => {
        const hit = document.createRange();
        hit.setStart(node, offset); hit.setEnd(node, offset + 1);
        const rect = hit.getBoundingClientRect();
        const event = new MouseEvent('mousedown', { bubbles: true, cancelable: true,
          button: 0, detail: 2, clientX: (rect.left + rect.right) / 2,
          clientY: (rect.top + rect.bottom) / 2 });
        node.parentElement.dispatchEvent(event);
        return { text: window.getSelection().toString(), prevented: event.defaultPrevented };
      };
      terminal.addEventListener('mousedown', selectTerminalDoubleClick);
      [selectAt(first, 5), selectAt(second, 1), selectAt(second, 2), selectAt(first, 4)];
    `;
    writeFileSync(
      harnessPath,
      String.raw`
const assert = require('node:assert/strict');
const { app, BrowserWindow } = require('electron');

const html = encodeURIComponent('<style>.row{display:block;white-space:pre}.run{display:inline-block;overflow:hidden;vertical-align:top}</style><div id="terminal"><div class="row"><span class="run" style="color:white">docker stack deploy -c </span><span class="run" style="color:red">portainer-agent-stack.yml </span><span class="run" style="color:red">portainer</span></div><div class="row"><span class="run">printf done</span></div></div>');

app.whenReady().then(async () => {
  const window = new BrowserWindow({ show: false });
  try {
    await window.loadURL('data:text/html;charset=utf-8,' + html);
    const result = await window.webContents.executeJavaScript(
      ${JSON.stringify(browserSetup)} + "const range=document.createRange();range.selectNodeContents(terminal);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);const selectedText=selection.toString();const clipboardData=new DataTransfer();const copyEvent=new ClipboardEvent('copy',{bubbles:true,cancelable:true,clipboardData});terminal.dispatchEvent(copyEvent);({clipboardText:clipboardData.getData('text/plain'),defaultPrevented:copyEvent.defaultPrevented,selectedText,remainingText:selection.toString()})",
    );
    const expectedText = 'docker stack deploy -c portainer-agent-stack.yml portainer\nprintf done';
    assert.deepEqual(result, {
      clipboardText: expectedText,
      defaultPrevented: true,
      selectedText: expectedText,
      remainingText: expectedText,
    });
    const outsideResult = await window.webContents.executeJavaScript(${JSON.stringify(`
      terminal.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true}));
      const insideText = selection.toString();
      const outside = document.createElement('div');
      outside.textContent = 'outside text';
      document.body.appendChild(outside);
      outside.addEventListener('pointerdown', (event) => event.stopPropagation());
      outside.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true}));
      const clearedText = selection.toString();
      range.selectNodeContents(outside);
      selection.addRange(range);
      outside.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true}));
      const unrelatedText = selection.toString();
      cleanup();
      selection.removeAllRanges();
      range.selectNodeContents(terminal);
      selection.addRange(range);
      outside.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true}));
      ({insideText, clearedText, unrelatedText, afterCleanup: selection.toString()});
    `)});
    assert.deepEqual(outsideResult, {insideText: expectedText, clearedText: '', unrelatedText: 'outside text', afterCleanup: expectedText});
    const doubleClicks = await window.webContents.executeJavaScript(${JSON.stringify(doubleClickChecks)});
    assert.deepEqual(doubleClicks, [
      { text: 'time', prevented: true },
      { text: 'time', prevented: true },
      { text: 'log: time    ', prevented: true },
      { text: 'log: time    ', prevented: true },
    ]);
    // Native mouse input exercises Chromium's default actions, which dispatchEvent skips.
    const points = await window.webContents.executeJavaScript(
      "(() => { const hit = document.createRange(); hit.setStart(first, 5); hit.setEnd(first, 6); const glyph = hit.getBoundingClientRect(); const bounds = row.getBoundingClientRect(); return [bounds.top, (bounds.top + bounds.bottom) / 2, bounds.bottom - 1].map(y => ({ x: Math.round((glyph.left + glyph.right) / 2), y: Math.round(y), expected: 'time' })).concat([{ x: Math.round(row.lastElementChild.getBoundingClientRect().right + 10), y: Math.round(bounds.top + 9), expected: row.textContent }]); })()"
    );
    window.webContents.focus();
    for (const { expected, ...point } of points) {
      await window.webContents.executeJavaScript("window.nativeSelection = new Promise(resolve => terminal.addEventListener('mouseup', () => setTimeout(() => resolve(window.getSelection().toString()), 0), {once:true})); undefined");
      window.webContents.sendInputEvent({ type: 'mouseMove', ...point });
      window.webContents.sendInputEvent({ type: 'mouseDown', button: 'left', clickCount: 2, ...point });
      window.webContents.sendInputEvent({ type: 'mouseUp', button: 'left', clickCount: 2, ...point });
      assert.equal(await window.webContents.executeJavaScript('window.nativeSelection'), expected);
    }
  } finally {
    window.destroy();
  }
  app.quit();
}).catch((error) => {
  console.error(error);
  app.exit(1);
});
`,
      'utf8',
    );

    const needsVirtualDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const executable = needsVirtualDisplay ? 'xvfb-run' : electronExecutable;
    const arguments_ = needsVirtualDisplay
      ? [
          '--auto-servernum',
          electronExecutable,
          '--no-sandbox', // Safe for this local data-URL test; npm's binary has no SUID helper.
          harnessPath,
        ]
      : [harnessPath];

    await execFileAsync(executable, arguments_, {
      env: environment,
      timeout: 30_000,
      windowsHide: true,
    });
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test('terminal input clears highlighting only when data is sent', () => {
  const source = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  for (const name of ['onKeyDown', 'onPaste', 'onCompositionEnd']) {
    const handler = source.match(
      new RegExp(name + '=\\{\\(event\\) => \\{([\\s\\S]*?)\\n      \\}\\}'),
    )![1];
    const calls: string[] = [];
    const run = new Function(
      'event',
      'terminalSelectionText',
      'shouldUseTerminalClipboardShortcut',
      'terminalCopyChordActiveRef',
      'terminalCopyChordAfterKeyDown',
      'terminalKeyData',
      'session',
      'terminalSelection',
      'onInput',
      'isSerial',
      'normalizeTerminalPasteText',
      'window',
      handler,
    );
    for (const hasData of [false, true]) {
      calls.length = 0;
      run(
        {
          currentTarget: {},
          data: hasData ? '字' : '',
          clipboardData: { getData: () => (hasData ? 'paste' : '') },
          preventDefault() {},
        },
        () => 'selection',
        () => false,
        { current: false },
        () => false,
        () => (hasData ? 'a' : undefined),
        { id: 's', backendSessionId: hasData ? 'backend' : undefined },
        () => ({ removeAllRanges: () => calls.push('clear') }),
        () => calls.push('input'),
        false,
        normalizeTerminalPasteText,
        {
          wormhole: {
            pasteClipboardToSsh: () => {
              calls.push('input');
              return Promise.resolve();
            },
          },
        },
      );
      assert.deepEqual(calls, hasData ? ['clear', 'input'] : [], name);
    }
  }
});

test('outside pointer clears only this terminal selection and listener is removed', () => {
  const source = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  const start = source.lastIndexOf(
    '  useEffect(() => {',
    source.indexOf('const clearOnOutsidePointer'),
  );
  const end = source.indexOf('}, [isActive, session.status]);', start);
  const body = stripTypeScriptTypes(
    'function effect() {' + source.slice(start + '  useEffect(() => {'.length, end) + '}',
  )
    .replace(/^function effect\(\) \{/, '')
    .replace(/\}$/, '');
  const listeners = new Map<string, (event: { target: object }) => void>();
  class FakeNode {}
  const inside = new FakeNode();
  let cleared = 0;
  const surface = { contains: (node: object) => node === inside };
  const run = new Function(
    'surfaceRef',
    'isActive',
    'session',
    'Node',
    'terminalSelection',
    'document',
    body,
  );
  const document = {
    addEventListener: (name: string, callback: (event: { target: object }) => void) =>
      listeners.set(name, callback),
    removeEventListener: (name: string, callback: unknown) => {
      assert.equal(listeners.get(name), callback);
      listeners.delete(name);
    },
  };
  const cleanup = run(
    { current: surface },
    true,
    { status: 'connected' },
    FakeNode,
    () => ({ removeAllRanges: () => cleared++ }),
    document,
  );
  const pointer = listeners.get('pointerdown')!;
  pointer({ target: inside });
  pointer({ target: {} });
  assert.equal(cleared, 0);
  pointer({ target: new FakeNode() });
  assert.equal(cleared, 1);
  cleanup();
  assert.equal(listeners.size, 0);
  for (const [active, status, current] of [
    [false, 'connected', surface],
    [true, 'failed', surface],
    [true, 'connected', null],
  ]) {
    assert.equal(
      run({ current }, active, { status }, FakeNode, () => undefined, document),
      undefined,
    );
    assert.equal(listeners.size, 0);
  }
});

test('asynchronous paste clears only its original selection', () => {
  const anchorNode = {};
  const focusNode = {};
  const copiedSelection = { anchorNode, anchorOffset: 2, focusNode, focusOffset: 8 };
  let clearCount = 0;

  assert.equal(
    clearTerminalSelectionIfUnchanged(
      { ...copiedSelection, removeAllRanges: () => clearCount++ },
      copiedSelection,
    ),
    true,
  );
  assert.equal(clearCount, 1);

  assert.equal(
    clearTerminalSelectionIfUnchanged(
      {
        anchorNode: focusNode,
        anchorOffset: 8,
        focusNode: anchorNode,
        focusOffset: 2,
        removeAllRanges: () => clearCount++,
      },
      copiedSelection,
    ),
    true,
  );
  assert.equal(clearCount, 2);

  assert.equal(
    clearTerminalSelectionIfUnchanged(
      { ...copiedSelection, focusOffset: 9, removeAllRanges: () => clearCount++ },
      copiedSelection,
    ),
    false,
  );
  assert.equal(clearTerminalSelectionIfUnchanged(undefined, copiedSelection), false);
  assert.equal(clearCount, 2);
});

test('right-click clears only after successful paste and preserves newer selections', async () => {
  const source = appSource.slice(appSource.indexOf('function SshTerminalSurface'));
  const handler = source.match(/onContextMenu=\{\(event\) => \{([\s\S]*?)\n      \}\}/)![1];
  const run = new Function(
    'event',
    'isSerial',
    'session',
    'terminalSelection',
    'window',
    'clearTerminalSelectionIfUnchanged',
    handler,
  );
  for (const outcome of [
    'success',
    'empty',
    'error',
    'changed',
    'cleared',
    'unselected',
    'serial',
    'disconnected',
    'unavailable',
  ]) {
    let clearCount = 0;
    let pasteCount = 0;
    const selection = {
      anchorNode: {},
      anchorOffset: 0,
      focusNode: {},
      focusOffset: 5,
      removeAllRanges: () => clearCount++,
    };
    let current = outcome === 'unselected' ? undefined : selection;
    let complete!: (result: { pasted: boolean }) => void;
    let fail!: (error: Error) => void;
    const pending = new Promise<{ pasted: boolean }>((resolve, reject) => {
      complete = resolve;
      fail = reject;
    });
    run(
      { currentTarget: {}, preventDefault() {} },
      outcome === 'serial',
      { backendSessionId: outcome === 'disconnected' ? undefined : 's' },
      () => current,
      {
        wormhole:
          outcome === 'unavailable'
            ? undefined
            : {
                pasteClipboardToSsh: () => {
                  pasteCount++;
                  return pending;
                },
              },
      },
      clearTerminalSelectionIfUnchanged,
    );
    assert.equal(clearCount, 0, 'must wait for actual paste');
    if (outcome === 'changed') selection.focusOffset++;
    if (outcome === 'cleared') current = undefined;
    if (outcome === 'error') fail(new Error('denied'));
    else complete({ pasted: outcome !== 'empty' });
    await Promise.resolve();
    await Promise.resolve();
    assert.equal(
      pasteCount,
      ['serial', 'disconnected', 'unavailable'].includes(outcome) ? 0 : 1,
      outcome,
    );
    assert.equal(clearCount, outcome === 'success' ? 1 : 0, outcome);
  }
});
