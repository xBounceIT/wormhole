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
  copyTerminalSelection,
  normalizeTerminalPasteText,
  shouldUseTerminalClipboardShortcut,
  terminalCopyChordAfterKeyDown,
  terminalCopyChordAfterKeyUp,
} from '../src/terminal-clipboard.ts';
import { terminalControlKeyData } from '../src/terminal-keyboard.ts';
import { requiresSshCertificateReplacement } from '../src/runtime-credential-errors.ts';
import {
  nextTerminalViewportResetSequence,
  scrollTerminalToBottom,
  terminalScrollEventKeepsBottomPin,
  terminalVisibleScrollback,
} from '../src/terminal-frame.ts';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const nativeSurfaceSource = readFileSync(
  new URL('../src/components/NativeTerminalSurface.tsx', import.meta.url),
  'utf8',
);
const nativeFrameSource = readFileSync(
  new URL('../src/native-terminal-frame.ts', import.meta.url),
  'utf8',
);
const nativeSurfaceStart = nativeSurfaceSource.indexOf('export function NativeTerminalSurface');
const require = createRequire(import.meta.url);
const electronExecutable = require('electron') as string;
const execFileAsync = promisify(execFile);

test('a delayed serial input error belongs only to its connected backend session', async () => {
  type SerialTab = { id: string; backendSessionId: string; status: string; error?: string };
  const connected: SerialTab = { id: 'tab', backendSessionId: 'first', status: 'connected' };
  const start = appSource.indexOf('  function sendSerialInput(');
  const end = appSource.indexOf('  async function trustSshHostKey(', start);
  assert.ok(start >= 0 && end > start);
  const source = stripTypeScriptTypes(appSource.slice(start, end));
  for (const next of [
    connected,
    { ...connected, backendSessionId: 'replacement' },
    { ...connected, status: 'closed' },
  ]) {
    const pending = Promise.withResolvers<void>();
    let sessions = [connected];
    const send = runInNewContext(source + '\nsendSerialInput;', {
      sessions,
      encodeTerminalData: (text: string) => Buffer.from(text).toString('base64'),
      window: { wormhole: { sendSerialInput: () => pending.promise } },
      Error,
      setSessions: (update: (current: SerialTab[]) => SerialTab[]) => {
        sessions = update(sessions);
      },
    });
    send('tab', 'x');
    sessions = [next];
    pending.reject(new Error('write failed'));
    await new Promise(setImmediate);
    if (next === connected) {
      assert.equal(sessions[0].status, 'failed');
      assert.equal(sessions[0].error, 'write failed');
    } else {
      assert.equal(sessions[0], next);
    }
  }
});

type TerminalConnectionStateProps = {
  session: {
    id: string;
    status: 'connecting' | 'failed' | 'disconnected';
    title?: string;
    host?: string;
    port?: number;
    serialSettings?: { baudRate: number };
    error?: string;
    credentialId?: string;
    hostKeyMismatch?: { expected: string; received: string };
    tunnelProgress?: object;
  };
  isSerial: boolean;
  onReconnect: (sessionId: string) => void;
  onTrustHostKey?: (sessionId: string, mismatch: object) => void;
};

// Execute the production JSX without loading App's unrelated native session lifecycles.
const connectionStateStart = appSource.indexOf('function SshTerminalConnectionState');
const connectionStateEnd = appSource.indexOf(
  'function SerialTerminalSurface',
  connectionStateStart,
);
assert.ok(connectionStateStart >= 0 && connectionStateEnd > connectionStateStart);
const connectionStateTransform = await transformWithOxc(
  appSource.slice(connectionStateStart, connectionStateEnd),
  'terminal-connection-state.tsx',
  { jsx: { runtime: 'classic' } },
);
let certificateEditor: ((id: string) => void) | null = null;
const renderConnectionState = runInNewContext(
  `${connectionStateTransform.code}\nSshTerminalConnectionState;`,
  {
    React,
    useContext: () => certificateEditor,
    SshCertificateEditorContext: {},
    requiresSshCertificateReplacement,
    Button: 'button',
    ConnectionLoading: 'connection-loading',
    protocolLabel: (protocol?: string) => protocol?.toUpperCase(),
    AlertCircle: 'error-icon',
    Terminal: 'terminal-icon',
    RefreshCcw: 'reconnect-icon',
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

test('terminal connection states show a concise loading status and preserve reconnect', () => {
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
      if (status === 'connecting') {
        assert.equal(element.type, 'connection-loading');
        assert.equal(element.props.protocol, protocol);
        assert.equal(element.props.status, isSerial ? 'Opening serial port…' : 'Connecting…');
        assert.equal(element.props.destination, undefined);
        assert.equal(reconnects.length, 0);
        continue;
      }
      const expectedTitle = `${protocol} ${status === 'failed' ? 'connection failed' : 'session closed'}`;
      const expectedMessage = isSerial
        ? 'The serial port closed the session.'
        : 'The remote host closed the connection.';
      assert.ok(markup.includes(expectedTitle), expectedTitle);
      assert.ok(markup.includes(expectedMessage), expectedMessage);
      assert.ok(markup.includes(isSerial ? 'Serial terminal' : 'Secure shell'));
      assert.ok(markup.includes('inherited target'));
      const elements = connectionStateElements(element);
      const icon = status === 'failed' ? 'error-icon' : 'terminal-icon';
      assert.ok(elements.some((child) => child.type === icon));
      const reconnect = elements.find((child) => child.type === 'button');
      assert.equal(typeof reconnect?.props.onClick, 'function');
      (reconnect!.props.onClick as () => void)();
      assert.deepEqual(reconnects, ['terminal-1']);
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

test('the loading screen shows VPN progress for a tunneled connection', () => {
  const tunnelProgress = { phase: 'authenticating', detail: 'Opening VPN' };
  for (const isSerial of [false, true]) {
    for (const status of ['connecting', 'failed', 'disconnected'] as const) {
      const element = renderConnectionState({
        session: { id: 'terminal-3', status, tunnelProgress },
        isSerial,
        onReconnect: () => undefined,
      });
      const connecting = status === 'connecting';
      assert.equal(
        element.props.tunnelProgress,
        connecting && !isSerial ? tunnelProgress : undefined,
      );
      assert.equal(
        element.props.status,
        connecting ? (isSerial ? 'Opening serial port…' : 'Connecting…') : undefined,
      );
    }
  }
  const ready = renderConnectionState({
    session: { id: 'terminal-3', status: 'connecting', tunnelProgress: { phase: 'ready' } },
    isSerial: false,
    onReconnect: () => undefined,
  });
  assert.deepEqual(ready.props.tunnelProgress, { phase: 'ready' });
  assert.equal(ready.props.status, 'Connecting…');
});

test('serial loading identifies the device and baud rate separately from the activity', () => {
  const element = renderConnectionState({
    session: {
      id: 'serial-1',
      title: 'Lab console',
      host: 'COM7',
      status: 'connecting',
      serialSettings: { baudRate: 115200 },
    },
    isSerial: true,
    onReconnect: () => undefined,
  });
  assert.equal(element.props.name, 'Lab console');
  assert.equal(element.props.destination, 'COM7');
  assert.equal(element.props.parameters, '115200 baud');
});

test('expired SSH certificates deep-link to their saved credential without changing reconnect', () => {
  const replaced: string[] = [];
  certificateEditor = (id) => replaced.push(id);
  try {
    const props: TerminalConnectionStateProps = {
      session: {
        id: 'expired',
        status: 'failed',
        credentialId: 'saved-key',
        error: 'SSH certificate expired on 2026-10-24 14:00 UTC',
      },
      isSerial: false,
      onReconnect: () => {},
    };
    const element = renderConnectionState(props);
    const replace = connectionStateElements(element).find(
      (child) => child.type === 'button' && child.props.children === 'Replace certificate…',
    );
    assert.ok(replace);
    (replace.props.onClick as () => void)();
    assert.deepEqual(replaced, ['saved-key']);
    for (const override of [
      { isSerial: true },
      { session: { ...props.session, status: 'connecting' as const } },
      { session: { ...props.session, credentialId: undefined } },
      { session: { ...props.session, error: 'SSH private key passphrase is required' } },
    ]) {
      assert.doesNotMatch(
        renderToStaticMarkup(renderConnectionState({ ...props, ...override })),
        /Replace certificate/,
      );
    }
  } finally {
    certificateEditor = null;
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
  let clipboardError: Error | undefined;
  let authorized = true;
  let clipboardEpoch = 0;
  let readClipboard: () => Promise<string> = async () => {
    if (clipboardError) throw clipboardError;
    return clipboardText;
  };
  new Function(
    'ipcMain',
    'isSshSessionId',
    'isSshInput',
    'serializeAuthOperation',
    'requireWorkspaceAuth',
    'requireAuthorizationEpoch',
    'sshBackend',
    'encodeTerminalClipboardText',
    'clipboard',
    'authSession',
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
    () => {
      if (!authorized) throw new Error('locked');
    },
    {
      // This fixture exercises the legacy workspace; protected generation/owner
      // fencing is exercised with actual native admissions in vault-ssh-wiring.
      captureOwner: () => () => {},
      sendInput: (...args: unknown[]) => calls.push(args),
    },
    encodeTerminalClipboardText,
    { readText: () => readClipboard() },
    {
      get authorizationEpoch() {
        return clipboardEpoch;
      },
      requireVerificationEpoch: (epoch: number) => {
        if (epoch !== clipboardEpoch) throw Error('locked while reading clipboard');
      },
    },
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
  clipboardError = new Error('clipboard unavailable');
  await assert.rejects(clipboard(null, 'session'), /clipboard unavailable/);
  assert.equal(calls.length, 5);
  clipboardError = undefined;
  await assert.rejects(input(null, 'session', 'YQ==', 'true'), /invalid/);
  await assert.rejects(input(null, 'session', 'bad'), /invalid/);
  await assert.rejects(input(null, 'invalid', 'YQ==', true), /invalid/);
  await assert.rejects(clipboard(null, 'invalid'), /invalid/);
  authorized = false;
  await assert.rejects(clipboard(null, 'session'), /locked/);
  await assert.rejects(input(null, 'session', 'YQ==', true), /locked/);
  assert.equal(calls.length, 5);
  authorized = true;
  let completeRead!: (value: string) => void;
  readClipboard = () =>
    new Promise((resolve) => {
      completeRead = resolve;
    });
  const lateRead = clipboard(null, 'session');
  await new Promise(setImmediate);
  authorized = false;
  completeRead('must not paste after lock');
  await assert.rejects(lateRead, /locked/);
  assert.equal(calls.length, 5);
  authorized = true;
  const relockedRead = clipboard(null, 'session');
  await new Promise(setImmediate);
  clipboardEpoch++;
  completeRead('stale across lock and unlock');
  await assert.rejects(relockedRead, /locked/);
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
  const surfaceSource = nativeSurfaceSource.slice(nativeSurfaceStart);
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

test('the mounted serial terminal handles clipboard, focus, resize and scrolling in Chromium', async () => {
  const start = nativeSurfaceSource.indexOf('const terminalFontSize');
  assert.ok(start >= 0);
  const helpers = readFileSync(
    new URL('../src/terminal-frame.ts', import.meta.url),
    'utf8',
  ).replaceAll('export function', 'function');
  const fixture = readFileSync(
    new URL('./fixtures/terminal-scroll.tsx', import.meta.url),
    'utf8',
  ).replace(
    'runTerminalScrollTests();',
    "runTerminalScrollTests().then(() => 'ok', (error) => String(error?.stack ?? error));",
  );
  const selectionSource = readFileSync(
    new URL('../src/terminal-selection.ts', import.meta.url),
    'utf8',
  ).replaceAll('export function', 'function');
  const frameApplicationSource = nativeFrameSource
    .slice(nativeFrameSource.indexOf('const terminalMaxScrollbackLines'))
    .replace(/^export /gm, '');
  const transformed = await transformWithOxc(
    [
      helpers,
      selectionSource,
      ...['clipboard', 'terminal-clipboard', 'terminal-keyboard'].map((name) =>
        readFileSync(new URL('../src/' + name + '.ts', import.meta.url), 'utf8').replace(
          /^export /gm,
          '',
        ),
      ),
      frameApplicationSource,
      nativeSurfaceSource.slice(start).replace('export function', 'function'),
      fixture,
    ].join('\n'),
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
  const evaluate = `try { eval(${JSON.stringify(renderer)}) } catch (error) { String(error?.stack ?? error) }`;
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
          const result = await window.webContents.executeJavaScript(${JSON.stringify(evaluate)});
          if (result !== 'ok') throw Error(result);
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
  const surfaceSource = nativeSurfaceSource.slice(nativeSurfaceStart);
  const copyHandler = surfaceSource.match(/onCopy=\{\(event\) => \{([\s\S]*?)\n      \}\}/)![1];
  const pointerStart = surfaceSource.lastIndexOf(
    '  useEffect(() => {',
    surfaceSource.indexOf('const clearOnOutsidePointer'),
  );
  const pointerEnd = surfaceSource.indexOf('}, [isActive, session.status]);', pointerStart);
  const browserSetup = stripTypeScriptTypes(
    nativeSurfaceSource.slice(
      nativeSurfaceSource.indexOf('function terminalSelection('),
      nativeSurfaceStart,
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
      { text: 'log: time', prevented: true },
      { text: 'log: time', prevented: true },
    ]);
    // Native mouse input exercises Chromium's default actions, which dispatchEvent skips.
    const points = await window.webContents.executeJavaScript(
      "(() => { const hit = document.createRange(); hit.setStart(first, 5); hit.setEnd(first, 6); const glyph = hit.getBoundingClientRect(); const bounds = row.getBoundingClientRect(); return [bounds.top, (bounds.top + bounds.bottom) / 2, bounds.bottom - 1].map(y => ({ x: Math.round((glyph.left + glyph.right) / 2), y: Math.round(y), expected: 'time' })).concat([{ x: Math.round(row.lastElementChild.getBoundingClientRect().right + 10), y: Math.round(bounds.top + 9), expected: row.textContent.trimEnd() }]); })()"
    );
    window.webContents.focus();
    for (const { expected, ...point } of points) {
      await window.webContents.executeJavaScript("window.nativeSelection = new Promise(resolve => terminal.addEventListener('mouseup', () => setTimeout(() => resolve(window.getSelection().toString()), 0), {once:true})); undefined");
      window.webContents.sendInputEvent({ type: 'mouseMove', ...point });
      window.webContents.sendInputEvent({ type: 'mouseDown', button: 'left', clickCount: 2, ...point });
      window.webContents.sendInputEvent({ type: 'mouseUp', button: 'left', clickCount: 2, ...point });
      assert.equal(await window.webContents.executeJavaScript('window.nativeSelection'), expected);
      if (expected === 'log: time') {
        assert.equal(await window.webContents.executeJavaScript(
          'selection.focusNode === second && selection.focusOffset === 2'
        ), true);
      }
    }
    const rowBoundaries = await window.webContents.executeJavaScript(${JSON.stringify(`
      const cases = [
        ['  log: ', 'time', '   ', '  '],
        ['caffè 😀', '  '],
        ['e\u0301', '  '],
        ['value', '\u00a0', '  '],
        ['\u2003', '  '],
        ['', '  ', ' '],
        [],
      ];
      cases.map(parts => {
        row.replaceChildren(...parts.map(text => {
          const span = document.createElement('span');
          span.style.cssText = 'display:inline-block;overflow:hidden;vertical-align:top';
          span.appendChild(document.createTextNode(text));
          return span;
        }));
        const bounds = row.getBoundingClientRect();
        row.dispatchEvent(new MouseEvent('mousedown', {
          bubbles: true, cancelable: true, button: 0, detail: 2,
          clientX: bounds.right - 1, clientY: bounds.top + 9,
        }));
        const selected = document.getSelection();
        const clipboardData = new DataTransfer();
        row.dispatchEvent(new ClipboardEvent('copy', {
          bubbles: true, cancelable: true, clipboardData,
        }));
        return {
          text: selected.toString(),
          copied: clipboardData.getData('text/plain'),
          endRun: [...row.children].findIndex(span => span.contains(selected.focusNode)),
          endOffset: selected.focusOffset,
        };
      });
    `)});
    assert.deepEqual(rowBoundaries, [
      { text: '  log: time', copied: '  log: time', endRun: 1, endOffset: 4 },
      { text: 'caffè 😀', copied: 'caffè 😀', endRun: 0, endOffset: 8 },
      { text: 'e\u0301', copied: 'e\u0301', endRun: 0, endOffset: 2 },
      { text: 'value\u00a0', copied: 'value\u00a0', endRun: 1, endOffset: 1 },
      { text: '\u2003', copied: '\u2003', endRun: 0, endOffset: 1 },
      { text: '', copied: '', endRun: 0, endOffset: 0 },
      { text: '', copied: '', endRun: -1, endOffset: 0 },
    ]);
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
