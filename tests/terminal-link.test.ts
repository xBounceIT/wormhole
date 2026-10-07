import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { parseTerminalLink } from '../electron/terminal-link.ts';
import { AuthSession } from '../electron/auth-session.ts';

test('terminal links accept HTTP(S) and reject unsafe or unbounded destinations', () => {
  assert.equal(
    parseTerminalLink('https://auth.openai.com/codex/device'),
    'https://auth.openai.com/codex/device',
  );
  assert.equal(
    parseTerminalLink('http://localhost:8080/a?q=1#test'),
    'http://localhost:8080/a?q=1#test',
  );
  assert.equal(parseTerminalLink('https://EXAMPLE.com'), 'https://example.com/');
  assert.equal(parseTerminalLink('https://example.com/a%20b'), 'https://example.com/a%20b');
  assert.equal(
    parseTerminalLink('https://例え.テスト/login'),
    'https://xn--r8jz45g.xn--zckzah/login',
  );
  assert.equal(
    parseTerminalLink('https://example.com/\u202ecodex'),
    'https://example.com/%E2%80%AEcodex',
  );
  const prefix = 'https://example.com/';
  const limit = prefix + 'a'.repeat(8192 - prefix.length);
  assert.equal(parseTerminalLink(limit), limit);
  for (const value of [
    undefined,
    null,
    1,
    {},
    '',
    '/relative',
    'http://',
    'https://[bad',
    'file:///C:/Windows',
    'javascript:alert(1)',
    'data:text/html,hello',
    'mailto:a@example.com',
    'ssh://host',
    'https://user:password@example.com',
    'https://user@example.com',
    ' https://example.com',
    'https://example.com/\n',
    'https://example.com/a\x00b',
    'https://example.com/a\x7fb',
    limit + 'a',
    prefix + 'é'.repeat(1500),
  ]) {
    assert.throws(() => parseTerminalLink(value), /terminal link is invalid/);
  }
});

test('a pending system-browser launch does not prevent workspace locking', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const slice = (from: string, to: string) => {
    const start = source.indexOf(from);
    const end = source.indexOf(to, start + from.length);
    assert.ok(start >= 0 && end > start);
    return source.slice(start, end);
  };
  const authSession = new AuthSession();
  authSession.remember({ configured: true }, true);
  let handler: (_event: object, value: unknown) => Promise<void>;
  let finishOpen!: () => void;
  let started!: () => void;
  const browserStarted = new Promise<void>((resolve) => {
    started = resolve;
  });
  const pendingBrowser = new Promise<void>((resolve) => {
    finishOpen = resolve;
  });
  const serialize = runInNewContext(
    stripTypeScriptTypes(`
    let authOperationQueue = Promise.resolve();
    ${slice('function serializeAuthOperation', 'function serializeAuthStateMutation')}
    ${slice('async function runAuthorizedOperation', 'function isAuthorizationEpochCurrent')}
    ${slice("  ipcMain.handle('ssh:open-link'", '\n  ipcMain.handle(')}
    serializeAuthOperation;
  `),
    {
      authSession,
      parseTerminalLink,
      ipcMain: {
        handle: (_channel: string, callback: typeof handler) => {
          handler = callback;
        },
      },
      requireWorkspaceAuth: async () => authSession.requireUnlocked(),
      shell: {
        openExternal: () => {
          started();
          return pendingBrowser;
        },
      },
    },
  );
  const opening = handler!({}, 'https://example.com').then(
    () => null,
    (error: Error) => error,
  );
  await browserStarted;
  let lockCompleted = false;
  const locking = serialize(async () => {
    authSession.lock();
    lockCompleted = true;
  });
  try {
    await new Promise(setImmediate);
    assert.equal(lockCompleted, true, 'browser launch blocked the authentication queue');
  } finally {
    finishOpen();
    await locking;
    await opening;
  }
  assert.equal(authSession.isAccessAllowed, false);
  assert.match((await opening)!.message, /Authentication is required/);
});

test('terminal link IPC validates, requires an unlocked workspace, and propagates browser failures', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf("  ipcMain.handle('ssh:open-link'");
  const end = source.indexOf('\n  ipcMain.handle(', start + 20);
  assert.ok(start >= 0 && end > start);
  let handler: (_event: object, value: unknown) => Promise<void>;
  const opened: string[] = [];
  let locked = false;
  let failed = false;
  runInNewContext(stripTypeScriptTypes(source.slice(start, end)), {
    ipcMain: {
      handle: (channel: string, callback: typeof handler) => {
        assert.equal(channel, 'ssh:open-link');
        handler = callback;
      },
    },
    parseTerminalLink,
    runAuthorizedOperation: async (operation: () => Promise<void>) => {
      if (locked) throw new Error('Locked');
      await operation();
    },
    shell: {
      openExternal: async (url: string) => {
        if (failed) throw new Error('Browser unavailable');
        opened.push(url);
      },
    },
  });
  await handler!({}, 'https://example.com');
  assert.deepEqual(opened, ['https://example.com/']);
  await assert.rejects(handler!({}, 'file:///tmp/test'), /invalid/);
  locked = true;
  await assert.rejects(handler!({}, 'https://example.com'), /Locked/);
  locked = false;
  failed = true;
  await assert.rejects(handler!({}, 'https://example.com'), /Browser unavailable/);
  assert.equal(opened.length, 1);

  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const method = preload.match(/openTerminalLink: ([^\n]+)/)?.[1];
  assert.ok(method);
  const calls: unknown[][] = [];
  const bridge = runInNewContext(stripTypeScriptTypes(`(${method.trim().replace(/,$/, '')})`), {
    ipcRenderer: {
      invoke: async (...args: unknown[]) => {
        calls.push(args);
      },
    },
  });
  await bridge('https://example.com');
  assert.deepEqual(calls, [['ssh:open-link', 'https://example.com']]);
});
