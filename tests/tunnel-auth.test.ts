import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Session } from 'node:inspector/promises';
import { stripTypeScriptTypes } from 'node:module';
import { setImmediate } from 'node:timers/promises';
import test, { after, before } from 'node:test';
import { runInNewContext } from 'node:vm';
import { TunnelFailureRegistry } from '../electron/tunnel-failure.ts';
import {
  encodeTunnelOAuthCallback,
  isFortinetIPsecRedirect,
  fortinetIPsecCallbackToken,
  fortinetSSLCallbackAuthId,
  fortinetSSLLoopback,
  isFortinetSSLCallbackSource,
  isMatchingOAuthRedirect,
  isSameCertificateHostname,
  tunnelPromptValueMaxBytes,
  tunnelAuthPartition,
  tunnelBrowserLoadFailure,
  TunnelBrowserPromptTracker,
} from '../electron/tunnel-auth.ts';

const redirect = 'http://localhost:2023/';
const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const popupFilename = 'wormhole-tunnel-auth-popup.js';
const popupScript = stripTypeScriptTypes(
  [
    'let tunnelBrowserAuthQueue = Promise.resolve();',
    mainSource.slice(
      mainSource.indexOf('function parseTunnelBrowserEvent('),
      mainSource.indexOf('let tunnelBrowserAuthQueue:'),
    ),
    mainSource.slice(
      mainSource.indexOf('function enqueueTunnelBrowserAuth('),
      mainSource.indexOf('class NativeBackendProcess'),
    ),
    `class BrowserAuthBackend {
      send = backendSend;
      child = {};
      browserPrompts = new TunnelBrowserPromptTracker();
      rendererTunnelPrompts = new Map();
      tunnelFailures = new TunnelFailureRegistry();
      outputBuffer = '';
      pending = new Map();`,
    mainSource.slice(
      mainSource.indexOf('  async releaseTunnel(leaseId:'),
      mainSource.indexOf('  async respondTunnelRoute(request:'),
    ),
    mainSource.slice(
      mainSource.indexOf('  async openWebTunnelEndpoint('),
      mainSource.indexOf('  async acquireTunnelRoute('),
    ),
    mainSource.slice(
      mainSource.indexOf('  private readOutput(chunk:'),
      mainSource.lastIndexOf('\n}', mainSource.indexOf('let nativeBackend:')),
    ),
    '}',
    '({ enqueue: enqueueTunnelBrowserAuth, getQueue: () => tunnelBrowserAuthQueue, backend: new BrowserAuthBackend() });',
  ].join('\n'),
);

// As in auth-session.test.ts, measure modified process-entrypoint handlers with V8.
// The normal module-coverage run owns its profiler and separately measures tunnel-auth.ts.
let profiler: Session | undefined;
before(async () => {
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE)
    return;
  profiler = new Session();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
});
after(async () => {
  if (!profiler) return;
  try {
    const scopes = [
      [
        popupScript.indexOf('function enqueueTunnelBrowserAuth('),
        popupScript.indexOf('async function runTunnelBrowserAuth('),
      ],
      [
        popupScript.indexOf('  const complete ='),
        popupScript.indexOf('  const matchesOAuthRedirect'),
      ],
      [
        popupScript.indexOf("authWindow.webContents.on('did-fail-load'"),
        popupScript.indexOf("authWindow.once('closed'"),
      ],
      [
        popupScript.indexOf('  const nextCandidate ='),
        popupScript.indexOf('  authWindow.webContents.setWindowOpenHandler'),
      ],
      [
        popupScript.indexOf('  const inspectNavigationSafely'),
        popupScript.indexOf('  const captureOAuthRedirect'),
      ],
      [
        popupScript.indexOf('    const webContentsId = authWindow.webContents.id;'),
        popupScript.indexOf("authWindow.webContents.on('did-fail-load'"),
      ],
      [popupScript.indexOf('  let cookieTimer'), popupScript.indexOf('class BrowserAuthBackend')],
      [popupScript.indexOf('  async respondTunnelPrompt('), popupScript.indexOf('readOutput(')],
      [
        popupScript.indexOf('  async releaseTunnel('),
        popupScript.indexOf('  async respondTunnelPrompt('),
      ],
      [
        popupScript.indexOf("if (message.type === 'tunnel.prompt-closed')"),
        popupScript.indexOf("if (message.type === 'tunnel.browser')"),
      ],
      [popupScript.lastIndexOf('rejectAll('), popupScript.lastIndexOf('\n}')],
    ];
    assert.ok(scopes.every(([start, end]) => start >= 0 && end > start));
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    const blocks = new Map<string, number>();
    for (const script of coverage.result.filter((script) => script.url === popupFilename)) {
      for (const fn of script.functions) {
        for (const range of fn.ranges) {
          if (!scopes.some(([start, end]) => range.startOffset >= start && range.endOffset <= end))
            continue;
          const key = `${range.startOffset}:${range.endOffset}`;
          blocks.set(key, (blocks.get(key) ?? 0) + range.count);
        }
      }
    }
    assert.ok(blocks.size > 0, 'Missing V8 coverage for browser authentication handlers');
    const percent = (100 * [...blocks.values()].filter((count) => count > 0).length) / blocks.size;
    console.log(
      `Modified browser authentication handlers: V8 block coverage ${percent.toFixed(2)}%`,
    );
  } finally {
    await profiler.post('Profiler.stopPreciseCoverage');
    profiler.disconnect();
  }
});

// Execute the production entrypoint's popup lifecycle with native window and network doubles.
// This exercises event/promise ordering without contacting an IdP or storing real credentials.
type BrowserCookie = { name: string; value: string; httpOnly?: boolean };
function browserAuthHarness(
  t: test.TestContext,
  event: Record<string, unknown> = {},
  cookies = {
    get: async (): Promise<BrowserCookie[]> => [],
    remove: async () => {},
  },
) {
  const loads: {
    url: string;
    resolve: () => void;
    reject: (error: Error) => void;
    window: AuthWindow;
  }[] = [];
  const windows: AuthWindow[] = [];
  const partitions: string[] = [];
  const windowPartitions: string[] = [];
  const responses: { cancelled: boolean; value: string; browserFailure?: string }[] = [];
  const diagnostics: unknown[][] = [];
  const authSession = { isAccessAllowed: true, authorizationEpoch: 1 };
  const rendererEvents: unknown[] = [];
  const renderer = {
    isDestroyed: () => false,
    webContents: { send: (_channel: string, event: unknown) => rendererEvents.push(event) },
  };
  const presented: AuthWindow[] = [];
  let expire!: () => void;
  let expireCleanup: (() => void) | undefined;
  let poll: (() => void) | undefined;
  let storageClears = 0;
  let receiveHeaders:
    | ((
        details: {
          url: string;
          webContentsId: number;
          resourceType: string;
          statusCode: number;
          responseHeaders: Record<string, string[]>;
        },
        callback: (result: { cancel?: boolean }) => void,
      ) => void)
    | null = null;
  type CertificateVerifier = (
    request: { hostname: string },
    done: (result: number) => void,
  ) => void;
  let verifyCertificate: CertificateVerifier | undefined;
  const browserSession = {
    setPermissionRequestHandler() {},
    setPermissionCheckHandler() {},
    setCertificateVerifyProc(verifier: CertificateVerifier) {
      verifyCertificate = verifier;
    },
    async clearStorageData() {
      storageClears++;
    },
    cookies,
    webRequest: {
      onHeadersReceived(listener: typeof receiveHeaders) {
        receiveHeaders = listener;
      },
    },
  };
  class AuthWindow extends EventEmitter {
    static getFocusedWindow() {
      return undefined;
    }
    static getAllWindows() {
      return [];
    }
    destroyed = false;
    windowOpenHandler?: (details: { url: string }) => { action: string };
    webContents = Object.assign(new EventEmitter(), {
      id: 7,
      setWindowOpenHandler: (handler: AuthWindow['windowOpenHandler']) => {
        this.windowOpenHandler = handler;
      },
    });
    isDestroyed() {
      return this.destroyed;
    }
    destroy() {
      this.destroyed = true;
      this.emit('closed');
      for (const load of loads) if (load.window === this) load.reject(new Error('Window closed'));
    }
    loadURL(url: string) {
      if (this.destroyed) return Promise.reject(new Error('Window closed'));
      return new Promise<void>((resolve, reject) =>
        loads.push({ url, resolve, reject, window: this }),
      );
    }
  }
  let window!: AuthWindow;
  const { enqueue, getQueue, backend } = runInNewContext(
    popupScript,
    {
      authSession,
      authLockRequested: false,
      isAuthorizationEpochCurrent: (epoch: number) =>
        authSession.isAccessAllowed && authSession.authorizationEpoch === epoch,
      isQuitting: false,
      randomUUID: () => 'relay-id',
      URL,
      Buffer,
      setInterval: (callback: () => void) => {
        poll = callback;
        return 1;
      },
      clearInterval: () => {
        poll = undefined;
      },
      setImmediate: globalThis.setImmediate,
      setTimeout: (callback: () => void, milliseconds: number) => {
        if (milliseconds === 1_000) {
          expireCleanup = callback;
          return 2;
        }
        expire = callback;
        return 1;
      },
      clearTimeout() {},
      backendSend: async (response: (typeof responses)[number]) => {
        responses.push(response);
        return { ok: true };
      },
      tunnelAuthPartition,
      isSameCertificateHostname,
      isMatchingOAuthRedirect,
      encodeTunnelOAuthCallback,
      isFortinetIPsecRedirect,
      fortinetIPsecCallbackToken,
      fortinetSSLCallbackAuthId,
      fortinetSSLLoopback,
      isFortinetSSLCallbackSource,
      tunnelPromptValueMaxBytes,
      tunnelBrowserLoadFailure,
      recordDiagnostic: (...args: unknown[]) => diagnostics.push(args),
      reportWarning: (message: string) => diagnostics.push(['WRN', message]),
      TunnelBrowserPromptTracker,
      TunnelFailureRegistry,
      nativeBackendLineLimit: 64 * 1024 * 1024,
      routeNativeOperationProgress() {},
      routeTunnelTestProgress: () => false,
      windowCloseCoordinators: new Set([renderer]),
      isSshSessionId: (value: unknown) => typeof value === 'string' && /^[\w-]{1,128}$/.test(value),
      electronSession: {
        fromPartition: (partition: string) => {
          partitions.push(partition);
          return browserSession;
        },
      },
      BrowserWindow: Object.assign(AuthWindow, { getAllWindows: () => [renderer] }),
      createApplicationWindow: (options: { webPreferences: { partition: string } }) => {
        window = new AuthWindow();
        windowPartitions.push(options.webPreferences.partition);
        windows.push(window);
        return window;
      },
      applicationIconPath: 'app.ico',
      nativeConnectionTimeoutMs: 315_000,
      mcpApprovalWindowCoordinator: {
        forgetTunnelAuthWindow() {},
        presentTunnelAuthWindow: (window: AuthWindow) => presented.push(window),
      },
    },
    { filename: popupFilename },
  );
  const urls = (event.urls as string[] | undefined) ?? [
    'https://firebox.example.test/auth/saml/login?from=sslvpn_client',
    'https://firebox.example.test/saml/login?from=sslvpn_client',
  ];
  const request = {
    sessionId: 'lease',
    promptId: 'prompt',
    title: 'WatchGuard SAML sign-in',
    urls,
    completion: 'query-token',
    ignoreCertificateErrors: false,
    ...event,
  };
  enqueue(backend, request);
  const finished: Promise<void> = getQueue();
  t.after(async () => {
    backend.browserPrompts.clear();
    for (const item of windows) if (!item.isDestroyed()) item.destroy();
    await setImmediate();
    expireCleanup?.();
    await getQueue();
  });
  return {
    loads,
    responses,
    authSession,
    rendererEvents,
    presented,
    finished,
    urls,
    windows,
    partitions,
    windowPartitions,
    diagnostics,
    backend,
    browserSession,
    certificateResult(hostname: string) {
      assert.ok(verifyCertificate);
      let result: number | undefined;
      verifyCertificate({ hostname }, (code) => {
        result = code;
      });
      return result;
    },
    get storageClears() {
      return storageClears;
    },
    receiveHeaders: (
      overrides: Partial<Parameters<NonNullable<typeof receiveHeaders>>[0]> = {},
    ) => {
      assert.ok(receiveHeaders);
      const results: boolean[] = [];
      receiveHeaders(
        {
          url: new URL('/remote/saml/login/', urls[0]).href,
          webContentsId: window.webContents.id,
          resourceType: 'mainFrame',
          statusCode: 302,
          responseHeaders: { Location: ['http://127.0.0.1:8020/?id=one-shot%2Bvalue'] },
          ...overrides,
        },
        (response) => results.push(response.cancel === true),
      );
      assert.equal(results.length, 1);
      return results[0];
    },
    enqueue: (overrides: Record<string, unknown>) => {
      enqueue(backend, { ...request, ...overrides });
      return getQueue();
    },
    emit: (message: unknown) => backend.readOutput(JSON.stringify(message) + '\n'),
    expire: () => expire(),
    expireCleanup: () => expireCleanup?.(),
    tick: async () => {
      poll?.();
      await setImmediate();
    },
    get window() {
      return window;
    },
    async fail(index: number, code = -105) {
      const load = loads[index];
      window.webContents.emit('did-fail-load', {}, code, 'untrusted error text', load.url, true);
      load.reject(Object.assign(new Error('untrusted error text'), { errno: code }));
      await setImmediate();
    },
  };
}

test('WatchGuard keeps the fallback popup alive when the initial load promise rejects', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  await auth.fail(0);
  assert.equal(auth.loads[1]?.url, auth.urls[1]);
  assert.equal(auth.window.isDestroyed(), false);
  assert.deepEqual(auth.responses, []);
  auth.loads[1].resolve();
  auth.window.webContents.emit(
    'did-navigate',
    {},
    'https://firebox.example.test/?user=test-user&token=ephemeral',
  );
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].cancelled, false);
  assert.equal(JSON.parse(auth.responses[0].value).token, 'ephemeral');
});

test('SAML ignores aborted and subframe loads while a redirect is in progress', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.window.webContents.emit('did-fail-load', {}, -105, 'subframe', auth.urls[0], false);
  await auth.fail(0, -3);
  assert.equal(auth.loads.length, 1);
  assert.equal(auth.window.isDestroyed(), false);
  assert.deepEqual(auth.responses, []);
});

for (const code of [-3, -102]) {
  test(`OAuth still captures a failed loopback callback with load error ${code}`, async (t) => {
    const auth = browserAuthHarness(t, { completion: 'oauth-code', redirectPrefix: redirect });
    await setImmediate();
    auth.window.webContents.emit(
      'did-fail-load',
      {},
      code,
      '',
      `${redirect}?code=authorization-code&state=expected-state`,
      true,
    );
    await setImmediate();
    assert.equal(auth.responses.length, 1);
    await auth.finished;
    assert.equal(auth.responses[0].cancelled, false);
    assert.equal(auth.responses[0].browserFailure, undefined);
    assert.equal(JSON.parse(auth.responses[0].value).code, 'authorization-code');
    assert.equal(auth.loads.length, 1);
  });
}

test('WatchGuard can reach the last fallback and only responds once after success', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  await auth.fail(0);
  assert.equal(auth.loads[1].url, auth.urls[1]);
  auth.loads[1].resolve();
  auth.window.webContents.emit(
    'did-navigate',
    {},
    'https://firebox.example.test/?user=test-user&token=ephemeral',
  );
  await auth.finished;
  auth.expire();
  auth.window.webContents.emit('did-fail-load', {}, -105, '', auth.urls[1], true);
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].cancelled, false);
  assert.equal(auth.responses[0].browserFailure, undefined);
});

for (const [code, failure] of [
  [-105, 'load'],
  [-202, 'certificate'],
] as const) {
  test(`exhausted SAML loads report ${failure} without exposing URL or error text`, async (t) => {
    const auth = browserAuthHarness(t);
    await setImmediate();
    for (let index = 0; index < auth.urls.length; index++) await auth.fail(index, code);
    await auth.finished;
    assert.equal(auth.window.isDestroyed(), true);
    assert.equal(auth.responses.length, 1);
    assert.equal(auth.responses[0].cancelled, false);
    assert.equal(auth.responses[0].browserFailure, failure);
    assert.equal(auth.responses[0].value, '');
    assert.doesNotMatch(JSON.stringify(auth.responses), /firebox|untrusted/);
  });
}

test('closing the SAML window remains a voluntary cancellation', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.window.destroy();
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].cancelled, true);
  assert.equal(auth.responses[0].browserFailure, undefined);
});

test('SAML authentication timeout reports an error instead of a user cancellation', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.expire();
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].cancelled, false);
  assert.equal(auth.responses[0].browserFailure, 'timeout');
});

const fortinetEvent = { completion: 'cookie', cookieName: 'SVPNCOOKIE', requireHttpOnly: true };

test('Fortinet IPsec accepts only an exact reserved loopback callback', async (t) => {
  const callback = 'http://127.0.0.1:41001/';
  const token = 'a1'.repeat(16);
  const auth = browserAuthHarness(t, { completion: 'fortinet-ipsec', redirectPrefix: callback });
  await setImmediate();
  for (const destination of [
    'http://127.0.0.1:41002/',
    'http://localhost:41001/',
    callback + 'other',
  ]) {
    auth.window.webContents.emit('will-redirect', {
      isMainFrame: true,
      url: destination + '?tokenid=' + token,
      preventDefault() {
        assert.fail('blocked unrelated navigation');
      },
    });
  }
  assert.deepEqual(auth.responses, []);
  let prevented = false;
  auth.window.webContents.emit('will-redirect', {
    isMainFrame: true,
    url: callback + '?tokenid=' + token + '&username=private-user',
    preventDefault() {
      prevented = true;
    },
  });
  assert.equal(prevented, true);
  assert.equal(auth.window.isDestroyed(), false, 'Chromium is still dispatching the redirect');
  assert.deepEqual(auth.responses, []);
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].value, token);
  assert.equal(auth.window.isDestroyed(), true);
});

test('Fortinet IPsec rejects invalid tokens and isolates every sign-in', async (t) => {
  const callback = 'http://127.0.0.1:41001/';
  const auth = browserAuthHarness(t, { completion: 'fortinet-ipsec', redirectPrefix: callback });
  await setImmediate();
  auth.window.webContents.emit('will-navigate', {
    isMainFrame: true,
    url: callback + '?tokenid=private-invalid',
    preventDefault() {},
  });
  await auth.finished;
  assert.equal(auth.responses[0].value, '');
  assert.equal(auth.responses[0].browserFailure, 'response');
  assert.notEqual(
    tunnelAuthPartition({ completion: 'fortinet-ipsec' }),
    tunnelAuthPartition({ completion: 'fortinet-ipsec' }),
  );
});

test('a deferred Fortinet IPsec callback cannot show its closed prompt or deliver a token after relock', async (t) => {
  const callback = 'http://127.0.0.1:41001/';
  const auth = browserAuthHarness(t, { completion: 'fortinet-ipsec', redirectPrefix: callback });
  await setImmediate();
  auth.window.webContents.emit('will-redirect', {
    isMainFrame: true,
    url: callback + '?tokenid=' + 'a1'.repeat(16),
    preventDefault() {},
  });
  auth.window.emit('ready-to-show');
  const popup = auth.window.windowOpenHandler?.({ url: 'https://idp.example.test/again' });
  const queued = auth.enqueue({ promptId: 'waiting-before-relock' });

  // The workspace can lock and unlock before the next main-loop turn.
  auth.authSession.authorizationEpoch++;
  auth.authSession.isAccessAllowed = false;
  const receivedWhileLocked = auth.enqueue({ promptId: 'received-while-locked' });
  auth.authSession.isAccessAllowed = true;
  await auth.finished;
  await setImmediate();
  assert.equal(auth.windows.length, 1);
  await Promise.all([queued, receivedWhileLocked]);
  assert.equal(auth.window.isDestroyed(), true);
  assert.equal(auth.responses.length, 3);
  assert.ok(auth.responses.every(({ cancelled, value }) => cancelled && value === ''));
  assert.deepEqual(auth.presented, []);
  assert.equal(popup?.action, 'deny');
  assert.equal(auth.loads.length, 1);
});

test('Fortinet IPsec callback parsing bounds ports and prevents ambiguous tokens', () => {
  assert.equal(isFortinetIPsecRedirect('http://127.0.0.1:41001/'), true);
  for (const value of [
    null,
    42,
    'bad',
    'https://127.0.0.1:41001/',
    'http://localhost:41001/',
    'http://127.0.0.1/',
    'http://127.0.0.1:0/',
    'http://127.0.0.1:65536/',
    'http://user@127.0.0.1:4000/',
    'http://127.0.0.1:4000/path',
    'http://127.0.0.1:4000/?state=x',
    'http://127.0.0.1:4000/#x',
  ])
    assert.equal(isFortinetIPsecRedirect(value), false);
  const base = 'http://127.0.0.1:41001/';
  assert.equal(
    fortinetIPsecCallbackToken(new URL(base + '?tokenid=' + 'A1'.repeat(16))),
    'A1'.repeat(16),
  );
  for (const query of [
    '',
    '?tokenid=bad',
    '?tokenid=' + 'a'.repeat(33),
    '?tokenid=' + 'a'.repeat(32) + '&tokenid=' + 'b'.repeat(32),
    '?tokenid=' + 'a'.repeat(32) + '#x',
  ])
    assert.equal(fortinetIPsecCallbackToken(new URL(base + query)), undefined);
});

test('native browser events accept only a bounded Fortinet IPsec loopback target', () => {
  const start = mainSource.indexOf('function parseTunnelBrowserEvent(');
  const end = mainSource.indexOf('let tunnelBrowserAuthQueue:', start);
  const parse = runInNewContext(
    stripTypeScriptTypes(mainSource.slice(start, end)) + '\nparseTunnelBrowserEvent',
    { URL, isFortinetIPsecRedirect },
  );
  const event = {
    sessionId: 'lease',
    promptId: 'prompt',
    title: 'Fortinet IPsec SAML sign-in',
    urls: ['https://vpn.test:1001/saml?request=1'],
    completion: 'fortinet-ipsec',
    redirectPrefix: 'http://127.0.0.1:45001/',
  };
  assert.equal(parse(event).completion, 'fortinet-ipsec');
  for (const redirectPrefix of [
    'http://evil.test:45001/',
    'http://127.0.0.1:45001/other',
    undefined,
  ])
    assert.equal(parse({ ...event, redirectPrefix }), undefined);
  assert.equal(parse({ ...event, urls: ['http://vpn.test/saml'] }), undefined);
});

test('backend prompt closure ends active and queued SAML prompts with matching ownership', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  void auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  const last = auth.enqueue({ sessionId: 'lease-three', promptId: 'prompt-three' });
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'other-lease', promptId: 'prompt' });
  assert.equal(auth.window.isDestroyed(), false);
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'lease-two', promptId: 'prompt-two' });
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'lease', promptId: 'prompt' });
  await setImmediate();
  assert.equal(auth.windows.length, 2);
  assert.equal(auth.windows[0].isDestroyed(), true);
  assert.equal(auth.windows[1].isDestroyed(), false);
  assert.deepEqual(auth.responses, []);
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'lease-three', promptId: 'prompt-three' });
  await last;
  assert.equal(auth.windows[1].isDestroyed(), true);
  assert.deepEqual(auth.responses, []);
});

test('backend loss closes a hidden SAML popup and discards queued prompts', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  const queued = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  auth.backend.rejectAll(new Error('Service stopped'));
  await queued;
  assert.equal(auth.windows.length, 1);
  assert.equal(auth.window.isDestroyed(), true);
  assert.deepEqual(auth.responses, []);
});

test('workspace VPN prompts close after a lock or a backend crash', async (t) => {
  const auth = browserAuthHarness(t);
  const prompt = { type: 'tunnel.prompt', sessionId: 'reconnect', promptId: 'plain-prompt' };
  const closed = { ...prompt, type: 'tunnel.prompt-closed' };
  auth.emit(prompt);
  auth.authSession.isAccessAllowed = false;
  auth.emit({ ...closed, sessionId: 'different-lease' });
  auth.emit({ ...prompt, promptId: 'hidden-prompt' });
  assert.deepEqual(JSON.parse(JSON.stringify(auth.rendererEvents)), [prompt]);
  auth.emit(closed);
  auth.authSession.isAccessAllowed = true;
  auth.emit(prompt);
  auth.backend.rejectAll(new Error('Backend crashed'));
  assert.deepEqual(JSON.parse(JSON.stringify(auth.rendererEvents)), [
    prompt,
    closed,
    prompt,
    closed,
  ]);
});

test('tunnel failure cleanup after backend exit never sends a release to a new process', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.backend.child = undefined;
  let cleanup: Promise<void> | undefined;
  auth.backend.tunnelFailures.watch('lease', () => {
    cleanup = auth.backend.releaseTunnel('lease');
  });
  auth.backend.rejectAll(new Error('Service exited'));
  await cleanup;
  // send() starts the native backend; cleanup must never call it after that backend died.
  assert.deepEqual(auth.responses, []);
  assert.equal(auth.window.isDestroyed(), true);
});

test('live tunnel release forgets its failure handler and retains backend errors', async (t) => {
  const auth = browserAuthHarness(t);
  auth.backend.tunnelFailures.watch('lease', () => assert.fail('released callback was retained'));
  await auth.backend.releaseTunnel('lease');
  assert.equal(auth.responses[0].action, 'tunnel.release');
  assert.equal(auth.responses[0].sessionId, 'lease');
  auth.backend.tunnelFailures.fail({ type: 'tunnel.failed', sessionId: 'lease' });
  auth.backend.send = async () => ({ ok: false, error: 'Release unavailable' });
  await assert.rejects(auth.backend.releaseTunnel('other'), /Release unavailable/);
  auth.backend.send = async () => ({ ok: false });
  await assert.rejects(auth.backend.releaseTunnel('other'), /Could not release/);
});

test('a paused browser relay cannot release a lease to a replacement backend', async (t) => {
  const auth = browserAuthHarness(t);
  let paused!: () => void;
  const disconnecting = new Promise<void>((resolve) => {
    paused = resolve;
  });
  const cleanup = auth.backend.releaseTunnel('lease', disconnecting);
  auth.backend.child = {};
  paused();
  await cleanup;
  assert.deepEqual(auth.responses, []);
});

test('the browser relay client waits for native acknowledgement and refuses commands after exit', async (t) => {
  const auth = browserAuthHarness(t);
  const commands: any[] = [];
  auth.backend.send = async (command: unknown) => {
    commands.push(command);
    return { ok: true, forwardPort: 45000 };
  };
  let exits = 0;
  const endpoint = await auth.backend.openWebTunnelEndpoint(() => exits++);
  assert.equal(endpoint.port, 45000);
  await endpoint.connect(2150);
  const paused = endpoint.disconnect();
  assert.equal(endpoint.disconnect(), paused);
  await paused;
  assert.deepEqual(
    commands.map(({ action, port }) => [action, port]),
    [
      ['browser-relay.open', undefined],
      ['browser-relay.route', 2150],
      ['browser-relay.route', 0],
    ],
  );
  auth.backend.rejectAll(new Error('Relay stopped'));
  assert.equal(exits, 1);
  await assert.rejects(endpoint.connect(2250), /endpoint is closed/);
  await endpoint.close();
  assert.equal(commands.length, 3);
});

test('native popup setup errors settle the prompt and leave the queue usable', async (t) => {
  const auth = browserAuthHarness(t);
  const configure = auth.browserSession.setCertificateVerifyProc;
  auth.browserSession.setCertificateVerifyProc = () => {
    throw new Error('private setup error');
  };
  await auth.finished;
  assert.equal(auth.responses[0]?.browserFailure, 'session');
  assert.doesNotMatch(JSON.stringify(auth.responses), /private setup/);
  auth.browserSession.setCertificateVerifyProc = configure;
  const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  await setImmediate();
  auth.window.destroy();
  await next;
  assert.equal(auth.responses.length, 2);
});

test('browser prompt tracking rejects duplicates, validates owners, and ignores stale finalizers', () => {
  const tracker = new TunnelBrowserPromptTracker();
  const first = tracker.begin('lease', 'prompt')!;
  assert.equal(tracker.begin('lease', 'prompt'), undefined);
  tracker.close('lease', undefined);
  tracker.close('other', 'prompt');
  assert.equal(first.aborted, false);
  tracker.close('lease', 'prompt');
  assert.equal(first.aborted, true);
  const next = tracker.begin('lease', 'prompt')!;
  tracker.finish('prompt', first);
  tracker.clear();
  assert.equal(next.aborted, true);
  const last = tracker.begin('lease', 'prompt')!;
  tracker.finish('prompt', last);
  tracker.close('lease', 'prompt');
  tracker.clear();
  assert.equal(last.aborted, false);
});

test('cancelled Fortinet initialization cannot load or remove cookies after a later prompt starts', async (t) => {
  let release!: (value: BrowserCookie[]) => void;
  let reads = 0;
  let removals = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () =>
      ++reads === 1
        ? new Promise((resolve) => {
            release = resolve;
          })
        : [],
    remove: async () => {
      removals++;
    },
  });
  await setImmediate();
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'lease', promptId: 'prompt' });
  await auth.finished;
  const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  await setImmediate();
  release([{ name: 'SVPNCOOKIE', value: 'stale' }]);
  await setImmediate();
  assert.equal(auth.loads.length, 1);
  assert.equal(removals, 0);
  assert.deepEqual(auth.responses, []);
  auth.window.destroy();
  await next;
});

test('slow Fortinet cleanup is bounded and cannot delete a later login cookie', async (t) => {
  let release!: (value: BrowserCookie[]) => void;
  let reads = 0;
  let removals = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () => {
      reads++;
      if (reads === 2) return [{ name: 'SVPNCOOKIE', value: 'ephemeral', httpOnly: true }];
      if (reads === 3)
        return new Promise((resolve) => {
          release = resolve;
        });
      return [];
    },
    remove: async () => {
      removals++;
    },
  });
  await setImmediate();
  await auth.tick();
  assert.equal(auth.responses[0]?.value, 'ephemeral');
  auth.expireCleanup();
  await auth.finished;
  const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  await setImmediate();
  release([{ name: 'SVPNCOOKIE', value: 'old' }]);
  await setImmediate();
  assert.equal(removals, 0);
  assert.equal(auth.windows.length, 2);
  auth.window.destroy();
  await next;
});

for (const peerFails of [false, true]) {
  test(`Fortinet releases the queue despite stalled cleanup and ${peerFails ? 'a peer failure' : 'a timeout'}`, async (t) => {
    let release!: () => void;
    let reads = 0;
    let removals = 0;
    const auth = browserAuthHarness(t, fortinetEvent, {
      get: async () => {
        reads++;
        if (reads === 2) return [{ name: 'SVPNCOOKIE', value: 'ephemeral', httpOnly: true }];
        if (reads === 3)
          return [
            { name: 'SVPNCOOKIE', value: 'old-one', httpOnly: true },
            { name: 'SVPNCOOKIE', value: 'old-two', httpOnly: true },
          ];
        return [];
      },
      remove: async () => {
        if (++removals === 1)
          return new Promise<void>((resolve) => {
            release = resolve;
          });
        if (peerFails) throw new Error('synthetic removal failure');
      },
    });
    await setImmediate();
    await auth.tick();
    const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
    try {
      auth.expireCleanup();
      await setImmediate();
      assert.equal(removals, 2);
      assert.equal(auth.windows.length, 2);
      assert.notEqual(auth.partitions[0], auth.partitions[1]);
      assert.equal(auth.responses.length, 1);
    } finally {
      release();
    }
    await setImmediate();
    assert.equal(auth.windows.length, 2);
    auth.window.destroy();
    await next;
  });
}

test('cancelling startup bounds an in-flight cookie removal without blocking the next login', async (t) => {
  let release!: () => void;
  let reads = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () => (++reads === 1 ? [{ name: 'SVPNCOOKIE', value: 'stale' }] : []),
    remove: async () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
  });
  await setImmediate();
  const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  auth.emit({ type: 'tunnel.prompt-closed', sessionId: 'lease', promptId: 'prompt' });
  try {
    await setImmediate();
    auth.expireCleanup();
    await setImmediate();
    assert.equal(auth.windows.length, 2);
    assert.notEqual(auth.partitions[0], auth.partitions[1]);
    assert.equal(auth.loads.length, 1);
    assert.deepEqual(auth.responses, []);
  } finally {
    release();
  }
  await setImmediate();
  assert.equal(auth.windows.length, 2);
  assert.equal(auth.loads.length, 1);
  auth.window.destroy();
  await next;
});

test('duplicate browser events and failed response writes do not block the queue', async (t) => {
  const auth = browserAuthHarness(t);
  void auth.enqueue({});
  await setImmediate();
  assert.equal(auth.windows.length, 1);
  const send = auth.backend.send;
  auth.backend.send = async () => {
    throw new Error('service write failed');
  };
  auth.window.destroy();
  await auth.finished;
  auth.backend.send = send;
  const next = auth.enqueue({ sessionId: 'lease-two', promptId: 'prompt-two' });
  await setImmediate();
  auth.window.destroy();
  await next;
  assert.equal(auth.responses.length, 1);
});

test('Fortinet accepts only a matching HttpOnly cookie and enforces the UTF-8 byte boundary', async (t) => {
  let reads = 0;
  let removals = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () => {
      reads++;
      if (reads === 1) return [];
      if (reads === 2)
        return [
          { name: 'other', value: 'ignored', httpOnly: true },
          { name: 'SVPNCOOKIE', value: '', httpOnly: true },
          { name: 'SVPNCOOKIE', value: 'ignored', httpOnly: false },
        ];
      return [
        { name: 'SVPNCOOKIE', value: 'é'.repeat(tunnelPromptValueMaxBytes / 2), httpOnly: true },
      ];
    },
    remove: async () => {
      removals++;
    },
  });
  await setImmediate();
  await auth.tick();
  assert.deepEqual(auth.responses, []);
  await auth.tick();
  await auth.finished;
  assert.equal(auth.responses[0].cancelled, false);
  assert.equal(Buffer.byteLength(auth.responses[0].value, 'utf8'), tunnelPromptValueMaxBytes);
  assert.equal(removals, 1);
});

test('Fortinet polling storage errors settle safely with a fixed diagnostic', async (t) => {
  let reads = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () => {
      if (++reads > 1) throw new Error('private storage error');
      return [];
    },
    remove: async () => {},
  });
  await setImmediate();
  await auth.tick();
  await auth.finished;
  assert.equal(auth.responses[0]?.browserFailure, 'session');
  assert.equal(auth.responses[0].cancelled, false);
  assert.doesNotMatch(JSON.stringify(auth.responses), /private storage/);
});

test('Fortinet cookie completion cannot be replaced by WatchGuard query parameters', async (t) => {
  const auth = browserAuthHarness(t, fortinetEvent);
  await setImmediate();
  auth.window.webContents.emit('did-navigate', {}, 'https://firebox.example.test/?user=u&token=t');
  await setImmediate();
  assert.deepEqual(auth.responses, []);
  assert.equal(auth.window.isDestroyed(), false);
});

test('Fortinet reports a host-check 403 only from the configured gateway and path', async (t) => {
  const gateway = 'https://vpn.example.test:10443';
  const auth = browserAuthHarness(t, {
    ...fortinetEvent,
    urls: [`${gateway}/remote/saml/start`],
  });
  await setImmediate();
  for (const url of [
    'https://login.example.test/remote/hostcheck_install',
    'https://vpn.example.test/remote/hostcheck_install',
    `${gateway}/remote/other`,
  ]) {
    auth.window.webContents.emit('did-navigate', {}, url, 403);
  }
  const hostCheck = `${gateway}/remote/hostcheck_install?user=private-user`;
  auth.window.webContents.emit('did-navigate', {}, hostCheck, 200);
  await setImmediate();
  assert.deepEqual(auth.responses, []);

  auth.window.webContents.emit('did-navigate', {}, hostCheck, 403);
  await setImmediate();
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].browserFailure, 'fortinet-hostcheck-forbidden');
  assert.equal(auth.responses[0].cancelled, false);
  assert.equal(auth.responses[0].value, '');
  assert.doesNotMatch(JSON.stringify(auth.responses), /private-user/);
  await auth.finished;
});

test('Fortinet rechecks for the VPN cookie after a host-check 403 overlaps polling', async (t) => {
  const gateway = 'https://vpn.example.test';
  let resolvePoll!: (cookies: BrowserCookie[]) => void;
  let reads = 0;
  const auth = browserAuthHarness(
    t,
    { ...fortinetEvent, urls: [`${gateway}/remote/saml/start`] },
    {
      get: async () => {
        if (++reads === 1) return [];
        if (reads === 2) {
          return new Promise<BrowserCookie[]>((resolve) => {
            resolvePoll = resolve;
          });
        }
        return [{ name: 'SVPNCOOKIE', value: 'issued-cookie', httpOnly: true }];
      },
      remove: async () => {},
    },
  );
  await setImmediate();
  await auth.tick();
  auth.window.webContents.emit('did-navigate', {}, `${gateway}/remote/hostcheck_install`, 403);
  resolvePoll([]);
  await setImmediate();
  assert.deepEqual(auth.responses, []);

  await auth.tick();
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].value, 'issued-cookie');
  assert.equal(auth.responses[0].browserFailure, undefined);
  await auth.finished;
});

const fortinetSSLCallbackEvent = {
  completion: 'fortinet-ssl',
  urls: ['https://vpn.example.test:10443/remote/saml/start?redirect=1'],
};

test('Fortinet SSL captures the gateway callback before a request to localhost', async (t) => {
  const auth = browserAuthHarness(t, fortinetSSLCallbackEvent);
  await setImmediate();
  for (const details of [
    { url: 'https://other.example.test/remote/saml/login' },
    { url: 'https://vpn.example.test:10443/remote/other' },
    { webContentsId: 8 },
    { resourceType: 'subFrame' },
    { statusCode: 200 },
    { responseHeaders: { Location: ['https://login.example.test/'] } },
  ]) {
    assert.equal(auth.receiveHeaders(details), false);
  }
  assert.deepEqual(auth.responses, []);
  assert.equal(
    auth.receiveHeaders({
      responseHeaders: { Location: ['http://[::1]:8020/?id=one-shot%2Bvalue'] },
    }),
    true,
  );
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].value, 'one-shot+value');
  assert.equal(auth.responses[0].browserFailure, undefined);
  assert.equal(auth.storageClears, 1);
});

test('Fortinet SSL rejects an ambiguous callback without forwarding a credential', async (t) => {
  const auth = browserAuthHarness(t, fortinetSSLCallbackEvent);
  await setImmediate();
  assert.equal(
    auth.receiveHeaders({
      responseHeaders: { location: ['http://localhost:9020/?id=first&id=second'] },
    }),
    true,
  );
  await auth.finished;
  assert.equal(auth.responses[0].browserFailure, 'response');
  assert.equal(auth.responses[0].value, '');
});

test('Fortinet SSL allows HTTPS navigation to a locally forwarded gateway', async (t) => {
  const gateway = 'https://127.0.0.1:10443';
  const auth = browserAuthHarness(t, {
    ...fortinetSSLCallbackEvent,
    urls: [`${gateway}/remote/saml/start?redirect=1`],
  });
  await setImmediate();
  const login = `${gateway}/remote/saml/login/`;
  assert.equal(auth.receiveHeaders({ responseHeaders: { Location: [login] } }), false);
  auth.window.webContents.emit('will-redirect', {
    url: login,
    preventDefault: () => assert.fail('gateway navigation was blocked'),
  });
  assert.deepEqual(auth.responses, []);

  assert.equal(auth.receiveHeaders(), true);
  assert.equal(auth.window.isDestroyed(), false, 'Chromium is still dispatching the redirect');
  await auth.finished;
  assert.equal(auth.responses[0].value, 'one-shot+value');
});

test('Fortinet SSL blocks loopback navigation from the identity provider', async (t) => {
  const auth = browserAuthHarness(t, fortinetSSLCallbackEvent);
  await setImmediate();
  let prevented = 0;
  const event = {
    url: 'http://localhost:9020/?id=one-shot',
    initiator: { url: 'https://login.example.test/' },
    preventDefault: () => prevented++,
  };
  assert.equal(
    auth.window.windowOpenHandler?.({ url: 'https://localhost.:9020/?id=one-shot' }).action,
    'deny',
  );
  assert.equal(auth.loads.length, 1);
  auth.window.webContents.emit('will-navigate', event);
  auth.window.webContents.emit('will-redirect', event);
  assert.equal(prevented, 2);
  assert.deepEqual(auth.responses, []);
  auth.window.webContents.emit('will-navigate', {
    ...event,
    initiator: { url: 'https://vpn.example.test:10443/remote/saml/login' },
  });
  await auth.finished;
  assert.equal(prevented, 3);
  assert.equal(auth.responses[0].value, 'one-shot');
});

test('a deferred Fortinet SSL callback discards its ID after a workspace relock', async (t) => {
  const auth = browserAuthHarness(t, fortinetSSLCallbackEvent);
  await setImmediate();
  assert.equal(auth.receiveHeaders(), true);
  auth.authSession.authorizationEpoch++;
  await auth.finished;
  assert.equal(auth.responses.length, 1);
  assert.equal(auth.responses[0].cancelled, true);
  assert.equal(auth.responses[0].value, '');
  assert.equal(auth.storageClears, 1);
});

test('WatchGuard ignores malformed, unrelated and incomplete navigation callbacks', async (t) => {
  let reads = 0;
  const auth = browserAuthHarness(
    t,
    {},
    {
      get: async () => {
        reads++;
        return [];
      },
      remove: async () => {},
    },
  );
  await setImmediate();
  for (const url of [
    'not a URL',
    'https://other.example.test/?user=u&token=t',
    'https://firebox.example.test/?user=u',
    'https://firebox.example.test/?token=t',
  ]) {
    auth.window.webContents.emit('did-navigate', {}, url);
  }
  await setImmediate();
  assert.equal(reads, 0);
  assert.deepEqual(auth.responses, []);
  auth.window.webContents.emit(
    'did-navigate',
    {},
    `https://firebox.example.test/?user=${'x'.repeat(1025)}&token=t`,
  );
  await setImmediate();
  assert.equal(auth.responses[0]?.browserFailure, 'response');
});

test('SAML callback extraction ignores in-page navigation from child frames', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  const url = 'https://firebox.example.test/?user=u&token=t';
  auth.window.webContents.emit('did-navigate-in-page', {}, url, false);
  await setImmediate();
  assert.deepEqual(auth.responses, []);
  assert.equal(auth.window.isDestroyed(), false);
  auth.window.webContents.emit('did-navigate-in-page', {}, url, true);
  await auth.finished;
  assert.equal(auth.responses[0].cancelled, false);
});

test('a crashed authentication renderer settles as an error and frees the popup', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.window.webContents.emit('render-process-gone', {}, { reason: 'crashed', exitCode: 1 });
  await setImmediate();
  assert.equal(
    JSON.stringify(auth.diagnostics),
    JSON.stringify([['ERR', 'VPN sign-in renderer exited', { reason: 'crashed', exitCode: 1 }]]),
  );
  assert.equal(auth.responses[0]?.browserFailure, 'session');
  assert.equal(auth.window.isDestroyed(), true);
  assert.equal(auth.responses[0].cancelled, false);
});

test('WatchGuard rejects excessive cookie counts rather than silently truncating them', async (t) => {
  const auth = browserAuthHarness(
    t,
    {},
    {
      get: async () => Array.from({ length: 257 }, () => ({ name: 'cookie', value: 'private' })),
      remove: async () => {},
    },
  );
  await setImmediate();
  auth.window.webContents.emit('did-navigate', {}, 'https://firebox.example.test/?user=u&token=t');
  await setImmediate();
  assert.equal(auth.responses[0]?.browserFailure, 'response');
  assert.equal(auth.responses[0].value, '');
});

test('WatchGuard HTTP fallback preserves IdP errors and ends after the last unavailable endpoint', async (t) => {
  const auth = browserAuthHarness(t);
  await setImmediate();
  auth.window.webContents.emit(
    'did-navigate',
    {},
    'https://idp.example.test/login',
    404,
    'Not found',
  );
  assert.equal(auth.loads.length, 1);
  for (let index = 0; index < auth.urls.length; index++) {
    auth.window.webContents.emit('did-navigate', {}, auth.urls[index], 404, 'Not found');
    auth.loads[index].resolve();
  }
  await auth.finished;
  assert.equal(auth.loads.length, auth.urls.length);
  assert.equal(auth.responses[0]?.browserFailure, 'load');
});

test('Fortinet never polls a stale completion cookie before startup cleanup finishes', async (t) => {
  let release!: (value: BrowserCookie[]) => void;
  let reads = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () =>
      ++reads === 1
        ? new Promise((resolve) => {
            release = resolve;
          })
        : [{ name: 'SVPNCOOKIE', value: 'stale', httpOnly: true }],
    remove: async () => {},
  });
  try {
    await auth.tick();
    assert.equal(reads, 1);
    assert.equal(auth.loads.length, 0);
    assert.deepEqual(auth.responses, []);
  } finally {
    release([]);
  }
});

test('Fortinet fails closed when removing a previous completion cookie fails', async (t) => {
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () => [{ name: 'SVPNCOOKIE', value: 'stale', httpOnly: true }],
    remove: async () => {
      throw new Error('private storage diagnostic');
    },
  });
  await setImmediate();
  assert.equal(auth.loads.length, 0);
  assert.equal(auth.responses[0]?.browserFailure, 'session');
  assert.equal(auth.responses[0].value, '');
});

test('Fortinet keeps at most one cookie poll in flight', async (t) => {
  let release!: (value: BrowserCookie[]) => void;
  let reads = 0;
  const auth = browserAuthHarness(t, fortinetEvent, {
    get: async () =>
      ++reads === 2
        ? new Promise((resolve) => {
            release = resolve;
          })
        : [],
    remove: async () => {},
  });
  await setImmediate();
  try {
    await auth.tick();
    await auth.tick();
    await auth.tick();
    assert.equal(reads, 2);
    assert.deepEqual(auth.responses, []);
  } finally {
    release([]);
  }
});

test('WatchGuard handles cookie storage failure without leaking native diagnostics', async (t) => {
  const auth = browserAuthHarness(
    t,
    {},
    {
      get: async () => {
        throw new Error('private storage diagnostic');
      },
      remove: async () => {},
    },
  );
  await setImmediate();
  auth.window.webContents.emit(
    'did-navigate',
    {},
    'https://firebox.example.test/?user=test-user&token=ephemeral',
  );
  await setImmediate();
  assert.equal(auth.responses[0]?.browserFailure, 'session');
  assert.equal(auth.responses[0].cancelled, false);
  assert.doesNotMatch(JSON.stringify(auth.responses), /private storage|ephemeral/);
});

for (const completion of ['query-token', 'oauth-code', 'cookie']) {
  test(`${completion} reports oversized credentials as an invalid response`, async (t) => {
    let reads = 0;
    const auth = browserAuthHarness(
      t,
      completion === 'cookie' ? fortinetEvent : { completion, redirectPrefix: redirect },
      {
        get: async () =>
          ++reads === 1 || completion !== 'cookie'
            ? []
            : [
                {
                  name: 'SVPNCOOKIE',
                  value: 'x'.repeat(tunnelPromptValueMaxBytes + 1),
                  httpOnly: true,
                },
              ],
        remove: async () => {},
      },
    );
    await setImmediate();
    if (completion === 'cookie') await auth.tick();
    else
      auth.window.webContents.emit(
        'did-navigate',
        {},
        completion === 'oauth-code'
          ? `${redirect}?error_description=${'x'.repeat(tunnelPromptValueMaxBytes)}`
          : `https://firebox.example.test/?user=test-user&token=${'x'.repeat(tunnelPromptValueMaxBytes)}`,
      );
    await setImmediate();
    assert.equal(auth.responses[0]?.browserFailure, 'response');
    assert.equal(auth.responses[0].cancelled, false);
    assert.equal(auth.responses[0].value, '');
  });
}

for (const status of [404, 410]) {
  test(`WatchGuard tries the next endpoint after HTTP ${status}`, async (t) => {
    const auth = browserAuthHarness(t);
    await setImmediate();
    auth.window.webContents.emit('did-navigate', {}, auth.urls[0], status, 'Not found');
    auth.loads[0].resolve();
    await setImmediate();
    assert.equal(auth.loads[1]?.url, auth.urls[1]);
    assert.equal(auth.window.isDestroyed(), false);
    assert.deepEqual(auth.responses, []);
  });
}

for (const origin of ['https://FIREBOX.example.test:443', 'https://[2001:0db8:0:0:0:0:0:1]:443']) {
  test(`WatchGuard HTTP fallback matches Chromium URL normalization for ${origin}`, async (t) => {
    const urls = [
      `${origin}/auth/saml/login?from=sslvpn_client`,
      `${origin}/saml/login?from=sslvpn_client`,
    ];
    const auth = browserAuthHarness(t, { urls });
    await setImmediate();
    auth.window.webContents.emit('did-navigate', {}, new URL(urls[0]).href, 404, 'Not found');
    auth.loads[0].resolve();
    await setImmediate();
    assert.equal(auth.loads[1]?.url, urls[1]);
    assert.equal(auth.window.isDestroyed(), false);
    assert.deepEqual(auth.responses, []);
  });
}

test('browser load failures classify Chromium certificate errors and ignore ERR_ABORTED', () => {
  assert.equal(tunnelBrowserLoadFailure(-3), undefined);
  for (const code of [-200, -201, -202, -299]) {
    assert.equal(tunnelBrowserLoadFailure(code), 'certificate');
  }
  for (const code of [-2, -105, -199, -300]) {
    assert.equal(tunnelBrowserLoadFailure(code), 'load');
  }
});

// BrowserWindow options live in the Electron entrypoint, which the project's
// loaded-module coverage excludes. Protect this declarative native UI setting
// with the same scoped source contract used for the authentication lifecycle.
test('VPN authentication popup uses the Wormhole application icon', () => {
  const start = mainSource.indexOf('const authWindow = createApplicationWindow({');
  assert.ok(start >= 0);
  const options = mainSource.slice(start, mainSource.indexOf('let candidate = 0;', start));
  assert.match(options, /\bicon:\s*applicationIconPath\s*,/);
});

test('OAuth callback matching accepts only the configured loopback endpoint', () => {
  assert.equal(isMatchingOAuthRedirect(new URL('http://localhost:2023/?code=ok'), redirect), true);
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:2023/other?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:20230/?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('http://localhost:2023@attacker.test/?code=no'), redirect),
    false,
  );
  assert.equal(
    isMatchingOAuthRedirect(new URL('https://localhost:2023/?code=no'), redirect),
    false,
  );
});

test('Azure captures server redirects and failed loopback loads before treating auth as cancelled', () => {
  const flow = mainSource.slice(
    mainSource.indexOf('async function runTunnelBrowserAuth'),
    mainSource.indexOf('class NativeBackendProcess'),
  );
  assert.match(flow, /webContents\.on\('will-redirect', captureOAuthRedirect\)/);
  assert.match(flow, /if \(!navigationEvent\.isMainFrame\) return/);

  const failedLoad = flow.slice(
    flow.indexOf("webContents.on('did-fail-load'"),
    flow.indexOf("authWindow.once('closed'"),
  );
  const callbackFallback = failedLoad.indexOf('matchesOAuthRedirect(new URL(url))');
  const cancellationFallback = failedLoad.indexOf('nextCandidate(failure)');
  assert.ok(callbackFallback >= 0);
  assert.ok(cancellationFallback > callbackFallback);
});

test('Azure callback payloads preserve OAuth results within the backend byte limit', () => {
  const payload = encodeTunnelOAuthCallback(
    new URL(
      'http://localhost:2023/?code=auth-code&state=expected&error=denied&error_description=No',
    ),
  );
  assert.deepEqual(JSON.parse(payload ?? ''), {
    code: 'auth-code',
    state: 'expected',
    error: 'denied',
    description: 'No',
  });

  const oversized = new URL('http://localhost:2023/');
  oversized.searchParams.set('error_description', 'é'.repeat(tunnelPromptValueMaxBytes));
  assert.equal(encodeTunnelOAuthCallback(oversized), undefined);
});

test('VPN browser authentication isolates Fortinet attempts and provider profiles', () => {
  const first = tunnelAuthPartition({ completion: 'cookie' });
  const second = tunnelAuthPartition({ completion: 'cookie' });
  assert.match(first, /^wormhole-tunnel-auth-fortinet-/);
  assert.ok(!first.startsWith('persist:'));
  assert.notEqual(first, second);
  assert.equal(
    tunnelAuthPartition({ completion: 'oauth-code' }),
    'persist:wormhole-tunnel-auth-azure',
  );
  assert.equal(
    new Set([
      tunnelAuthPartition({ completion: 'cookie' }),
      tunnelAuthPartition({
        completion: 'query-token',
        origin: 'https://firebox.example.test',
        ignoreCertificateErrors: false,
      }),
      tunnelAuthPartition({ completion: 'oauth-code' }),
    ]).size,
    3,
  );
});

test('WatchGuard browser profiles isolate cached certificate decisions by origin and policy', () => {
  const verified = tunnelAuthPartition({
    completion: 'query-token',
    origin: 'https://firebox.example.test',
    ignoreCertificateErrors: false,
  });
  assert.equal(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://FIREBOX.example.test:443/ignored-path',
      ignoreCertificateErrors: false,
    }),
  );
  assert.notEqual(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://firebox.example.test',
      ignoreCertificateErrors: true,
    }),
  );
  assert.notEqual(
    verified,
    tunnelAuthPartition({
      completion: 'query-token',
      origin: 'https://other-firebox.example.test',
      ignoreCertificateErrors: false,
    }),
  );
});

test('WatchGuard delegates certificate verification except for its explicitly trusted gateway', async (t) => {
  for (const [origin, matching, other] of [
    [
      'https://firebox.example.test',
      ['FIREBOX.EXAMPLE.TEST', 'firebox.example.test.'],
      'firebox.example.test.evil',
    ],
    ['https://[2001:db8::1]', ['2001:db8::1', '[2001:DB8::1]'], '2001:db8::2'],
  ] as const) {
    for (const ignoreCertificateErrors of [false, true]) {
      const auth = browserAuthHarness(t, { urls: [origin], ignoreCertificateErrors });
      await setImmediate();
      for (const host of matching)
        assert.equal(auth.certificateResult(host), ignoreCertificateErrors ? 0 : -3);
      assert.equal(auth.certificateResult(other), -3);
      auth.window.destroy();
      await auth.finished;
    }
  }
});

test('consecutive Fortinet windows use distinct temporary profiles even for the same gateway', async (t) => {
  const auth = browserAuthHarness(t, {
    ...fortinetEvent,
    title: 'Fortinet SAML sign-in',
    urls: ['https://vpn.example.test/remote/saml/start'],
  });
  await setImmediate();
  assert.equal(auth.loads[0].url, 'https://vpn.example.test/remote/saml/start');
  auth.window.destroy();
  await auth.finished;
  const next = auth.enqueue({ promptId: 'second-account' });
  await setImmediate();
  assert.equal(auth.partitions.length, 2);
  assert.notEqual(auth.partitions[0], auth.partitions[1]);
  for (const partition of auth.partitions) {
    assert.match(partition, /^wormhole-tunnel-auth-fortinet-/);
    assert.ok(!partition.startsWith('persist:'));
  }
  assert.deepEqual(auth.windowPartitions, auth.partitions);
  auth.window.destroy();
  await next;
  assert.equal(auth.responses.length, 2);
  assert.ok(auth.responses.every((response) => response.cancelled));
});
