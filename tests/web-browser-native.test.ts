import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test, { before, after } from 'node:test';
import { Session as InspectorSession } from 'node:inspector/promises';
import vm from 'node:vm';
import { randomUUID } from 'node:crypto';
import {
  WebBrowserTabs,
  webBrowserTabLimit,
  resolveWebBrowserAddress,
  isAbortedWebNavigation,
  isWebBrowserRouteRequestAllowed,
  fetchWebBrowserFavicon,
  webBrowserFaviconUrlLimit,
} from '../electron/web-browser-tabs.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import { adjustWebZoom } from '../electron/web-zoom.ts';
import { TunnelLeaseRegistry } from '../electron/tunnel-lease-registry.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';
import { KeyedTaskTracker } from '../electron/keyed-task-tracker.ts';
import { ExtensionMutationGuard } from '../electron/extension-mutation-guard.ts';
import {
  buildBitwardenBrowserContext,
  buildBitwardenPersistentRouteKey,
  getBitwardenBrowserPartition,
} from '../electron/bitwarden-browser-profile.ts';
import { getInSessionNavigationUrl } from '../electron/web-new-window-navigation.ts';
import {
  createBitwardenActiveTabContext,
  selectBitwardenTabRegistrationPartition,
} from '../electron/bitwarden-active-tab-bridge.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

let profiler: InspectorSession | undefined;
before(async () => {
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE)
    return;
  profiler = new InspectorSession();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
});
after(async () => {
  if (!profiler) return;
  try {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    const methods = new Set([
      'open',
      'setBounds',
      'capturePreview',
      'command',
      'browserNavigationUrl',
      'addBrowserTab',
      'showBrowserTab',
      'destroyBrowserTab',
      'backendStopped',
      'configureWebContents',
      'failBrowserTab',
      'sendEvent',
      'openExtensionTabInSession',
      'ensureChromeExtensionApis',
      'retireBitwardenProfile',
      'isBitwardenProfileUnused',
      'describeWebNavigationError',
      'describeWebLoadFailure',
    ]);
    const blocks = new Map<string, number>();
    const previewBlocks = new Map<string, number>();
    const errorBlocks = new Map<string, number>();
    for (const script of coverage.result.filter((item) =>
      ['wormhole-web-browser-native.js', 'wormhole-web-browser-errors.js'].includes(item.url),
    )) {
      const scopes = script.functions
        .filter((fn) => methods.has(fn.functionName))
        .map((fn) => fn.ranges[0]);
      const previewScopes = script.functions
        .filter((fn) => ['setBounds', 'capturePreview'].includes(fn.functionName))
        .map((fn) => fn.ranges[0]);
      for (const fn of script.functions) {
        if (
          !scopes.some(
            (scope) =>
              fn.ranges[0].startOffset >= scope.startOffset &&
              fn.ranges[0].endOffset <= scope.endOffset,
          )
        )
          continue;
        for (const range of fn.ranges) {
          const key = `${script.url}:${range.startOffset}:${range.endOffset}`;
          blocks.set(key, (blocks.get(key) ?? 0) + range.count);
          if (script.url === 'wormhole-web-browser-errors.js')
            errorBlocks.set(key, (errorBlocks.get(key) ?? 0) + range.count);
          if (
            previewScopes.some(
              (scope) =>
                range.startOffset >= scope.startOffset && range.endOffset <= scope.endOffset,
            )
          ) {
            previewBlocks.set(key, (previewBlocks.get(key) ?? 0) + range.count);
          }
        }
      }
    }
    assert.ok(blocks.size > 0);
    const percent = (100 * [...blocks.values()].filter((value) => value > 0).length) / blocks.size;
    console.log(`Native browser handlers: V8 block coverage ${percent.toFixed(2)}%`);
    assert.ok(
      percent >= coverageThreshold,
      `Native browser coverage is below ${coverageThreshold}%`,
    );
    const previewPercent =
      (100 * [...previewBlocks.values()].filter((value) => value > 0).length) / previewBlocks.size;
    console.log(`Native overlay preview: V8 block coverage ${previewPercent.toFixed(2)}%`);
    assert.ok(
      previewPercent >= coverageThreshold,
      `Overlay preview coverage is below ${coverageThreshold}%`,
    );
    const errorPercent =
      (100 * [...errorBlocks.values()].filter((value) => value > 0).length) / errorBlocks.size;
    console.log(`Native navigation errors: V8 block coverage ${errorPercent.toFixed(2)}%`);
    assert.ok(
      errorPercent >= coverageThreshold,
      `Navigation error coverage is below ${coverageThreshold}%`,
    );
    await profiler.post('Profiler.stopPreciseCoverage');
  } finally {
    profiler.disconnect();
  }
});

// Run the production native controller, replacing only Electron and the Go transport.
// Real React/Chromium interaction is covered separately in web-browser.test.ts.
function browserHarness({ socks = '127.0.0.1:1080', active = true } = {}) {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('class WebSurfaceManager');
  const end = source.indexOf('function clampWindowDimension', start);
  const code = stripTypeScriptTypes(
    `${source.slice(start, end).replace("const { ElectronChromeExtensions } = await import('electron-chrome-extensions');", 'const { ElectronChromeExtensions } = globalThis;')}; globalThis.Manager = WebSurfaceManager;`,
    { mode: 'transform' },
  );
  const sessions = new Map<string, Record<string, unknown>>();
  const releases: string[] = [],
    acquisitions: unknown[] = [],
    events: any[] = [],
    menus: any[] = [],
    copiedLinks: string[] = [];
  const authSession = { authorizationEpoch: 1, isAccessAllowed: true };
  const fromPartition = (partition: string) => {
    if (!sessions.has(partition))
      sessions.set(partition, {
        setProxy: async (proxy: unknown) => {
          sessions.get(partition)!.proxy = proxy;
        },
        setPermissionRequestHandler() {},
        setPermissionCheckHandler() {},
        fetch: async () => new Response(null, { status: 404 }),
        webRequest: {
          onBeforeRequest(handler: unknown) {
            sessions.get(partition)!.requestFilter = handler;
          },
        },
      });
    return sessions.get(partition)!;
  };
  class Contents extends EventEmitter {
    url = '';
    title = '';
    destroyed = false;
    loading = false;
    back = false;
    forward = false;
    reloads = 0;
    zoomFactor = 1;
    policy = '';
    editing: string[] = [];
    opens: (details: { url: string }) => any;
    session: Record<string, unknown>;
    navigationHistory = {
      canGoBack: () => this.back,
      canGoForward: () => this.forward,
      goBack: () => {
        this.back = false;
      },
      goForward: () => {
        this.forward = false;
      },
    };
    constructor(partition = '') {
      super();
      this.session = fromPartition(partition);
    }
    setWindowOpenHandler(handler: Contents['opens']) {
      this.opens = handler;
    }
    setWebRTCIPHandlingPolicy(policy: string) {
      this.policy = policy;
    }
    isDestroyed() {
      return this.destroyed;
    }
    isLoading() {
      return this.loading;
    }
    getURL() {
      return this.url;
    }
    getTitle() {
      return this.title;
    }
    focus() {}
    undo() {
      this.editing.push('undo');
    }
    redo() {
      this.editing.push('redo');
    }
    cut() {
      this.editing.push('cut');
    }
    copy() {
      this.editing.push('copy');
    }
    paste() {
      this.editing.push('paste');
    }
    selectAll() {
      this.editing.push('select-all');
    }
    getZoomFactor() {
      return this.zoomFactor;
    }
    setZoomFactor(factor: number) {
      this.zoomFactor = factor;
    }
    async loadURL(url: string) {
      this.loading = true;
      this.emit('did-start-loading');
      this.url = url;
      this.title = url === 'about:blank' ? '' : new URL(url).hostname;
      this.loading = false;
      this.emit('did-navigate');
      this.emit('did-finish-load');
      this.emit('did-stop-loading');
    }
    reload() {
      this.reloads++;
      this.emit('did-start-loading');
    }
    stop() {
      this.loading = false;
    }
    close() {
      this.destroyed = true;
      this.emit('destroyed');
    }
    send(_channel: string, event: unknown) {
      events.push(event);
    }
  }
  class View {
    webContents: Contents;
    visible = false;
    visibilityChanges: boolean[] = [];
    boundsChanges: unknown[] = [];
    bounds: unknown;
    constructor(options: any) {
      this.webContents = options.webContents ?? new Contents(options.webPreferences.partition);
    }
    setBounds(bounds: unknown) {
      this.bounds = bounds;
      this.boundsChanges.push(bounds);
    }
    getBounds() {
      return this.bounds ?? { x: 0, y: 0, width: 1, height: 1 };
    }
    setVisible(value: boolean) {
      this.visible = value;
      this.visibilityChanges.push(value);
    }
    getVisible() {
      return this.visible;
    }
  }
  const children = new Set<View>();
  const owner = Object.assign(new EventEmitter(), {
    id: 1,
    isDestroyed: () => false,
    webContents: new Contents(),
    contentView: {
      addChildView: (view: View) => children.add(view),
      removeChildView: (view: View) => children.delete(view),
    },
  });
  const backend = {
    acquireTunnelRoute: async (request: unknown) => {
      acquisitions.push(request);
      return { active, socksEndpoint: socks };
    },
    bindTunnelForwarder: async () => ({ host: '127.0.0.1', port: 53001 }),
  };
  const sandbox = {
    WebBrowserTabs,
    webBrowserTabLimit,
    WebSessionAttemptTracker,
    TunnelLeaseRegistry,
    KeyedSingleFlight,
    KeyedTaskTracker,
    ExtensionMutationGuard,
    getInSessionNavigationUrl,
    createBitwardenActiveTabContext,
    selectBitwardenTabRegistrationPartition,
    resolveWebBrowserAddress,
    isAbortedWebNavigation,
    isWebBrowserRouteRequestAllowed,
    fetchWebBrowserFavicon,
    webBrowserFaviconUrlLimit,
    AbortController,
    clipboard: { writeText: (text: string) => copiedLinks.push(text) },
    Menu: class {
      items: any[];
      static buildFromTemplate(items: any[]) {
        const menu = new this();
        menu.items = items;
        return menu;
      }
      append(item: any) {
        this.items.push(item);
      }
      popup() {
        menus.push(this);
      }
    },
    adjustWebZoom,
    buildBitwardenBrowserContext,
    buildBitwardenPersistentRouteKey,
    getBitwardenBrowserPartition,
    randomUUID,
    URL,
    console,
    setTimeout,
    clearTimeout,
    clearInterval,
    WebContentsView: View,
    authSession,
    isAuthorizationEpochCurrent: (epoch: number) =>
      authSession.isAccessAllowed && authSession.authorizationEpoch === epoch,
    electronSession: { fromPartition },
    electronNet: {
      request: (options: any) => {
        const request: any = new EventEmitter();
        const controller = new AbortController();
        request.abort = () => {
          if (!controller.signal.aborted) {
            controller.abort();
            request.emit('abort');
            request.emit('close');
          }
        };
        request.end = async () => {
          try {
            const response = await options.session.fetch(options.url, {
              signal: controller.signal,
              credentials:
                options.credentials === 'same-origin'
                  ? new URL(options.url).origin === options.origin
                    ? 'include'
                    : 'omit'
                  : options.credentials,
              redirect: options.redirect,
            });
            if (controller.signal.aborted) return;
            const incoming: any = Object.assign(new EventEmitter(), {
              statusCode: response.status,
              headers: Object.fromEntries([...response.headers]),
            });
            request.emit('response', incoming);
            if (controller.signal.aborted) return;
            const data = new Uint8Array(await response.arrayBuffer());
            if (controller.signal.aborted) return;
            incoming.emit('data', data);
            incoming.emit('end');
            request.emit('close');
          } catch (error) {
            request.emit('error', error);
          }
        };
        return request;
      },
    },
    validateWebTarget: (value: unknown) => value,
    runBackend: async (action: string, request: any) =>
      action === 'extension-read'
        ? { enabled: false }
        : {
            url: request.nodeId ? 'https://saved.internal/' : request.address,
            host: new URL(request.nodeId ? 'https://saved.internal/' : request.address).hostname,
            port: 443,
            protocol: 'https',
            ignoreCertErrors: request.ignoreCertErrors ?? false,
            tunnelConfigId: request.nodeId ? 'vpn-saved' : request.tunnelConfigId,
          },
    getNativeBackend: () => backend,
    releaseNativeTunnelLease: async (lease: string) => {
      releases.push(lease);
    },
    afterBitwardenPopupInputEvent: async (operation: () => Promise<void>) => operation(),
    describeWebNavigationError: () => 'Navigation failed',
    describeWebLoadFailure: () => 'Target unavailable',
    webMaxUrlLength: 4096,
    bitwardenExtensionHostMaxListeners: 100,
    isQuitting: false,
    ElectronChromeExtensions: class {
      options: any;
      constructor(options: any) {
        this.options = options;
      }
      addTab() {}
      removeTab(contents: unknown) {
        this.options.removeTab(contents);
      }
      selectTab() {}
    },
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(code, context, { filename: 'wormhole-web-browser-native.js' });
  const manager = new (context as any).Manager();
  const open = (
    sessionId = 'browser-1',
    tunnelConfigId: string | undefined = 'vpn-1',
    extra = {},
  ) =>
    manager.open(owner, {
      sessionId,
      attempt: 1,
      protocol: 'https',
      address: 'https://router.internal/',
      tunnelConfigId,
      ...extra,
    });
  const command = (operation: string, extra = {}, sessionId = 'browser-1') =>
    manager.command(owner, { sessionId, operation, ...extra });
  return {
    manager,
    open,
    command,
    owner,
    sessions,
    acquisitions,
    releases,
    events,
    children,
    authSession,
    backend,
    sandbox,
    menus,
    copiedLinks,
  };
}

test('browser favicons use the owning session, reject route escapes and cancel stale work', async () => {
  const h = browserHarness({ socks: '' });
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const contents = record.view.webContents;
  const requests: any[] = [];
  contents.session.fetch = async (url: string, options: RequestInit) => {
    requests.push({ url, ...options });
    return new Response(new Uint8Array([1, 2, 3]), { headers: { 'content-type': 'image/png' } });
  };
  const icon = (urls: string[]) => contents.emit('page-favicon-updated', {}, urls);
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  icon(['https://outside.internal/icon.png', 'https://router.internal/icon.png']);
  await settle();
  assert.equal(requests[0].url, 'https://127.0.0.1:53001/icon.png');
  assert.equal(requests[0].credentials, 'include');
  assert.equal(record.tabs.snapshot('vpn').tabs[0].favicon, 'data:image/png;base64,AQID');
  icon(['https://router.internal/icon.png']);
  await settle();
  assert.equal(requests.length, 1, 'duplicate favicon events share the loaded icon');
  contents.session.fetch = () => {
    throw new Error('Session unavailable');
  };
  assert.doesNotThrow(() => icon(['https://router.internal/unavailable.png']));
  await settle();
  assert.equal(record.disposed, false, 'optional icon failures must not close the browser');
  let finish!: (response: Response) => void;
  contents.session.fetch = (url: string, options: RequestInit) => {
    requests.push({ url, ...options });
    return new Promise<Response>((resolve) => {
      finish = resolve;
    });
  };
  icon(['https://router.internal/old.png']);
  await h.command('navigate', { url: 'https://router.internal/new-page' });
  assert.equal(requests.at(-1).signal.aborted, true);
  finish(new Response('old', { headers: { 'content-type': 'image/png' } }));
  await settle();
  assert.equal(record.tabs.snapshot('vpn').tabs[0].favicon, undefined);
  icon(['data:image/png;base64,AQID']);
  assert.equal(requests.at(-1).url, 'data:image/png;base64,AQID');
  const finishing = finish;
  h.manager.close('browser-1');
  assert.equal(requests.at(-1).signal.aborted, true);
  finishing(new Response(null));
  await settle();
});

test('favicon credentials stay on their page origin rather than following arbitrary icon hosts', async () => {
  const h = browserHarness();
  await h.open('direct', undefined, { tunnelConfigId: undefined });
  const contents = h.manager.surfaces.get('direct').view.webContents;
  const requests: any[] = [];
  contents.session.fetch = async (url: string, options: RequestInit) => {
    requests.push({ url, ...options });
    return new Response(new Uint8Array([1]), { headers: { 'content-type': 'image/png' } });
  };
  for (const [url, credentials] of [
    ['https://other.internal/favicon.png', 'omit'],
    ['https://router.internal/favicon.png', 'include'],
    ['http://router.internal/favicon.png', 'omit'],
  ] as const) {
    contents.emit('page-favicon-updated', {}, [url]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(requests.at(-1).credentials, credentials);
  }
  h.manager.close('direct');
});

test('right-click provides browser editing, navigation, routed links and optional Bitwarden items', async () => {
  const h = browserHarness({ socks: '' });
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const contents = record.view.webContents;
  const flags = {
    canUndo: true,
    canRedo: true,
    canCut: true,
    canCopy: true,
    canPaste: true,
    canSelectAll: true,
  };
  const context = (details = {}) =>
    contents.emit(
      'context-menu',
      {},
      {
        isEditable: false,
        selectionText: '',
        linkURL: '',
        editFlags: flags,
        ...details,
      },
    );
  const click = async (label: string) => {
    const item = h.menus.at(-1).items.find((entry: any) => entry.label === label);
    assert.ok(item, label);
    item.click();
    await new Promise((resolve) => setImmediate(resolve));
  };
  context();
  assert.ok(h.menus.at(-1).items.some((item: any) => item.label === 'Reload'));
  assert.equal(h.menus.at(-1).items.find((item: any) => item.label === 'Back').enabled, false);
  context({ isEditable: true });
  for (const label of ['Undo', 'Redo', 'Cut', 'Copy', 'Paste', 'Select all']) await click(label);
  assert.deepEqual(contents.editing, ['undo', 'redo', 'cut', 'copy', 'paste', 'select-all']);
  context({ selectionText: 'Selected' });
  await click('Copy');
  await click('Reload');
  assert.equal(contents.reloads, 1);
  context({ linkURL: 'https://127.0.0.1:53001/help' });
  await click('Copy link address');
  assert.equal(h.copiedLinks[0], 'https://router.internal/help');
  const open = h.menus.at(-1).items.find((item: any) => item.label === 'Open link in new tab');
  open.click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(record.tabs.size, 2);
  await click('Reload');
  assert.equal(contents.reloads, 1, 'a menu opened in another tab cannot execute commands');
  record.tabs.select(record.tabs.snapshot('vpn').tabs[0].id);
  context({ linkURL: 'https://outside.internal/' });
  assert.equal(
    h.menus.at(-1).items.find((item: any) => item.label === 'Open link in new tab').enabled,
    false,
  );
  record.bitwarden = { partition: record.partition };
  const extensionItem = { label: 'Bitwarden' };
  h.manager.chromeExtensionApis.set(record.partition, {
    getContextMenuItems: () => [extensionItem],
    removeTab() {},
  });
  context();
  assert.equal(h.menus.at(-1).items.at(-1), extensionItem);
  h.manager.chromeExtensionApis.set(record.partition, {
    getContextMenuItems() {
      throw new Error('Closed');
    },
    removeTab() {},
  });
  context();
  assert.ok(h.menus.at(-1).items.some((item: any) => item.label === 'Reload'));
  const count = h.menus.length;
  h.authSession.isAccessAllowed = false;
  context();
  assert.equal(h.menus.length, count);
  await click('Reload');
  assert.equal(contents.reloads, 1);
  h.authSession.isAccessAllowed = true;
  h.manager.synchronizeBitwardenStorageInBridge = async () => {};
  h.manager.close('browser-1');
});

test('bounds validation accepts only explicit, hidden preview requests with bounded geometry', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('function isWebBoundsRequest(');
  const end = source.indexOf('function isWebCommandRequest(', start);
  const validate = vm.runInNewContext(stripTypeScriptTypes(`(${source.slice(start, end)})`), {
    isRecord: (value: unknown) => value !== null && typeof value === 'object',
    isSshSessionId: (value: unknown) => typeof value === 'string' && value.length > 0,
    isUuid: vm.runInNewContext(
      stripTypeScriptTypes(
        `(${source.slice(source.indexOf('function isUuid('), source.indexOf('const webMaxUrlLength'))})`,
      ),
    ),
    webMaxSurfaceCoordinate: 100_000,
  });
  const request = { sessionId: 'browser', x: 0, y: 40, width: 900, height: 600, visible: false };
  for (const capturePreview of [undefined, false])
    assert.equal(validate({ ...request, capturePreview }), true);
  const previewId = randomUUID();
  assert.equal(validate({ ...request, capturePreview: true, previewId }), true);
  assert.equal(validate({ ...request, previewId }), true);
  assert.equal(validate({ ...request, visible: true }), true);
  for (const value of [
    null,
    { ...request, visible: 'false' },
    { ...request, capturePreview: 1 },
    { ...request, capturePreview: 'true' },
    { ...request, capturePreview: true },
    { ...request, previewId: true },
    { ...request, previewId: '' },
    { ...request, previewId: 'unbounded'.repeat(1000) },
    { ...request, previewId, visible: true },
    { ...request, capturePreview: true, visible: true },
    { ...request, width: 100_001 },
    { ...request, height: 0 },
    { ...request, x: NaN },
    { ...request, y: -1 },
  ])
    assert.equal(validate(value), false);
});

test('overlay previews retain the page and its VPN lease, coalesce captures and resume the same tab', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const view = record.view;
  const bounds = { sessionId: 'browser-1', x: 20, y: 80, width: 900, height: 600, visible: true };
  await h.manager.setBounds(h.owner, bounds);
  let captures = 0;
  view.webContents.capturePage = async (rect: unknown, options: unknown) => {
    captures++;
    assert.deepEqual(JSON.parse(JSON.stringify(rect)), { x: 0, y: 0, width: 900, height: 600 });
    assert.equal((options as any).stayHidden, true);
    return {
      isEmpty: () => false,
      getSize: () => ({ width: 900, height: 600 }),
      toJPEG: () => Buffer.from('page'),
    };
  };
  const request = { ...bounds, visible: false, capturePreview: true, previewId: randomUUID() };
  assert.equal(await h.manager.setBounds({}, request), undefined);
  const results = await Promise.all([
    h.manager.setBounds(h.owner, request),
    h.manager.setBounds(h.owner, { ...request, width: 850 }),
  ]);
  assert.deepEqual(results, ['data:image/jpeg;base64,cGFnZQ==', 'data:image/jpeg;base64,cGFnZQ==']);
  assert.equal(captures, 1);
  assert.equal(
    view.visible,
    true,
    'The page must remain visible while the renderer decodes and paints',
  );
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false });
  assert.equal(view.visible, false);
  assert.equal(h.releases.length, 0);
  await h.manager.setBounds(h.owner, bounds);
  assert.equal(record.preview, undefined);
  assert.equal(record.view, view);
  assert.equal(view.visible, true);
  assert.equal(view.webContents.getURL(), 'https://router.internal/');
  assert.equal(h.acquisitions.length, 1);
  h.manager.close('browser-1');
});

test('stable bounds and live resizes never hide and re-show the selected native view', async () => {
  const h = browserHarness();
  await h.open();
  const view = h.manager.surfaces.get('browser-1').view;
  const bounds = { sessionId: 'browser-1', x: 20, y: 80, width: 900, height: 600, visible: true };
  await h.manager.setBounds(h.owner, bounds);
  const toggles = view.visibilityChanges.length;
  const layouts = view.boundsChanges.length;
  for (let i = 0; i < 4; i++) await h.manager.setBounds(h.owner, { ...bounds, x: 20.1 });
  assert.equal(view.boundsChanges.length, layouts);
  assert.equal(view.visibilityChanges.length, toggles);
  await h.manager.setBounds(h.owner, { ...bounds, width: 800 });
  assert.equal(view.boundsChanges.length, layouts + 1);
  assert.equal(
    view.visibilityChanges.length,
    toggles,
    'Resizing must retain the live compositor surface',
  );
  h.manager.close('browser-1');
});

test('preview acknowledgements cannot hide a resumed page or a different overlay, tab or authorization', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const view = record.view;
  const bounds = { sessionId: 'browser-1', x: 0, y: 0, width: 900, height: 600, visible: true };
  await h.manager.setBounds(h.owner, bounds);
  view.webContents.capturePage = async () => ({
    isEmpty: () => false,
    getSize: () => ({ width: 10, height: 10 }),
    toJPEG: () => Buffer.from('page'),
  });
  const firstId = randomUUID(),
    secondId = randomUUID();
  const request = { ...bounds, visible: false, capturePreview: true, previewId: firstId };
  await h.manager.setBounds(h.owner, request);
  await h.manager.setBounds(h.owner, { ...request, previewId: secondId });
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false });
  assert.equal(
    view.visible,
    true,
    'An old menu acknowledgement must not hide the page for its replacement',
  );
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false, previewId: secondId });
  assert.equal(view.visible, false);
  await h.manager.setBounds(h.owner, bounds);
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false, previewId: secondId });
  assert.equal(view.visible, true, 'Closing the menu invalidates queued acknowledgements');
  await h.manager.setBounds(h.owner, request);
  record.preview.tabId = 'different-tab';
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false });
  assert.equal(view.visible, true);
  record.preview.tabId = record.tabs.activeId;
  h.authSession.authorizationEpoch++;
  await h.manager.setBounds(h.owner, { ...request, capturePreview: false });
  assert.equal(view.visible, true);
  h.manager.close('browser-1');
});

test('late overlay captures cannot reveal a locked, resumed, closed or replaced browser', async () => {
  for (const action of ['lock', 'reauthorize', 'resume', 'close', 'owner-closed', 'new-tab']) {
    const h = browserHarness();
    await h.open();
    const record = h.manager.surfaces.get('browser-1');
    const view = record.view;
    const bounds = { sessionId: 'browser-1', x: 0, y: 0, width: 900, height: 600, visible: true };
    await h.manager.setBounds(h.owner, bounds);
    let finish!: (image: any) => void;
    view.webContents.capturePage = () =>
      new Promise((resolve) => {
        finish = resolve;
      });
    const pending = h.manager.setBounds(h.owner, {
      ...bounds,
      visible: false,
      capturePreview: true,
      previewId: randomUUID(),
    });
    if (action === 'lock') {
      h.authSession.isAccessAllowed = false;
      h.authSession.authorizationEpoch++;
      h.manager.hideAll();
    } else if (action === 'reauthorize') {
      h.authSession.authorizationEpoch++;
    } else if (action === 'resume') {
      await h.manager.setBounds(h.owner, bounds);
    } else if (action === 'close') {
      h.manager.close('browser-1');
    } else if (action === 'owner-closed') {
      h.owner.isDestroyed = () => true;
    } else {
      await h.command('new-tab');
    }
    finish({
      isEmpty: () => false,
      getSize: () => ({ width: 10, height: 10 }),
      toJPEG: () => Buffer.from('page'),
    });
    assert.equal(await pending, undefined, action);
    if (action === 'resume') assert.equal(view.visible, true);
    if (action === 'lock') {
      assert.equal(view.visible, false);
      assert.equal(
        await h.manager.setBounds(h.owner, {
          ...bounds,
          visible: false,
          capturePreview: true,
          previewId: randomUUID(),
        }),
        undefined,
      );
    }
    h.owner.isDestroyed = () => false;
    h.manager.close('browser-1');
  }
});

test('overlay captures bound image dimensions and IPC payloads and tolerate empty or failed captures', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const view = record.view;
  await h.manager.setBounds(h.owner, {
    sessionId: 'browser-1',
    x: 0,
    y: 0,
    width: 9000,
    height: 6000,
    visible: true,
  });
  let resized: any;
  view.webContents.capturePage = async (rect: any) => {
    assert.equal(rect.width, 4096);
    assert.equal(rect.height, 4096);
    return {
      isEmpty: () => false,
      getSize: () => ({ width: 6000, height: 4000 }),
      resize: (options: any) => {
        resized = options;
        return { toJPEG: () => Buffer.from('bounded') };
      },
    };
  };
  assert.match(await h.manager.capturePreview(view), /^data:image\/jpeg;base64,/);
  assert.equal(resized.width, 2048);
  view.webContents.capturePage = async () => ({ isEmpty: () => true });
  assert.equal(await h.manager.capturePreview(view), undefined);
  view.webContents.capturePage = async () => ({
    isEmpty: () => false,
    getSize: () => ({ width: 10, height: 10 }),
    toJPEG: () => Buffer.alloc(4 * 1024 * 1024 + 1),
  });
  assert.equal(await h.manager.capturePreview(view), undefined);
  view.webContents.capturePage = async () => {
    throw new Error('Tab closed');
  };
  const result = await h.manager.setBounds(h.owner, {
    sessionId: 'browser-1',
    x: 0,
    y: 0,
    width: 900,
    height: 600,
    visible: false,
    capturePreview: true,
    previewId: randomUUID(),
  });
  assert.equal(result, undefined);
  assert.equal(view.visible, false, 'Capture failure must still leave the menu accessible');
  h.manager.close('browser-1');
});

test('each browser owns its profile and one VPN lease shared by all its tabs', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const firstTabId = record.tabs.activeId;
  const first = record.view;
  h.manager.setBounds(h.owner, {
    sessionId: 'browser-1',
    x: 10,
    y: 80,
    width: 900,
    height: 600,
    visible: true,
  });
  assert.equal(first.visible, true);
  await h.command('new-tab');
  const secondTabId = record.tabs.activeId;
  const second = record.view;
  assert.equal(first.visible, false);
  assert.equal(second.visible, true);
  assert.equal(second.webContents.getURL(), 'about:blank');
  assert.equal(record.tabs.snapshot('vpn').tabs[1].url, 'about:blank');
  assert.equal(first.webContents.session, second.webContents.session);
  assert.equal(second.webContents.policy, 'disable_non_proxied_udp');
  assert.equal(h.acquisitions.length, 1);
  assert.equal(
    (h.sessions.get(record.partition)!.proxy as any).proxyRules,
    'socks5://127.0.0.1:1080',
  );
  assert.equal((h.sessions.get(record.partition)!.proxy as any).proxyBypassRules, '<-loopback>');
  await h.command('navigate', { url: 'https://another.internal/admin' });
  assert.equal(second.webContents.getURL(), 'https://another.internal/admin');
  await h.command('select-tab', { tabId: firstTabId });
  assert.equal(record.view, first);
  await h.command('close-tab', { tabId: secondTabId });
  assert.equal(second.webContents.destroyed, true);
  assert.equal(first.webContents.destroyed, false);
  assert.equal(h.releases.length, 0);
  await h.command('close-tab', { tabId: firstTabId });
  assert.equal(record.tabs.size, 1);
  await h.open('browser-2');
  assert.notEqual(h.manager.surfaces.get('browser-2').partition, record.partition);
  h.manager.close('browser-1');
  await Promise.resolve();
  assert.equal(first.webContents.destroyed, true);
  assert.equal(h.releases.length, 1);
  h.manager.close('browser-2');
});

test('zoom commands target the selected tab and ignore a tab switch during popup dismissal', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const firstId = record.tabs.activeId;
  const first = record.view.webContents;
  await h.command('new-tab');
  const secondId = record.tabs.activeId;
  await h.command('navigate', { url: 'https://switch.internal/' });
  const second = record.view.webContents;
  await h.command('zoom-in');
  assert.equal(second.zoomFactor, 1.1);
  assert.equal(first.zoomFactor, 1);
  assert.equal(h.owner.webContents.zoomFactor, 1);
  await h.command('select-tab', { tabId: firstId });
  await h.command('zoom-out');
  assert.equal(first.zoomFactor, 0.9);
  assert.equal(second.zoomFactor, 1.1);

  let dismiss!: () => void;
  h.manager.bitwardenPopups.set('browser-1', {});
  h.manager.closeBitwardenPopup = () =>
    new Promise<void>((resolve) => {
      dismiss = resolve;
    });
  const pending = h.command('zoom-in');
  record.tabs.select(secondId);
  dismiss();
  await pending;
  assert.equal(first.zoomFactor, 0.9);
  assert.equal(second.zoomFactor, 1.1, 'a delayed zoom cannot target a newly selected tab');
  h.manager.bitwardenPopups.clear();
  h.manager.close('browser-1');
});

test('Bitwarden-enabled browser opens keep appliance cookie seed identities isolated', async () => {
  const h = browserHarness();
  const runBackend = h.sandbox.runBackend;
  h.sandbox.runBackend = async (action: string, request: any) =>
    action === 'extension-read'
      ? {
          enabled: true,
          installed: { path: '/extension', version: '1', defaultPopup: 'popup.html' },
        }
      : runBackend(action, request);
  const seeds: any[] = [];
  h.manager.loadBitwardenExtension = async (
    _partition: string,
    _path: string,
    _key: string,
    _popup: string,
    seed: unknown,
  ) => {
    seeds.push(seed);
    return { id: 'test', defaultPopup: 'popup.html' };
  };
  h.manager.synchronizeBitwardenStorageInBridge = async () => {};
  await h.open('browser-one');
  await h.open('browser-two');
  assert.equal(seeds.length, 2);
  assert.notEqual(seeds[0].routeKey, seeds[1].routeKey);
  assert.notEqual(
    h.manager.surfaces.get('browser-one').partition,
    h.manager.surfaces.get('browser-two').partition,
  );
  h.manager.closeForWindow(h.owner);
  assert.equal(h.manager.bitwardenExtensionMutation.canAutoMutate, true);
});

test('native popup links create sibling tabs and preserve opener support', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const original = record.view;
  const result = original.webContents.opens({ url: 'https://docs.internal/' });
  assert.equal(result.action, 'allow');
  assert.equal(result.outlivesOpener, true);
  const popup = result.createWindow({ webPreferences: { nodeIntegration: true, sandbox: false } });
  assert.equal(record.tabs.size, 2);
  assert.equal(popup, record.view.webContents);
  assert.equal(original.webContents.getURL(), 'https://router.internal/');
  assert.equal(original.webContents.opens({ url: 'file:///private' }).action, 'deny');
  const blank = popup.opens({ url: 'about:blank' });
  assert.equal(blank.action, 'allow');
  blank.createWindow({});
  const guest = new original.webContents.constructor(record.partition);
  const guestWindow = original.webContents.opens({ url: 'https://auth.internal/' });
  assert.equal(
    guestWindow.createWindow({ webContents: guest }),
    guest,
    'adopt the guest supplied by Chromium so window.open can return',
  );
  assert.equal(guest.getURL(), '', 'Chromium owns initial navigation of its supplied guest');
  h.authSession.isAccessAllowed = false;
  assert.equal(popup.opens({ url: 'https://docs.internal/' }).action, 'deny');
  h.manager.close('browser-1');
});

test('page failures, aborted loads and tab crashes keep the browser route alive', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const first = record.view;
  first.webContents.emit('did-fail-load', {}, -3, 'aborted', '', true);
  first.webContents.emit('did-fail-load', {}, -105, 'subframe', '', false);
  assert.equal(record.tabs.snapshot('vpn').tabs[0].error, undefined);
  first.webContents.emit('did-fail-load', {}, -105, 'unreachable', '', true);
  first.webContents.emit('did-finish-load');
  assert.equal(record.tabs.snapshot('vpn').tabs[0].error, 'Target unavailable');
  await h.command('reload');
  assert.equal(first.webContents.reloads, 1);
  assert.equal(record.tabs.snapshot('vpn').tabs[0].error, undefined);
  first.webContents.emit('render-process-gone');
  assert.match(record.tabs.snapshot('vpn').tabs[0].error, /stopped unexpectedly/);
  assert.equal(h.releases.length, 0);
  await h.command('new-tab');
  first.webContents.close();
  assert.equal(record.tabs.size, 1);
  assert.equal(h.manager.surfaces.has('browser-1'), true);
  h.manager.backendStopped();
  assert.equal(h.manager.surfaces.size, 0);
  assert.equal(h.children.size, 0);
  assert.ok(h.events.some((event) => event.type === 'failed' && /VPN/.test(event.error)));
});

test('forwarder tabs rewrite their host and deny cross-host navigation and subresources', async () => {
  const h = browserHarness({ socks: '' });
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  await h.command('new-tab');
  await h.command('navigate', { url: 'https://router.internal/settings' });
  assert.equal(record.view.webContents.getURL(), 'https://127.0.0.1:53001/settings');
  assert.equal(record.tabs.snapshot('vpn').tabs[1].url, 'https://router.internal/settings');
  await assert.rejects(h.command('navigate', { url: 'https://other.internal/' }), /VPN route/);
  const filter = h.sessions.get(record.partition)!.requestFilter as any;
  filter({ url: 'https://other.internal/script.js' }, ({ cancel }: any) =>
    assert.equal(cancel, true),
  );
  filter({ url: 'https://127.0.0.1:53001/script.js' }, ({ cancel }: any) =>
    assert.equal(cancel, false),
  );
  filter({ url: 'wss://127.0.0.1:53001/live' }, ({ cancel }: any) => assert.equal(cancel, false));
  filter({ url: 'wss://outside.internal/live' }, ({ cancel }: any) => assert.equal(cancel, true));
  h.manager.close('browser-1');
});

test('pending commands cannot navigate a replacement browser or a newly selected tab', async () => {
  for (const change of ['replace', 'select']) {
    const h = browserHarness();
    await h.open();
    const source = h.manager.surfaces.get('browser-1');
    let finish!: () => void;
    const closed = new Promise<void>((resolve) => {
      finish = resolve;
    });
    h.manager.bitwardenPopups.set('browser-1', {});
    h.manager.closeBitwardenPopup = async () => {
      await closed;
      h.manager.bitwardenPopups.delete('browser-1');
    };
    const pending = h.command('navigate', { url: 'https://unintended.internal/' });
    if (change === 'replace') await h.open();
    else h.manager.addBrowserTab('browser-1', source, 'about:blank');
    const current = h.manager.surfaces.get('browser-1');
    const expected = current.view.webContents.getURL();
    finish();
    await pending;
    assert.equal(current.view.webContents.getURL(), expected, change);
    h.manager.close('browser-1');
  }
});

test('native tab changes invalidate and dismiss the previous Bitwarden popup', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const popup = { setVisible() {} };
  h.manager.bitwardenPopups.set('browser-1', popup);
  h.manager.bitwardenPopupRequest = { sessionId: 'browser-1' };
  let closes = 0;
  h.manager.closeBitwardenPopup = async () => {
    closes++;
    h.manager.bitwardenPopups.delete('browser-1');
  };
  h.manager.addBrowserTab('browser-1', record, 'about:blank');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(closes, 1);
  assert.equal(h.manager.bitwardenPopupRequest, undefined);
  assert.equal(h.manager.bitwardenPopups.size, 0);
  h.manager.close('browser-1');
});

test('tab setup failures roll back their native view and preserve the active browser', async () => {
  for (const phase of ['attach', 'extension']) {
    const h = browserHarness();
    await h.open();
    const record = h.manager.surfaces.get('browser-1');
    const original = record.view;
    let allocated: any;
    const attach = h.owner.contentView.addChildView;
    h.owner.contentView.addChildView = (view) => {
      allocated = view;
      if (phase === 'attach') throw new Error('Owner is closing');
      return attach(view);
    };
    if (phase === 'extension') {
      record.bitwarden = {
        partition: record.partition,
        popupUrl: 'chrome-extension://test/popup.html',
      };
      h.manager.chromeExtensionApis.set(record.partition, {
        addTab() {
          throw new Error('Extension bridge unavailable');
        },
        removeTab() {},
      });
      h.manager.synchronizeBitwardenStorageInBridge = async () => {};
    }
    await assert.rejects(h.command('new-tab'), /Owner is closing|Extension bridge unavailable/);
    assert.equal(record.tabs.size, 1, phase);
    assert.equal(record.view, original);
    assert.equal(allocated.webContents.destroyed, true);
    assert.equal(h.children.size, 1);
    assert.equal(h.releases.length, 0);
    h.manager.close('browser-1');
  }
});

test('native shortcuts, hidden surfaces, owner isolation, and direct browsers stay independent', async () => {
  const h = browserHarness();
  await h.open('browser-1', undefined);
  // Explicit direct route, without the helper's default tunnel argument.
  await h.manager.open(h.owner, {
    sessionId: 'direct',
    attempt: 1,
    address: 'https://direct.internal/',
    protocol: 'https',
  });
  const record = h.manager.surfaces.get('direct');
  assert.equal(record.route, 'direct');
  assert.equal(h.sessions.get(record.partition)!.proxy, undefined);
  const initialTabId = record.tabs.activeId;
  record.view.webContents.back = true;
  record.view.webContents.forward = true;
  await h.command('back', {}, 'direct');
  await h.command('forward', {}, 'direct');
  await h.command('stop', {}, 'direct');
  assert.equal(record.view.webContents.back, false);
  assert.equal(record.view.webContents.forward, false);
  await h.manager.command({}, { sessionId: 'direct', operation: 'new-tab' });
  assert.equal(record.tabs.size, 1);
  const key = async (value: string, shift = false) => {
    let prevented = false;
    record.view.webContents.emit(
      'before-input-event',
      {
        preventDefault: () => {
          prevented = true;
        },
      },
      { type: 'keyDown', control: true, key: value, shift },
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(prevented, true);
  };
  await key('t');
  assert.equal(record.tabs.size, 2);
  await key('l');
  assert.ok(h.events.some((event) => event.type === 'focus-address'));
  await key('Tab');
  assert.equal(record.tabs.activeId, initialTabId);
  await key('Tab', true);
  await key('w');
  assert.equal(record.tabs.size, 1);
  h.manager.setBounds(h.owner, {
    sessionId: 'direct',
    x: 0,
    y: 0,
    width: 100,
    height: 100,
    visible: true,
  });
  h.manager.hideAll();
  assert.equal(record.view.visible, false);
  h.manager.backendStopped();
  assert.equal(h.manager.surfaces.has('direct'), true);
  h.manager.closeForWindow(h.owner);
  assert.equal(h.manager.surfaces.size, 0);
});

test('Bitwarden creates, selects and closes real browser tabs without replacing the appliance', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  const api = await h.manager.ensureChromeExtensionApis(record.partition);
  record.bitwarden = {
    partition: record.partition,
    popupUrl: 'chrome-extension://test/popup.html',
  };
  record.bitwardenTabRegistered = true;
  h.manager.activeBitwardenSessions.set(record.partition, 'browser-1');
  h.manager.synchronizeBitwardenStorageInBridge = async () => {};
  const original = record.view;
  const [created, owner] = await h.manager.openExtensionTabInSession(record.partition, {
    url: 'https://vault.internal/',
  });
  assert.equal(owner, h.owner);
  assert.notEqual(created, original.webContents);
  assert.equal(original.webContents.getURL(), 'https://router.internal/');
  api.options.selectTab(original.webContents);
  assert.equal(record.view, original);
  const details: any = {};
  api.options.assignTabDetails(details, created);
  assert.equal(details.url, 'https://vault.internal/');
  api.options.removeTab(created);
  assert.equal(record.tabs.size, 1);
  api.options.removeTab(original.webContents);
  assert.equal(record.tabs.size, 1);
  assert.equal(record.view.webContents.getURL(), 'about:blank');
  await assert.rejects(
    h.manager.openExtensionTabInSession(record.partition, { url: 'file:///private' }),
    /cannot be opened/,
  );
  h.authSession.isAccessAllowed = false;
  await assert.rejects(
    h.manager.openExtensionTabInSession(record.partition, { url: 'https://vault.internal/' }),
    /Authentication/,
  );
  h.manager.close('browser-1');
});

test('closed dedicated Bitwarden profiles unload only after storage is saved and stay safe during reopen', async () => {
  for (const scenario of [
    'closed',
    'reopening',
    'reopened-during-save',
    'loading',
    'active',
    'save-failed',
    'background-closed',
    'background-gone',
  ]) {
    const h = browserHarness();
    await h.open();
    const record = h.manager.surfaces.get('browser-1');
    record.bitwarden = {
      partition: record.partition,
      popupUrl: 'chrome-extension://test/popup.html',
    };
    h.manager.extensionIds.set(record.partition, 'test');
    h.manager.extensionLoadKeys.set(record.partition, 'version');
    h.manager.extensionPopupPaths.set(record.partition, 'popup.html');
    const removals: string[] = [];
    h.sessions.get(record.partition)!.extensions = {
      removeExtension: (id: string) => removals.push(id),
    };
    let finishFlush!: () => void;
    const flush = new Promise<void>((resolve) => {
      finishFlush = resolve;
    });
    h.manager.synchronizeBitwardenStorageInBridge = () =>
      h.manager.bitwardenStorageTasks.run(record.partition, () => flush);
    h.manager.bitwardenBackgroundContents = () => (scenario === 'background-gone' ? undefined : {});
    h.manager.synchronizeBitwardenStorageCore = async () => {
      if (scenario === 'save-failed') throw new Error('Protected storage unavailable');
      if (scenario === 'reopened-during-save')
        h.manager.pendingOpenOwners.set('browser-1', h.owner);
      if (scenario === 'background-closed') return false;
      return true;
    };
    h.manager.close('browser-1');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(removals.length, 0);
    await h.manager.retireBitwardenProfile(record.partition);
    if (scenario === 'reopening') h.manager.pendingOpenOwners.set('browser-1', h.owner);
    if (scenario === 'loading') h.manager.extensionLoads.set(record.partition, Promise.resolve());
    if (scenario === 'active')
      h.manager.surfaces.set('replacement', { ...record, disposed: false });
    finishFlush();
    await new Promise((resolve) => setImmediate(resolve));
    const retired = scenario === 'closed' || scenario === 'background-gone';
    assert.equal(removals.length, retired ? 1 : 0);
    assert.equal(h.manager.extensionIds.has(record.partition), !retired);
    assert.equal(h.manager.extensionLoadKeys.has(record.partition), !retired);
    assert.equal(h.manager.extensionPopupPaths.has(record.partition), !retired);
    h.manager.pendingOpenOwners.clear();
    h.manager.extensionLoads.clear();
    h.manager.surfaces.clear();
    h.manager.synchronizeBitwardenStorageCore = async () => true;
    await h.manager.retireBitwardenProfile(record.partition);
    assert.equal(removals.length, 1, 'Unused profiles must be retryable without double unload');
  }
});

test('failed and cancelled acquisitions stay closed without disposing a replacement browser', async () => {
  const h = browserHarness();
  let resume!: (value: unknown) => void;
  const runBackend = h.sandbox.runBackend;
  let pending = true;
  h.sandbox.runBackend = async (action: string, request: any) => {
    const result = await runBackend(action, request);
    if (action === 'web-target' && pending) {
      pending = false;
      return new Promise((resolve) => {
        resume = () => resolve(result);
      });
    }
    return result;
  };
  const opening = h.open();
  const rejected = assert.rejects(opening, /superseded/);
  await new Promise((resolve) => setImmediate(resolve));
  await h.open();
  const replacement = h.manager.surfaces.get('browser-1');
  resume(undefined);
  await rejected;
  assert.equal(h.manager.surfaces.get('browser-1'), replacement);
  assert.equal(replacement.view.webContents.destroyed, false);
  h.manager.close('browser-1');
  const failed = browserHarness();
  failed.backend.acquireTunnelRoute = async () => {
    throw new Error('VPN unavailable');
  };
  await assert.rejects(failed.open(), /VPN unavailable/);
  assert.equal(failed.children.size, 0);
  assert.equal(failed.releases.length, 1);
});

test('a VPN browser cannot finish opening after its acquired lease disappears during setup', async () => {
  const h = browserHarness();
  const runBackend = h.sandbox.runBackend;
  let resume!: () => void;
  h.sandbox.runBackend = async (action: string, request: any) => {
    if (action === 'extension-read')
      return new Promise((resolve) => {
        resume = () => resolve({ enabled: false });
      });
    return runBackend(action, request);
  };
  const opening = h.open();
  const outcome = opening.then(
    () => 'connected',
    () => 'rejected',
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.acquisitions.length, 1);
  h.manager.backendStopped();
  resume();
  assert.equal(await outcome, 'rejected');
  assert.equal(h.children.size, 0);
  assert.equal(h.manager.surfaces.size, 0);
  assert.equal(
    h.events.some((event) => event.type === 'connected'),
    false,
  );
});

test('an explicit Direct route choice releases its unused lease and labels the browser accurately', async () => {
  const h = browserHarness({ active: false, socks: '' });
  const target = await h.open();
  const record = h.manager.surfaces.get('browser-1');
  assert.equal(target.browser.route, 'direct');
  assert.equal(record.tunnelLeaseId, undefined);
  assert.equal(h.manager.tunnelLeases.has('browser-1'), false);
  assert.equal(h.releases.length, 1);
  assert.equal(h.sessions.get(record.partition)!.proxy, undefined);
  h.manager.close('browser-1');
});

test('cancelled native shortcuts cannot focus a replacement tab after a delayed popup flush', async () => {
  const h = browserHarness();
  await h.open();
  const record = h.manager.surfaces.get('browser-1');
  let focusCalls = 0;
  h.owner.webContents.focus = () => {
    focusCalls++;
  };
  let resume!: () => void;
  const flush = new Promise<void>((resolve) => {
    resume = resolve;
  });
  h.manager.bitwardenPopups.set('browser-1', { setVisible() {} });
  h.manager.closeBitwardenPopup = async () => {
    await flush;
    h.manager.bitwardenPopups.delete('browser-1');
  };
  record.view.webContents.emit(
    'before-input-event',
    { preventDefault() {} },
    { type: 'keyDown', control: true, key: 't' },
  );
  await new Promise((resolve) => setImmediate(resolve));
  h.manager.addBrowserTab('browser-1', record, 'https://replacement.internal/');
  resume();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(record.tabs.size, 2);
  assert.equal(focusCalls, 0);
  assert.equal(
    h.events.some((event) => event.type === 'focus-address'),
    false,
  );
  h.manager.close('browser-1');
});

test('production navigation errors retain diagnostic codes without copying sensitive URL text', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const code = source.slice(
    source.indexOf('function describeWebNavigationError('),
    source.indexOf('const webSurfaces = new WebSurfaceManager();'),
  );
  const formatters = vm.runInNewContext(
    stripTypeScriptTypes(`${code}; ({ describeWebNavigationError, describeWebLoadFailure });`),
    { Error },
    { filename: 'wormhole-web-browser-errors.js' },
  );
  const format = formatters.describeWebNavigationError;
  const secret = 'synthetic-sensitive-value';
  assert.doesNotMatch(
    format(new Error(`ERR_FAILED (-2) loading https://example.test/?token=${secret}#${secret}`)),
    /synthetic-sensitive-value/,
  );
  for (const value of [
    undefined,
    null,
    'untrusted error text',
    {},
    { errno: NaN },
    { code: `ERR_FAILED\n${secret}` },
    { code: 'x'.repeat(1000) },
  ]) {
    assert.equal(format(value), 'The browser could not start the page.');
  }
  assert.match(format({ code: 'ERR_FAILED' }), /ERR_FAILED/);
  for (const [errno, expected] of [
    [-105, /resolved/],
    [-102, /unreachable/],
    [-118, /timed out/],
    [-101, /reset/],
    [-100, /reset/],
    ...[-200, -201, -202, -203, -204].map((value) => [value, /certificate/]),
    [-2, /ERR_FAILED/],
  ] as const) {
    assert.match(format({ errno, code: 'ERR_FAILED', message: secret }), expected);
  }
  assert.equal(formatters.describeWebLoadFailure(-2, secret), 'Navigation failed.');
  assert.equal(formatters.describeWebLoadFailure(-2, ''), 'Navigation failed.');
});

test('navigation restrictions, certificate scope, cancellations and tab limits fail closed', async () => {
  const h = browserHarness({ socks: '' });
  await h.open('browser-1', 'vpn-1', { ignoreCertErrors: true });
  const record = h.manager.surfaces.get('browser-1');
  const contents = record.view.webContents;
  const prevent = (url: string) => {
    let prevented = false;
    contents.emit(
      'will-navigate',
      {
        preventDefault: () => {
          prevented = true;
        },
      },
      url,
    );
    return prevented;
  };
  assert.equal(prevent('https://outside.internal/'), true);
  assert.equal(prevent('https://router.internal/admin'), true);
  assert.equal(contents.getURL(), 'https://127.0.0.1:53001/admin');
  assert.equal(prevent('https://127.0.0.1:53001/'), false);
  contents.emit('page-title-updated');
  contents.emit('did-navigate-in-page');
  for (const [url, allowed] of [
    ['https://127.0.0.1:53001/', true],
    ['https://other.internal/', false],
  ] as const) {
    let accepted;
    contents.emit('certificate-error', { preventDefault() {} }, url, '', {}, (value: boolean) => {
      accepted = value;
    });
    assert.equal(accepted, allowed);
  }
  contents.loadURL = async () => {
    throw { code: 'ERR_ABORTED' };
  };
  await h.command('navigate', { url: 'https://router.internal/redirect' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(record.tabs.snapshot('vpn').tabs[0].error, undefined);
  contents.loadURL = async () => {
    throw new Error('Connection refused');
  };
  await h.command('navigate', { url: 'https://router.internal/failure' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(record.tabs.snapshot('vpn').tabs[0].error, 'Navigation failed');
  h.authSession.isAccessAllowed = false;
  assert.equal(prevent('https://127.0.0.1:53001/'), true);
  await h.command('new-tab');
  assert.equal(record.tabs.size, 1);
  h.authSession.isAccessAllowed = true;
  await h.command('select-tab', { tabId: 'missing' });
  await h.command('close-tab', { tabId: 'missing' });
  for (let index = 1; index < webBrowserTabLimit; index++) await h.command('new-tab');
  await assert.rejects(h.command('new-tab'), /cannot open another tab/);
  assert.equal(record.view.webContents.opens({ url: 'https://router.internal/' }).action, 'deny');
  h.manager.setBounds(
    {},
    { sessionId: 'browser-1', x: 0, y: 0, width: 100, height: 100, visible: true },
  );
  h.manager.close('browser-1');
  const count = h.events.length;
  h.manager.failBrowserTab('browser-1', record, record.tabs.activeId, 'Late failure');
  await h.command('reload');
  assert.equal(h.events.length, count);
});
