import type { BrowserWindow } from 'electron';
import { randomUUID } from 'node:crypto';
import { vpnStorageDocument } from './vault-vpn-storage-document.ts';
import { vpnSSOArchiveBytes } from './vault-vpn-sso.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';

type Context = { ancestors: string[]; origin: string; storageKey: string };
type Snapshot = Context & { state: Record<string, unknown> };
type Frame = { id: string; parentId?: string; url: string; loaderId: string };
type Located = { frame: Frame; sessionId?: string };
type Cookie = Record<string, unknown>;
type Options = {
  window: BrowserWindow;
  current(): boolean;
  attemptCookie: string;
  invalidated?(): void;
};
const unavailable = () => Error('VPN browser storage unavailable.');
const maxContexts = 128;
const origin = (value: unknown): value is string => {
  if (typeof value !== 'string' || value.length > 4096) return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && !u.username && !u.password && u.origin === value;
  } catch {
    return false;
  }
};
const contextKey = (c: Context) => JSON.stringify([c.ancestors, c.origin, c.storageKey]);
function cookieParameters(value: unknown, attemptCookie: string): Cookie {
  if (!vaultRecord(value)) throw unavailable();
  const required = [
    'name',
    'value',
    'domain',
    'path',
    'expires',
    'size',
    'httpOnly',
    'secure',
    'session',
    'priority',
    'sourceScheme',
    'sourcePort',
  ];
  if (
    !vaultFields(value, [
      ...required,
      ...['sameSite', 'partitionKey', 'partitionKeyOpaque'].filter((key) =>
        Object.hasOwn(value, key),
      ),
    ]) ||
    typeof value.name !== 'string' ||
    value.name === attemptCookie ||
    value.name.length > 4096 ||
    typeof value.value !== 'string' ||
    value.value.length > 65536 ||
    typeof value.domain !== 'string' ||
    value.domain.length > 4096 ||
    typeof value.path !== 'string' ||
    !value.path.startsWith('/') ||
    value.path.length > 4096 ||
    typeof value.httpOnly !== 'boolean' ||
    typeof value.secure !== 'boolean' ||
    typeof value.session !== 'boolean' ||
    !Number.isFinite(value.expires) ||
    !Number.isSafeInteger(value.size) ||
    (value.size as number) < 0 ||
    !['Low', 'Medium', 'High'].includes(value.priority as string) ||
    !['Unset', 'NonSecure', 'Secure'].includes(value.sourceScheme as string) ||
    !Number.isInteger(value.sourcePort) ||
    (value.sourcePort as number) < -1 ||
    (value.sourcePort as number) > 65535 ||
    (value.sameSite !== undefined &&
      !['Strict', 'Lax', 'None'].includes(value.sameSite as string)) ||
    (value.partitionKeyOpaque !== undefined && value.partitionKeyOpaque !== false)
  )
    throw unavailable();
  const host = value.domain.replace(/^\./, '');
  const url = new URL('https://' + host + '/');
  if (url.hostname !== host || url.username || url.password || url.port || url.pathname !== '/')
    throw unavailable();
  const out: Cookie = {
    name: value.name,
    value: value.value,
    path: value.path,
    secure: value.secure,
    httpOnly: value.httpOnly,
    priority: value.priority,
    sourceScheme: value.sourceScheme,
    sourcePort: value.sourcePort,
  };
  // Supplying a host-only cookie as a domain cookie widens its authority.
  if (value.domain.startsWith('.')) out.domain = value.domain;
  else out.url = url.href;
  if (!value.session) out.expires = value.expires;
  if (value.sameSite !== undefined) out.sameSite = value.sameSite;
  if (value.partitionKey !== undefined) {
    const p = value.partitionKey;
    if (
      !vaultRecord(p) ||
      !vaultFields(p, ['topLevelSite', 'hasCrossSiteAncestor']) ||
      !origin(p.topLevelSite) ||
      typeof p.hasCrossSiteAncestor !== 'boolean'
    )
      throw unavailable();
    out.partitionKey = {
      topLevelSite: p.topLevelSite,
      hasCrossSiteAncestor: p.hasCrossSiteAncestor,
    };
  }
  return out;
}

// Private native adapter for ONE volatile authentication window. The actor must
// consult permitsRequest for every request and keep the window hidden until
// publish. No archive or script endpoint is exposed through the preload bridge.
export class VaultVPNStorageDriver {
  private readonly window: BrowserWindow;
  private readonly session: Electron.Session;
  private readonly debugger: Electron.Debugger;
  private readonly accepted: () => boolean;
  private readonly attemptCookie: string;
  private readonly invalidated?: () => void;
  private readonly path = '/.well-known/wormhole-native-storage/' + randomUUID();
  private readonly synthetic = new Set<string>();
  private readonly targets = new Map<string, string | undefined>();
  private readonly frames = new Map<string, Located>();
  private readonly contexts = new Map<string, Context>();
  private readonly observations = new Set<Promise<void>>();
  private readonly commands = new Set<Promise<unknown>>();
  private readonly actions = new Set<Promise<unknown>>();
  private offline = true;
  private phase: 'restore' | 'live' | 'capture' | 'failed' | 'closed' = 'restore';
  private fault = false;
  private busy = false;
  private imported = false;
  private handled = false;
  private attached = false;
  private cleanup?: Promise<void>;
  private constructor(options: Options) {
    this.window = options.window;
    this.session = options.window.webContents.session;
    this.debugger = options.window.webContents.debugger;
    this.accepted = options.current.bind(options);
    this.attemptCookie = options.attemptCookie;
    this.invalidated = options.invalidated?.bind(options);
  }
  static async open(options: Options, reserved?: (driver: VaultVPNStorageDriver) => void) {
    const driver = new VaultVPNStorageDriver(options);
    try {
      reserved?.(driver);
      driver.check();
      if (
        driver.session.isPersistent() ||
        driver.window.webContents.debugger.isAttached() ||
        !/^[\x21-\x7e]{1,256}$/.test(driver.attemptCookie)
      )
        throw unavailable();
      // A new hidden WebContents has no initialized page target yet. Establish
      // a local blank document before issuing CDP commands; no network is used.
      await driver.window.loadURL('about:blank');
      driver.check();
      const d = driver.window.webContents.debugger;
      d.attach('1.3');
      driver.attached = true;
      d.on('message', driver.message);
      d.on('detach', driver.detached);
      driver.handleOffline();
      await driver.send('Page.enable');
      await driver.send('Runtime.enable');
      await driver.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
      });
      driver.check();
      return driver;
    } catch {
      await driver.close();
      throw unavailable();
    }
  }
  get isOffline() {
    return this.offline;
  }
  permitsRequest(url: string, webContentsId: number, resourceType: string) {
    try {
      this.check();
    } catch {
      return false;
    }
    return (
      !this.offline ||
      (webContentsId === this.window.webContents.id &&
        ['mainFrame', 'subFrame'].includes(resourceType) &&
        this.synthetic.has(url))
    );
  }
  private check() {
    let current = false;
    try {
      current = this.accepted();
    } catch {}
    if (
      !current ||
      this.window.isDestroyed() ||
      this.phase === 'closed' ||
      this.phase === 'failed' ||
      this.fault
    ) {
      this.offline = true;
      throw unavailable();
    }
  }
  private async send(
    method: string,
    parameters: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<any> {
    this.check();
    const task = this.debugger.sendCommand(method, parameters, sessionId || undefined);
    this.commands.add(task);
    try {
      const result = await task;
      this.check();
      return result;
    } finally {
      this.commands.delete(task);
    }
  }
  private detached = () => {
    if (this.phase !== 'closed') this.invalidate();
  };
  private handleOffline() {
    this.session.protocol.handle('https', (request) => {
      const allowed = this.offline && this.synthetic.has(request.url);
      return new Response(
        allowed ? '<!doctype html><meta charset="utf-8"><title>Sign-in</title>' : '',
        {
          status: allowed ? 200 : 403,
          headers: {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'none'; frame-src https:",
          },
        },
      );
    });
    this.handled = true;
  }
  private invalidate() {
    if (this.fault) return;
    this.fault = true;
    this.offline = true;
    queueMicrotask(() => {
      try {
        this.invalidated?.();
      } catch {}
    });
  }
  private message = (_event: unknown, method: string, parameters: any, sessionId?: string) => {
    if (this.phase === 'closed' || this.phase === 'failed') return;
    if (this.observations.size >= 512) {
      this.invalidate();
      return;
    }
    let work: Promise<void> | undefined;
    if (method === 'Target.attachedToTarget') {
      if (parameters.targetInfo.type === 'iframe') {
        if (this.targets.size >= 256) {
          this.invalidate();
          return;
        }
        this.targets.set(parameters.sessionId, sessionId || undefined);
        work = this.prepareTarget(parameters.sessionId);
      } else if (
        ['worker', 'shared_worker', 'service_worker'].includes(parameters.targetInfo.type)
      ) {
        // Other writers need a separate snapshot/quiescence adapter.
        this.invalidate();
      }
    } else if (method === 'Target.detachedFromTarget') this.dropTarget(parameters.sessionId);
    else if (method === 'Page.frameNavigated' && this.phase === 'live') {
      const frame = parameters.frame as Frame;
      if (!sessionId && !frame.parentId) this.frames.clear();
      if (!this.frames.has(frame.id) && this.frames.size >= 512) {
        this.invalidate();
        return;
      }
      this.frames.set(frame.id, { frame: { ...frame }, sessionId });
    } else if (method === 'Page.frameDetached' && parameters.reason === 'remove') {
      this.frames.delete(parameters.frameId);
    } else if (
      method === 'Runtime.executionContextCreated' &&
      this.phase === 'live' &&
      parameters.context.auxData?.isDefault
    ) {
      const located = this.frames.get(parameters.context.auxData.frameId);
      if (located) work = this.observe(located.frame, sessionId);
      else {
        this.invalidate();
      }
    }
    if (work) {
      const tracked = work
        .catch(() => {
          this.invalidate();
        })
        .finally(() => this.observations.delete(tracked));
      this.observations.add(tracked);
    }
  };
  private dropTarget(id: string) {
    for (const [child, parent] of this.targets) if (parent === id) this.dropTarget(child);
    this.targets.delete(id);
    for (const [key, located] of this.frames) if (located.sessionId === id) this.frames.delete(key);
  }
  private async prepareTarget(sessionId: string) {
    await this.send('Page.enable', {}, sessionId);
    await this.send('Runtime.enable', {}, sessionId);
    await this.send(
      'Target.setAutoAttach',
      { autoAttach: true, waitForDebuggerOnStart: false, flatten: true },
      sessionId,
    );
    if (this.phase === 'live') await this.scanTarget(sessionId);
  }
  private async scanTarget(sessionId?: string) {
    await this.send('Page.enable', {}, sessionId);
    const { frameTree } = await this.send('Page.getFrameTree', {}, sessionId);
    const visit = async (tree: any): Promise<void> => {
      this.frames.set(tree.frame.id, { frame: { ...tree.frame }, sessionId });
      await this.observe(tree.frame, sessionId);
      for (const child of tree.childFrames ?? []) await visit(child);
    };
    await visit(frameTree);
  }
  private async observe(frame: Frame, sessionId?: string) {
    if (frame.url === 'about:blank' || !frame.url) return;
    const u = new URL(frame.url);
    if (u.protocol !== 'https:' || u.username || u.password) throw unavailable();
    const ancestors: string[] = [];
    let parent = frame.parentId;
    while (parent) {
      if (ancestors.length >= 8) throw unavailable();
      const next = this.frames.get(parent)?.frame;
      if (!next) throw unavailable();
      const p = new URL(next.url);
      if (p.protocol !== 'https:' || p.username || p.password) throw unavailable();
      ancestors.unshift(p.origin);
      parent = next.parentId;
    }
    const { storageKey } = await this.send(
      'Storage.getStorageKeyForFrame',
      { frameId: frame.id },
      sessionId,
    );
    // A fast redirect must not associate an old origin with a new document's key.
    if (
      this.frames.get(frame.id)?.frame.loaderId !== frame.loaderId ||
      typeof storageKey !== 'string' ||
      storageKey.length > 16384 ||
      !storageKey.startsWith(u.origin + '/')
    )
      throw unavailable();
    const c = { ancestors, origin: u.origin, storageKey };
    const key = contextKey(c);
    if (!this.contexts.has(key) && this.contexts.size >= maxContexts) throw unavailable();
    this.contexts.set(key, c);
  }
  private async locate(url: string): Promise<Located> {
    for (const sessionId of [undefined, ...this.targets.keys()]) {
      const { frameTree } = await this.send('Page.getFrameTree', {}, sessionId);
      const find = (tree: any): Frame | undefined =>
        tree.frame.url === url ? tree.frame : (tree.childFrames ?? []).map(find).find(Boolean);
      const frame = find(frameTree);
      if (frame) return { frame, sessionId };
    }
    throw unavailable();
  }
  private async evaluate(located: Located, expression: string) {
    const { executionContextId } = await this.send(
      'Page.createIsolatedWorld',
      {
        frameId: located.frame.id,
        worldName: 'wormhole-native-vpn-storage',
      },
      located.sessionId,
    );
    const response = await this.send(
      'Runtime.evaluate',
      {
        contextId: executionContextId,
        expression,
        awaitPromise: true,
        returnByValue: true,
      },
      located.sessionId,
    );
    if (response.exceptionDetails || response.result?.type === 'error') throw unavailable();
    return response.result?.value;
  }
  private async document(c: Context): Promise<Located> {
    this.synthetic.clear();
    const chain = [...c.ancestors, c.origin];
    const urls = chain.map((o, i) => o + this.path + '/' + i);
    for (const url of urls) this.synthetic.add(url);
    await this.window.loadURL(urls[0]);
    await Promise.all([...this.observations]);
    this.check();
    let found = await this.locate(urls[0]);
    for (const url of urls.slice(1)) {
      await this.evaluate(
        found,
        `new Promise((resolve,reject)=>{const frame=document.createElement('iframe');frame.onload=()=>resolve(true);frame.onerror=()=>reject(Error('Offline frame unavailable.'));frame.src=${JSON.stringify(url)};document.body.append(frame);})`,
      );
      await Promise.all([...this.observations]);
      found = await this.locate(url);
    }
    const { storageKey } = await this.send(
      'Storage.getStorageKeyForFrame',
      { frameId: found.frame.id },
      found.sessionId,
    );
    if (storageKey !== c.storageKey) throw unavailable();
    return found;
  }
  private async serialize(c: Context, operation: 'capture' | 'restore', state?: unknown) {
    const located = await this.document(c);
    if (operation === 'capture') {
      const estimate = await this.evaluate(located, 'navigator.storage.estimate()');
      if (
        !Number.isFinite(estimate?.usage) ||
        estimate.usage > vpnSSOArchiveBytes ||
        Object.entries(estimate.usageDetails ?? {}).some(
          ([name, bytes]) => typeof bytes !== 'number' || (bytes > 0 && name !== 'indexedDB'),
        )
      )
        throw unavailable();
    }
    const result = await this.evaluate(
      located,
      `(${vpnStorageDocument.toString()})(JSON.parse(${JSON.stringify(JSON.stringify({ operation, origin: c.origin, ...(state === undefined ? {} : { state }) }))}))`,
    );
    if (typeof result !== 'string' || Buffer.byteLength(result) > vpnSSOArchiveBytes)
      throw unavailable();
    return JSON.parse(result);
  }
  private async action<T>(phase: 'restore' | 'live', work: () => Promise<T>): Promise<T> {
    this.check();
    if (this.busy || this.phase !== phase) throw unavailable();
    this.busy = true;
    const task = (async () => {
      let result: T | undefined;
      try {
        result = await work();
        this.check();
        return result;
      } catch {
        if (Buffer.isBuffer(result)) result.fill(0);
        this.offline = true;
        if (this.phase !== 'closed') this.phase = 'failed';
        throw unavailable();
      } finally {
        this.busy = false;
      }
    })();
    this.actions.add(task);
    try {
      return await task;
    } finally {
      this.actions.delete(task);
    }
  }
  // Consumes the owned plaintext, including on refused admission.
  async apply(bytes: Uint8Array): Promise<void> {
    try {
      await this.action('restore', async () => {
        if (this.imported || bytes.byteLength > vpnSSOArchiveBytes) throw unavailable();
        this.imported = true;
        if (bytes.byteLength === 0) return;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        const archive = JSON.parse(text);
        if (
          !vaultRecord(archive) ||
          !vaultFields(archive, ['formatVersion', 'contexts', 'cookies']) ||
          archive.formatVersion !== 1 ||
          !Array.isArray(archive.contexts) ||
          archive.contexts.length > maxContexts ||
          !Array.isArray(archive.cookies) ||
          archive.cookies.length > 10000
        )
          throw unavailable();
        const seen = new Set<string>(),
          states = new Map<string, string>();
        for (const c of archive.contexts) {
          if (
            !vaultRecord(c) ||
            !vaultFields(c, ['ancestors', 'origin', 'storageKey', 'state']) ||
            !origin(c.origin) ||
            !Array.isArray(c.ancestors) ||
            c.ancestors.length > 8 ||
            !c.ancestors.every(origin) ||
            typeof c.storageKey !== 'string' ||
            c.storageKey.length > 16384 ||
            !c.storageKey.startsWith(c.origin + '/') ||
            !vaultRecord(c.state) ||
            c.state.origin !== c.origin
          )
            throw unavailable();
          const snapshot = c as Snapshot;
          const id = contextKey(snapshot);
          if (seen.has(id)) throw unavailable();
          seen.add(id);
          // Local storage/IDB alias when Chromium assigns the same storage key;
          // session storage remains tied to this top-level browsing context.
          const persistent = JSON.stringify([snapshot.state.local, snapshot.state.databases]);
          const prior = states.get(snapshot.storageKey);
          if (prior !== undefined && prior !== persistent) throw unavailable();
          await this.serialize(
            snapshot,
            'restore',
            prior === undefined ? snapshot.state : { ...snapshot.state, databases: [] },
          );
          states.set(snapshot.storageKey, persistent);
          this.contexts.set(id, {
            ancestors: [...snapshot.ancestors],
            origin: snapshot.origin,
            storageKey: snapshot.storageKey,
          });
        }
        // Cookie validation precedes any cookie insertion. The fresh gateway
        // bearer is excluded from archives and still needs its own issuer proof.
        const cookies = archive.cookies.map((c: unknown) =>
          cookieParameters(c, this.attemptCookie),
        );
        const cookieIDs = new Set<string>();
        for (const c of cookies) {
          const id = JSON.stringify([c.name, c.domain ?? c.url, c.path, c.partitionKey ?? null]);
          if (cookieIDs.has(id)) throw unavailable();
          cookieIDs.add(id);
        }
        const active = (c: Cookie, now: number) =>
          c.expires === undefined || (c.expires as number) > now;
        const before = Date.now() / 1000;
        await this.send('Network.setCookies', {
          cookies: cookies.filter((c) => active(c, before)),
        });
        const restored = (await this.send('Network.getAllCookies')).cookies;
        if (!Array.isArray(restored) || restored.length > 10000) throw unavailable();
        // Expiry while at rest (or during native import) is normal browser
        // deletion, not failed restoration. Session cookies have no expires.
        const after = Date.now() / 1000;
        const expectedCookies = cookies
          .filter((c) => active(c, after))
          .map((c) => JSON.stringify(c))
          .sort();
        const actualCookies = restored
          .map((c: unknown) => cookieParameters(c, this.attemptCookie))
          .filter((c: Cookie) => active(c, after))
          .map((c: Cookie) => JSON.stringify(c))
          .sort();
        if (
          expectedCookies.length !== actualCookies.length ||
          expectedCookies.some((c, i) => c !== actualCookies[i])
        )
          throw unavailable();
      });
    } finally {
      bytes.fill(0);
    }
  }
  async publish(): Promise<void> {
    await this.action('restore', async () => {
      if (!this.imported) throw unavailable();
      this.session.protocol.unhandle('https');
      this.handled = false;
      this.synthetic.clear();
      this.phase = 'live';
      this.offline = false;
    });
  }
  async capture(): Promise<Buffer> {
    return this.action('live', async () => {
      this.offline = true;
      // Stop admitting new writers before draining committed frame observations.
      await this.send('Page.stopLoading');
      await this.scanTarget();
      for (const target of this.targets.keys()) await this.scanTarget(target);
      await Promise.all([...this.observations]);
      this.check();
      this.phase = 'capture';
      this.handleOffline();
      await this.session.closeAllConnections();
      this.check();
      const first = this.contexts.values().next().value;
      if (first) await this.document(first);
      else {
        // Even an empty inventory must leave no live page writers behind.
        await this.window.loadURL('about:blank');
        this.check();
      }
      const contexts: Snapshot[] = [];
      let archiveBytes = Buffer.byteLength(
        JSON.stringify({ formatVersion: 1, contexts: [], cookies: [] }),
      );
      // Navigating the original top-level context ends page/iframe writers;
      // sessionStorage remains in that same browsing-context namespace.
      for (const c of this.contexts.values()) {
        const { usage, usageBreakdown } = await this.send('Storage.getUsageAndQuota', {
          origin: c.origin,
        });
        if (
          !Number.isFinite(usage) ||
          usage > vpnSSOArchiveBytes ||
          !Array.isArray(usageBreakdown) ||
          usageBreakdown.some(
            (item: any) =>
              item.usage > 0 &&
              !['indexeddb', 'local_storage', 'cookies', 'shader_cache'].includes(item.storageType),
          )
        )
          throw unavailable();
        const state = await this.serialize(c, 'capture');
        const snapshot = { ...c, ancestors: [...c.ancestors], state };
        archiveBytes += Buffer.byteLength(JSON.stringify(snapshot)) + (contexts.length ? 1 : 0);
        if (archiveBytes > vpnSSOArchiveBytes) throw unavailable();
        contexts.push(snapshot);
      }
      const { cookies: all } = await this.send('Network.getAllCookies');
      if (!Array.isArray(all) || all.length > 10000) throw unavailable();
      const cookies = all.filter((c: any) => c.name !== this.attemptCookie);
      for (const [index, c] of cookies.entries()) {
        cookieParameters(c, this.attemptCookie);
        archiveBytes += Buffer.byteLength(JSON.stringify(c)) + (index ? 1 : 0);
        if (archiveBytes > vpnSSOArchiveBytes) throw unavailable();
      }
      const bytes = Buffer.from(JSON.stringify({ formatVersion: 1, contexts, cookies }));
      if (bytes.byteLength > vpnSSOArchiveBytes) {
        bytes.fill(0);
        throw unavailable();
      }
      return bytes;
    });
  }
  // The actor destroys its window BEFORE joining close. Detaching cancels CDP
  // work; retry remains possible when protocol cleanup cannot be confirmed.
  close(): Promise<void> {
    if (this.cleanup) return this.cleanup;
    this.offline = true;
    this.phase = 'closed';
    const task = Promise.resolve().then(async () => {
      const d = this.debugger;
      d.removeListener('message', this.message);
      d.removeListener('detach', this.detached);
      if (this.attached && !this.window.isDestroyed() && d.isAttached()) d.detach();
      this.attached = false;
      await Promise.allSettled([...this.actions, ...this.commands, ...this.observations]);
      if (this.handled) {
        this.session.protocol.unhandle('https');
        this.handled = false;
      }
      this.contexts.clear();
      this.frames.clear();
      this.targets.clear();
      this.synthetic.clear();
    });
    this.cleanup = task.catch(() => {
      this.cleanup = undefined;
      throw unavailable();
    });
    return this.cleanup;
  }
}
