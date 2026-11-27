import { vaultFields, vaultRecord } from './vault-contract.ts';
import {
  maxWebSessionArchiveBytes,
  type WebSessionArchiveStore,
} from './vault-web-session-archive.ts';

type CookieJar = Pick<Electron.Cookies, 'get' | 'on' | 'off'>;
type CookieView = Pick<Electron.WebContents, 'debugger' | 'getURL' | 'isDestroyed' | 'loadURL'>;
type Options = {
  url: string;
  store: WebSessionArchiveStore;
  jar: CookieJar;
  views: () => readonly CookieView[];
  authorized: () => boolean;
};

type StoredCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sourceScheme: 'Secure' | 'NonSecure';
  sourcePort: number;
  expires: number;
  priority: 'Low' | 'Medium' | 'High';
  sameSite?: 'Strict' | 'Lax' | 'None';
  partitionKey?: { topLevelSite: string; hasCrossSiteAncestor: false };
};

const maxCookies = 256;
const checkpointDelay = 175;

function sameHost(domain: unknown, url: URL): domain is string {
  return typeof domain === 'string' && (domain === url.hostname || domain === '.' + url.hostname);
}

function cookiePath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith('/') &&
    value.length <= 2048 &&
    // Chromium cookie paths are used to build a URL for each scoped lookup.
    // oxlint-disable-next-line no-control-regex
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function firstPartyKey(value: unknown, target: URL): value is StoredCookie['partitionKey'] {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['topLevelSite', 'hasCrossSiteAncestor']) ||
    typeof value.topLevelSite !== 'string' ||
    value.topLevelSite.length > 1024 ||
    value.hasCrossSiteAncestor !== false
  )
    return false;
  const site = URL.parse(value.topLevelSite);
  return Boolean(
    site &&
    site.origin === value.topLevelSite &&
    !site.port &&
    site.protocol === target.protocol &&
    (site.hostname === target.hostname || target.hostname.endsWith('.' + site.hostname)),
  );
}

function scopedCookie(value: unknown, target: URL): StoredCookie | undefined {
  if (!vaultRecord(value)) return undefined;
  const {
    name,
    value: contents,
    domain,
    path,
    secure,
    httpOnly,
    sourceScheme,
    sourcePort,
    expires,
    sameSite,
    priority,
    partitionKey,
    partitionKeyOpaque,
  } = value;
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  if (
    typeof name !== 'string' ||
    typeof contents !== 'string' ||
    name.length + contents.length > 4096 ||
    !sameHost(domain, target) ||
    !cookiePath(path) ||
    typeof secure !== 'boolean' ||
    typeof httpOnly !== 'boolean' ||
    (sourceScheme !== 'Secure' && sourceScheme !== 'NonSecure') ||
    sourcePort !== port ||
    typeof expires !== 'number' ||
    !Number.isFinite(expires) ||
    (expires !== -1 && expires <= 0) ||
    (priority !== 'Low' && priority !== 'Medium' && priority !== 'High') ||
    (sameSite !== undefined &&
      sameSite !== 'Strict' &&
      sameSite !== 'Lax' &&
      sameSite !== 'None') ||
    partitionKeyOpaque === true ||
    (partitionKey !== undefined && !firstPartyKey(partitionKey, target))
  )
    return undefined;
  return {
    name,
    value: contents,
    domain,
    path,
    secure,
    httpOnly,
    sourceScheme,
    sourcePort: port,
    expires,
    priority,
    ...(sameSite ? { sameSite } : {}),
    ...(partitionKey ? { partitionKey } : {}),
  };
}

function readCookies(bytes: Uint8Array, target: URL): StoredCookie[] {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      !vaultRecord(value) ||
      !vaultFields(value, ['version', 'cookies']) ||
      value.version !== 1 ||
      !Array.isArray(value.cookies) ||
      value.cookies.length > maxCookies
    )
      throw Error('Invalid web cookie archive.');
    const cookies = value.cookies.map((cookie: unknown) => scopedCookie(cookie, target));
    if (cookies.some((cookie) => !cookie)) throw Error('Invalid web cookie archive.');
    const now = Date.now() / 1000;
    return (cookies as StoredCookie[]).filter(
      (cookie) => cookie.expires === -1 || cookie.expires > now,
    );
  } finally {
    bytes.fill(0);
  }
}

function onTarget(view: CookieView, target: URL): boolean {
  return !view.isDestroyed() && URL.parse(view.getURL())?.origin === target.origin;
}

// Main invokes two fixed Chromium commands on its own isolated WebContents.
// The cookie jar API is used only to enumerate paths and observe changes.
async function captureCookies(
  view: CookieView,
  jar: CookieJar,
  target: URL,
  active: () => boolean,
) {
  const cookies = await jar.get({ domain: target.hostname });
  if (!active() || !onTarget(view, target)) return undefined;
  const paths = new Set<string>();
  for (const { domain, path } of cookies) {
    if (sameHost(domain, target) && cookiePath(path)) paths.add(target.origin + path);
    if (paths.size > maxCookies) throw Error('Web cookie archive exceeds its limit.');
  }
  if (!paths.size) return [];
  const connection = view.debugger;
  connection.attach('1.3');
  try {
    const result: unknown = await connection.sendCommand('Network.getCookies', {
      urls: [...paths],
    });
    if (!active() || !onTarget(view, target)) return undefined;
    if (
      !vaultRecord(result) ||
      !Array.isArray(result.cookies) ||
      result.cookies.length > maxCookies
    )
      throw Error('Web cookie archive exceeds its limit.');
    return result.cookies.flatMap((value: unknown) => {
      const cookie = scopedCookie(value, target);
      return cookie ? [cookie] : [];
    });
  } finally {
    if (!view.isDestroyed() && connection.isAttached()) connection.detach();
  }
}

async function restoreCookies(
  view: CookieView,
  target: URL,
  cookies: StoredCookie[],
  active: () => boolean,
) {
  await view.loadURL('about:blank');
  if (!active() || view.isDestroyed() || view.getURL() !== 'about:blank')
    throw Error('Web cookie restore was superseded.');
  const connection = view.debugger;
  connection.attach('1.3');
  try {
    for (const { domain, expires, ...cookie } of cookies) {
      if (!active() || view.isDestroyed() || view.getURL() !== 'about:blank')
        throw Error('Web cookie restore was superseded.');
      const result = await connection.sendCommand('Network.setCookie', {
        ...cookie,
        url: target.origin,
        ...(domain.startsWith('.') ? { domain } : {}),
        ...(expires === -1 ? {} : { expires }),
      });
      if (result.success !== true) throw Error('Could not restore a browser cookie.');
    }
  } finally {
    if (!view.isDestroyed() && connection.isAttached()) connection.detach();
  }
}

export class VaultWebCookieCheckpoint {
  private revision = '0';
  private saved = false;
  private stopped = false;
  private observing = false;
  private dirty = false;
  private timer?: NodeJS.Timeout;
  private pending?: Promise<void>;
  private closing?: Promise<void>;
  private readonly options: Options;
  private readonly target: URL;

  constructor(options: Options) {
    this.options = options;
    this.target = new URL(options.url);
  }

  private active = () => !this.stopped && this.options.authorized();

  async restore(view: CookieView): Promise<void> {
    const { store, jar } = this.options;
    const initial = await store.read();
    try {
      if (!this.active()) throw Error('Web cookie restore was superseded.');
      this.revision = initial.revision;
      if (initial.bytes) {
        // Consume the archived revision before seeding the browser so a failed
        // restore cannot reapply the same login repeatedly.
        this.revision = await store.forget(this.revision);
        if (!this.active()) throw Error('Web cookie restore was superseded.');
        const cookies = readCookies(initial.bytes, this.target);
        if (cookies.length) {
          await restoreCookies(view, this.target, cookies, this.active);
          this.dirty = true;
        }
      }
      if (!this.active()) throw Error('Web cookie restore was superseded.');
      jar.on('changed', this.changed);
      this.observing = true;
    } finally {
      initial.bytes?.fill(0);
    }
  }

  ready(): void {
    this.schedule();
  }

  private changed = (_event: Electron.Event, cookie: Electron.Cookie) => {
    if (!this.active() || !sameHost(cookie.domain, this.target)) return;
    this.dirty = true;
    // Invalidate an existing checkpoint as soon as possible on logout/update.
    if (this.saved) void this.run(false).catch(() => {});
    this.schedule();
  };

  private schedule(): void {
    if (!this.observing || !this.active() || !this.dirty || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.run(true).catch(() => {});
    }, checkpointDelay);
    this.timer.unref();
  }

  private run(write: boolean): Promise<void> {
    if (this.pending) return this.pending;
    if (!this.active() || !this.dirty) return Promise.resolve();
    this.pending = this.checkpoint(write).finally(() => {
      this.pending = undefined;
      if (this.observing && write && this.saved && this.dirty) void this.run(false).catch(() => {});
      this.schedule();
    });
    return this.pending;
  }

  private async checkpoint(write: boolean): Promise<void> {
    const { store, views, jar } = this.options;
    try {
      if (this.saved) {
        this.revision = await store.forget(this.revision);
        this.saved = false;
      }
      if (!write || !this.active()) return;
      this.dirty = false;
      const view = views().find((candidate) => onTarget(candidate, this.target));
      if (!view) return;
      const cookies = await captureCookies(view, jar, this.target, this.active);
      if (!cookies?.length || this.dirty || !this.active()) return;
      const bytes = new TextEncoder().encode(JSON.stringify({ version: 1, cookies }));
      try {
        if (bytes.length > maxWebSessionArchiveBytes)
          throw Error('Web cookie archive exceeds its limit.');
        this.revision = await store.save(this.revision, bytes);
        this.saved = true;
      } finally {
        bytes.fill(0);
      }
    } catch {
      this.stop();
      throw Error('Web cookie checkpoint failed.');
    }
  }

  flush(): Promise<void> {
    return (this.closing ??= this.flushAndStop());
  }

  private async flushAndStop(): Promise<void> {
    try {
      if (!this.observing) return;
      await this.checkpointNow();
      // A change observed during capture invalidates that snapshot. Make one
      // more attempt while the view still belongs to this checkpoint.
      await this.run(true);
    } finally {
      this.stop();
      await this.pending;
    }
  }

  async checkpointNow(): Promise<void> {
    clearTimeout(this.timer);
    this.timer = undefined;
    await this.pending;
    // A cookie change during the previous save may have queued its erasure.
    if (this.pending) await this.pending;
    // Chromium can commit Set-Cookie before delivering its change event.
    // Explicit checkpoints read the current jar even if no event has arrived.
    if (this.observing) this.dirty = true;
    await this.run(true);
  }

  stop(): void {
    this.stopped = true;
    this.unobserve();
  }

  private unobserve(): void {
    if (this.observing) this.options.jar.off('changed', this.changed);
    this.observing = false;
    clearTimeout(this.timer);
    this.timer = undefined;
  }
}
