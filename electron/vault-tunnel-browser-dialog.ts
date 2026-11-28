import type { BrowserWindow, BrowserWindowConstructorOptions } from 'electron';
import { randomUUID } from 'node:crypto';
import {
  fortinetSSLLoopback,
  fortinetSSLCallbackAuthId,
  isFortinetSSLCallbackSource,
  isSameCertificateHostname,
} from './tunnel-auth.ts';
import { protectSecretWindow } from './vault-window-policy.ts';
import {
  parseVaultTunnelBrowserContext,
  sealTunnelBrowserToken,
  tunnelBrowserCallbackToken,
  type VaultTunnelBrowserContext,
} from './vault-tunnel-browser.ts';
import {
  parseVaultTunnelCookieContext,
  sealTunnelCookie,
  tunnelCookieDigest,
  tunnelCookieResponseDigest,
  type VaultTunnelCookieContext,
} from './vault-tunnel-cookie.ts';
type BrowserContext = VaultTunnelBrowserContext | VaultTunnelCookieContext;
const parseContext = (value: unknown) =>
  value && typeof value === 'object' && ('cookieName' in value || 'completion' in value)
    ? parseVaultTunnelCookieContext(value)
    : parseVaultTunnelBrowserContext(value);
import type { VaultTunnelAuthenticationEnvelope } from './vault-tunnel-authentication.ts';
import type { VaultRoutePlanRequest } from './vault-route.ts';
import {
  parseVaultTunnelFallbackBinding,
  type VaultTunnelFallbackBinding,
} from './vault-tunnel-fallback.ts';
import type { VaultVPNBrowserSession } from './vault-vpn-browser-session.ts';

type StorageSession = Pick<
  VaultVPNBrowserSession,
  'isOffline' | 'permitsRequest' | 'restore' | 'capture' | 'close'
>;

type Options = {
  createWindow(options: BrowserWindowConstructorOptions): BrowserWindow;
  present?(window: BrowserWindow): void;
  forget?(window: BrowserWindow): void;
  platform?: NodeJS.Platform;
  storage?(options: {
    window: BrowserWindow;
    current(): boolean;
    failed(): void;
    context: BrowserContext;
    signal: AbortSignal;
    request?: VaultRoutePlanRequest;
    fallback?: VaultTunnelFallbackBinding;
  }): StorageSession | undefined;
};
type Actor = {
  context: BrowserContext;
  window: BrowserWindow;
  cancel(): Promise<void>;
};
const unavailable = () => Error('VPN browser authentication unavailable.');
function key(c: BrowserContext) {
  return JSON.stringify([c.binding, c.challengeId]);
}
function allowedResource(url: URL, context: BrowserContext, type: string): boolean {
  if (url.username || url.password) return false;
  if ('completion' in context && fortinetSSLLoopback(url.href, new URL(context.startURL).origin))
    return false;
  if (url.protocol === 'https:' || (url.protocol === 'wss:' && type === 'webSocket')) {
    const gateway = new URL(context.startURL);
    const origin = url.protocol === 'wss:' ? 'https://' + url.host : url.origin;
    // Do not let a gateway certificate exception spread to another port or
    // hostname spelling through Chromium's cached certificate decisions.
    return (
      !context.ignoreCertificateErrors ||
      !isSameCertificateHostname(url.hostname, gateway.hostname) ||
      origin === gateway.origin
    );
  }
  return ['data:', 'blob:'].includes(url.protocol) && type !== 'mainFrame';
}

// One volatile partition per native attempt, with no preload or app IPC. A
// failed native close or storage cleanup retains the exact actor for retry.
export class VaultTunnelBrowserDialog {
  private readonly actors = new Map<string, Actor>();
  private readonly uncertain = new Set<Actor>();
  private readonly owners = new Map<
    BrowserWindow,
    {
      actors: Set<Actor>;
      cancel: () => void;
      navigation: (_e: unknown, _url: string, _inPlace: boolean, main: boolean) => void;
    }
  >();
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
  }
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    value: unknown,
    signal: AbortSignal,
    request?: VaultRoutePlanRequest,
    fallback?: VaultTunnelFallbackBinding,
  ): Promise<VaultTunnelAuthenticationEnvelope> {
    const context = parseContext(value);
    const source =
      fallback !== undefined && request
        ? parseVaultTunnelFallbackBinding(fallback, {
            ...request,
            primary: fallback?.primary,
            fallbackRequestId: fallback?.fallback?.requestId,
          })
        : undefined;
    if (
      fallback !== undefined &&
      (!source ||
        context?.binding.kind !== 2 ||
        JSON.stringify(context.binding) !== JSON.stringify(source.fallback))
    )
      return Promise.reject(unavailable());
    const ownerCurrent = () => {
      try {
        return !signal.aborted && !parent.isDestroyed() && accepted();
      } catch {
        return false;
      }
    };
    if (
      !context ||
      this.uncertain.size > 0 ||
      this.actors.size >= 32 ||
      this.actors.has(key(context)) ||
      !ownerCurrent()
    )
      return Promise.reject(unavailable());
    const window = this.options.createWindow({
      parent,
      width: 900,
      height: 700,
      show: false,
      autoHideMenuBar: true,
      title: 'callbackURL' in context ? 'Fortinet IPsec SAML sign-in' : 'Fortinet SSL sign-in',
      webPreferences: {
        partition: 'vault-tunnel-browser-' + randomUUID(),
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    const session = window.webContents.session,
      abort = new AbortController();
    let resolve!: (value: VaultTunnelAuthenticationEnvelope) => void,
      reject!: (e: Error) => void,
      closing = false,
      cleanup: Promise<void> | undefined,
      sealing: Promise<VaultTunnelAuthenticationEnvelope> | undefined,
      storage: StorageSession | undefined,
      preparation: Promise<void> | undefined,
      published = false,
      presented = false,
      cookieDigest: string | undefined,
      cookieChanged:
        | ((_event: unknown, cookie: Electron.Cookie, cause: string, removed: boolean) => void)
        | undefined;
    const result = new Promise<VaultTunnelAuthenticationEnvelope>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const current = () => !closing && !window.isDestroyed() && ownerCurrent();
    const retain = async (envelope: VaultTunnelAuthenticationEnvelope) => {
      if (storage) {
        await storage.capture();
        if (!current()) throw unavailable();
      }
      return envelope;
    };
    const stop = (): Promise<void> => {
      if (cleanup) return cleanup;
      closing = true;
      abort.abort();
      clearTimeout(timer);
      if (cookieChanged) session.cookies.removeListener('changed', cookieChanged);
      signal.removeEventListener('abort', cancel);
      const task = Promise.resolve().then(async () => {
        if (!window.isDestroyed()) window.destroy();
        if (!window.isDestroyed()) throw unavailable();
        this.options.forget?.(window);
        // Close native custody concurrently, then join startup/sealing and retry
        // exact late handles before releasing this actor's reservation.
        const storageClose = storage?.close();
        const pending = await Promise.allSettled([preparation, sealing, storageClose]);
        await storage?.close();
        if (pending[2].status === 'rejected') throw unavailable();
        await session.closeAllConnections();
        await session.clearStorageData();
        await session.clearCache();
        await session.clearAuthCache();
        this.unwatchOwner(parent, actor);
        this.uncertain.delete(actor);
        if (this.actors.get(key(context)) === actor) this.actors.delete(key(context));
      });
      const tracked = task.catch(() => {
        this.uncertain.add(actor);
        if (cleanup === tracked) cleanup = undefined;
        throw unavailable();
      });
      cleanup = tracked;
      return tracked;
    };
    const finish = (envelope?: VaultTunnelAuthenticationEnvelope): Promise<void> => {
      const valid = Boolean(envelope) && current();
      return stop().then(
        () => {
          if (valid && ownerCurrent()) resolve(envelope!);
          else reject(unavailable());
        },
        () => {
          reject(unavailable());
          throw unavailable();
        },
      );
    };
    const cancel = () => {
      void finish().catch(() => {});
    };
    const present = () => {
      if (presented || !published || !current()) return;
      presented = true;
      try {
        (this.options.present ?? ((w) => w.show()))(window);
      } catch {
        cancel();
      }
    };
    const timer = setTimeout(cancel, 300000);
    timer.unref();
    const actor: Actor = { context, window, cancel: () => finish() };
    this.actors.set(key(context), actor);
    this.watchOwner(parent, actor);
    const inspect = (raw: string): boolean => {
      if (!('callbackURL' in context)) return false;
      let u: URL;
      try {
        u = new URL(raw);
      } catch {
        return false;
      }
      if (u.origin !== new URL(context.callbackURL).origin) return false;
      if (closing || sealing) return true;
      const token = tunnelBrowserCallbackToken(raw, context);
      if (!token || !current()) {
        token?.fill(0);
        cancel();
        return true;
      }
      sealing = sealTunnelBrowserToken(context, token, abort.signal).then(retain);
      void sealing
        .then(
          (envelope) => finish(envelope),
          () => finish(),
        )
        .catch(() => {});
      return true;
    };
    const sealCredential = (challenge: VaultTunnelCookieContext, credential: string) => {
      if (sealing || !current() || !published) return;
      sealing = sealTunnelCookie(
        challenge,
        new TextEncoder().encode(credential),
        abort.signal,
      ).then(retain);
      void sealing
        .then(
          (envelope) => finish(envelope),
          () => finish(),
        )
        .catch(() => {});
    };
    const gatewayOrigin = new URL(context.startURL).origin;
    const navigation = (
      event: Electron.Event<{
        isMainFrame: boolean;
        url: string;
        initiator?: { url: string } | null;
      }>,
      redirect = false,
    ) => {
      if (!event.isMainFrame) return;
      if ('completion' in context) {
        const target = fortinetSSLLoopback(event.url, gatewayOrigin);
        if (target) {
          event.preventDefault();
          if (!redirect && isFortinetSSLCallbackSource(event.initiator?.url ?? '', gatewayOrigin)) {
            const id = fortinetSSLCallbackAuthId(target);
            if (id) sealCredential(context, id);
            else cancel();
          }
          return;
        }
      }
      if (inspect(event.url)) {
        event.preventDefault();
        return;
      }
      try {
        const u = new URL(event.url);
        if (u.protocol === 'https:' && allowedResource(u, context, 'mainFrame') && current())
          return;
      } catch {}
      event.preventDefault();
      cancel();
    };
    try {
      if ((this.options.platform ?? process.platform) !== 'linux') protectSecretWindow(window);
      window.setMenu(null);
      session.setPermissionRequestHandler((_c, _p, callback) => callback(false));
      session.setPermissionCheckHandler(() => false);
      session.on('will-download', (event) => event.preventDefault());
      if ('cookieName' in context) {
        session.webRequest.onHeadersReceived((details, callback) => {
          try {
            if (
              current() &&
              details.webContentsId === window.webContents.id &&
              details.statusCode >= 200 &&
              details.statusCode < 400 &&
              new URL(details.url).origin === new URL(context.startURL).origin
            ) {
              const digest = tunnelCookieResponseDigest(details.responseHeaders);
              if (digest !== undefined) {
                cookieDigest = digest ?? undefined;
              }
            }
          } catch {
            cancel();
          }
          callback({ cancel: !current() });
        });
        cookieChanged = (_event, cookie, _cause, removed) => {
          if (
            removed ||
            !current() ||
            sealing ||
            !cookieDigest ||
            cookie.name !== context.cookieName ||
            !cookie.httpOnly
          )
            return;
          const target = new URL(context.startURL);
          const domain = (cookie.domain ?? '').toLowerCase().replace(/^\./, ''),
            host = target.hostname.toLowerCase();
          if (!domain) return;
          if (host !== domain && (cookie.hostOnly || !host.endsWith('.' + domain))) return;
          const path = cookie.path || '/';
          if (
            !target.pathname.startsWith(path) ||
            (target.pathname.length > path.length &&
              !path.endsWith('/') &&
              target.pathname[path.length] !== '/')
          )
            return;
          if (tunnelCookieDigest(cookie.value) !== cookieDigest) return;
          sealCredential(context, cookie.value);
        };
        session.cookies.on('changed', cookieChanged);
      } else if ('completion' in context) {
        session.webRequest.onHeadersReceived((details, callback) => {
          if (
            !current() ||
            !published ||
            details.webContentsId !== window.webContents.id ||
            details.resourceType !== 'mainFrame' ||
            ![301, 302, 303, 307, 308].includes(details.statusCode) ||
            !isFortinetSSLCallbackSource(details.url, gatewayOrigin)
          ) {
            callback({ cancel: !current() });
            return;
          }
          const locations = Object.entries(details.responseHeaders ?? {})
            .filter(([name]) => name.toLowerCase() === 'location')
            .flatMap(([, values]) => values);
          const target = locations
            .map((url) => fortinetSSLLoopback(url, gatewayOrigin))
            .find((url) => url !== undefined);
          callback({ cancel: Boolean(target) });
          if (target) {
            const id = locations.length === 1 && fortinetSSLCallbackAuthId(target);
            if (id) sealCredential(context, id);
            else cancel();
          }
        });
      }

      session.webRequest.onBeforeRequest((details, callback) => {
        let cancelRequest = true;
        try {
          const u = new URL(details.url);
          if ('callbackURL' in context && u.origin === new URL(context.callbackURL).origin) {
            callback({ cancel: true });
            if (
              details.resourceType === 'mainFrame' &&
              details.webContentsId === window.webContents.id
            )
              inspect(details.url);
            return;
          }
          cancelRequest =
            !current() ||
            !allowedResource(u, context, details.resourceType) ||
            (storage
              ? !storage.permitsRequest(
                  details.url,
                  details.webContentsId ?? -1,
                  details.resourceType,
                )
              : !published);
        } catch {}
        callback({ cancel: cancelRequest });
      });
      window.webContents.on('certificate-error', (event, url, _error, _certificate, callback) => {
        let allowed = false;
        try {
          allowed =
            current() &&
            context.ignoreCertificateErrors &&
            new URL(url).origin === new URL(context.startURL).origin;
        } catch {}
        event.preventDefault();
        callback(allowed);
      });
      window.webContents.on('will-navigate', (event) => navigation(event));
      window.webContents.on('will-redirect', (event) => navigation(event, true));
      window.webContents.on('will-frame-navigate', (event) => {
        if (event.isMainFrame) navigation(event);
      });
      window.webContents.setWindowOpenHandler(({ url }) => {
        if (!inspect(url)) {
          try {
            const u = new URL(url);
            if (current() && u.protocol === 'https:' && allowedResource(u, context, 'mainFrame'))
              void window.loadURL(u.href).catch(() => {});
          } catch {}
        }
        return { action: 'deny' };
      });
      window.webContents.on('before-input-event', (event, input) => {
        if (
          ['F5', 'F12'].includes(input.key) ||
          ((input.control || input.meta) && ['p', 's', 'r'].includes(input.key.toLowerCase()))
        )
          event.preventDefault();
      });
      window.webContents.on('context-menu', (event) => event.preventDefault());
      window.webContents.once('render-process-gone', cancel);
      window.once('closed', cancel);
      window.once('ready-to-show', present);
      window.webContents.on('did-fail-load', (_event, code, _description, _url, main) => {
        if (main && code !== -3) cancel();
      });
      signal.addEventListener('abort', cancel, { once: true });
      storage = this.options.storage?.({
        window,
        current,
        failed: cancel,
        context,
        signal: abort.signal,
        request,
        ...(source ? { fallback: source } : {}),
      });
      preparation = (async () => {
        if (storage) await storage.restore();
        if (!current()) throw unavailable();
        published = true;
      })();
      void preparation
        .then(() => {
          if (!current()) {
            cancel();
            return;
          }
          // Native window destruction terminates navigation. Its observer may
          // complete late, and must never show a retired or replacement actor.
          void window
            .loadURL(context.startURL)
            .then(() => {
              if (current()) present();
              else cancel();
            })
            .catch(() => {});
        })
        // Redirects may abort the original load promise. did-fail-load owns
        // actual failures; an aborted promise must not cancel token sealing.
        .catch(cancel);
      if (!current()) cancel();
    } catch {
      cancel();
    }
    return result;
  }
  private watchOwner(parent: BrowserWindow, actor: Actor) {
    let owner = this.owners.get(parent);
    if (!owner) {
      const actors = new Set<Actor>();
      const cancel = () => {
        for (const current of [...actors]) void current.cancel().catch(() => {});
      };
      const navigation = (_e: unknown, _url: string, _inPlace: boolean, main: boolean) => {
        if (main) cancel();
      };
      owner = { actors, cancel, navigation };
      this.owners.set(parent, owner);
      parent.on('closed', cancel);
      parent.webContents.on('did-start-navigation', navigation);
      parent.webContents.on('render-process-gone', cancel);
    }
    owner.actors.add(actor);
  }
  private unwatchOwner(parent: BrowserWindow, actor: Actor) {
    const owner = this.owners.get(parent);
    if (!owner) return;
    owner.actors.delete(actor);
    if (owner.actors.size) return;
    parent.removeListener('closed', owner.cancel);
    parent.webContents.removeListener('did-start-navigation', owner.navigation);
    parent.webContents.removeListener('render-process-gone', owner.cancel);
    this.owners.delete(parent);
  }
  cancelChallenge(value: BrowserContext): Promise<void> {
    const context = parseContext(value);
    if (!context) return Promise.reject(unavailable());
    return this.actors.get(key(context))?.cancel() ?? Promise.resolve();
  }
}
