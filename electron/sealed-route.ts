import {
  parseVaultTunnelAuthenticationChallenge,
  parseVaultTunnelAuthenticationEnvelope,
  type VaultTunnelAuthenticationContext,
  type VaultTunnelAuthenticationEnvelope,
} from './vault-tunnel-authentication.ts';
import {
  parseVaultTunnelBrowserChallenge,
  parseVaultTunnelBrowserEnvelope,
  type VaultTunnelBrowserContext,
} from './vault-tunnel-browser.ts';
import {
  parseVaultTunnelCookieChallenge,
  parseVaultTunnelCookieEnvelope,
  type VaultTunnelCookieContext,
} from './vault-tunnel-cookie.ts';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { stopChildProcess } from './rdp.ts';
import { parseVaultNativeObject, vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  validVaultRouteEndpoint,
  parseVaultRouteBinding,
  parseVaultRouteBundle,
  parseVaultRoutePlanRequest,
  type VaultRouteBinding,
  type VaultRouteBundle,
  type VaultRoutePlanRequest,
  type VaultRouteRequest,
} from './vault-route.ts';
import {
  parseVaultTunnelFallbackBinding,
  parseVaultTunnelFallbackBundle,
  type VaultTunnelFallbackBinding,
  type VaultTunnelFallbackBundle,
  type VaultTunnelFallbackPlanRequest,
  type VaultTunnelFallbackRequest,
} from './vault-tunnel-fallback.ts';

export type SealedRouteOpen = { sessionId: string; nodeId: string; credentialId?: string };
export type SealedRouteLease = {
  readonly binding: Readonly<VaultRouteBinding>;
  readonly endpoint: string;
  readonly active: boolean;
  readonly closed: Promise<void>;
  release(): Promise<void>;
};
type Options = {
  executable: () => string;
  workspaceId: () => string | undefined;
  authorized: (epoch: number) => boolean;
  plan: (request: VaultRoutePlanRequest) => Promise<VaultRouteBinding>;
  bundle: (request: VaultRouteRequest) => Promise<VaultRouteBundle>;
  fallback?: {
    plan(request: VaultTunnelFallbackPlanRequest): Promise<VaultTunnelFallbackBinding>;
    bundle(request: VaultTunnelFallbackRequest): Promise<VaultTunnelFallbackBundle>;
  };
  timeoutMs?: number;
  authentication?: {
    prompt: (
      context:
        | VaultTunnelAuthenticationContext
        | VaultTunnelBrowserContext
        | VaultTunnelCookieContext,
      current: () => boolean,
      signal: AbortSignal,
      request: Readonly<VaultRoutePlanRequest>,
      fallback?: Readonly<VaultTunnelFallbackBinding>,
    ) => Promise<VaultTunnelAuthenticationEnvelope>;
    close: (
      context:
        | VaultTunnelAuthenticationContext
        | VaultTunnelBrowserContext
        | VaultTunnelCookieContext,
    ) => Promise<void>;
  };
};
type Spawn = (executable: string, args: string[]) => ChildProcessWithoutNullStreams;
type Consumer = {
  request: VaultRoutePlanRequest;
  owner: () => boolean;
  resolve: (lease: SealedRouteLease) => void;
  reject: (error: Error) => void;
  end: () => void;
  closed: Promise<void>;
  timer: NodeJS.Timeout;
  binding?: VaultRouteBinding;
  entry?: Entry;
  fallbackKey?: string;
};
type Entry = {
  key: string;
  baseKey: string;
  request: VaultRoutePlanRequest;
  binding: VaultRouteBinding;
  child: ChildProcessWithoutNullStreams;
  consumers: Set<Consumer>;
  retiredSessions: Set<string>;
  phase:
    | 'recipient'
    | 'bundle'
    | 'connecting'
    | 'authenticating'
    | 'ready'
    | 'retired'
    | 'retiring-primary'
    | 'planning-fallback';
  fallback?: VaultTunnelFallbackBinding;
  transition?: Promise<void>;
  origin: Consumer;
  authentication?: {
    context:
      | VaultTunnelAuthenticationContext
      | VaultTunnelBrowserContext
      | VaultTunnelCookieContext;
    abort: AbortController;
    work: Promise<void>;
  };
  chunks: Buffer[];
  bytes: number;
  timer: NodeJS.Timeout;
  endpoint?: string;
  primaryRecipient?: string;
  stop?: Promise<void>;
};

// Metadata-only edits may advance rowVersion without changing the running
// configuration. Every consumer nevertheless obtains its own fresh native plan.
function routeKey(b: VaultRouteBinding): string {
  return JSON.stringify([
    b.workspaceId,
    b.fileId,
    b.epoch,
    b.tunnelConfigId,
    b.kind,
    b.configurationVersion,
  ]);
}

function fallbackKey(pair: VaultTunnelFallbackBinding): string {
  return JSON.stringify([routeKey(pair.primary), routeKey(pair.fallback)]);
}

/** Main-only pool. Leases and endpoints must never cross renderer IPC. */
export class SealedRouteBroker {
  private readonly consumers = new Map<string, Consumer>();
  private readonly entries = new Map<string, Entry>();
  private readonly options: Options;
  private readonly spawnChild: Spawn;
  private closing?: Promise<void>;
  private closingPending = false;
  private readonly timeout: number;

  constructor(
    options: Options,
    spawnChild: Spawn = (exe, args) => spawn(exe, args, { stdio: 'pipe', windowsHide: true }),
  ) {
    this.timeout = options.timeoutMs ?? 330000;
    if (!Number.isSafeInteger(this.timeout) || this.timeout < 1 || this.timeout > 360000)
      throw Error('Invalid route timeout.');
    this.options = options;
    this.spawnChild = spawnChild;
  }

  acquire(
    value: SealedRouteOpen,
    epoch: number,
    owner: () => boolean = () => true,
  ): Promise<SealedRouteLease> {
    if (
      !vaultRecord(value) ||
      Object.keys(value).some((key) => !['sessionId', 'nodeId', 'credentialId'].includes(key)) ||
      !vaultID(value.sessionId) ||
      !vaultID(value.nodeId) ||
      (value.credentialId !== undefined && !vaultID(value.credentialId))
    )
      return Promise.reject(Error('Invalid route request.'));
    const request = parseVaultRoutePlanRequest({
      workspaceId: this.options.workspaceId(),
      nodeId: value.nodeId,
      credentialOverride: value.credentialId ?? '',
      sessionId: value.sessionId,
      requestId: randomUUID(),
      epoch,
    });
    if (
      !request ||
      this.closing ||
      this.consumers.size >= 128 ||
      this.consumers.has(request.sessionId) ||
      [...this.entries.values()].some((e) => e.retiredSessions.has(request.sessionId))
    )
      return Promise.reject(Error('Vault route is unavailable.'));
    return new Promise((resolve, reject) => {
      let end!: () => void;
      const closed = new Promise<void>((done) => {
        end = done;
      });
      const c: Consumer = {
        request,
        owner,
        resolve,
        reject,
        closed,
        end,
        timer: setTimeout(() => {
          void this.release(c).catch(() => undefined);
        }, this.timeout),
      };
      this.consumers.set(request.sessionId, c);
      if (!this.current(c)) {
        void this.release(c).catch(() => undefined);
        return;
      }
      void this.prepare(c).catch(() => {
        void this.release(c).catch(() => undefined);
      });
    });
  }

  private authorized(request: VaultRoutePlanRequest): boolean {
    try {
      return (
        !this.closing &&
        this.options.workspaceId() === request.workspaceId &&
        this.options.authorized(request.epoch)
      );
    } catch {
      return false;
    }
  }
  private current(c: Consumer): boolean {
    try {
      return (
        this.consumers.get(c.request.sessionId) === c && this.authorized(c.request) && c.owner()
      );
    } catch {
      return false;
    }
  }
  private live(e: Entry): boolean {
    return (
      e.phase !== 'retired' &&
      this.entries.get(e.key) === e &&
      [...e.consumers].some((c) => this.current(c)) &&
      this.authorized(e.request)
    );
  }

  private async prepare(c: Consumer): Promise<void> {
    const result = await this.options.plan({ ...c.request });
    if (!this.current(c)) throw Error('Vault route is unavailable.');
    const binding = parseVaultRouteBinding(result, c.request);
    if (!binding) throw Error('Invalid route plan.');
    if (this.quarantined([binding])) throw Error('Vault route is stopping.');
    c.binding = binding;
    const key = routeKey(binding);
    let e = this.entries.get(key);
    if (
      !e &&
      this.options.fallback &&
      [...this.entries.values()].some((entry) => entry.baseKey === key && entry.fallback)
    ) {
      const pair = await this.planFallback(c);
      if (this.quarantined([pair.primary, pair.fallback])) throw Error('Vault route is stopping.');
      e = this.entries.get(fallbackKey(pair)) ?? this.entries.get(key);
      if (e?.fallback) c.fallbackKey = e.key;
    }
    if (e) {
      if (!this.live(e)) throw Error('Vault route is stopping.');
      e.consumers.add(c);
      c.entry = e;
      if (e.phase === 'ready') this.publish(c, e);
      return;
    }
    if (this.entries.size >= 32) throw Error('Route limit reached.');
    const child = this.spawnChild(this.options.executable(), [
      '--operation',
      binding.kind === 9 && this.options.fallback ? 'tunnel-primary-sealed' : 'tunnel-sealed',
    ]);
    e = {
      key,
      baseKey: key,
      request: c.request,
      binding,
      child,
      consumers: new Set([c]),
      retiredSessions: new Set(),
      phase: 'recipient',
      origin: c,
      chunks: [],
      bytes: 0,
      timer: setTimeout(() => this.fail(e!), this.timeout),
    };
    c.entry = e;
    this.entries.set(key, e);
    this.watch(e, child);
  }

  private quarantined(bindings: VaultRouteBinding[]): boolean {
    return [...this.entries.values()].some(
      (e) =>
        e.phase === 'retired' &&
        bindings.some((binding) =>
          [e.binding, ...(e.fallback ? [e.fallback.fallback] : [])].some(
            (source) =>
              source.workspaceId === binding.workspaceId &&
              source.fileId === binding.fileId &&
              source.tunnelConfigId === binding.tunnelConfigId,
          ),
        ),
    );
  }

  private watch(e: Entry, child: ChildProcessWithoutNullStreams): void {
    const current = () => e.child === child && this.entries.get(e.key) === e;
    const fail = () => {
      if (current()) this.fail(e);
    };
    child.on('error', fail);
    child.stdin.on('error', fail);
    child.stdout.on('error', fail);
    child.stderr.on('error', fail);
    child.stderr.on('data', () => {});
    child.stdout.on('data', (chunk: Buffer) => {
      if (current()) this.receive(e, chunk);
    });
    const end = () => {
      if (current() && e.phase !== 'retiring-primary' && e.phase !== 'planning-fallback')
        this.fail(e);
    };
    child.stdout.on('end', end);
    // Descendants may retain stdio after the route owner has exited. Revoke
    // leases immediately; pipe closure is only an additional failure signal.
    child.once('exit', end);
    child.once('close', end);
  }

  private async planFallback(c: Consumer): Promise<VaultTunnelFallbackBinding> {
    if (!this.current(c) || !c.binding || c.binding.kind !== 9 || !this.options.fallback)
      throw Error('Vault fallback is unavailable.');
    const q = { ...c.request, primary: { ...c.binding }, fallbackRequestId: randomUUID() };
    const result = await this.options.fallback.plan(structuredClone(q));
    if (!this.current(c)) throw Error('Vault fallback is unavailable.');
    const pair = parseVaultTunnelFallbackBinding(result, q);
    if (!pair) throw Error('Invalid vault fallback plan.');
    return pair;
  }

  private async admitFallback(c: Consumer, e: Entry): Promise<void> {
    const pair = await this.planFallback(c);
    if (
      !this.live(e) ||
      c.entry !== e ||
      fallbackKey(pair) !== e.key ||
      this.quarantined([pair.primary, pair.fallback])
    )
      throw Error('Vault fallback changed.');
    c.fallbackKey = e.key;
    if (e.phase === 'ready') this.publish(c, e);
  }

  private beginFallback(e: Entry): void {
    e.phase = 'retiring-primary';
    e.authentication?.abort.abort();
    const task = Promise.resolve()
      .then(async () => {
        const auth = e.authentication;
        const retired = await Promise.allSettled([
          stopChildProcess(e.child, {
            gracefulTimeoutMs: 8000,
            forceKill: false,
            nativeExecutable: this.options.executable(),
          }).then((stopped) => {
            if (!stopped) throw Error('VPN shutdown could not be confirmed.');
          }),
          ...(auth
            ? [this.options.authentication!.close(structuredClone(auth.context)), auth.work]
            : []),
        ]);
        if (retired.some((r) => r.status === 'rejected'))
          throw Error('VPN shutdown could not be confirmed.');
        if (!this.live(e)) throw Error('Vault fallback is unavailable.');
        e.authentication = undefined;
        if (!this.current(e.origin)) {
          const origin = [...e.consumers].find((c) => this.current(c) && c.binding);
          if (!origin?.binding) throw Error('Vault fallback is unavailable.');
          e.origin = origin;
          e.request = origin.request;
          e.binding = origin.binding;
        }
        e.phase = 'planning-fallback';
        const pair = await this.planFallback(e.origin);
        if (
          !this.live(e) ||
          !this.current(e.origin) ||
          this.quarantined([pair.primary, pair.fallback])
        )
          throw Error('Vault fallback is unavailable.');
        const key = fallbackKey(pair);
        if (this.entries.has(key)) throw Error('Vault fallback is already owned.');
        if (this.entries.get(e.key) === e) this.entries.delete(e.key);
        e.key = key;
        e.fallback = pair;
        e.origin.fallbackKey = key;
        this.entries.set(key, e);
        for (const c of [...e.consumers]) {
          if (c === e.origin) continue;
          try {
            await this.admitFallback(c, e);
          } catch {
            this.detach(c);
          }
        }
        if (!this.live(e) || !this.current(e.origin)) throw Error('Vault fallback is unavailable.');
        const child = this.spawnChild(this.options.executable(), [
          '--operation',
          'tunnel-fallback-sealed',
        ]);
        e.child = child;
        e.phase = 'recipient';
        e.chunks = [];
        e.bytes = 0;
        this.watch(e, child);
        if (!this.live(e)) throw Error('Vault fallback is unavailable.');
      })
      .catch(() => this.fail(e));
    e.transition = task;
    void task.finally(() => {
      if (e.transition === task) e.transition = undefined;
    });
  }

  private receive(e: Entry, chunk: Buffer): void {
    try {
      if (!this.live(e) || !Buffer.isBuffer(chunk) || this.transitioning(e)) {
        this.fail(e);
        return;
      }
      let offset = 0;
      while (offset < chunk.length && e.phase !== 'retired') {
        const newline = chunk.indexOf(10, offset),
          end = newline < 0 ? chunk.length : newline;
        const part = chunk.subarray(offset, end);
        if (e.bytes + part.length > 32768 || e.chunks.length >= 1024) {
          this.fail(e);
          return;
        }
        e.chunks.push(part);
        e.bytes += part.length;
        if (newline < 0) return;
        const raw = Buffer.concat(e.chunks, e.bytes);
        e.chunks = [];
        e.bytes = 0;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(
          raw.at(-1) === 13 ? raw.subarray(0, -1) : raw,
        );
        const value = parseVaultNativeObject(text);
        if (
          raw.length > 1024 &&
          (!vaultRecord(value) ||
            (value.type !== 'browser-authentication-required' &&
              value.type !== 'cookie-authentication-required'))
        ) {
          this.fail(e);
          return;
        }
        this.line(e, value);
        offset = newline + 1;
        if (this.transitioning(e) && offset < chunk.length) {
          this.fail(e);
          return;
        }
      }
    } catch {
      this.fail(e);
    }
  }
  private transitioning(e: Entry): boolean {
    return e.phase === 'retiring-primary' || e.phase === 'planning-fallback';
  }
  private line(e: Entry, value: unknown): void {
    if (!this.live(e) || !vaultRecord(value)) {
      this.fail(e);
      return;
    }
    if (value.type === 'fallback-required') {
      if (
        !vaultFields(value, ['type', 'sessionId', 'requestId']) ||
        value.sessionId !== e.request.sessionId ||
        value.requestId !== e.request.requestId ||
        e.binding.kind !== 9 ||
        e.fallback ||
        e.transition ||
        e.phase !== 'connecting' ||
        !this.options.fallback
      ) {
        this.fail(e);
        return;
      }
      this.beginFallback(e);
      return;
    }
    if (e.phase === 'recipient') {
      if (
        !vaultFields(value, ['type', 'publicKey']) ||
        value.type !== 'recipient' ||
        !canonicalBase64(value.publicKey, 32, 32) ||
        (e.fallback !== undefined && value.publicKey === e.primaryRecipient)
      ) {
        this.fail(e);
        return;
      }
      if (!e.fallback) e.primaryRecipient = value.publicKey;
      const request: VaultRouteRequest = { ...e.request, publicKey: value.publicKey };
      const child = e.child;
      const fallbackRequest = e.fallback
        ? { ...e.request, binding: structuredClone(e.fallback), publicKey: value.publicKey }
        : undefined;
      e.phase = 'bundle';
      void Promise.resolve()
        .then(async (): Promise<VaultRouteBundle | VaultTunnelFallbackBundle> => {
          if (!this.live(e) || e.child !== child) throw Error('Vault route is unavailable.');
          return fallbackRequest
            ? this.options.fallback!.bundle(structuredClone(fallbackRequest))
            : this.options.bundle({ ...request });
        })
        .then((result) => {
          if (!this.live(e) || e.child !== child) {
            this.fail(e);
            return;
          }
          const bundle = fallbackRequest
            ? parseVaultTunnelFallbackBundle(result, fallbackRequest)
            : parseVaultRouteBundle(result, request);
          if (
            !bundle ||
            JSON.stringify(bundle.binding) !== JSON.stringify(e.fallback ?? e.binding)
          ) {
            this.fail(e);
            return;
          }
          const frame = JSON.stringify(bundle) + '\n';
          if (Buffer.byteLength(frame) + child.stdin.writableLength > 8 * 1024 * 1024) {
            this.fail(e);
            return;
          }
          e.phase = 'connecting';
          child.stdin.write(frame, (error) => {
            if (error && e.child === child) this.fail(e);
          });
        })
        .catch(() => {
          if (e.child === child) this.fail(e);
        });
      return;
    }
    if (
      value.type === 'authentication-required' ||
      value.type === 'browser-authentication-required' ||
      value.type === 'cookie-authentication-required'
    ) {
      const cookie = value.type === 'cookie-authentication-required';
      const browser = value.type === 'browser-authentication-required';
      const activeBinding = e.fallback?.fallback ?? e.binding;
      const child = e.child;
      const context = cookie
        ? parseVaultTunnelCookieChallenge(value, activeBinding)
        : browser
          ? parseVaultTunnelBrowserChallenge(value, activeBinding)
          : parseVaultTunnelAuthenticationChallenge(value, activeBinding);
      if (
        e.phase !== 'connecting' ||
        e.authentication ||
        !context ||
        !this.options.authentication ||
        !this.current(e.origin) ||
        !e.consumers.has(e.origin)
      ) {
        this.fail(e);
        return;
      }
      const abort = new AbortController();
      const active = () =>
        this.live(e) &&
        e.child === child &&
        this.current(e.origin) &&
        e.consumers.has(e.origin) &&
        !abort.signal.aborted;
      e.phase = 'authenticating';
      const auth = { context, abort, work: Promise.resolve() };
      e.authentication = auth;
      auth.work = Promise.resolve()
        .then(async () => {
          if (!active()) throw Error('VPN authentication closed.');
          const result = await this.options.authentication!.prompt(
            structuredClone(context),
            active,
            abort.signal,
            Object.freeze({ ...e.request }),
            ...(e.fallback ? [structuredClone(e.fallback)] : []),
          );
          const envelope = cookie
            ? parseVaultTunnelCookieEnvelope(result)
            : browser
              ? parseVaultTunnelBrowserEnvelope(result)
              : parseVaultTunnelAuthenticationEnvelope(result);
          if (!active() || !envelope) throw Error('VPN authentication closed.');
          const frame =
            JSON.stringify({
              type: cookie
                ? 'cookie-authentication'
                : browser
                  ? 'browser-authentication'
                  : 'authentication',
              sessionId: e.request.sessionId,
              challengeId: context.challengeId,
              envelope,
            }) + '\n';
          if (Buffer.byteLength(frame) + child.stdin.writableLength > 8 * 1024 * 1024)
            throw Error('VPN input unavailable.');
          e.phase = 'connecting';
          child.stdin.write(frame, (error) => {
            if (error && e.child === child) this.fail(e);
          });
        })
        .catch(() => {
          if (e.child === child) this.fail(e);
        });
      return;
    }
    if (
      e.phase !== 'connecting' ||
      !vaultFields(value, ['type', 'sessionId', 'endpoint']) ||
      value.type !== 'ready' ||
      value.sessionId !== e.request.sessionId ||
      !validVaultRouteEndpoint(value.endpoint)
    ) {
      this.fail(e);
      return;
    }
    e.endpoint = value.endpoint;
    e.phase = 'ready';
    clearTimeout(e.timer);
    for (const c of [...e.consumers]) this.publish(c, e);
  }
  private publish(c: Consumer, e: Entry): void {
    if (!this.current(c) || !this.live(e) || !c.binding || !e.endpoint) {
      void this.release(c).catch(() => undefined);
      return;
    }
    if (e.fallback && c.fallbackKey !== e.key) return;
    clearTimeout(c.timer);
    const broker = this;
    c.resolve(
      Object.freeze({
        binding: Object.freeze({ ...c.binding }),
        endpoint: e.endpoint,
        closed: c.closed,
        get active() {
          return broker.current(c) && broker.live(e) && e.phase === 'ready';
        },
        release: () => this.release(c),
      }),
    );
  }

  private detach(c: Consumer): void {
    if (this.consumers.get(c.request.sessionId) === c) this.consumers.delete(c.request.sessionId);
    clearTimeout(c.timer);
    c.entry?.consumers.delete(c);
    c.reject(Error('Vault route closed.'));
    c.end();
  }
  private release(c: Consumer): Promise<void> {
    const e = c.entry;
    this.detach(c);
    if (
      e &&
      (e.consumers.size === 0 || (e.authentication && e.phase !== 'ready' && e.origin === c))
    ) {
      e.retiredSessions.add(c.request.sessionId);
      return this.stop(e);
    }
    return Promise.resolve();
  }
  private fail(e: Entry): void {
    void this.stop(e).catch(() => undefined);
  }
  private stop(e: Entry): Promise<void> {
    if (e.stop) return e.stop;
    e.phase = 'retired';
    e.authentication?.abort.abort();
    clearTimeout(e.timer);
    e.chunks = [];
    e.bytes = 0;
    for (const c of [...e.consumers]) {
      e.retiredSessions.add(c.request.sessionId);
      this.detach(c);
    }
    const task = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        ...(e.transition ? [e.transition] : []),
        stopChildProcess(e.child, {
          gracefulTimeoutMs: 8000,
          forceKill: false,
          nativeExecutable: this.options.executable(),
        }).then((stopped) => {
          if (!stopped) throw Error('VPN shutdown could not be confirmed.');
        }),
        ...(e.authentication
          ? [
              Promise.resolve().then(() =>
                this.options.authentication!.close(structuredClone(e.authentication!.context)),
              ),
              e.authentication.work,
            ]
          : []),
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('VPN shutdown could not be confirmed.');
      if (this.entries.get(e.key) === e) this.entries.delete(e.key);
    });
    const tracked = task.catch((error) => {
      if (e.stop === tracked) e.stop = undefined;
      throw error;
    });
    e.stop = tracked;
    return tracked;
  }
  close(sessionId: string): Promise<void> {
    const c = this.consumers.get(sessionId);
    if (c) return this.release(c);
    // Pending acquisition has no lease receipt yet. Retain its session identity
    // so protocol-owner retries still join the same unconfirmed cleanup.
    const e = [...this.entries.values()].find((entry) => entry.retiredSessions.has(sessionId));
    return e ? this.stop(e) : Promise.resolve();
  }
  closeAll(): Promise<void> {
    if (this.closing && this.closingPending) return this.closing;
    this.closingPending = true;
    // Reserve shutdown before ending streams: callbacks can synchronously reenter.
    const task = Promise.resolve().then(async () => {
      for (const c of [...this.consumers.values()]) {
        c.entry?.retiredSessions.add(c.request.sessionId);
        this.detach(c);
      }
      const results = await Promise.allSettled([...this.entries.values()].map((e) => this.stop(e)));
      if (results.some((r) => r.status === 'rejected'))
        throw Error('VPN shutdown could not be confirmed.');
    });
    const tracked = task.then(
      () => {
        if (this.closing === tracked) {
          this.closing = undefined;
          this.closingPending = false;
        }
      },
      (error) => {
        if (this.closing === tracked) this.closingPending = false;
        // A rejected shutdown remains an admission barrier until an explicit
        // retry confirms the original native process has stopped.
        throw error;
      },
    );
    this.closing = tracked;
    return tracked;
  }
}
