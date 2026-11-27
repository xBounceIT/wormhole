import { randomUUID } from 'node:crypto';
import type { Session, WebContents, WebFrameMain } from 'electron';
import {
  bitwardenDocumentPacketBytes,
  bitwardenDocumentTimeoutMs,
  parseBitwardenBridgeOwner,
  parseBitwardenBridgeReceipt,
  type BitwardenBridgeOwner,
  type BitwardenDocumentOperation,
  type BitwardenExtensionBridge,
} from './vault-bitwarden-bridge-contract.ts';
import {
  parseBrowserTransferRequest,
  parseBrowserProfileClosed,
  parseBrowserTransferCancelled,
} from './vault-bitwarden-native.ts';
import {
  browserTransferChunkCount,
  parseBrowserTransferContext,
  parseBrowserTransferManifest,
  parseBrowserTransferPacket,
  type BrowserTransferContext,
} from './vault-bitwarden-transfer.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';

type Contents = Pick<
  WebContents,
  | 'mainFrame'
  | 'session'
  | 'getType'
  | 'isLoadingMainFrame'
  | 'isDestroyed'
  | 'on'
  | 'removeListener'
>;
export type BitwardenDocumentFrame = {
  processId: number;
  routingId: number;
  frameToken: string;
  osProcessId: number;
};
type Options = {
  contents: Contents;
  session: Session;
  url: string;
  owner: unknown;
  asset: string;
  current(): boolean;
  // Supplied only by the trusted native profile owner, never by page IPC.
  sandboxed(frame: Readonly<BitwardenDocumentFrame>): boolean;
};
const unavailable = () => Error('Bitwarden document is unavailable.');

// Main-only endpoint. It owns one exact background document, never arbitrary
// JavaScript or storage access. All returned DTOs were validated in that world.
export class VaultBitwardenDocumentEndpoint implements BitwardenExtensionBridge {
  private readonly options: Options;
  private readonly owner: BitwardenBridgeOwner;
  private readonly frame: WebFrameMain;
  private readonly frameIdentity: Readonly<BitwardenDocumentFrame>;
  private readonly token = randomUUID();
  private readonly pending = new Set<{ reject(): void; cleanup: boolean }>();
  private readonly onNavigation = (
    event: { isMainFrame?: boolean },
    _url: string,
    _inPlace: boolean,
    main: boolean,
  ) => {
    if ((event.isMainFrame ?? main) !== false) this.revoke();
  };
  private readonly onGone = () => this.revoke();
  private initializing: Promise<void> | undefined;
  private closing: Promise<{ closed: true }> | undefined;
  private canceling: Promise<{ cancelled: true }> | undefined;
  private active: object | undefined;
  private sequence = 0;
  private generation = 0;
  private ready = false;
  private attempted = false;
  private injected = false;
  private bootstrapSettled = true;
  private revoked = false;
  private faulted = false;
  private closed = false;
  private disposed = false;

  constructor(options: Options) {
    try {
      const owner = parseBitwardenBridgeOwner(options.owner),
        url = new URL(options.url);
      if (
        !owner ||
        url.protocol !== 'chrome-extension:' ||
        !/^[a-p]{32}$/.test(url.hostname) ||
        url.username ||
        url.password ||
        url.port ||
        url.search ||
        url.hash ||
        url.href !== options.url ||
        options.url.length > 2048 ||
        typeof options.asset !== 'string' ||
        !options.asset.length ||
        Buffer.byteLength(options.asset) > 1024 * 1024
      )
        throw unavailable();
      this.options = { ...options, owner };
      this.owner = owner;
      this.frame = options.contents.mainFrame;
      this.frameIdentity = Object.freeze({
        osProcessId: this.frame.osProcessId,
        processId: this.frame.processId,
        routingId: this.frame.routingId,
        frameToken: this.frame.frameToken,
      });
      if (!this.sameDocument() || !options.current()) throw unavailable();
      options.contents.on('did-start-navigation', this.onNavigation);
      options.contents.on('render-process-gone', this.onGone);
      options.contents.on('destroyed', this.onGone);
    } catch {
      throw unavailable();
    }
  }

  initialize(): Promise<void> {
    if (this.ready) {
      try {
        this.check(false);
        return Promise.resolve();
      } catch {
        return Promise.reject(unavailable());
      }
    }
    if (this.initializing) return this.initializing;
    if (this.attempted || this.closed) return Promise.reject(unavailable());
    this.attempted = true;
    this.initializing = Promise.resolve()
      .then(async () => {
        const isolated = await this.evaluate(
          `typeof process==='undefined'&&typeof require==='undefined'&&typeof wormhole==='undefined'&&isSecureContext&&location.href===${JSON.stringify(this.options.url)}`,
          false,
          true,
          true,
        );
        this.check(false, true);
        if (isolated !== true) throw unavailable();
        const deadline = Date.now() + bitwardenDocumentTimeoutMs;
        const script = `if(Date.now()>=${deadline}||location.href!==${JSON.stringify(this.options.url)})throw Error('Bitwarden document is unavailable.');\n${this.options.asset}\nWormholeVaultBitwarden.install(${JSON.stringify(this.owner)},${JSON.stringify(this.token)},${JSON.stringify(this.options.url)})`;
        const raw = await this.evaluate(script, false, true);
        const value: unknown = this.decode(raw, 64);
        this.check(false, true);
        if (
          !vaultRecord(value) ||
          !vaultFields(value, ['ready', 'version']) ||
          value.ready !== true ||
          value.version !== 1
        )
          throw unavailable();
        this.ready = true;
      })
      .catch(() => {
        this.faulted = true;
        throw unavailable();
      })
      .finally(() => {
        this.initializing = undefined;
      });
    return this.initializing;
  }

  prepare() {
    return this.call(
      'prepare',
      () => null,
      (value) => {
        const q = parseBrowserTransferRequest(value);
        return q && this.owned(q) ? q : undefined;
      },
    );
  }

  bind(value: unknown) {
    return this.call(
      'bind',
      () => this.context(value),
      (result, input) => {
        const c = input as BrowserTransferContext;
        const manifest =
          vaultRecord(result) && vaultFields(result, ['chunks', 'manifest'])
            ? parseBrowserTransferManifest(result.manifest, c, 'capture')
            : undefined;
        return manifest &&
          (result as { chunks: unknown }).chunks === browserTransferChunkCount(manifest)
          ? { chunks: browserTransferChunkCount(manifest), manifest }
          : undefined;
      },
    );
  }

  next() {
    return this.call(
      'next',
      () => null,
      (result) => {
        const c = vaultRecord(result) && this.context(result.context);
        return c ? parseBrowserTransferPacket(result, c, 'capture') : undefined;
      },
    );
  }

  accept(value: unknown) {
    return this.call(
      'accept',
      () => {
        const c = vaultRecord(value) && this.context(value.context);
        return c ? parseBrowserTransferPacket(value, c, 'restore') : undefined;
      },
      (result) => parseBitwardenBridgeReceipt(result),
    );
  }

  cancel(): Promise<{ cancelled: true }> {
    if (this.disposed) return Promise.resolve({ cancelled: true });
    if (this.closing) return this.closing.then(() => ({ cancelled: true }));
    if (this.canceling) return this.canceling;
    this.generation++;
    this.active = undefined;
    this.interrupt(false);
    this.canceling = Promise.resolve()
      .then(() => this.cleanup('cancel', parseBrowserTransferCancelled))
      .then((value) => {
        this.faulted = false;
        return value;
      })
      .finally(() => {
        this.canceling = undefined;
      });
    return this.canceling;
  }

  dispose(): Promise<{ closed: true }> {
    if (this.disposed) return Promise.resolve({ closed: true });
    if (this.closing) return this.closing;
    this.closed = true;
    this.generation++;
    this.interrupt(false);
    this.closing = Promise.resolve()
      .then(async () => {
        await this.initializing?.catch(() => undefined);
        if (!this.options.contents.isDestroyed() && this.injected) {
          // A timed-out bootstrap may still be queued. Do not acknowledge missing
          // state until that original execution settled, or the document is gone.
          if (!this.bootstrapSettled) throw unavailable();
          await this.cleanup('dispose', parseBrowserProfileClosed);
        }
        return this.finishDispose();
      })
      .catch(() => {
        if (this.options.contents.isDestroyed()) return this.finishDispose();
        throw unavailable();
      })
      .finally(() => {
        this.closing = undefined;
      });
    return this.closing;
  }

  private owned(value: { workspaceId: string; profileId: string; epoch: number }): boolean {
    return Object.entries(this.owner).every(([k, v]) => value[k as keyof typeof value] === v);
  }
  private context(value: unknown): BrowserTransferContext | undefined {
    const c = parseBrowserTransferContext(value);
    return c && this.owned(c) ? c : undefined;
  }
  private sameDocument(): boolean {
    try {
      const c = this.options.contents,
        f = this.frame;
      return (
        !c.isDestroyed() &&
        c.session === this.options.session &&
        c.getType() === 'backgroundPage' &&
        !c.isLoadingMainFrame() &&
        c.mainFrame === f &&
        !f.isDestroyed() &&
        !f.detached &&
        f.url === this.options.url &&
        f.processId === this.frameIdentity.processId &&
        f.routingId === this.frameIdentity.routingId &&
        f.frameToken === this.frameIdentity.frameToken &&
        f.osProcessId === this.frameIdentity.osProcessId &&
        this.options.sandboxed(this.frameIdentity) === true
      );
    } catch {
      return false;
    }
  }
  private check(cleanup: boolean, bootstrap = false): void {
    if (
      this.revoked ||
      !this.sameDocument() ||
      (!cleanup &&
        (this.closed || !this.options.current() || (!bootstrap && (!this.ready || this.faulted))))
    )
      throw unavailable();
  }
  private revoke(): void {
    this.revoked = true;
    this.interrupt(true);
  }
  private interrupt(all: boolean): void {
    for (const pending of [...this.pending]) if (all || !pending.cleanup) pending.reject();
  }
  private finishDispose(): { closed: true } {
    this.disposed = true;
    const c = this.options.contents;
    c.removeListener('did-start-navigation', this.onNavigation);
    c.removeListener('render-process-gone', this.onGone);
    c.removeListener('destroyed', this.onGone);
    return { closed: true };
  }
  private decode(raw: unknown, limit: number): unknown {
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > limit) throw unavailable();
    return JSON.parse(raw);
  }
  private evaluate(
    script: string,
    cleanup: boolean,
    bootstrap = false,
    probe = false,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (ok: boolean, value?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.pending.delete(pending);
        if (ok) resolve(value);
        else reject(unavailable());
      };
      const pending = { cleanup, reject: () => finish(false) };
      const timer = setTimeout(() => finish(false), bitwardenDocumentTimeoutMs);
      this.pending.add(pending);
      try {
        this.check(cleanup, bootstrap);
        const result = this.frame.executeJavaScript(script);
        if (bootstrap && !probe) {
          this.injected = true;
          this.bootstrapSettled = false;
        }
        void Promise.resolve(result).then(
          (value) => {
            if (bootstrap && !probe) this.bootstrapSettled = true;
            finish(true, value);
          },
          () => {
            if (bootstrap && !probe) this.bootstrapSettled = true;
            finish(false);
          },
        );
      } catch {
        finish(false);
      }
    });
  }
  private dispatch(operation: BitwardenDocumentOperation, input: unknown, cleanup: boolean) {
    this.check(cleanup);
    const id = ++this.sequence;
    if (!Number.isSafeInteger(id)) throw unavailable();
    const payload = JSON.stringify(input);
    if (Buffer.byteLength(payload) > (operation === 'accept' ? bitwardenDocumentPacketBytes : 2048))
      throw unavailable();
    const deadline = Date.now() + bitwardenDocumentTimeoutMs;
    return this.evaluate(
      `WormholeVaultBitwarden.invoke(${JSON.stringify(this.token)},${id},${JSON.stringify(operation)},${payload},${deadline})`,
      cleanup,
    );
  }
  private call<T>(
    operation: BitwardenDocumentOperation,
    input: () => unknown,
    parse: (value: unknown, input: unknown) => T | undefined,
  ): Promise<T> {
    if (this.active || this.canceling || this.closing) return Promise.reject(unavailable());
    const token = {},
      stamp = this.generation;
    this.active = token;
    return Promise.resolve()
      .then(async () => {
        this.check(false);
        if (stamp !== this.generation || this.active !== token) throw unavailable();
        const payload = input();
        if (payload === undefined) throw unavailable();
        const raw = await this.dispatch(operation, payload, false);
        this.check(false);
        if (stamp !== this.generation) throw unavailable();
        const value = parse(
          this.decode(raw, operation === 'next' ? bitwardenDocumentPacketBytes : 2048),
          payload,
        );
        if (value === undefined) throw unavailable();
        return value;
      })
      .catch(() => {
        if (stamp === this.generation) this.faulted = true;
        throw unavailable();
      })
      .finally(() => {
        if (this.active === token) this.active = undefined;
      });
  }
  private async cleanup<T>(
    operation: 'cancel' | 'dispose',
    parse: (value: unknown) => T | undefined,
  ): Promise<T> {
    try {
      const raw = await this.dispatch(operation, null, true);
      this.check(true);
      const value = parse(this.decode(raw, 64));
      if (value === undefined) throw unavailable();
      return value;
    } catch {
      this.faulted = true;
      throw unavailable();
    }
  }
}
