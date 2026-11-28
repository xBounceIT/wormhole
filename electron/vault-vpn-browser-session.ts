import type { BrowserWindow } from 'electron';
import { VaultVPNBrowserRecipient } from './vault-vpn-browser.ts';
import { VaultVPNStorageDriver } from './vault-vpn-storage-driver.ts';
import {
  parseVaultTunnelCookieContext,
  type VaultTunnelCookieContext,
} from './vault-tunnel-cookie.ts';
import {
  parseVaultTunnelBrowserContext,
  type VaultTunnelBrowserContext,
} from './vault-tunnel-browser.ts';
import { parseVaultRoutePlanRequest, type VaultRoutePlanRequest } from './vault-route.ts';
import {
  parseVaultTunnelFallbackBinding,
  type VaultTunnelFallbackBinding,
} from './vault-tunnel-fallback.ts';
import { parseVaultSecurity, type VaultSecurity } from './vault-security.ts';
import { beginNativeVPNSSO, type VPNSSOBegin } from './vault-vpn-sso.ts';

type Capability = Awaited<ReturnType<typeof beginNativeVPNSSO>>;
type Recipient = Pick<VaultVPNBrowserRecipient, 'metadata' | 'restore' | 'capture' | 'close'>;
type Driver = Pick<
  VaultVPNStorageDriver,
  'isOffline' | 'permitsRequest' | 'apply' | 'publish' | 'capture' | 'close'
>;
type Options = {
  window: BrowserWindow;
  request: VaultRoutePlanRequest;
  fallback?: VaultTunnelFallbackBinding;
  context: VaultTunnelCookieContext | VaultTunnelBrowserContext;
  signal: AbortSignal;
  current(): boolean;
  failed?(): void;
  executable: string;
  authority: {
    security(): Promise<VaultSecurity>;
    begin(value: VPNSSOBegin, reserved?: (capability: Capability) => void): Promise<Capability>;
  };
};
type Adapters = {
  recipient(
    options: Parameters<typeof VaultVPNBrowserRecipient.open>[0],
    reserved?: (recipient: Recipient) => void,
  ): Promise<Recipient>;
  storage(
    options: Parameters<typeof VaultVPNStorageDriver.open>[0],
    reserved?: (driver: Driver) => void,
  ): Promise<Driver>;
};
const unavailable = () => Error('VPN browser custody unavailable.');

// One native actor owns this object synchronously, before restore starts. Every
// late capability remains attached to its original root/window and is joined by
// close; only the actor may present or destroy its window.
export class VaultVPNBrowserSession {
  private readonly options: Options;
  private readonly adapters: Adapters;
  private recipient?: Recipient;
  private driver?: Driver;
  private capability?: Capability;
  private work?: Promise<unknown>;
  private cleanup?: Promise<void>;
  private closed = false;
  private phase: 'new' | 'restored' | 'captured' | 'failed' = 'new';
  constructor(
    options: Options,
    adapters: Adapters = {
      recipient: (q, reserved) => VaultVPNBrowserRecipient.open(q, undefined, reserved),
      storage: (q, reserved) => VaultVPNStorageDriver.open(q, reserved),
    },
  ) {
    const request = parseVaultRoutePlanRequest(options.request),
      context =
        parseVaultTunnelCookieContext(options.context) ??
        parseVaultTunnelBrowserContext(options.context);
    let fallback: VaultTunnelFallbackBinding | undefined;
    if (options.fallback !== undefined) {
      fallback =
        request &&
        parseVaultTunnelFallbackBinding(options.fallback, {
          ...request,
          primary: options.fallback?.primary,
          fallbackRequestId: options.fallback?.fallback?.requestId,
        });
      if (
        !fallback ||
        context?.binding.kind !== 2 ||
        JSON.stringify(context.binding) !== JSON.stringify(fallback.fallback)
      )
        throw unavailable();
    }
    if (
      !request ||
      !context ||
      request.workspaceId !== context.binding.workspaceId ||
      request.nodeId !== context.binding.nodeId ||
      request.sessionId !== context.binding.sessionId ||
      (fallback?.fallback.requestId ?? request.requestId) !== context.binding.requestId ||
      request.epoch !== context.binding.epoch ||
      !options.executable
    )
      throw unavailable();
    this.options = {
      window: options.window,
      request,
      ...(fallback ? { fallback } : {}),
      context,
      signal: options.signal,
      executable: options.executable,
      failed: options.failed?.bind(options),
      current: options.current.bind(options),
      authority: {
        security: options.authority.security.bind(options.authority),
        begin: options.authority.begin.bind(options.authority),
      },
    };
    this.adapters = {
      recipient: adapters.recipient.bind(adapters),
      storage: adapters.storage.bind(adapters),
    };
    this.check();
  }
  get isOffline() {
    return this.closed || this.phase !== 'restored' || !this.driver || this.driver.isOffline;
  }
  permitsRequest(url: string, webContentsId: number, resourceType: string) {
    try {
      this.check();
    } catch {
      return false;
    }
    return this.driver?.permitsRequest(url, webContentsId, resourceType) ?? false;
  }
  private check() {
    let current = false;
    try {
      current = this.options.current();
    } catch {}
    if (
      this.closed ||
      this.phase === 'failed' ||
      this.options.signal.aborted ||
      this.options.window.isDestroyed() ||
      !current
    )
      throw unavailable();
  }
  private async run(expected: 'new' | 'restored', work: () => Promise<void>) {
    this.check();
    if (this.work || this.phase !== expected) throw unavailable();
    const task = (async () => {
      try {
        await work();
        this.check();
      } catch {
        this.phase = 'failed';
        throw unavailable();
      }
    })();
    this.work = task;
    try {
      await task;
    } finally {
      if (this.work === task) this.work = undefined;
    }
  }
  restore(): Promise<void> {
    return this.run('new', async () => {
      const security = parseVaultSecurity(await this.options.authority.security());
      this.check();
      if (!security || !['default', 'standard'].includes(security.effective)) throw unavailable();
      this.recipient = await this.adapters.recipient(
        {
          executable: this.options.executable,
          signal: this.options.signal,
          current: () => {
            try {
              this.check();
              return true;
            } catch {
              return false;
            }
          },
        },
        (recipient) => {
          this.recipient = recipient;
        },
      );
      this.check();
      const metadata = this.recipient.metadata;
      if (security.effective === 'standard' && !metadata.lockedMemory) throw unavailable();
      this.capability = await this.options.authority.begin(
        {
          request: structuredClone(this.options.request),
          binding: structuredClone(this.options.context.binding),
          challengeId: this.options.context.challengeId,
          profileId: metadata.profileId,
          restorePublicKey: metadata.publicKey,
          startURL: this.options.context.startURL,
          ignoreCertificateErrors: this.options.context.ignoreCertificateErrors,
          ...(this.options.fallback ? { fallback: structuredClone(this.options.fallback) } : {}),
        },
        (capability) => {
          this.capability = capability;
        },
      );
      this.check();
      if (this.capability.offer.context.policySequence !== security.sequence) throw unavailable();
      this.driver = await this.adapters.storage(
        {
          window: this.options.window,
          attemptCookie: 'SVPNCOOKIE',
          invalidated: () => {
            this.phase = 'failed';
            this.options.failed?.();
          },
          current: () => {
            try {
              this.check();
              return true;
            } catch {
              return false;
            }
          },
        },
        (driver) => {
          this.driver = driver;
        },
      );
      this.check();
      const archive = await this.recipient.restore(this.capability.offer, (i) =>
        this.capability!.take(i),
      );
      try {
        this.check();
        await this.driver.apply(archive);
      } finally {
        archive.fill(0);
      }
      this.check();
      await this.capability.acknowledge();
      this.check();
      await this.driver.publish();
      this.check();
      this.phase = 'restored';
    });
  }
  capture(): Promise<void> {
    return this.run('restored', async () => {
      const archive = await this.driver!.capture();
      try {
        this.check();
        await this.recipient!.capture(archive, (p) => this.capability!.push(p));
      } finally {
        archive.fill(0);
      }
      this.check();
      await this.capability!.commit();
      this.check();
      this.phase = 'captured';
    });
  }
  // The owner first destroys the exact window and aborts its native signal.
  // Close both before and after the joined work to collect late begin replies.
  close(): Promise<void> {
    if (this.cleanup) return this.cleanup;
    this.closed = true;
    const closeKnown = async () => {
      const results = await Promise.allSettled([
        Promise.resolve().then(() => this.driver?.close()),
        Promise.resolve().then(() => this.capability?.cancel()),
        Promise.resolve().then(() => this.recipient?.close()),
      ]);
      if (results.some((r) => r.status === 'rejected')) throw unavailable();
    };
    const task = (async () => {
      const early = await Promise.allSettled([closeKnown()]);
      await Promise.allSettled(this.work ? [this.work] : []);
      await closeKnown();
      if (early.some((r) => r.status === 'rejected')) throw unavailable();
    })();
    this.cleanup = task.catch(() => {
      this.cleanup = undefined;
      throw unavailable();
    });
    return this.cleanup;
  }
}
