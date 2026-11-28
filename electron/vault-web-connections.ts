import { randomUUID } from 'node:crypto';
import { vaultID } from './vault-contract.ts';
import {
  parseVaultWebPlan,
  parseVaultWebViewReply,
  type VaultWebPlan,
  type VaultWebTarget,
  type VaultWebView,
} from './vault-web.ts';
import {
  parseVaultRouteBinding,
  validVaultRouteEndpoint,
  type VaultRouteBinding,
  type VaultRoutePlanRequest,
} from './vault-route.ts';
import { type VaultQuickTarget, type VaultQuickTargetLease } from './vault-quick-target.ts';
import type { SealedRouteBroker, SealedRouteLease } from './sealed-route.ts';
import type { WebSessionArchiveStore } from './vault-web-session-archive.ts';

export { parseVaultWebOpen, parseVaultWebRequest } from './vault-web-open.ts';
import { parseVaultWebOpen, type VaultWebOpen } from './vault-web-open.ts';

type BrowserClosure = 'route' | 'view-revoked' | 'view-unavailable';

type Entry = {
  scope: Omit<VaultRoutePlanRequest, 'nodeId'>;
  nodeId?: string;
  archiveNode?: string;
  quickTarget?: VaultQuickTarget;
  targetLease?: VaultQuickTargetLease;
  admitting?: Promise<void>;
  owner: () => boolean;
  onClosed: (reason: BrowserClosure) => void;
  view?: VaultWebView;
  reject: (error: Error) => void;
  retired: boolean;
  pending: boolean;
  lease?: SealedRouteLease;
  stop?: Promise<void>;
  routeStop?: Promise<void>;
  timer: NodeJS.Timeout;
};
type Options = {
  workspaceId: () => string | undefined;
  authorized: (epoch: number) => boolean;
  plan: (q: VaultRoutePlanRequest) => Promise<VaultWebPlan>;
  archive?: (plan: VaultWebPlan, active: () => boolean) => WebSessionArchiveStore | undefined;
  checkViews?: (workspaceId: string, views: VaultWebView[]) => Promise<boolean[]>;
  routes: Pick<SealedRouteBroker, 'acquire' | 'close' | 'closeAll'>;
  quickTarget?: (
    target: VaultQuickTarget,
    sessionId: string,
    epoch: number,
    accepted: () => boolean,
  ) => Promise<VaultQuickTargetLease>;
  timeoutMs?: number;
};
export type PreparedVaultWebConnection = {
  target: VaultWebTarget & { proxyUrl?: string };
  route: 'direct' | 'socks5';
  active: () => boolean;
  archive?: WebSessionArchiveStore;
};
function sameRoute(a: VaultRouteBinding, b: VaultRouteBinding): boolean {
  return Object.entries(a).every(([key, value]) => b[key as keyof VaultRouteBinding] === value);
}
// Main-only preparation with an owned route broker. One browser owns one
// lease shared by all its tabs.
// Neither native route endpoints nor this active predicate are renderer DTOs.
export class VaultWebConnections {
  private readonly options: Options;
  private readonly entries = new Map<string, Entry>();
  private closing?: Promise<void>;
  private closingPending = false;
  private routesRetiring = false;
  private viewTimer?: NodeJS.Timeout;
  private viewCheck?: Promise<void>;
  private checkRequested = false;
  constructor(options: Options) {
    if (
      options.timeoutMs !== undefined &&
      (!Number.isSafeInteger(options.timeoutMs) ||
        options.timeoutMs < 1 ||
        options.timeoutMs > 360000)
    )
      throw Error('Invalid web opening timeout.');
    this.options = options;
  }
  has(id: string): boolean {
    return this.entries.has(id);
  }
  private current(e: Entry): boolean {
    try {
      return (
        !this.closing &&
        !this.routesRetiring &&
        !e.retired &&
        this.entries.get(e.scope.sessionId) === e &&
        this.options.workspaceId() === e.scope.workspaceId &&
        this.options.authorized(e.scope.epoch) &&
        e.owner()
      );
    } catch {
      return false;
    }
  }
  private usable(e: Entry): boolean {
    return this.current(e) && (!e.lease || e.lease.active);
  }
  async open(
    value: VaultWebOpen,
    epoch: number,
    owner: () => boolean,
    onClosed: (reason: BrowserClosure) => void,
  ): Promise<PreparedVaultWebConnection> {
    const workspaceId = this.options.workspaceId(),
      input = parseVaultWebOpen(value);
    if (
      !input ||
      !vaultID(workspaceId) ||
      !Number.isSafeInteger(epoch) ||
      epoch < 1 ||
      this.closing ||
      this.routesRetiring ||
      this.entries.has(input.sessionId) ||
      this.entries.size >= 32 ||
      !this.options.authorized(epoch) ||
      !owner()
    )
      throw Error('Vault web connection is unavailable.');
    const scope: Entry['scope'] = {
      workspaceId,
      sessionId: input.sessionId,
      requestId: randomUUID(),
      credentialOverride: '',
      epoch,
    };
    let reject!: (error: Error) => void;
    const cancelled = new Promise<never>((_resolve, no) => {
      reject = no;
    });
    const e: Entry = {
      scope,
      nodeId: input.nodeId,
      quickTarget: input.quickTarget,
      reject,
      owner,
      onClosed,
      retired: false,
      pending: false,
      timer: setTimeout(() => {
        void this.stop(e).catch(() => {});
      }, this.options.timeoutMs ?? 330000),
    };
    e.timer.unref();
    this.entries.set(scope.sessionId, e);
    try {
      return await Promise.race([this.prepare(e), cancelled]);
    } catch {
      await this.stop(e);
      throw Error('Vault web connection could not be prepared.');
    }
  }
  private async prepare(e: Entry): Promise<PreparedVaultWebConnection> {
    let nodeId = e.nodeId;
    if (e.quickTarget) {
      if (!this.options.quickTarget) throw Error('Protected Quick Connect is unavailable.');
      const admission = Promise.resolve().then(async () => {
        if (!this.current(e)) throw Error('Web opening cancelled.');
        e.targetLease = await this.options.quickTarget!(
          e.quickTarget!,
          e.scope.sessionId,
          e.scope.epoch,
          () => this.current(e),
        );
      });
      e.admitting = admission;
      await admission;
      if (!this.usable(e)) throw Error('Web opening cancelled.');
      nodeId = e.targetLease!.reference.id;
    }
    if (!vaultID(nodeId)) throw Error('Invalid web target receipt.');
    const q: VaultRoutePlanRequest = { ...e.scope, nodeId };
    let plan = parseVaultWebPlan(await this.options.plan({ ...q }), q);
    if (!plan || Boolean(plan.temporary) !== Boolean(e.quickTarget) || !this.usable(e))
      throw Error('Invalid web plan.');
    let proxyUrl: string | undefined;
    if (plan.route) {
      const original = plan;
      e.pending = true;
      const lease = await this.options.routes.acquire(
        { sessionId: q.sessionId, nodeId: q.nodeId },
        q.epoch,
        () => this.current(e),
      );
      e.pending = false;
      e.lease = lease;
      e.routeStop = undefined;
      if (!this.current(e)) {
        await lease.release();
        e.lease = undefined;
        throw Error('Web opening cancelled.');
      }
      const binding = parseVaultRouteBinding(lease.binding, {
        ...q,
        requestId: lease.binding.requestId,
      });
      if (
        !binding ||
        !validVaultRouteEndpoint(lease.endpoint) ||
        !lease.active ||
        !sameRoute({ ...original.route!, requestId: binding.requestId }, binding)
      )
        throw Error('Web route changed.');
      const ended = () => {
        const notify = this.current(e);
        // An opened Quick browser retains its target until its presentation
        // owner confirms view/profile cleanup and explicitly closes it.
        if (e.quickTarget) {
          e.retired = true;
          clearTimeout(e.timer);
          e.reject(Error('Vault web opening cancelled.'));
        }
        if (notify) {
          try {
            e.onClosed('route');
          } catch {
            /* The presentation owner may already be gone. */
          }
        }
        if (!e.quickTarget) void this.stop(e).catch(() => {});
      };
      void lease.closed.then(ended, ended);
      const refreshed = { ...q, requestId: binding.requestId };
      plan = parseVaultWebPlan(await this.options.plan({ ...refreshed }), refreshed);
      if (
        !plan ||
        Boolean(plan.temporary) !== Boolean(e.quickTarget) ||
        !plan.route ||
        !this.usable(e) ||
        !sameRoute(plan.route, binding) ||
        plan.target.url !== original.target.url ||
        plan.target.ignoreCertErrors !== original.target.ignoreCertErrors ||
        plan.archiveBinding !== original.archiveBinding ||
        plan.viewGeneration !== original.viewGeneration
      )
        throw Error('Web target changed.');
      proxyUrl = `socks5://${lease.endpoint}`;
    }
    if (!this.usable(e)) throw Error('Web opening cancelled.');
    if (plan.viewGeneration) {
      if (!this.options.checkViews) throw Error('Shared browser View checks are unavailable.');
      e.view = { nodeId, generation: plan.viewGeneration };
      this.scheduleViewCheck();
    }
    clearTimeout(e.timer);
    const active = () => this.usable(e);
    const archive =
      plan.archiveBinding &&
      !plan.temporary &&
      ![...this.entries.values()].some((entry) => entry.archiveNode === nodeId)
        ? this.options.archive?.(plan, active)
        : undefined;
    if (archive) e.archiveNode = nodeId;
    return {
      target: { ...plan.target, ...(proxyUrl ? { proxyUrl } : {}) },
      route: proxyUrl ? 'socks5' : 'direct',
      active,
      ...(archive ? { archive } : {}),
    };
  }

  // Notifications can arrive during an in-flight check. Join that request and
  // read again so a later revocation cannot be hidden by its earlier reply.
  verifyViews(): Promise<void> {
    clearTimeout(this.viewTimer);
    this.viewTimer = undefined;
    this.checkRequested = true;
    if (this.viewCheck) return this.viewCheck;
    this.viewCheck = Promise.resolve()
      .then(async () => {
        while (this.checkRequested) {
          this.checkRequested = false;
          await this.verifyCurrentViews();
        }
      })
      .finally(() => {
        this.viewCheck = undefined;
        this.scheduleViewCheck();
      });
    return this.viewCheck;
  }

  private async verifyCurrentViews(): Promise<void> {
    const check = this.options.checkViews;
    const active = [...this.entries.values()].filter((entry) => entry.view && this.current(entry));
    if (!check || active.length === 0) return;
    let current: boolean[] | undefined;
    try {
      const result = await check(
        active[0].scope.workspaceId,
        active.map((entry) => ({ ...entry.view! })),
      );
      current = parseVaultWebViewReply({ current: result }, active.length);
    } catch {
      // Live cookies remain usable only while the native admission can confirm
      // their generation. A transport failure does not prove a View revocation.
    }
    for (const [index, entry] of active.entries()) {
      if (current?.[index] || !this.current(entry)) continue;
      this.retire(entry);
      try {
        entry.onClosed(current ? 'view-revoked' : 'view-unavailable');
      } catch {
        /* The original presentation owner may already be gone. */
      }
      void this.stop(entry).catch(() => {});
    }
  }

  private scheduleViewCheck(): void {
    if (![...this.entries.values()].some((entry) => entry.view && this.current(entry))) {
      clearTimeout(this.viewTimer);
      this.viewTimer = undefined;
      return;
    }
    if (this.viewCheck || this.viewTimer) return;
    this.viewTimer = setTimeout(() => {
      void this.verifyViews();
    }, 30_000);
    this.viewTimer.unref();
  }

  private retire(e: Entry): void {
    e.retired = true;
    e.reject(Error('Vault web opening cancelled.'));
    clearTimeout(e.timer);
    if (e.view) this.scheduleViewCheck();
  }
  private stopRoute(e: Entry): Promise<void> {
    this.retire(e);
    if (e.routeStop) return e.routeStop;
    const task = Promise.resolve().then(async () => {
      if (e.lease) await e.lease.release();
      else if (e.pending) await this.options.routes.close(e.scope.sessionId);
    });
    const tracked = task.catch((error) => {
      if (e.routeStop === tracked) e.routeStop = undefined;
      throw error;
    });
    e.routeStop = tracked;
    return tracked;
  }
  private stop(e: Entry): Promise<void> {
    if (e.stop) return e.stop;
    this.retire(e);
    const task = Promise.resolve().then(async () => {
      await this.stopRoute(e);
      // A late native registration must finish in the original owner before
      // shutdown can acknowledge that its target authority was retired.
      if (e.admitting) await Promise.allSettled([e.admitting]);
      await e.targetLease?.release();
      if (this.entries.get(e.scope.sessionId) === e) this.entries.delete(e.scope.sessionId);
    });
    const tracked = task.catch((error) => {
      if (e.stop === tracked) e.stop = undefined;
      throw error;
    });
    e.stop = tracked;
    return tracked;
  }
  retireRoute(id: string): Promise<void> {
    const e = this.entries.get(id);
    return e ? this.stopRoute(e) : Promise.resolve();
  }
  async retireAllRoutes(): Promise<void> {
    this.routesRetiring = true;
    const results = await Promise.allSettled(
      [...this.entries.values()].map((e) => this.stopRoute(e)),
    );
    const all = await Promise.allSettled([this.options.routes.closeAll()]);
    if ([...results, ...all].some((r) => r.status === 'rejected'))
      throw Error('Web route shutdown could not be confirmed.');
  }
  close(id: string): Promise<void> {
    const e = this.entries.get(id);
    return e ? this.stop(e) : Promise.resolve();
  }
  closeAll(): Promise<void> {
    if (this.closing && this.closingPending) return this.closing;
    this.closingPending = true;
    const task = Promise.resolve().then(async () => {
      const stopped = await Promise.allSettled([...this.entries.values()].map((e) => this.stop(e)));
      const all = await Promise.allSettled([this.options.routes.closeAll()]);
      if ([...stopped, ...all].some((r) => r.status === 'rejected'))
        throw Error('Web route shutdown could not be confirmed.');
    });
    const tracked = task.then(
      () => {
        if (this.closing === tracked) {
          this.closing = undefined;
          this.closingPending = false;
          this.routesRetiring = false;
        }
      },
      (error) => {
        if (this.closing === tracked) this.closingPending = false;
        throw error;
      },
    );
    this.closing = tracked;
    return tracked;
  }
}
