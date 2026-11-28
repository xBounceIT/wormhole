import type { WebContents } from 'electron';
import { vaultRecord } from './vault-contract.ts';
import {
  parseVaultVncCommand,
  type VaultVncCommand,
  type VaultVncController,
} from './vault-vnc-controller.ts';
import type { VaultQuickTarget, VaultQuickTargetLease } from './vault-quick-target.ts';

type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener' | 'send'>;
type Event = { sender: Owner };
type Options = {
  controller: Pick<VaultVncController, 'has' | 'command' | 'closeForOwner' | 'closeAll'>;
  workspace: () => boolean;
  trusted: (event: Event) => boolean;
  authorize: <T>(run: (epoch: number) => Promise<T>, cleanup: () => Promise<void>) => Promise<T>;
  quickTarget: (
    target: VaultQuickTarget,
    sessionId: string,
    epoch: number,
    accepted: () => boolean,
  ) => Promise<VaultQuickTargetLease>;
};
type Opening = { cancelled: boolean; done: Promise<void>; finish: () => void };
type Closing = { owner: Owner; work?: Promise<void> };

/** Reserve public ownership before authorization, including unsaved native admission. */
export class VaultVncIpc {
  private readonly options: Options;
  private readonly owners = new Map<string, Owner>();
  private readonly admissions = new Map<string, object>();
  private readonly retirements = new Map<Owner, () => void>();
  private readonly openings = new Map<string, Opening>();
  private readonly targets = new Map<string, VaultQuickTargetLease>();
  private readonly closing = new Map<string, Closing>();
  private stopping = false;
  private shutdown?: Promise<void>;
  constructor(options: Options) {
    this.options = options;
  }
  handles(value: unknown): boolean {
    return (
      this.options.workspace() ||
      (vaultRecord(value) &&
        typeof value.sessionId === 'string' &&
        (this.owners.has(value.sessionId) || this.options.controller.has(value.sessionId)))
    );
  }
  private requireOwner(event: Event, id: string): void {
    if (
      !this.options.trusted(event) ||
      event.sender.isDestroyed() ||
      (this.owners.has(id) && this.owners.get(id) !== event.sender) ||
      (this.closing.has(id) && this.closing.get(id)!.owner !== event.sender)
    )
      throw Error('Invalid vault VNC owner.');
  }
  private reserve(owner: Owner, id: string): void {
    if (!this.owners.has(id) && this.owners.size >= 32)
      throw Error('Close a session before opening another.');
    this.owners.set(id, owner);
    if (this.retirements.has(owner)) return;
    const retire = () => {
      for (const [id, current] of this.owners)
        if (current === owner) void this.disconnect(owner, id).catch(() => {});
    };
    this.retirements.set(owner, retire);
    owner.on('destroyed', retire);
    owner.on('did-start-loading', retire);
  }
  private releaseOwner(id: string): void {
    const owner = this.owners.get(id);
    this.owners.delete(id);
    this.admissions.delete(id);
    if (!owner || [...this.owners.values()].includes(owner)) return;
    const retire = this.retirements.get(owner)!;
    owner.removeListener('destroyed', retire);
    owner.removeListener('did-start-loading', retire);
    this.retirements.delete(owner);
  }
  private async releaseTarget(id: string, lease = this.targets.get(id)): Promise<void> {
    if (!lease) return;
    await lease.release();
    if (this.targets.get(id) === lease) this.targets.delete(id);
  }
  async command(event: Event, value: unknown): Promise<void> {
    const q = parseVaultVncCommand(value);
    if (!q) throw Error('Invalid vault VNC request.');
    this.requireOwner(event, q.sessionId);
    if (q.action === 'vnc.disconnect') return this.disconnect(event.sender, q.sessionId);
    if (q.action === 'vnc.connect') return this.open(event, q);
    const admission = this.admissions.get(q.sessionId);
    const current = () =>
      admission !== undefined &&
      this.admissions.get(q.sessionId) === admission &&
      !this.openings.has(q.sessionId) &&
      !this.closing.has(q.sessionId) &&
      this.owners.get(q.sessionId) === event.sender &&
      !this.stopping &&
      this.options.workspace() &&
      this.options.trusted(event) &&
      !event.sender.isDestroyed();
    if (!current()) throw Error('VNC session is unavailable.');
    await this.options.authorize(
      async (epoch) => {
        if (!current()) throw Error('VNC session is unavailable.');
        await this.options.controller.command(event.sender, current, q, epoch);
        if (!current()) throw Error('VNC operation was cancelled.');
      },
      () =>
        this.admissions.get(q.sessionId) === admission &&
        this.owners.get(q.sessionId) === event.sender
          ? this.options.controller.closeForOwner(event.sender, q.sessionId)
          : Promise.resolve(),
    );
  }
  private async open(
    event: Event,
    q: Extract<VaultVncCommand, { action: 'vnc.connect' }>,
  ): Promise<void> {
    if (!this.options.workspace()) throw Error('Vault VNC is locked.');
    if (this.stopping || this.openings.has(q.sessionId) || this.closing.has(q.sessionId))
      throw Error('VNC session is busy.');
    this.reserve(event.sender, q.sessionId);
    this.admissions.set(q.sessionId, {});
    let finish!: () => void;
    const opening: Opening = {
      cancelled: false,
      done: new Promise((resolve) => {
        finish = resolve;
      }),
      finish: () => finish(),
    };
    this.openings.set(q.sessionId, opening);
    const current = () =>
      !this.stopping &&
      !opening.cancelled &&
      this.owners.get(q.sessionId) === event.sender &&
      this.options.workspace() &&
      this.options.trusted(event) &&
      !event.sender.isDestroyed();
    try {
      await this.options.authorize(
        async (epoch) => {
          if (!current()) throw Error('VNC opening was cancelled.');
          let target: VaultQuickTargetLease | undefined;
          if (q.quickTarget || this.targets.has(q.sessionId)) {
            await this.options.controller.closeForOwner(event.sender, q.sessionId);
            await this.releaseTarget(q.sessionId);
            if (!current()) throw Error('VNC opening was cancelled.');
          }
          if (q.quickTarget) {
            target = await this.options.quickTarget(q.quickTarget, q.sessionId, epoch, current);
            this.targets.set(q.sessionId, target);
            if (!current()) throw Error('VNC opening was cancelled.');
          }
          await this.options.controller.command(
            event.sender,
            current,
            {
              action: 'vnc.connect',
              sessionId: q.sessionId,
              nodeId: target ? target.reference.id : q.nodeId!,
              ...(q.credentialId !== undefined ? { credentialId: q.credentialId } : {}),
              ...(q.manualPassword ? { manualPassword: true } : {}),
            },
            epoch,
            target ? () => this.releaseTarget(q.sessionId, target) : undefined,
          );
          if (!current()) throw Error('VNC opening was cancelled.');
        },
        async () => {
          opening.cancelled = true;
          await this.options.controller.closeForOwner(event.sender, q.sessionId);
        },
      );
      if (!current()) throw Error('VNC opening was cancelled.');
    } catch {
      opening.cancelled = true;
      await this.options.controller.closeForOwner(event.sender, q.sessionId);
      await this.releaseTarget(q.sessionId);
      if (!this.options.controller.has(q.sessionId)) this.releaseOwner(q.sessionId);
      throw Error('VNC connection could not be opened.');
    } finally {
      if (this.openings.get(q.sessionId) === opening) this.openings.delete(q.sessionId);
      opening.finish();
    }
  }
  private disconnect(owner: Owner, id: string): Promise<void> {
    if (
      !this.owners.has(id) &&
      !this.openings.has(id) &&
      !this.closing.has(id) &&
      !this.options.controller.has(id)
    )
      return Promise.resolve();
    let closing = this.closing.get(id);
    if (closing?.work) return closing.work;
    closing ??= { owner };
    this.closing.set(id, closing);
    const opening = this.openings.get(id);
    if (opening) opening.cancelled = true;
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        this.options.controller.closeForOwner(owner, id),
        opening?.done,
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('VNC shutdown could not be confirmed.');
      await this.releaseTarget(id);
      if (this.closing.get(id) === closing) {
        this.releaseOwner(id);
        this.closing.delete(id);
      }
    });
    closing.work = work.catch((error) => {
      closing!.work = undefined;
      throw error;
    });
    return closing.work;
  }
  closeAll(): Promise<void> {
    if (this.shutdown) return this.shutdown;
    this.stopping = true;
    for (const opening of this.openings.values()) opening.cancelled = true;
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        this.options.controller.closeAll(),
        ...[...this.openings.values()].map((o) => o.done),
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('VNC shutdown could not be confirmed.');
      const released = await Promise.allSettled(
        [...this.targets.keys()].map((id) => this.releaseTarget(id)),
      );
      if (released.some((r) => r.status === 'rejected'))
        throw Error('VNC target retirement could not be confirmed.');
      for (const id of this.owners.keys()) this.releaseOwner(id);
      this.closing.clear();
      this.stopping = false;
    });
    this.shutdown = work.finally(() => {
      this.shutdown = undefined;
    });
    return this.shutdown;
  }
}
