import type { WebContents } from 'electron';
import type { SealedSshAdmission, SealedSshConnected } from './sealed-ssh.ts';
import { vaultID } from './vault-contract.ts';
import { parseVaultSshOpen, type VaultSshOpen } from './vault-ssh-open.ts';
import type { VaultQuickTarget, VaultQuickTargetLease } from './vault-quick-target.ts';

type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener'>;
type Event = { sender: Owner };
type NativeOpen = Extract<VaultSshOpen, { nodeId: string }>;
type Options = {
  workspace: () => boolean;
  trusted: (event: Event) => boolean;
  authorize: <T>(run: (epoch: number) => Promise<T>, cleanup: () => Promise<void>) => Promise<T>;
  quickTarget: (
    target: VaultQuickTarget,
    sessionId: string,
    epoch: number,
    current: () => boolean,
  ) => Promise<VaultQuickTargetLease>;
  native: {
    hasReservation: (id: string) => boolean;
    owns: (owner: Owner, id: string) => boolean;
    capture: (event: Event, id: string) => () => void;
    share: (
      owner: Owner,
      sourceId: string,
      id: string,
      current: () => boolean,
    ) => Promise<SealedSshConnected>;
    admit: (
      owner: Owner,
      q: NativeOpen,
      epoch: number,
      current: () => boolean,
      retired: () => Promise<void>,
    ) => SealedSshAdmission;
    close: (owner: Owner, id: string) => Promise<void>;
    retire: (owner: Owner, id: string) => Promise<void>;
    retireOwner: (owner: Owner, ids: readonly string[]) => Promise<void>;
    closeAll: () => Promise<void>;
  };
};
type Entry = {
  id: string;
  rootId: string;
  owner: Owner;
  cancelled: boolean;
  adopted: boolean;
  target?: VaultQuickTargetLease;
  opening?: Promise<void>;
  closing?: Promise<void>;
  failedClose: boolean;
  memberClosed: boolean;
  securityRetired: boolean;
  finish: () => void;
};
type OwnerStop = { work?: Promise<void> };

/** Primary admissions own targets; native cohorts may outlive their terminal member. */
export class VaultSshIpc {
  private readonly options: Options;
  private readonly entries = new Map<string, Entry>();
  private readonly hooks = new Map<Owner, () => void>();
  private readonly ownerStops = new Map<Owner, OwnerStop>();
  private stopping = false;
  private shutdown?: Promise<void>;
  constructor(options: Options) {
    this.options = options;
  }
  handles(id: string): boolean {
    return (
      this.options.workspace() || this.entries.has(id) || this.options.native.hasReservation(id)
    );
  }
  isQuickTarget(q: {
    workspaceId: string;
    sessionId: string;
    nodeId: string;
    epoch: number;
  }): boolean {
    const e = this.entries.get(q.sessionId),
      ref = e?.target?.reference;
    return Boolean(
      e?.adopted &&
      !e.cancelled &&
      ref &&
      ref.id === q.nodeId &&
      ref.workspaceId === q.workspaceId &&
      ref.sessionId === q.sessionId &&
      ref.epoch === q.epoch,
    );
  }
  private requireOwner(event: Event, id: string): void {
    if (
      !vaultID(id) ||
      !this.options.trusted(event) ||
      event.sender.isDestroyed() ||
      (this.entries.has(id) && this.entries.get(id)!.owner !== event.sender)
    )
      throw Error('Invalid vault SSH owner.');
  }
  private forget(e: Entry): void {
    if (this.entries.get(e.id) !== e) return;
    this.entries.delete(e.id);
    if ([...this.entries.values()].some((other) => other.owner === e.owner)) return;
    const hook = this.hooks.get(e.owner)!;
    e.owner.removeListener('destroyed', hook);
    e.owner.removeListener('did-start-loading', hook);
    e.owner.removeListener('render-process-gone', hook);
    this.hooks.delete(e.owner);
  }
  private forgetRetired(e: Entry): void {
    if (e.cancelled && !e.adopted && !e.target && !e.opening && !e.closing && !e.failedClose)
      this.forget(e);
  }
  private async releaseTarget(e: Entry): Promise<void> {
    const target = e.target;
    if (!target) return;
    await target.release();
    if (e.target === target) e.target = undefined;
  }
  private reserve(owner: Owner, id: string, rootId: string): Entry {
    let finish!: () => void;
    const e: Entry = {
      id,
      rootId,
      owner,
      cancelled: false,
      adopted: false,
      failedClose: false,
      memberClosed: false,
      securityRetired: false,
      opening: new Promise((r) => {
        finish = r;
      }),
      finish: () => finish(),
    };
    this.entries.set(id, e);
    if (!this.hooks.has(owner)) {
      const retire = () => {
        void this.retireOwner(owner).catch(() => {});
      };
      this.hooks.set(owner, retire);
      owner.on('destroyed', retire);
      owner.on('did-start-loading', retire);
      owner.on('render-process-gone', retire);
    }
    return e;
  }
  private current(e: Entry, event: Event): boolean {
    try {
      return (
        this.entries.get(e.id) === e &&
        !e.cancelled &&
        !this.stopping &&
        !this.ownerStops.has(e.owner) &&
        this.options.workspace() &&
        this.options.trusted(event) &&
        !e.owner.isDestroyed()
      );
    } catch {
      return false;
    }
  }
  private finishOpening(e: Entry): void {
    e.opening = undefined;
    e.finish();
    this.forgetRetired(e);
  }
  async open(event: Event, value: unknown): Promise<SealedSshConnected> {
    const q = parseVaultSshOpen(value);
    if (!q) throw Error('Invalid vault SSH request.');
    this.requireOwner(event, q.sessionId);
    if (
      !this.options.workspace() ||
      this.stopping ||
      this.ownerStops.has(event.sender) ||
      this.entries.has(q.sessionId) ||
      this.options.native.hasReservation(q.sessionId) ||
      this.entries.size >= 128 ||
      [...this.entries.values()].filter((e) => e.id === e.rootId).length >= 32
    )
      throw Error('Vault SSH session is unavailable.');
    const e = this.reserve(event.sender, q.sessionId, q.sessionId);
    const current = () => this.current(e, event);
    const cleanup = async (force = false) => {
      if (this.entries.get(e.id) !== e) return;
      e.cancelled = true;
      if (e.adopted) {
        if (
          e.memberClosed &&
          !force &&
          !e.securityRetired &&
          this.options.workspace() &&
          this.options.trusted(event) &&
          !e.owner.isDestroyed()
        )
          await this.options.native.close(e.owner, e.id);
        else await this.options.native.retire(e.owner, e.id);
      }
      if (!e.adopted) await this.releaseTarget(e);
    };
    try {
      const result = await this.options.authorize(
        async (epoch) => {
          if (!current()) throw Error('SSH opening was cancelled.');
          if (q.quickTarget) {
            e.target = await this.options.quickTarget(q.quickTarget, e.id, epoch, current);
            if (!current()) throw Error('SSH opening was cancelled.');
          }
          const input: NativeOpen = {
            sessionId: e.id,
            nodeId: e.target ? e.target.reference.id : q.nodeId!,
            columns: q.columns,
            rows: q.rows,
            ...(q.mode ? { mode: q.mode } : {}),
            ...(q.credentialId ? { credentialId: q.credentialId } : {}),
            ...(q.manualCredentials ? { manualCredentials: true } : {}),
            ...(q.manualKeyPassphrase ? { manualKeyPassphrase: true } : {}),
          };
          const admission = this.options.native.admit(e.owner, input, epoch, current, async () => {
            await this.releaseTarget(e);
            e.adopted = false;
            e.cancelled = true;
            for (const child of this.entries.values()) {
              if (child.rootId !== e.id) continue;
              child.cancelled = true;
              child.securityRetired = true;
              this.forgetRetired(child);
            }
          });
          e.adopted = admission.accepted;
          const result = await admission.result;
          if (!current()) throw Error('SSH opening was cancelled.');
          return result;
        },
        () => cleanup(true),
      );
      if (!current()) throw Error('SSH opening was cancelled.');
      return result;
    } catch {
      try {
        await cleanup();
      } catch {
        throw Error('SSH shutdown could not be confirmed.');
      }
      throw Error('Vault SSH connection could not be opened.');
    } finally {
      this.finishOpening(e);
    }
  }
  async share(event: Event, sourceId: string, id: string): Promise<SealedSshConnected> {
    this.requireOwner(event, id);
    const source = this.entries.get(sourceId),
      root = source && this.entries.get(source.rootId);
    if (
      !vaultID(sourceId) ||
      sourceId === id ||
      !source ||
      !root?.adopted ||
      source.cancelled ||
      root.securityRetired ||
      source.owner !== event.sender ||
      !this.options.workspace() ||
      this.stopping ||
      this.ownerStops.has(event.sender) ||
      this.entries.has(id) ||
      this.options.native.hasReservation(id) ||
      this.entries.size >= 128
    )
      throw Error('Source vault SSH connection is unavailable.');
    const sourceCurrent = this.options.native.capture(event, sourceId);
    const e = this.reserve(event.sender, id, root.id),
      current = () => this.current(e, event);
    const cleanup = async (force = false) => {
      if (this.entries.get(id) !== e) return;
      e.cancelled = true;
      if (force) await this.options.native.retire(e.owner, e.rootId);
      else await this.options.native.close(e.owner, id);
    };
    try {
      const result = await this.options.authorize(
        async () => {
          sourceCurrent();
          if (!current()) throw Error('SFTP opening was cancelled.');
          const result = await this.options.native.share(e.owner, sourceId, id, current);
          if (!current()) throw Error('SFTP opening was cancelled.');
          return result;
        },
        () => cleanup(true),
      );
      if (!current()) throw Error('SFTP opening was cancelled.');
      return result;
    } catch {
      try {
        await cleanup();
      } catch {
        e.failedClose = true;
        throw Error('SSH shutdown could not be confirmed.');
      }
      throw Error('SFTP connection could not be opened.');
    } finally {
      this.finishOpening(e);
    }
  }
  close(event: Event, id: string): Promise<void> {
    this.requireOwner(event, id);
    const e = this.entries.get(id);
    if (!e) {
      if (!this.options.native.hasReservation(id)) return Promise.resolve();
      if (!this.options.native.owns(event.sender, id)) throw Error('Invalid vault SSH owner.');
      return this.options.native.close(event.sender, id);
    }
    if (e.closing) return e.closing;
    e.cancelled = true;
    e.memberClosed = true;
    const opening = e.opening;
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([this.options.native.close(e.owner, id), opening]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('SSH shutdown could not be confirmed.');
      await this.options.native.close(e.owner, id);
      if (!e.adopted) await this.releaseTarget(e);
      e.failedClose = false;
    });
    e.closing = work
      .catch(() => {
        e.failedClose = true;
        throw Error('SSH shutdown could not be confirmed.');
      })
      .finally(() => {
        e.closing = undefined;
        this.forgetRetired(e);
      });
    return e.closing;
  }
  private retireOwner(owner: Owner): Promise<void> {
    const previous = this.ownerStops.get(owner);
    if (previous?.work) return previous.work;
    const state: OwnerStop = previous ?? {};
    this.ownerStops.set(owner, state);
    const entries = [...this.entries.values()].filter((e) => e.owner === owner);
    for (const e of entries) {
      e.cancelled = true;
      e.securityRetired = true;
    }
    const retired = this.options.native.retireOwner(
      owner,
      entries.map((e) => e.id),
    );
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([retired, ...entries.map((e) => e.opening)]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('SSH shutdown could not be confirmed.');
      const released = await Promise.allSettled(
        entries.map(async (e) => {
          if (e.adopted) throw Error('SSH shutdown could not be confirmed.');
          await this.releaseTarget(e);
        }),
      );
      if (released.some((r) => r.status === 'rejected'))
        throw Error('SSH shutdown could not be confirmed.');
      for (const e of entries) {
        e.failedClose = false;
        this.forgetRetired(e);
      }
      this.ownerStops.delete(owner);
    });
    state.work = work.finally(() => {
      state.work = undefined;
    });
    return state.work;
  }
  closeAll(): Promise<void> {
    if (this.shutdown) return this.shutdown;
    this.stopping = true;
    const entries = [...this.entries.values()];
    for (const e of entries) {
      e.cancelled = true;
      e.securityRetired = true;
    }
    const retired = this.options.native.closeAll();
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        retired,
        ...entries.map((e) => e.opening),
        ...[...this.ownerStops.values()].map((s) => s.work),
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('SSH shutdown could not be confirmed.');
      const released = await Promise.allSettled(
        entries.map(async (e) => {
          if (e.adopted) throw Error('SSH shutdown could not be confirmed.');
          await this.releaseTarget(e);
        }),
      );
      if (released.some((r) => r.status === 'rejected'))
        throw Error('SSH shutdown could not be confirmed.');
      for (const e of entries) this.forget(e);
      this.ownerStops.clear();
      this.stopping = false;
    });
    this.shutdown = work.finally(() => {
      this.shutdown = undefined;
    });
    return this.shutdown;
  }
}
