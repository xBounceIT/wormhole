import type { WebContents } from 'electron';
import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { parseVaultQuickTarget, type VaultQuickTarget } from './vault-quick-target.ts';
import type { SealedVncBackend, SealedVncEvent, SealedVncOpen } from './sealed-vnc.ts';

type VncControl =
  | { action: 'vnc.disconnect'; sessionId: string }
  | { action: 'vnc.pointer'; sessionId: string; x: number; y: number; buttons: number }
  | { action: 'vnc.key'; sessionId: string; keysym: number; down: boolean };
export type VaultVncCommand =
  | ({ action: 'vnc.connect'; sessionId: string; manualPassword?: true } & (
      | { nodeId: string; credentialId?: string; quickTarget?: never }
      | { quickTarget: VaultQuickTarget; nodeId?: never; credentialId?: never }
    ))
  | VncControl;
export type VaultVncNativeCommand = ({ action: 'vnc.connect' } & SealedVncOpen) | VncControl;
export function parseVaultVncCommand(value: unknown): VaultVncCommand | undefined {
  if (!vaultRecord(value) || !vaultID(value.sessionId)) return undefined;
  const { action, sessionId } = value;
  switch (action) {
    case 'vnc.connect': {
      if (
        !vaultFields(value, [
          'action',
          'sessionId',
          ...(value.quickTarget !== undefined ? ['quickTarget'] : ['nodeId']),
          ...(value.credentialId !== undefined ? ['credentialId'] : []),
          ...(value.manualPassword !== undefined ? ['manualPassword'] : []),
        ]) ||
        (value.manualPassword !== undefined && value.manualPassword !== true) ||
        (value.quickTarget === undefined
          ? !vaultID(value.nodeId)
          : value.nodeId !== undefined || value.credentialId !== undefined) ||
        (value.credentialId !== undefined && !vaultID(value.credentialId))
      )
        return undefined;
      const quickTarget =
        value.quickTarget === undefined ? undefined : parseVaultQuickTarget(value.quickTarget);
      if (
        value.quickTarget !== undefined &&
        (!quickTarget ||
          quickTarget.protocol !== 'vnc' ||
          (value.manualPassword === true && quickTarget.credentialId !== ''))
      )
        return undefined;
      return {
        action,
        sessionId,
        ...(quickTarget
          ? { quickTarget }
          : {
              nodeId: value.nodeId as string,
              ...(value.credentialId ? { credentialId: value.credentialId as string } : {}),
            }),
        ...(value.manualPassword ? { manualPassword: true as const } : {}),
      };
    }
    case 'vnc.disconnect':
      return vaultFields(value, ['action', 'sessionId']) ? { action, sessionId } : undefined;
    case 'vnc.pointer':
      if (
        !vaultFields(value, ['action', 'sessionId', 'x', 'y', 'buttons']) ||
        ![value.x, value.y].every(
          (n) => Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 65535,
        ) ||
        !Number.isInteger(value.buttons) ||
        (value.buttons as number) < 0 ||
        (value.buttons as number) > 255
      )
        return undefined;
      return {
        action,
        sessionId,
        x: value.x as number,
        y: value.y as number,
        buttons: value.buttons as number,
      };
    case 'vnc.key':
      if (
        !vaultFields(value, ['action', 'sessionId', 'keysym', 'down']) ||
        typeof value.down !== 'boolean' ||
        !Number.isInteger(value.keysym) ||
        (value.keysym as number) < 1 ||
        (value.keysym as number) > 0xffffffff
      )
        return undefined;
      return { action, sessionId, keysym: value.keysym as number, down: value.down };
    default:
      return undefined;
  }
}

type Backend = Pick<SealedVncBackend, 'open' | 'send' | 'close' | 'closeAll'>;
type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener' | 'send'>;
type Entry = {
  id: string;
  owner: Owner;
  trusted: () => boolean;
  epoch: number;
  started: boolean;
  cancelled: boolean;
  retire: () => void;
  stop?: Promise<void>;
  releaseTarget?: () => Promise<void>;
};

// Associates public session IDs with one main-frame owner. The relay's process
// reservation remains authoritative until shutdown is confirmed, even if the
// renderer has already removed its tab or a replacement open supersedes it.
export class VaultVncController {
  private readonly entries = new Map<string, Entry>();
  private readonly backend: Backend;
  private readonly authorized: (epoch: number) => boolean;
  private closing?: Promise<void>;
  private closingPending = false;
  constructor(
    create: (onEvent: (event: SealedVncEvent) => void) => Backend,
    authorized: (epoch: number) => boolean,
  ) {
    this.authorized = authorized;
    this.backend = create((event) => this.forward(event));
  }
  private current(entry: Entry): boolean {
    return (
      !this.closing &&
      !entry.cancelled &&
      this.entries.get(entry.id) === entry &&
      !entry.owner.isDestroyed() &&
      entry.trusted() &&
      this.authorized(entry.epoch)
    );
  }
  async command(
    owner: Owner,
    trusted: () => boolean,
    command: VaultVncNativeCommand,
    epoch: number,
    releaseTarget?: () => Promise<void>,
  ): Promise<void> {
    if (!trusted() || owner.isDestroyed()) throw Error('Invalid VNC owner.');
    const existing = this.entries.get(command.sessionId);
    if (existing && existing.owner !== owner) throw Error('VNC session belongs to another window.');
    if (command.action === 'vnc.disconnect') {
      if (existing) await this.stop(existing);
      return;
    }
    if (this.closing || !this.authorized(epoch)) throw Error('Vault VNC is locked.');
    if (command.action !== 'vnc.connect') {
      if (!existing || !this.current(existing) || !existing.started)
        throw Error('VNC session is unavailable.');
      const { action, ...fields } = command;
      this.backend.send(command.sessionId, {
        ...fields,
        type: action === 'vnc.pointer' ? 'pointer' : 'key',
      });
      return;
    }
    const entry: Entry = {
      id: command.sessionId,
      owner,
      trusted,
      epoch,
      started: false,
      releaseTarget,
      cancelled: false,
      retire: () => {
        void this.stop(entry).catch(() => {});
      },
    };
    this.entries.set(entry.id, entry);
    owner.on('destroyed', entry.retire);
    owner.on('did-start-loading', entry.retire);
    try {
      if (existing) await this.stop(existing);
      if (!this.current(entry)) throw Error('VNC opening was cancelled.');
      entry.started = true;
      await this.backend.open(
        {
          sessionId: entry.id,
          nodeId: command.nodeId,
          ...(command.credentialId ? { credentialId: command.credentialId } : {}),
          ...(command.manualPassword ? { manualPassword: true as const } : {}),
        },
        epoch,
        () => this.current(entry),
      );
      if (!this.current(entry)) throw Error('VNC opening was cancelled.');
    } catch {
      await this.stop(entry);
      throw Error('VNC connection could not be opened.');
    }
  }
  private forward(event: SealedVncEvent): void {
    const entry = this.entries.get(event.sessionId);
    if (!entry || !entry.started) return;
    if (!this.current(entry)) {
      void this.stop(entry).catch(() => {});
      return;
    }
    try {
      entry.owner.send('backend:event', event);
    } catch {
      void this.stop(entry).catch(() => {});
      return;
    }
    if (
      event.type === 'vnc.status' &&
      (event.status === 'failed' || event.status === 'disconnected')
    )
      void this.stop(entry).catch(() => {});
  }
  private stop(entry: Entry): Promise<void> {
    if (entry.stop) return entry.stop;
    entry.cancelled = true;
    // Reserve before calling close: relay callbacks can synchronously reenter.
    let resolve!: () => void, reject!: (error: unknown) => void;
    entry.stop = new Promise<void>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const stopping = entry.stop;
    void stopping.catch(() => {});
    const failed = (error: unknown) => {
      if (entry.stop === stopping) entry.stop = undefined;
      reject(error);
    };
    const finish = () => {
      entry.owner.removeListener('destroyed', entry.retire);
      entry.owner.removeListener('did-start-loading', entry.retire);
      if (this.entries.get(entry.id) === entry) this.entries.delete(entry.id);
      resolve();
    };
    try {
      void this.backend
        .close(entry.id)
        .then(async () => {
          await entry.releaseTarget?.();
          finish();
        })
        .catch(failed);
    } catch (error) {
      failed(error);
    }
    return stopping;
  }
  has(id: string): boolean {
    return this.entries.has(id);
  }
  ownerForSession(id: string): Owner | undefined {
    const entry = this.entries.get(id);
    return entry && this.current(entry) ? entry.owner : undefined;
  }
  closeForOwner(owner: Owner, id: string): Promise<void> {
    const entry = this.entries.get(id);
    return entry?.owner === owner ? this.stop(entry) : Promise.resolve();
  }
  closeAll(): Promise<void> {
    if (this.closing && this.closingPending) return this.closing;
    this.closingPending = true;
    const task = Promise.resolve().then(async () => {
      const results = await Promise.allSettled(
        [...this.entries.values()].map((entry) => this.stop(entry)),
      );
      const all = await Promise.allSettled([this.backend.closeAll()]);
      if ([...results, ...all].some((result) => result.status === 'rejected'))
        throw Error('VNC shutdown could not be confirmed.');
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
        // Keep the failed shutdown as an admission barrier until an explicit retry
        // confirms every original resource has stopped.
        throw error;
      },
    );
    this.closing = tracked;
    return tracked;
  }
}
