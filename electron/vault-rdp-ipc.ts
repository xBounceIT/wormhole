import type { WebContents } from 'electron';
import type { RdpBackendEvent, RdpSurfaceRect } from './rdp-contract.ts';
import { isRdpSurfaceRectWithinNativeBounds } from './rdp-contract.ts';
import { parseSealedRdpControl } from './sealed-rdp-contract.ts';
import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import {
  parseVaultQuickTarget,
  type VaultQuickTarget,
  type VaultQuickTargetLease,
} from './vault-quick-target.ts';
import type { VaultRdpController } from './vault-rdp-controller.ts';

export type VaultRdpOpenRequest = {
  sessionId: string;
  manualCredentials?: true;
  bounds: RdpSurfaceRect;
} & (
  | { nodeId: string; credentialId?: string; quickTarget?: never }
  | { quickTarget: VaultQuickTarget; nodeId?: never; credentialId?: never }
);
type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener' | 'send'>;
type Event = { sender: Owner };
type Controller = Pick<
  VaultRdpController,
  'has' | 'open' | 'control' | 'closeForOwner' | 'closeAll'
>;
type Options = {
  controller: Controller;
  workspace: () => boolean;
  trusted: (event: Event) => boolean;
  unlocked: () => Promise<void>;
  authorize: <T>(run: (epoch: number) => Promise<T>, cleanup: () => Promise<void>) => Promise<T>;
  surface: (
    event: Event,
    sessionId: string,
    bounds?: RdpSurfaceRect,
  ) => {
    ownerWindow: string;
    bounds?: RdpSurfaceRect;
    requireContentProtection?: true;
  };
  quickTarget?: (
    target: VaultQuickTarget,
    sessionId: string,
    epoch: number,
    accepted: () => boolean,
  ) => Promise<VaultQuickTargetLease>;
  forget: (sessionId: string) => void;
};
type Opening = { cancelled: boolean; done: Promise<void>; finish: () => void };
type Closing = { owner: Owner; work?: Promise<RdpBackendEvent> };

function rendererBounds(value: unknown): RdpSurfaceRect | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['x', 'y', 'width', 'height'])) return undefined;
  const rect = value as RdpSurfaceRect;
  return isRdpSurfaceRectWithinNativeBounds(rect) ? { ...rect } : undefined;
}
export function parseVaultRdpOpenRequest(value: unknown): VaultRdpOpenRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'sessionId',
      ...(value.quickTarget !== undefined ? ['quickTarget'] : ['nodeId']),
      'bounds',
      ...(value.credentialId !== undefined ? ['credentialId'] : []),
      ...(value.manualCredentials !== undefined ? ['manualCredentials'] : []),
    ]) ||
    !vaultID(value.sessionId) ||
    (value.quickTarget === undefined
      ? !vaultID(value.nodeId)
      : value.nodeId !== undefined || value.credentialId !== undefined) ||
    (value.credentialId !== undefined && !vaultID(value.credentialId)) ||
    (value.manualCredentials !== undefined &&
      (value.manualCredentials !== true || value.credentialId !== undefined))
  )
    return undefined;
  const quickTarget =
    value.quickTarget === undefined ? undefined : parseVaultQuickTarget(value.quickTarget);
  if (
    value.quickTarget !== undefined &&
    (!quickTarget ||
      quickTarget.protocol !== 'rdp' ||
      (value.manualCredentials === true && quickTarget.credentialId !== ''))
  )
    return undefined;
  const bounds = rendererBounds(value.bounds);
  return bounds
    ? {
        sessionId: value.sessionId,
        ...(quickTarget
          ? { quickTarget }
          : {
              nodeId: value.nodeId as string,
              ...(value.credentialId !== undefined ? { credentialId: value.credentialId } : {}),
            }),
        bounds,

        ...(value.manualCredentials === true ? { manualCredentials: true } : {}),
      }
    : undefined;
}
function surfaceRequest(value: unknown, operation = false) {
  if (
    !vaultRecord(value) ||
    !vaultID(value.sessionId) ||
    !vaultFields(value, [
      'sessionId',
      ...(operation ? ['operation'] : []),
      ...(value.bounds !== undefined ? ['bounds'] : []),
    ])
  )
    throw Error('Invalid vault RDP surface request.');
  const bounds = value.bounds === undefined ? undefined : rendererBounds(value.bounds);
  if (value.bounds !== undefined && !bounds) throw Error('Invalid vault RDP bounds.');
  return { sessionId: value.sessionId, bounds, operation: value.operation };
}
const ack = (sessionId: string): RdpBackendEvent => ({ type: 'ack', sessionId });

/** Public IPC admission accepts saved identity or public quick metadata; never secrets or bundles. */
export class VaultRdpIpc {
  private readonly options: Options;
  private readonly targets = new Map<string, VaultQuickTargetLease>();
  private readonly openings = new Map<string, Opening>();
  private readonly closing = new Map<string, Closing>();
  private readonly visibility = new Map<string, boolean>();
  private readonly ownerRetirement = new Map<Owner, () => void>();
  private readonly owners = new Map<string, Owner>();
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
      throw Error('Invalid vault RDP owner.');
  }
  private checkCapacity(id: string): void {
    if (!this.owners.has(id) && this.owners.size >= 32)
      throw Error('Close a session before opening another.');
  }
  private reserveOwner(owner: Owner, id: string): void {
    this.checkCapacity(id);
    this.owners.set(id, owner);
    if (this.ownerRetirement.has(owner)) return;
    const retire = () => {
      for (const [session, current] of this.owners)
        if (current === owner) void this.disconnect({ sender: owner }, session).catch(() => {});
    };
    this.ownerRetirement.set(owner, retire);
    owner.on('destroyed', retire);
    owner.on('did-start-loading', retire);
  }
  private releaseOwner(id: string): void {
    const owner = this.owners.get(id);
    this.owners.delete(id);
    this.visibility.delete(id);
    if (!owner || [...this.owners.values()].includes(owner)) return;
    const retire = this.ownerRetirement.get(owner)!;
    owner.removeListener('destroyed', retire);
    owner.removeListener('did-start-loading', retire);
    this.ownerRetirement.delete(owner);
  }
  private async releaseTarget(id: string, target = this.targets.get(id)): Promise<void> {
    if (!target) return;
    await target.release();
    if (this.targets.get(id) === target) this.targets.delete(id);
  }
  async open(event: Event, value: unknown): Promise<RdpBackendEvent> {
    const q = parseVaultRdpOpenRequest(value);
    if (!q || !this.options.workspace()) throw Error('Invalid vault RDP request.');
    this.requireOwner(event, q.sessionId);
    if (this.stopping || this.openings.has(q.sessionId) || this.closing.has(q.sessionId))
      throw Error('RDP session is busy.');
    this.checkCapacity(q.sessionId);
    this.options.surface(event, q.sessionId, q.bounds);
    let finish!: () => void;
    const opening: Opening = {
      cancelled: false,
      done: new Promise<void>((resolve) => {
        finish = resolve;
      }),
      finish: () => finish(),
    };
    this.openings.set(q.sessionId, opening);
    this.reserveOwner(event.sender, q.sessionId);
    const current = () =>
      !this.stopping &&
      !opening.cancelled &&
      this.owners.get(q.sessionId) === event.sender &&
      this.options.workspace() &&
      this.options.trusted(event) &&
      !event.sender.isDestroyed();
    try {
      const response = await this.options.authorize(
        async (epoch) => {
          if (!current()) throw Error('RDP opening was cancelled.');
          let target: VaultQuickTargetLease | undefined;
          if (q.quickTarget || this.targets.has(q.sessionId)) {
            await this.options.controller.closeForOwner(event.sender, q.sessionId);
            await this.releaseTarget(q.sessionId);
            if (!current()) throw Error('RDP opening was cancelled.');
          }
          if (q.quickTarget) {
            if (!this.options.quickTarget) throw Error('Protected Quick Connect is unavailable.');
            target = await this.options.quickTarget(q.quickTarget, q.sessionId, epoch, current);
            this.targets.set(q.sessionId, target);
            if (!current()) throw Error('RDP opening was cancelled.');
          }
          // Geometry may have changed while authorization was pending. Main owns
          // the remembered rectangle and the native HWND, never the renderer.
          const surface = this.options.surface(event, q.sessionId);
          if (!surface.bounds) throw Error('RDP surface is unavailable.');
          const response = await this.options.controller.open(
            event.sender,
            current,
            {
              sessionId: q.sessionId,
              nodeId: target ? target.reference.id : q.nodeId!,
              ...(q.credentialId !== undefined ? { credentialId: q.credentialId } : {}),
              ...(q.manualCredentials ? { manualCredentials: true } : {}),
              ...surface,
              bounds: surface.bounds,
              visible: this.visibility.get(q.sessionId) ?? true,
            },
            epoch,
            target ? () => this.releaseTarget(q.sessionId, target) : undefined,
          );
          if (!current()) throw Error('RDP opening was cancelled.');
          return response;
        },
        async () => {
          opening.cancelled = true;
          await this.options.controller.closeForOwner(event.sender, q.sessionId);
        },
      );
      if (!current()) throw Error('RDP opening was cancelled.');
      return response;
    } catch {
      opening.cancelled = true;
      await this.options.controller.closeForOwner(event.sender, q.sessionId);
      await this.releaseTarget(q.sessionId);
      if (!this.options.controller.has(q.sessionId)) {
        this.releaseOwner(q.sessionId);
        this.options.forget(q.sessionId);
      }
      throw Error('RDP connection could not be opened.');
    } finally {
      if (this.openings.get(q.sessionId) === opening) this.openings.delete(q.sessionId);
      opening.finish();
    }
  }
  async resize(event: Event, value: unknown): Promise<RdpBackendEvent> {
    const q = surfaceRequest(value);
    this.requireOwner(event, q.sessionId);
    await this.options.unlocked();
    this.requireOwner(event, q.sessionId);
    this.checkCapacity(q.sessionId);
    const surface = this.options.surface(event, q.sessionId, q.bounds);
    if (q.bounds || this.options.controller.has(q.sessionId))
      this.reserveOwner(event.sender, q.sessionId);
    if (!this.options.controller.has(q.sessionId)) return ack(q.sessionId);
    if (!surface.bounds) throw Error('RDP surface is unavailable.');
    return this.options.controller.control(
      event.sender,
      () => this.options.trusted(event),
      q.sessionId,
      { op: 'resize', bounds: surface.bounds },
    );
  }
  async input(event: Event, value: unknown): Promise<void> {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, ['sessionId', 'lifecycleId', 'input']) ||
      !vaultID(value.sessionId) ||
      !vaultID(value.lifecycleId)
    )
      throw Error('Invalid vault RDP input.');
    const command = parseSealedRdpControl({ op: 'input', input: value.input });
    if (!command) throw Error('Invalid vault RDP input.');
    const sessionId = value.sessionId,
      lifecycleId = value.lifecycleId;
    this.requireOwner(event, sessionId);
    await this.options.unlocked();
    this.requireOwner(event, sessionId);
    await this.options.controller.control(
      event.sender,
      () => this.options.trusted(event),
      sessionId,
      command,
      lifecycleId,
    );
  }
  async command(event: Event, value: unknown): Promise<RdpBackendEvent> {
    const q = surfaceRequest(value, true);
    this.requireOwner(event, q.sessionId);
    if (!['show', 'hide', 'focus', 'disconnect'].includes(q.operation as string))
      throw Error('Invalid RDP operation.');
    if (q.operation === 'disconnect') {
      this.options.surface(event, q.sessionId); // assert ownership of an idle remembered surface too
      return this.disconnect(event, q.sessionId);
    }
    await this.options.unlocked();
    this.requireOwner(event, q.sessionId);
    this.checkCapacity(q.sessionId);
    const surface = this.options.surface(event, q.sessionId, q.bounds);
    if (q.bounds) this.reserveOwner(event.sender, q.sessionId);
    if (q.operation === 'show' || q.operation === 'hide') {
      this.reserveOwner(event.sender, q.sessionId);
      this.visibility.set(q.sessionId, q.operation === 'show');
    }
    if (!this.options.controller.has(q.sessionId)) return ack(q.sessionId);
    if (q.operation === 'show' && !surface.bounds) throw Error('RDP surface is unavailable.');
    return this.options.controller.control(
      event.sender,
      () => this.options.trusted(event),
      q.sessionId,
      q.operation === 'show'
        ? { op: 'show', bounds: surface.bounds! }
        : { op: q.operation as 'hide' | 'focus' },
    );
  }
  private disconnect(event: Event, id: string): Promise<RdpBackendEvent> {
    if (
      !this.owners.has(id) &&
      !this.openings.has(id) &&
      !this.closing.has(id) &&
      !this.options.controller.has(id)
    )
      return Promise.resolve(ack(id));
    let closing = this.closing.get(id);
    if (closing?.work) return closing.work;
    closing ??= { owner: event.sender };
    this.closing.set(id, closing);
    const opening = this.openings.get(id);
    if (opening) opening.cancelled = true;
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        this.options.controller.closeForOwner(event.sender, id),
        opening?.done,
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('RDP shutdown could not be confirmed.');
      await this.releaseTarget(id);
      if (this.closing.get(id) === closing) {
        this.releaseOwner(id);
        this.closing.delete(id);
        this.options.forget(id);
      }
      return ack(id);
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
    const task = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        this.options.controller.closeAll(),
        ...[...this.openings.values()].map((opening) => opening.done),
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('RDP shutdown could not be confirmed.');
      const released = await Promise.allSettled(
        [...this.targets.keys()].map((id) => this.releaseTarget(id)),
      );
      if (released.some((r) => r.status === 'rejected'))
        throw Error('RDP target retirement could not be confirmed.');
      for (const id of this.owners.keys()) {
        this.options.forget(id);
        this.releaseOwner(id);
      }
      this.closing.clear();
      this.stopping = false;
    });
    this.shutdown = task.finally(() => {
      this.shutdown = undefined;
    });
    return this.shutdown;
  }
}
