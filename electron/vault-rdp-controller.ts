import type { WebContents } from 'electron';
import { randomUUID } from 'node:crypto';
import { parseSealedRdpOpen } from './sealed-rdp-contract.ts';
import type { SealedRdpBackend, SealedRdpOpen, SealedRdpControl } from './sealed-rdp.ts';
import type { RdpBackendEvent } from './rdp-contract.ts';

type Backend = Pick<SealedRdpBackend, 'open' | 'command' | 'close' | 'closeAll'>;
type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener' | 'send'>;
type Entry = {
  id: string;
  owner: Owner;
  trusted: () => boolean;
  epoch: number;
  started: boolean;
  lifecycle: string;
  initial?: RdpBackendEvent;
  cancelled: boolean;
  retire: () => void;
  stop?: Promise<void>;
  releaseTarget?: () => Promise<void>;
};

// Associates public session IDs with one main-frame owner. The relay's process
// reservation remains authoritative until shutdown is confirmed, even if the
// renderer has already removed its tab or a replacement open supersedes it.
export class VaultRdpController {
  private readonly entries = new Map<string, Entry>();
  private readonly backend: Backend;
  private readonly authorized: (epoch: number) => boolean;
  private readonly observe?: (event: RdpBackendEvent, owner: Owner) => void;
  private readonly certificate?: (event: RdpBackendEvent, owner: Owner) => void;
  private closing?: Promise<void>;
  private closingPending = false;
  constructor(
    create: (onEvent: (event: RdpBackendEvent) => void) => Backend,
    authorized: (epoch: number) => boolean,
    certificate?: (event: RdpBackendEvent, owner: Owner) => void,
    observe?: (event: RdpBackendEvent, owner: Owner) => void,
  ) {
    this.authorized = authorized;
    this.certificate = certificate;
    this.observe = observe;
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
  has(id: string): boolean {
    return this.entries.has(id);
  }
  async open(
    owner: Owner,
    trusted: () => boolean,
    request: SealedRdpOpen,
    epoch: number,
    releaseTarget?: () => Promise<void>,
  ): Promise<RdpBackendEvent> {
    const q = parseSealedRdpOpen(request);
    if (!q || !trusted() || owner.isDestroyed()) throw Error('Invalid RDP owner.');
    const existing = this.entries.get(q.sessionId);
    if (existing && existing.owner !== owner) throw Error('RDP session belongs to another window.');
    if (this.closing || !this.authorized(epoch)) throw Error('Vault RDP is locked.');
    const entry: Entry = {
      id: q.sessionId,
      lifecycle: randomUUID(),
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
      if (!this.current(entry)) throw Error('RDP opening was cancelled.');
      entry.started = true;
      await this.backend.open(q, epoch, () => this.current(entry));
      if (!this.current(entry) || !entry.initial) throw Error('RDP opening was cancelled.');
      return entry.initial;
    } catch {
      await this.stop(entry);
      throw Error('RDP connection could not be opened.');
    }
  }
  async control(
    owner: Owner,
    trusted: () => boolean,
    id: string,
    command: SealedRdpControl,
    lifecycle?: string,
  ): Promise<RdpBackendEvent> {
    const entry = this.entries.get(id);
    if (
      !trusted() ||
      owner.isDestroyed() ||
      !entry ||
      entry.owner !== owner ||
      !entry.started ||
      !this.current(entry) ||
      (lifecycle !== undefined && lifecycle !== entry.lifecycle)
    )
      throw Error('RDP session is unavailable.');
    const event = await this.backend.command(id, command);
    if (!this.current(entry)) throw Error('RDP operation was cancelled.');
    const normalized = { ...event, lifecycleId: entry.lifecycle };
    this.observe?.(normalized, owner);
    return normalized;
  }
  private forward(event: RdpBackendEvent): void {
    const entry = event.sessionId ? this.entries.get(event.sessionId) : undefined;
    if (!entry || !entry.started) return;
    if (!this.current(entry)) {
      void this.stop(entry).catch(() => {});
      return;
    }
    event = { ...event, lifecycleId: entry.lifecycle };
    if (event.requestId && (event.type === 'ready' || event.type === 'started'))
      entry.initial = event;
    try {
      if (event.type === 'certificate') {
        if (!this.certificate) throw Error('RDP certificate handler unavailable.');
        this.certificate(event, entry.owner);
        return;
      }
      this.observe?.(event, entry.owner);
      entry.owner.send('rdp:event', event);
    } catch {
      void this.stop(entry).catch(() => {});
      return;
    }
    if (['exited', 'disconnected', 'fatalError', 'error'].includes(event.type))
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
        throw Error('RDP shutdown could not be confirmed.');
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
