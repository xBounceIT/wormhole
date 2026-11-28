import type { WebContents } from 'electron';
import { vaultID } from './vault-contract.ts';
import { parseVaultWebRequest, type VaultWebRequest } from './vault-web-open.ts';

type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener'>;
type Event = { sender: Owner };
type Entry = {
  owner: Owner;
  cancelled: boolean;
  opening?: Promise<void>;
  closing?: Promise<void>;
};
type Options<T> = {
  workspace: () => boolean;
  trusted: (event: Event) => boolean;
  authorize: <R>(run: () => Promise<R>, cleanup: () => Promise<void>) => Promise<R>;
  open: (owner: Owner, request: VaultWebRequest, current: () => boolean) => Promise<T>;
  close: (owner: Owner, id: string) => Promise<void>;
  closeAll: () => Promise<void>;
};

/** Reserve a browser before authorization; tabs share its existing native owner. */
export class VaultWebIpc<T> {
  private readonly options: Options<T>;
  private readonly entries = new Map<string, Entry>();
  private readonly hooks = new Map<Owner, () => void>();
  private stopping = false;
  private shutdown?: Promise<void>;
  constructor(options: Options<T>) {
    this.options = options;
  }
  handles(id: string): boolean {
    return this.options.workspace() || this.entries.has(id);
  }
  private requireOwner(event: Event, id: string): void {
    if (
      !vaultID(id) ||
      !this.options.trusted(event) ||
      event.sender.isDestroyed() ||
      (this.entries.has(id) && this.entries.get(id)!.owner !== event.sender)
    )
      throw Error('Invalid vault web owner.');
  }
  private forget(id: string, entry: Entry): void {
    if (this.entries.get(id) !== entry) return;
    this.entries.delete(id);
    if ([...this.entries.values()].some((e) => e.owner === entry.owner)) return;
    const hook = this.hooks.get(entry.owner)!;
    entry.owner.removeListener('destroyed', hook);
    entry.owner.removeListener('did-start-loading', hook);
    entry.owner.removeListener('render-process-gone', hook);
    this.hooks.delete(entry.owner);
  }
  async open(event: Event, value: unknown): Promise<T> {
    const request = parseVaultWebRequest(value);
    if (!request) throw Error('Invalid vault web request.');
    const id = request.sessionId;
    this.requireOwner(event, id);
    const previous = this.entries.get(id);
    if (
      !this.options.workspace() ||
      this.stopping ||
      previous?.opening ||
      previous?.closing ||
      previous?.cancelled ||
      (!previous && this.entries.size >= 32)
    )
      throw Error('Vault web session is unavailable.');
    if (previous) previous.cancelled = true;
    const entry: Entry = { owner: event.sender, cancelled: false };
    let finish!: () => void;
    entry.opening = new Promise((resolve) => {
      finish = resolve;
    });
    this.entries.set(id, entry);
    if (!this.hooks.has(entry.owner)) {
      const retire = () => {
        for (const [id, e] of this.entries)
          if (e.owner === entry.owner) void this.disconnect(id, e).catch(() => {});
      };
      this.hooks.set(entry.owner, retire);
      entry.owner.on('destroyed', retire);
      entry.owner.on('did-start-loading', retire);
      entry.owner.on('render-process-gone', retire);
    }
    const current = () =>
      this.entries.get(id) === entry &&
      !entry.cancelled &&
      !this.stopping &&
      this.options.workspace() &&
      this.options.trusted(event) &&
      !entry.owner.isDestroyed();
    const cleanup = async () => {
      if (this.entries.get(id) !== entry) return;
      entry.cancelled = true;
      await this.options.close(entry.owner, id);
    };
    try {
      const result = await this.options.authorize(async () => {
        if (!current()) throw Error('Web opening was cancelled.');
        const result = await this.options.open(entry.owner, request, current);
        if (!current()) throw Error('Web opening was cancelled.');
        return result;
      }, cleanup);
      if (!current()) throw Error('Web opening was cancelled.');
      return result;
    } catch {
      await cleanup();
      // A concurrent close owns the reservation until it joins this opening.
      if (!entry.closing) this.forget(id, entry);
      throw Error('Vault web connection could not be opened.');
    } finally {
      entry.opening = undefined;
      finish();
    }
  }
  close(event: Event, id: string): Promise<void> {
    this.requireOwner(event, id);
    const entry = this.entries.get(id);
    return entry ? this.disconnect(id, entry, true) : Promise.resolve();
  }
  private disconnect(id: string, entry: Entry, userClose = false): Promise<void> {
    const opening = entry.opening;
    // A settled browser can checkpoint while its original trusted owner is
    // closing it. Pending opens, owner loss and lock still revoke immediately.
    if (!userClose || opening) entry.cancelled = true;
    if (entry.closing) return entry.closing;
    const work = Promise.resolve().then(async () => {
      const result = await Promise.allSettled([this.options.close(entry.owner, id), opening]);
      entry.cancelled = true;
      if (result.some((r) => r.status === 'rejected'))
        throw Error('Web shutdown could not be confirmed.');
      // The original open may have returned a late native receipt.
      await this.options.close(entry.owner, id);
      this.forget(id, entry);
    });
    entry.closing = work.catch(() => {
      entry.cancelled = true;
      entry.closing = undefined;
      throw Error('Web shutdown could not be confirmed.');
    });
    return entry.closing;
  }
  closeAll(): Promise<void> {
    if (this.shutdown) return this.shutdown;
    this.stopping = true;
    for (const entry of this.entries.values()) entry.cancelled = true;
    const work = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        this.options.closeAll(),
        ...[...this.entries].map(([id, entry]) => this.disconnect(id, entry)),
      ]);
      if (results.some((r) => r.status === 'rejected'))
        throw Error('Web shutdown could not be confirmed.');
      await this.options.closeAll();
      this.stopping = false;
    });
    this.shutdown = work.finally(() => {
      this.shutdown = undefined;
    });
    return this.shutdown;
  }
}
