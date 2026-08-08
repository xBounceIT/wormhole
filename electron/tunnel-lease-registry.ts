export type TunnelLeaseRelease = (leaseId: string) => Promise<void>;

type TunnelLeaseEntry = {
  leaseId: string;
  active: boolean;
  release?: Promise<void>;
};

/** Tracks tunnel intent separately from release completion so cancelled acquisitions stay closed. */
export class TunnelLeaseRegistry {
  private readonly entries = new Map<string, TunnelLeaseEntry>();

  claim(ownerId: string, leaseId: string): void {
    if (this.entries.has(ownerId)) {
      throw new Error('The previous VPN tunnel lease has not been released yet.');
    }
    this.entries.set(ownerId, { leaseId, active: true });
  }

  isActive(ownerId: string, leaseId: string): boolean {
    const entry = this.entries.get(ownerId);
    return entry?.active === true && entry.leaseId === leaseId;
  }

  has(ownerId: string): boolean {
    return this.entries.has(ownerId);
  }

  keys(): string[] {
    return [...this.entries.keys()];
  }

  async release(ownerId: string, release: TunnelLeaseRelease): Promise<void> {
    const entry = this.entries.get(ownerId);
    if (!entry) return;
    entry.active = false;
    if (entry.release) return entry.release;

    const task = release(entry.leaseId)
      .then(() => {
        if (this.entries.get(ownerId) === entry) this.entries.delete(ownerId);
      })
      .finally(() => {
        if (this.entries.get(ownerId) === entry) entry.release = undefined;
      });
    entry.release = task;
    return task;
  }

  async releaseAll(release: TunnelLeaseRelease): Promise<PromiseSettledResult<void>[]> {
    return Promise.allSettled(this.keys().map((ownerId) => this.release(ownerId, release)));
  }

  clear(): void {
    this.entries.clear();
  }
}
