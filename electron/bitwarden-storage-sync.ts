import type { StorageSnapshot } from './bitwarden-storage.js';

export type BitwardenBrowserStorageSnapshot = StorageSnapshot & {
  revision: number;
  profileRevision: number;
  restore: boolean;
  durable: boolean;
};

type StorageSync = {
  read(): Promise<BitwardenBrowserStorageSnapshot>;
  capture(): Promise<StorageSnapshot>;
  restore(snapshot: StorageSnapshot, expected: StorageSnapshot): Promise<void>;
  commit(
    snapshot: StorageSnapshot,
    sourceRevision: number,
  ): Promise<BitwardenBrowserStorageSnapshot>;
  flush(): Promise<void>;
  markRevision?(revision: number): Promise<void>;
  hydrated?(): void;
};

export async function synchronizeBitwardenStorage(
  storage: StorageSync,
  initialize = false,
): Promise<void> {
  const shared = await storage.read();
  if (initialize && !shared.durable && shared.revision === 0) {
    // An unreadable protected store is not a new installation. Retrying an empty capture here
    // would eventually overwrite the remembered login when the native key store recovers.
    throw new Error('Bitwarden saved browser storage is temporarily unavailable.');
  }
  let revision = shared.profileRevision;
  if (initialize && shared.revision > 0) {
    // A revision marker survives background restarts and even loss of Chromium's store.
    // It proves a previous save, not that the new extension context still has that data.
    // Hydrate before permitting this context to overwrite the protected recovery snapshot.
    const before = await storage.capture();
    revision = Math.max(revision, before.nativeRevision ?? 0);
    // A marker inside Chromium survives normal restart but disappears with a lost/replaced
    // extension origin. Only this native marker proves that the data survived. An external
    // marker can be newer than a recovered backup even though Chromium's store is gone.
    // Matching/newer native state retains token refreshes and logouts since the checkpoint.
    if ((before.nativeRevision ?? 0) < shared.revision) {
      await storage.restore(
        {
          localJson: shared.localJson,
          // No session is written to disk. On cold startup retain the new background's runtime
          // bookkeeping while restoring the remembered account; its vault stays locked as configured.
          sessionJson: shared.sessionJson === '{}' ? before.sessionJson : shared.sessionJson,
        },
        before,
      );
      revision = shared.revision;
    }
  }
  // Once hydration succeeded, a later disk failure must not make a retry overwrite new edits.
  storage.hydrated?.();
  for (let attempt = 0; attempt < 3; attempt++) {
    // Capture first: even a stale profile can contain a new login or a refreshed token.
    // Go merges its changes against the last accepted capture for this profile.
    const captured = await storage.capture();
    await storage.flush();
    const accepted = await storage.commit(captured, revision);
    if (!accepted.restore) {
      if (!accepted.durable)
        throw new Error('Bitwarden browser storage could not be saved securely.');
      await storage.markRevision?.(accepted.revision);
      await storage.flush();
      return;
    }
    // The page can change while Go saves the snapshot. Never replace those newer edits.
    await storage.restore(accepted, captured);
    revision = accepted.revision;
  }
  throw new Error('Bitwarden browser storage changed during synchronization; retry required.');
}

// Only the monotonically increasing change counter crosses the polling boundary.
// Concurrent ticks coalesce, failures retry, and edits during a save remain dirty.
export class BitwardenStorageCheckpoint {
  private savedRevision: number | undefined;
  private pending: Promise<void> | undefined;

  get isPending(): boolean {
    return this.pending !== undefined;
  }

  run(readRevision: () => Promise<number>, save: () => Promise<void>): Promise<void> {
    if (this.pending) return this.pending;
    this.pending = (async () => {
      const revision = await readRevision();
      if (revision === this.savedRevision) return;
      await save();
      this.savedRevision = revision;
    })().finally(() => {
      this.pending = undefined;
    });
    return this.pending;
  }
}
