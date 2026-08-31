export const defaultSidebarWidth = 320;
// Keeps the Connections title and its five header actions visible at the resize limit.
export const minSidebarWidth = 256;
export const maxSidebarWidth = 600;
export const sidebarSaveDelayMs = 250;

export function normalizeSidebarWidth(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return defaultSidebarWidth;
  return Math.min(maxSidebarWidth, Math.max(minSidebarWidth, Math.round(value)));
}

type Scheduler = {
  set(callback: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
};

const defaultScheduler: Scheduler = {
  set: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clear: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function createDebouncedSidebarWriter(
  write: (width: number) => void | Promise<void>,
  options: { delayMs?: number; scheduler?: Scheduler; initialWidth?: unknown } = {},
) {
  const delayMs = options.delayMs ?? sidebarSaveDelayMs;
  const scheduler = options.scheduler ?? defaultScheduler;
  let handle: unknown;
  let pending: number | undefined;
  let commitQueue = Promise.resolve();
  let lastWritten =
    options.initialWidth === undefined ? undefined : normalizeSidebarWidth(options.initialWidth);
  const commit = async (): Promise<void> => {
    const width = pending;
    pending = undefined;
    if (width !== undefined && width !== lastWritten) {
      await write(width);
      lastWritten = width;
    }
  };
  const enqueueCommit = (): Promise<void> => {
    commitQueue = commitQueue.then(commit, commit);
    return commitQueue;
  };
  return {
    schedule(value: unknown) {
      pending = normalizeSidebarWidth(value);
      if (handle !== undefined) scheduler.clear(handle);
      handle = scheduler.set(() => {
        handle = undefined;
        void enqueueCommit().catch(() => undefined);
      }, delayMs);
    },
    async flush() {
      if (handle !== undefined) scheduler.clear(handle);
      handle = undefined;
      await enqueueCommit();
    },
    cancel() {
      if (handle !== undefined) scheduler.clear(handle);
      handle = undefined;
      pending = undefined;
    },
  };
}
