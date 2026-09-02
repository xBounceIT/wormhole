export type WindowCloseReason =
  | 'window'
  | 'quit'
  | 'update'
  | 'system-shutdown'
  | 'renderer-failure';

export function normalizeWindowCloseConfirmation(value: unknown): boolean {
  return value !== false;
}

export function parseWindowCloseSettingUpdate(value: unknown): { updated: true } {
  if (!value || typeof value !== 'object' || (value as { updated?: unknown }).updated !== true) {
    throw new Error('Wormhole returned an invalid window close setting response.');
  }
  return { updated: true };
}

type ReasonScheduler = {
  set(callback: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
};

const reasonScheduler: ReasonScheduler = {
  set: (callback, delayMs) => setTimeout(callback, delayMs),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export class WindowCloseReasonTracker {
  private current: WindowCloseReason = 'window';
  private resetHandle: unknown;
  private readonly scheduler: ReasonScheduler;

  constructor(scheduler: ReasonScheduler = reasonScheduler) {
    this.scheduler = scheduler;
  }

  get reason(): WindowCloseReason {
    return this.current;
  }

  beginSystemShutdown(): void {
    this.current = 'system-shutdown';
    if (this.resetHandle !== undefined) this.scheduler.clear(this.resetHandle);
    this.resetHandle = this.scheduler.set(() => {
      this.resetHandle = undefined;
      this.current = 'window';
    }, 10_000);
  }

  confirmSystemShutdown(): void {
    this.cancelReset();
    this.current = 'system-shutdown';
  }

  rendererFailed(): void {
    this.cancelReset();
    this.current = 'renderer-failure';
  }

  dispose(): void {
    this.cancelReset();
  }

  private cancelReset(): void {
    if (this.resetHandle !== undefined) this.scheduler.clear(this.resetHandle);
    this.resetHandle = undefined;
  }
}

export type WindowCloseRequest = {
  reason: WindowCloseReason;
  confirmationEnabled: boolean;
  confirm(activeCount: number): Promise<boolean>;
  teardown(): Promise<void>;
  close(): void;
};

export async function runWindowTeardown(
  flushBrowserState: () => Promise<void>,
  closeRendererSessions: () => Promise<void>,
): Promise<void> {
  try {
    await flushBrowserState();
  } finally {
    await closeRendererSessions();
  }
}

export class WindowCloseCoordinator {
  private activeCount = 0;
  private state: 'idle' | 'prompting' | 'tearing-down' | 'complete' = 'idle';

  updateActiveCount(value: unknown): void {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 1000) {
      this.activeCount = value;
    }
  }

  get isComplete(): boolean {
    return this.state === 'complete';
  }

  get connectedSessionCount(): number {
    return this.activeCount;
  }

  async request(request: WindowCloseRequest): Promise<boolean> {
    if (this.state === 'complete') {
      request.close();
      return true;
    }
    if (this.state !== 'idle') return false;

    if (request.reason === 'window' && request.confirmationEnabled && this.activeCount > 0) {
      this.state = 'prompting';
      let confirmed = false;
      try {
        confirmed = await request.confirm(this.activeCount);
      } catch {
        confirmed = false;
      }
      if (!confirmed) {
        this.state = 'idle';
        return false;
      }
    }

    this.state = 'tearing-down';
    try {
      await request.teardown();
    } finally {
      this.state = 'complete';
      request.close();
    }
    return true;
  }
}
