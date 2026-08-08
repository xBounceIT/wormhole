import { randomUUID } from 'node:crypto';
import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import type {
  RdpBackendEvent,
  RdpCommandRequest,
  RdpProfile,
  RdpStartRequest,
  RdpSurfaceRect,
} from './rdp-contract.js';

type RdpWireCommand = {
  op: 'start' | 'resize' | 'show' | 'hide' | 'focus' | 'disconnect' | 'shutdown';
  requestId: string;
  sessionId?: string;
  lifecycleId?: string;
  ownerWindow?: string;
  bounds?: RdpSurfaceRect;
  profile?: RdpProfile;
};

type RdpBackendClientOptions = {
  executable: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
};

type PendingRequest = {
  resolve: (event: RdpBackendEvent) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
  op: RdpWireCommand['op'];
  sessionId?: string;
  lifecycleId?: string;
};

const requestTimeoutMs = 15_000;
const startRequestTimeoutMs = 315_000;

export type ChildProcessStopOptions = {
  gracefulTimeoutMs?: number;
  forceKillTimeoutMs?: number;
};

const defaultGracefulTimeoutMs = 10_000;
const defaultForceKillTimeoutMs = 3_000;

/** Closes stdin, waits for process exit, then force-kills and waits once more if necessary. */
export async function stopChildProcess(
  child: Pick<
    ChildProcess,
    'stdin' | 'exitCode' | 'signalCode' | 'once' | 'removeListener' | 'kill'
  >,
  options: ChildProcessStopOptions = {},
): Promise<boolean> {
  if (hasExited(child)) return true;
  try {
    child.stdin?.end();
  } catch {
    // A closed input pipe means graceful shutdown has already started.
  }
  if (await waitForChildExit(child, options.gracefulTimeoutMs ?? defaultGracefulTimeoutMs)) {
    return true;
  }
  try {
    child.kill();
  } catch {
    // The process may have exited between the timeout and the kill request.
  }
  return waitForChildExit(child, options.forceKillTimeoutMs ?? defaultForceKillTimeoutMs);
}

function hasExited(child: Pick<ChildProcess, 'exitCode' | 'signalCode'>): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function waitForChildExit(
  child: Pick<ChildProcess, 'exitCode' | 'signalCode' | 'once' | 'removeListener'>,
  timeoutMs: number,
): Promise<boolean> {
  if (hasExited(child)) return Promise.resolve(true);
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (exited: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.removeListener('close', onClose);
      resolve(exited);
    };
    const onClose = () => finish(true);
    const timeout = setTimeout(() => finish(hasExited(child)), Math.max(0, timeoutMs));
    child.once('close', onClose);
  });
}

/**
 * Supervises one long-lived Go RDP controller. The controller owns all native/process work;
 * this class only frames commands and routes secret-free lifecycle events to the BrowserWindow.
 */
export class RdpBackendClient {
  private readonly options: RdpBackendClientOptions;
  private process: ChildProcessWithoutNullStreams | undefined;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly listeners = new Set<(event: RdpBackendEvent) => void>();
  private readonly bounds = new Map<string, RdpSurfaceRect>();
  private readonly sessionIds = new Set<string>();
  private readonly lifecycleIds = new Map<string, string>();
  private starting: Promise<void> | undefined;
  private disposing: Promise<void> | undefined;

  constructor(options: RdpBackendClientOptions) {
    this.options = options;
  }

  onEvent(listener: (event: RdpBackendEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  rememberBounds(sessionId: string, bounds: RdpSurfaceRect): void {
    this.bounds.set(sessionId, sanitizeBounds(bounds));
  }

  beginStart(sessionId: string): string {
    const lifecycleId = randomUUID();
    this.lifecycleIds.set(sessionId, lifecycleId);
    this.sessionIds.add(sessionId);
    return lifecycleId;
  }

  currentLifecycleId(sessionId: string): string | undefined {
    return this.lifecycleIds.get(sessionId);
  }

  cancelStart(sessionId: string, lifecycleId: string): void {
    if (this.lifecycleIds.get(sessionId) === lifecycleId) this.forgetSession(sessionId);
  }

  async start(
    request: RdpStartRequest,
    ownerWindow: string,
    bounds?: RdpSurfaceRect,
    preparedLifecycleId?: string,
  ): Promise<RdpBackendEvent> {
    const lifecycleId = preparedLifecycleId ?? this.beginStart(request.sessionId);
    if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
      throw new Error('RDP connection was superseded before its native session could start.');
    }
    const remembered = bounds ? sanitizeBounds(bounds) : this.bounds.get(request.sessionId);
    if (remembered) this.bounds.set(request.sessionId, remembered);
    await this.ensureProcess();
    if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
      throw new Error('RDP connection was superseded before its native session could start.');
    }
    try {
      const response = await this.send({
        op: 'start',
        sessionId: request.sessionId,
        lifecycleId,
        ownerWindow,
        profile: request.profile,
        bounds: remembered,
      });
      if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
        throw new Error('RDP connection was superseded while its native session was starting.');
      }
      return response;
    } catch (error) {
      const child = this.process;
      if (child && !child.killed && child.stdin.writable) {
        await this.sendToProcess(child, {
          op: 'disconnect',
          requestId: randomUUID(),
          sessionId: request.sessionId,
          lifecycleId,
          ownerWindow,
          bounds: remembered,
        }).catch(() => undefined);
      }
      this.cancelStart(request.sessionId, lifecycleId);
      throw error;
    }
  }

  async resize(request: RdpCommandRequest, ownerWindow: string): Promise<RdpBackendEvent> {
    if (request.bounds) this.rememberBounds(request.sessionId, request.bounds);
    // Renderer measurement starts before the native connection so Start can use real surface
    // bounds instead of the backend's 1x1 race placeholder. Measuring an idle surface must not
    // spawn the backend; if Start is already creating it, wait for that one process.
    if (this.starting) await this.starting;
    if (
      !this.sessionIds.has(request.sessionId) ||
      !this.process ||
      this.process.killed ||
      !this.process.stdin.writable
    ) {
      return { type: 'ack', sessionId: request.sessionId };
    }
    return this.send({
      op: 'resize',
      sessionId: request.sessionId,
      lifecycleId: this.lifecycleIds.get(request.sessionId),
      ownerWindow,
      bounds: request.bounds ? this.bounds.get(request.sessionId) : undefined,
    });
  }

  async command(
    op: Extract<RdpWireCommand['op'], 'show' | 'hide' | 'focus' | 'disconnect'>,
    sessionId: string,
    ownerWindow: string,
    bounds?: RdpSurfaceRect,
    expectedLifecycleId?: string,
  ): Promise<RdpBackendEvent> {
    const child = this.process;
    const lifecycleId = expectedLifecycleId ?? this.lifecycleIds.get(sessionId);
    if (
      (op === 'hide' || op === 'disconnect') &&
      (!child || child.killed || !child.stdin.writable)
    ) {
      if (op === 'disconnect') {
        if (lifecycleId) this.cancelStart(sessionId, lifecycleId);
        else this.forgetSession(sessionId);
      }
      return { type: 'ack', sessionId, lifecycleId };
    }
    if (bounds) this.rememberBounds(sessionId, bounds);
    await this.ensureProcess();
    try {
      return await this.send({
        op,
        sessionId,
        lifecycleId,
        ownerWindow,
        bounds: this.bounds.get(sessionId),
      });
    } finally {
      if (op === 'disconnect') {
        if (lifecycleId) this.cancelStart(sessionId, lifecycleId);
        else this.forgetSession(sessionId);
      }
    }
  }

  async dispose(): Promise<void> {
    if (this.disposing) return this.disposing;
    this.disposing = this.disposeCurrentProcess().finally(() => {
      this.disposing = undefined;
    });
    return this.disposing;
  }

  async hideAll(ownerWindow: string): Promise<void> {
    const child = this.process;
    if (!child || child.killed || !child.stdin.writable) return;

    const sessionIds = [...new Set([...this.sessionIds, ...this.bounds.keys()])];
    await Promise.allSettled(
      sessionIds.map((sessionId) =>
        this.sendToProcess(child, {
          op: 'hide',
          requestId: randomUUID(),
          sessionId,
          lifecycleId: this.lifecycleIds.get(sessionId),
          ownerWindow,
          bounds: this.bounds.get(sessionId),
        }),
      ),
    );
  }

  cancelPendingStarts(ownerWindow: string): void {
    const child = this.process;
    for (const [requestId, request] of [...this.pending]) {
      if (request.op !== 'start' || !request.sessionId) continue;
      this.pending.delete(requestId);
      clearTimeout(request.timer);
      request.reject(new Error('RDP connection cancelled while Wormhole locked.'));
      const lifecycleId = request.lifecycleId;
      if (lifecycleId) this.cancelStart(request.sessionId, lifecycleId);
      else this.forgetSession(request.sessionId);
      if (!child || child.killed || !child.stdin.writable) continue;
      void this.sendToProcess(child, {
        op: 'disconnect',
        requestId: randomUUID(),
        sessionId: request.sessionId,
        lifecycleId,
        ownerWindow,
        bounds: this.bounds.get(request.sessionId),
      }).catch(() => undefined);
    }
  }

  private async ensureProcess(): Promise<void> {
    if (this.disposing) throw new Error('RDP backend is stopping.');
    if (this.process && !this.process.killed) return;
    if (this.starting) return this.starting;

    this.starting = new Promise<void>((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(this.options.executable, this.options.args, {
          env: this.options.env ?? process.env,
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch (error) {
        reject(toError(error, 'Could not start the RDP backend.'));
        return;
      }

      this.process = child;
      const output = createInterface({ input: child.stdout });
      output.on('line', (line) => this.handleLineForProcess(child, line));
      child.stdin.once('error', () => {
        if (this.process !== child) return;
        this.process = undefined;
        this.rejectPending('RDP backend input pipe closed.');
        this.terminateSessions();
        void stopChildProcess(child);
      });
      child.stderr.on('data', () => {
        // The Go boundary intentionally emits only sanitized errors. Do not surface or retain
        // native stderr: FreeRDP and platform helpers can include server/user details there.
      });
      child.once('error', (error) => {
        if (this.process !== child) return;
        this.process = undefined;
        reject(toError(error, 'Could not start the RDP backend.'));
        this.rejectPending('RDP backend failed to start.');
        this.terminateSessions();
      });
      child.once('close', () => {
        output.close();
        if (this.process !== child) return;
        this.process = undefined;
        this.rejectPending('RDP backend exited.');
        this.terminateSessions();
      });
      resolve();
    }).finally(() => {
      this.starting = undefined;
    });

    return this.starting;
  }

  private send(command: Omit<RdpWireCommand, 'requestId'>): Promise<RdpBackendEvent> {
    const child = this.process;
    if (!child || child.killed || !child.stdin.writable) {
      return Promise.reject(new Error('RDP backend is not running.'));
    }
    return this.sendToProcess(child, { ...command, requestId: randomUUID() });
  }

  private sendToProcess(
    child: ChildProcessWithoutNullStreams,
    command: RdpWireCommand,
  ): Promise<RdpBackendEvent> {
    return new Promise<RdpBackendEvent>((resolve, reject) => {
      const timer = setTimeout(
        () => {
          this.pending.delete(command.requestId);
          reject(new Error('RDP backend did not acknowledge the command.'));
        },
        command.op === 'start' ? startRequestTimeoutMs : requestTimeoutMs,
      );
      this.pending.set(command.requestId, {
        resolve,
        reject,
        timer,
        op: command.op,
        sessionId: command.sessionId,
        lifecycleId: command.lifecycleId,
      });
      try {
        child.stdin.write(`${JSON.stringify(command)}\n`, (error) => {
          if (!error) return;
          clearTimeout(timer);
          if (this.pending.delete(command.requestId)) {
            reject(toError(error, 'Could not send the RDP command.'));
          }
        });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(command.requestId);
        reject(toError(error, 'Could not send the RDP command.'));
      }
    });
  }

  private handleLine(line: string): void {
    let event: RdpBackendEvent;
    try {
      event = JSON.parse(line) as RdpBackendEvent;
    } catch {
      return;
    }
    if (!event || typeof event.type !== 'string') return;
    if (event.requestId) {
      const request = this.pending.get(event.requestId);
      if (request) {
        clearTimeout(request.timer);
        this.pending.delete(event.requestId);
        if (event.type === 'error') {
          request.reject(new Error(event.message || 'RDP backend command failed.'));
        } else {
          request.resolve(event);
        }
      }
    }
    if (
      event.sessionId &&
      event.lifecycleId &&
      this.lifecycleIds.get(event.sessionId) !== event.lifecycleId
    ) {
      return;
    }
    if (
      event.sessionId &&
      (event.type === 'disconnected' ||
        event.type === 'fatalError' ||
        event.type === 'exited' ||
        event.type === 'error')
    ) {
      this.forgetSession(event.sessionId);
    }
    for (const listener of this.listeners) listener(event);
  }

  private handleLineForProcess(child: ChildProcessWithoutNullStreams, line: string): void {
    if (this.process !== child) return;
    this.handleLine(line);
  }

  private forgetSession(sessionId: string): void {
    this.sessionIds.delete(sessionId);
    this.lifecycleIds.delete(sessionId);
    this.bounds.delete(sessionId);
  }

  private async disposeCurrentProcess(): Promise<void> {
    const child = this.process;
    this.starting = undefined;
    this.terminateSessions();
    this.bounds.clear();
    if (!child) {
      this.rejectPending('RDP backend stopped.');
      return;
    }

    try {
      await this.sendToProcess(child, { op: 'shutdown', requestId: randomUUID() });
    } catch {
      // The process may already have exited. Closing stdin remains safe and idempotent.
    }
    this.rejectPending('RDP backend stopped.');
    const exited = await stopChildProcess(child);
    if (!exited) console.warn('[Wormhole] RDP backend did not exit after its force-kill timeout.');
    if (this.process === child) this.process = undefined;
  }

  private terminateSessions(): void {
    const sessions = [...this.sessionIds].map((sessionId) => ({
      sessionId,
      lifecycleId: this.lifecycleIds.get(sessionId),
    }));
    this.sessionIds.clear();
    this.lifecycleIds.clear();
    for (const { sessionId, lifecycleId } of sessions) {
      this.bounds.delete(sessionId);
      for (const listener of this.listeners) {
        listener({
          type: 'exited',
          sessionId,
          ...(lifecycleId ? { lifecycleId } : {}),
        });
      }
    }
  }

  private rejectPending(message: string): void {
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error(message));
    }
    this.pending.clear();
  }
}

function sanitizeBounds(bounds: RdpSurfaceRect): RdpSurfaceRect {
  return {
    x: finiteInteger(bounds.x),
    y: finiteInteger(bounds.y),
    width: Math.max(1, Math.min(16_384, finiteInteger(bounds.width))),
    height: Math.max(1, Math.min(16_384, finiteInteger(bounds.height))),
  };
}

function finiteInteger(value: number): number {
  return Number.isFinite(value) ? Math.round(value) : 0;
}

function toError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}
