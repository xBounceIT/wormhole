import { randomUUID } from 'node:crypto';
import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
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
  lifecycleGeneration?: number;
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
  lifecycleGeneration?: number;
};

const requestTimeoutMs = 15_000;
const startRequestTimeoutMs = 315_000;
const maxRdpCommandBytes = 256 * 1024;
const maxRdpEventBytes = 256 * 1024;
const maxRdpSurfaceCoordinate = 1_000_000;
const maxRdpSurfaceDimension = 16_384;

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
  private readonly lifecycleGenerations = new Map<string, number>();
  private readonly disconnects = new Map<string, Promise<RdpBackendEvent>>();
  private outputBuffer = '';
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
    return lifecycleId;
  }

  currentLifecycleId(sessionId: string): string | undefined {
    return this.lifecycleIds.get(sessionId);
  }

  cancelStart(sessionId: string, lifecycleId: string): void {
    if (this.lifecycleIds.get(sessionId) === lifecycleId) this.forgetSession(sessionId);
  }

  hasSession(sessionId: string): boolean {
    return this.sessionIds.has(sessionId);
  }

  async start(
    request: RdpStartRequest,
    ownerWindow: string,
    bounds?: RdpSurfaceRect,
    preparedLifecycleId?: string,
    lifecycleGeneration?: number,
  ): Promise<RdpBackendEvent> {
    const lifecycleId = preparedLifecycleId ?? this.beginStart(request.sessionId);
    if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
      throw new Error('RDP connection was superseded before it could start.');
    }
    if (lifecycleGeneration === undefined) {
      this.lifecycleGenerations.delete(request.sessionId);
    } else {
      this.lifecycleGenerations.set(request.sessionId, lifecycleGeneration);
    }
    const remembered = bounds ? sanitizeBounds(bounds) : this.bounds.get(request.sessionId);
    if (remembered) this.bounds.set(request.sessionId, remembered);
    await this.ensureProcess();
    if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
      throw new Error('RDP connection was superseded before it could start.');
    }
    try {
      const response = await this.send({
        op: 'start',
        sessionId: request.sessionId,
        lifecycleId,
        ownerWindow,
        profile: request.profile,
        bounds: remembered,
        lifecycleGeneration,
      });
      if (this.lifecycleIds.get(request.sessionId) !== lifecycleId) {
        throw new Error('RDP connection was superseded while it was starting.');
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
          lifecycleGeneration,
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
    if (op !== 'disconnect') {
      return this.executeCommand(op, sessionId, ownerWindow, bounds, expectedLifecycleId);
    }
    const pending = this.disconnects.get(sessionId);
    if (pending) return pending;
    const disconnect = this.executeCommand(
      op,
      sessionId,
      ownerWindow,
      bounds,
      expectedLifecycleId,
    ).finally(() => {
      if (this.disconnects.get(sessionId) === disconnect) this.disconnects.delete(sessionId);
    });
    this.disconnects.set(sessionId, disconnect);
    return disconnect;
  }

  private async executeCommand(
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
    if (this.disposing) throw new Error('RDP service is stopping.');
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
        reject(toError(error, 'Could not start the RDP service.'));
        return;
      }

      this.process = child;
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string | Buffer) => {
        this.readOutputForProcess(child, String(chunk));
      });
      child.stdin.once('error', () => {
        this.handleProcessFailure(child, 'RDP service connection closed.');
      });
      child.stderr.on('data', () => {
        // The Go boundary intentionally emits only sanitized errors. Do not surface or retain
        // native stderr: FreeRDP and platform helpers can include server/user details there.
      });
      child.once('error', (error) => {
        if (this.process !== child) return;
        reject(toError(error, 'Could not start the RDP service.'));
        this.handleProcessFailure(child, 'RDP service failed to start.');
      });
      child.once('close', () => {
        this.handleProcessFailure(child, 'RDP service stopped.');
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
      return Promise.reject(new Error('RDP service is not running.'));
    }
    return this.sendToProcess(child, { ...command, requestId: randomUUID() });
  }

  private sendToProcess(
    child: ChildProcessWithoutNullStreams,
    command: RdpWireCommand,
  ): Promise<RdpBackendEvent> {
    let encodedCommand: string;
    try {
      encodedCommand = JSON.stringify(command);
    } catch {
      return Promise.reject(new Error('RDP command could not be encoded.'));
    }
    if (Buffer.byteLength(encodedCommand, 'utf8') > maxRdpCommandBytes) {
      return Promise.reject(new Error('RDP command is too large.'));
    }
    return new Promise<RdpBackendEvent>((resolve, reject) => {
      const timer = setTimeout(
        () => {
          this.pending.delete(command.requestId);
          reject(new Error('RDP service did not respond.'));
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
        lifecycleGeneration: command.lifecycleGeneration,
      });
      try {
        child.stdin.write(`${encodedCommand}\n`, (error) => {
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
    const requestId = event.requestId;
    if (requestId) {
      const request = this.pending.get(requestId);
      if (request) {
        if (request.lifecycleId !== undefined && event.lifecycleId === undefined) {
          event = { ...event, lifecycleId: request.lifecycleId };
        }
        if (request.lifecycleGeneration !== undefined && event.lifecycleGeneration === undefined) {
          event = { ...event, lifecycleGeneration: request.lifecycleGeneration };
        }
        clearTimeout(request.timer);
        this.pending.delete(requestId);
        if (event.type === 'error') {
          request.reject(new Error(event.message || 'RDP request failed.'));
        } else {
          const startLifecycleIsCurrent =
            !request.lifecycleId ||
            (request.sessionId !== undefined &&
              this.lifecycleIds.get(request.sessionId) === request.lifecycleId);
          if (request.op === 'start' && request.sessionId && startLifecycleIsCurrent) {
            this.sessionIds.add(request.sessionId);
            if (request.lifecycleId) {
              this.lifecycleIds.set(request.sessionId, request.lifecycleId);
            }
            if (request.lifecycleGeneration === undefined) {
              this.lifecycleGenerations.delete(request.sessionId);
            } else {
              this.lifecycleGenerations.set(request.sessionId, request.lifecycleGeneration);
            }
          }
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
      !requestId &&
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

  private readOutputForProcess(child: ChildProcessWithoutNullStreams, chunk: string): void {
    if (this.process !== child) return;
    this.outputBuffer += chunk;
    while (true) {
      const newline = this.outputBuffer.indexOf('\n');
      if (newline < 0) {
        if (Buffer.byteLength(this.outputBuffer, 'utf8') > maxRdpEventBytes) {
          this.handleProcessFailure(child, 'RDP service returned too much data.');
        }
        return;
      }
      const line = this.outputBuffer.slice(0, newline).trim();
      this.outputBuffer = this.outputBuffer.slice(newline + 1);
      if (Buffer.byteLength(line, 'utf8') > maxRdpEventBytes) {
        this.handleProcessFailure(child, 'RDP service returned too much data.');
        return;
      }
      if (line) this.handleLine(line);
      if (this.process !== child) return;
    }
  }

  private forgetSession(sessionId: string): void {
    this.sessionIds.delete(sessionId);
    this.lifecycleIds.delete(sessionId);
    this.bounds.delete(sessionId);
    this.lifecycleGenerations.delete(sessionId);
  }

  private handleProcessFailure(child: ChildProcessWithoutNullStreams, message: string): void {
    if (this.process !== child) return;
    this.process = undefined;
    this.outputBuffer = '';
    try {
      if (!child.killed) child.kill();
    } catch {
      // The process can already be gone when its close event reaches this handler.
    }
    this.rejectPending(message);
    this.terminateSessions(-1, 'The RDP controller exited unexpectedly.');
  }

  private async disposeCurrentProcess(): Promise<void> {
    const child = this.process;
    this.starting = undefined;
    this.terminateSessions();
    this.bounds.clear();
    if (!child) {
      this.rejectPending('RDP service stopped.');
      return;
    }

    try {
      await this.sendToProcess(child, { op: 'shutdown', requestId: randomUUID() });
    } catch {
      // The process may already have exited. Closing stdin remains safe and idempotent.
    }
    this.rejectPending('RDP service stopped.');
    const exited = await stopChildProcess(child);
    if (!exited) console.warn('[Wormhole] RDP service did not stop within the allowed time.');
    if (this.process === child) this.process = undefined;
  }

  private terminateSessions(code?: number, message?: string): void {
    const trackedSessionIds = new Set([...this.sessionIds, ...this.lifecycleIds.keys()]);
    const sessions = [...trackedSessionIds].map((sessionId) => ({
      sessionId,
      lifecycleId: this.lifecycleIds.get(sessionId),
      lifecycleGeneration: this.lifecycleGenerations.get(sessionId),
    }));
    this.sessionIds.clear();
    this.lifecycleIds.clear();
    this.lifecycleGenerations.clear();
    for (const { sessionId, lifecycleId, lifecycleGeneration } of sessions) {
      this.bounds.delete(sessionId);
      for (const listener of this.listeners) {
        listener({
          type: 'exited',
          sessionId,
          ...(lifecycleId ? { lifecycleId } : {}),
          ...(lifecycleGeneration !== undefined ? { lifecycleGeneration } : {}),
          ...(code !== undefined ? { code } : {}),
          ...(message ? { message } : {}),
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
    x: clamp(finiteInteger(bounds.x), -maxRdpSurfaceCoordinate, maxRdpSurfaceCoordinate),
    y: clamp(finiteInteger(bounds.y), -maxRdpSurfaceCoordinate, maxRdpSurfaceCoordinate),
    width: clamp(finiteInteger(bounds.width), 1, maxRdpSurfaceDimension),
    height: clamp(finiteInteger(bounds.height), 1, maxRdpSurfaceDimension),
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function finiteInteger(value: number): number {
  return Number.isFinite(value) ? Math.round(value) : 0;
}

function toError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}
