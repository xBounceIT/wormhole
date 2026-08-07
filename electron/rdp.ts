import { randomUUID } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
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
};

const requestTimeoutMs = 15_000;
const startRequestTimeoutMs = 315_000;

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
  private starting: Promise<void> | undefined;

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

  async start(
    request: RdpStartRequest,
    ownerWindow: string,
    bounds?: RdpSurfaceRect,
  ): Promise<RdpBackendEvent> {
    this.sessionIds.add(request.sessionId);
    const remembered = bounds ? sanitizeBounds(bounds) : this.bounds.get(request.sessionId);
    if (remembered) this.bounds.set(request.sessionId, remembered);
    await this.ensureProcess();
    return this.send({
      op: 'start',
      sessionId: request.sessionId,
      ownerWindow,
      profile: request.profile,
      bounds: remembered,
    });
  }

  async resize(request: RdpCommandRequest, ownerWindow: string): Promise<RdpBackendEvent> {
    if (request.bounds) this.rememberBounds(request.sessionId, request.bounds);
    await this.ensureProcess();
    return this.send({
      op: 'resize',
      sessionId: request.sessionId,
      ownerWindow,
      bounds: request.bounds ? this.bounds.get(request.sessionId) : undefined,
    });
  }

  async command(
    op: Extract<RdpWireCommand['op'], 'show' | 'hide' | 'focus' | 'disconnect'>,
    sessionId: string,
    ownerWindow: string,
    bounds?: RdpSurfaceRect,
  ): Promise<RdpBackendEvent> {
    const child = this.process;
    if (
      (op === 'hide' || op === 'disconnect') &&
      (!child || child.killed || !child.stdin.writable)
    ) {
      if (op === 'disconnect') this.forgetSession(sessionId);
      return { type: 'ack', sessionId };
    }
    if (bounds) this.rememberBounds(sessionId, bounds);
    await this.ensureProcess();
    const response = await this.send({
      op,
      sessionId,
      ownerWindow,
      bounds: this.bounds.get(sessionId),
    });
    if (op === 'disconnect') {
      this.forgetSession(sessionId);
    }
    return response;
  }

  async dispose(): Promise<void> {
    this.sessionIds.clear();
    this.bounds.clear();
    const child = this.process;
    this.starting = undefined;
    if (!child) return;

    try {
      await this.sendToProcess(child, { op: 'shutdown', requestId: randomUUID() });
    } catch {
      // The process may already have exited. The finally path still closes the pipes.
    }
    if (this.process === child) this.process = undefined;
    if (!child.killed) child.kill();
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('RDP backend stopped.'));
    }
    this.pending.clear();
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
      this.forgetSession(request.sessionId);
      if (!child || child.killed || !child.stdin.writable) continue;
      void this.sendToProcess(child, {
        op: 'disconnect',
        requestId: randomUUID(),
        sessionId: request.sessionId,
        ownerWindow,
        bounds: this.bounds.get(request.sessionId),
      }).catch(() => undefined);
    }
  }

  private async ensureProcess(): Promise<void> {
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
      });
      child.once('close', () => {
        output.close();
        if (this.process !== child) return;
        this.process = undefined;
        this.rejectPending('RDP backend exited.');
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
    for (const listener of this.listeners) listener(event);
  }

  private handleLineForProcess(child: ChildProcessWithoutNullStreams, line: string): void {
    if (this.process !== child) return;
    this.handleLine(line);
  }

  private forgetSession(sessionId: string): void {
    this.sessionIds.delete(sessionId);
    this.bounds.delete(sessionId);
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
