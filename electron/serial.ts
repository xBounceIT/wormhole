import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface, type Interface } from 'node:readline';

export type SerialSettings = {
  baudRate: number;
  dataBits: number;
  stopBits: number;
  parity: number;
  flowControl: number;
};

export type SerialConnectedResponse = SerialSettings & {
  sessionId: string;
  portName: string;
};

export type SerialTerminalCell = {
  character: string;
  foreground: number;
  background: number;
};

export type SerialTerminalFrame = {
  columns: number;
  rows: number;
  full: boolean;
  cells?: SerialTerminalCell[];
  changes: Array<SerialTerminalCell & { index: number }>;
  scrollbackReset: boolean;
  viewportReset: boolean;
  scrollback?: Array<{
    runs: Array<{
      text: string;
      cells: number;
      foreground: number;
      background: number;
    }>;
  }>;
  cursorX: number;
  cursorY: number;
  cursorVisible: boolean;
  applicationCursor: boolean;
  title?: string;
  sequence: number;
};

export type SerialBackendEvent =
  | ({ type: 'connected' } & SerialConnectedResponse)
  | { type: 'screen'; sessionId: string; frame: SerialTerminalFrame }
  | { type: 'closed'; sessionId: string }
  | { type: 'error'; sessionId: string; error: string };

export type SerialOpenRequest = {
  sessionId: string;
  nodeId?: string;
  portName?: string;
  settings?: SerialSettings;
  columns: number;
  rows: number;
};

type PendingOpen = {
  resolve: (response: SerialConnectedResponse) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
};

const backendTimeoutMs = 30_000;
const maxSessionIdLength = 128;
const maxPortNameLength = 256;
const maxInputLength = 1_500_000;
const maxTerminalCells = 500 * 500;
const maxScrollbackLines = 5000;
const maxScrollbackLineLength = 2048;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxSessionIdLength &&
    value.trim() === value
  );
}

function isSettingsValue(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

export function isSerialOpenRequest(value: unknown): value is SerialOpenRequest {
  if (!isRecord(value) || !isSessionId(value.sessionId)) return false;
  const nodeId = value.nodeId;
  const portName = value.portName;
  if (nodeId !== undefined && !isSessionId(nodeId)) {
    return false;
  }
  if (
    portName !== undefined &&
    (typeof portName !== 'string' ||
      portName.trim() !== portName ||
      portName.length === 0 ||
      portName.length > maxPortNameLength)
  ) {
    return false;
  }
  if (!nodeId && !portName) return false;
  if (!isSettingsValue(value.columns, 0, 500) || !isSettingsValue(value.rows, 0, 500)) {
    return false;
  }
  if (value.settings === undefined) return true;
  if (!isRecord(value.settings)) return false;
  return (
    isSettingsValue(value.settings.baudRate, 0, 10_000_000) &&
    isSettingsValue(value.settings.dataBits, 0, 8) &&
    isSettingsValue(value.settings.stopBits, 0, 3) &&
    isSettingsValue(value.settings.parity, 0, 4) &&
    isSettingsValue(value.settings.flowControl, 0, 3)
  );
}

export function isSerialSessionId(value: unknown): value is string {
  return isSessionId(value);
}

export function isSerialInput(value: unknown): value is string {
  return typeof value === 'string' && value.length <= maxInputLength;
}

function isTerminalCell(value: unknown): value is SerialTerminalCell {
  return (
    isRecord(value) &&
    typeof value.character === 'string' &&
    value.character.length <= 8 &&
    isSettingsValue(value.foreground, 0, 0xffff) &&
    isSettingsValue(value.background, 0, 0xffff)
  );
}

function isScrollbackLine(
  value: unknown,
  maxCells: number,
): value is NonNullable<SerialTerminalFrame['scrollback']>[number] {
  if (!isRecord(value) || !Array.isArray(value.runs) || value.runs.length > maxCells) return false;
  let textLength = 0;
  let cellCount = 0;
  for (const run of value.runs) {
    if (
      !isRecord(run) ||
      typeof run.text !== 'string' ||
      run.text.length === 0 ||
      run.text.length > maxScrollbackLineLength ||
      !isSettingsValue(run.cells, 1, maxCells) ||
      !isSettingsValue(run.foreground, 0, 0xffff) ||
      !isSettingsValue(run.background, 0, 0xffff)
    ) {
      return false;
    }
    textLength += run.text.length;
    cellCount += run.cells;
    if (textLength > maxScrollbackLineLength || cellCount > maxCells) return false;
  }
  return true;
}

function parseTerminalFrame(value: unknown): SerialTerminalFrame | undefined {
  if (
    !isRecord(value) ||
    !isSettingsValue(value.columns, 1, 500) ||
    !isSettingsValue(value.rows, 1, 500) ||
    (value.full !== undefined && typeof value.full !== 'boolean') ||
    (value.scrollback_reset !== undefined && typeof value.scrollback_reset !== 'boolean') ||
    (value.viewport_reset !== undefined && typeof value.viewport_reset !== 'boolean') ||
    !isSettingsValue(value.cursor_x, 0, value.columns - 1) ||
    !isSettingsValue(value.cursor_y, 0, value.rows - 1) ||
    typeof value.cursor_visible !== 'boolean' ||
    typeof value.application_cursor !== 'boolean' ||
    !isSettingsValue(value.sequence, 1, Number.MAX_SAFE_INTEGER)
  ) {
    return undefined;
  }

  const cellCount = value.columns * value.rows;
  let cells: SerialTerminalCell[] | undefined;
  if (value.cells !== undefined) {
    if (
      !Array.isArray(value.cells) ||
      value.cells.length > maxTerminalCells ||
      !value.cells.every(isTerminalCell)
    ) {
      return undefined;
    }
    cells = value.cells;
  }
  const full = value.full === true;
  if (full && (!cells || cells.length !== cellCount)) return undefined;

  const changes: Array<SerialTerminalCell & { index: number }> = [];
  if (value.changes !== undefined) {
    if (!Array.isArray(value.changes) || value.changes.length > cellCount) return undefined;
    for (const change of value.changes) {
      const index = isRecord(change) ? change.index : undefined;
      if (!isSettingsValue(index, 0, cellCount - 1) || !isTerminalCell(change)) {
        return undefined;
      }
      changes.push({ ...change, index });
    }
  }

  let scrollback: SerialTerminalFrame['scrollback'];
  if (value.scrollback !== undefined) {
    if (
      !Array.isArray(value.scrollback) ||
      value.scrollback.length > maxScrollbackLines ||
      !value.scrollback.every((line) => isScrollbackLine(line, value.columns as number))
    ) {
      return undefined;
    }
    scrollback = value.scrollback.map((line) => ({
      runs: line.runs.map((run) => ({
        text: run.text,
        cells: run.cells,
        foreground: run.foreground,
        background: run.background,
      })),
    }));
  }

  return {
    columns: value.columns,
    rows: value.rows,
    full,
    cells,
    changes,
    scrollbackReset: value.scrollback_reset === true,
    viewportReset: value.viewport_reset === true,
    scrollback,
    cursorX: value.cursor_x,
    cursorY: value.cursor_y,
    cursorVisible: value.cursor_visible,
    applicationCursor: value.application_cursor,
    title: typeof value.title === 'string' ? value.title.slice(0, 2048) : undefined,
    sequence: value.sequence,
  };
}

function parseSerialBackendEvent(line: string): SerialBackendEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || typeof value.type !== 'string' || !isSessionId(value.session_id)) {
    return undefined;
  }
  if (
    value.type === 'connected' &&
    typeof value.port_name === 'string' &&
    value.port_name.length > 0 &&
    value.port_name.length <= maxPortNameLength &&
    isSettingsValue(value.baud_rate, 1, 10_000_000) &&
    isSettingsValue(value.data_bits, 5, 8) &&
    isSettingsValue(value.stop_bits, 1, 3) &&
    isSettingsValue(value.parity, 0, 4) &&
    isSettingsValue(value.flow_control, 0, 3)
  ) {
    return {
      type: 'connected',
      sessionId: value.session_id,
      portName: value.port_name,
      baudRate: value.baud_rate,
      dataBits: value.data_bits,
      stopBits: value.stop_bits,
      parity: value.parity,
      flowControl: value.flow_control,
    };
  }
  if (value.type === 'screen') {
    const frame = parseTerminalFrame(value.frame);
    return frame ? { type: 'screen', sessionId: value.session_id, frame } : undefined;
  }
  if (value.type === 'closed') return { type: 'closed', sessionId: value.session_id };
  if (value.type === 'error' && typeof value.error === 'string') {
    return { type: 'error', sessionId: value.session_id, error: value.error };
  }
  return undefined;
}

type SerialBackendOptions = {
  executable: string;
  args: string[];
};

/** Owns one long-lived Go serial controller and exposes only validated terminal events. */
export class SerialBackendClient {
  private readonly options: SerialBackendOptions;
  private process: ChildProcessWithoutNullStreams | undefined;
  private lineReader: Interface | undefined;
  private readonly activeSessions = new Set<string>();
  private readonly openWaiters = new Map<string, PendingOpen>();
  private readonly listeners = new Set<(event: SerialBackendEvent) => void>();
  private starting: Promise<void> | undefined;

  constructor(options: SerialBackendOptions) {
    this.options = options;
  }

  onEvent(listener: (event: SerialBackendEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async open(request: SerialOpenRequest): Promise<SerialConnectedResponse> {
    if (this.openWaiters.has(request.sessionId) || this.activeSessions.has(request.sessionId)) {
      throw new Error('Serial session id is already in use.');
    }
    await this.ensureProcess();
    return new Promise<SerialConnectedResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const waiter = this.openWaiters.get(request.sessionId);
        if (!waiter || waiter.timeout !== timeout) return;
        this.openWaiters.delete(request.sessionId);
        reject(new Error('Serial connection timed out.'));
        try {
          this.write({ type: 'close', session_id: request.sessionId });
        } catch {
          // The controller may already have exited; the timeout has released the renderer.
        }
      }, backendTimeoutMs);
      this.openWaiters.set(request.sessionId, { resolve, reject, timeout });
      try {
        this.write({
          type: 'open',
          session_id: request.sessionId,
          node_id: request.nodeId ?? '',
          port_name: request.portName ?? '',
          baud_rate: request.settings?.baudRate ?? 0,
          data_bits: request.settings?.dataBits ?? 0,
          stop_bits: request.settings?.stopBits ?? 0,
          parity: request.settings?.parity ?? 0,
          flow_control: request.settings?.flowControl ?? 0,
          columns: request.columns,
          rows: request.rows,
        });
      } catch (error) {
        this.openWaiters.delete(request.sessionId);
        clearTimeout(timeout);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  sendInput(sessionId: string, data: string): void {
    this.write({ type: 'input', session_id: sessionId, data });
  }

  resize(sessionId: string, columns: number, rows: number): void {
    this.write({ type: 'resize', session_id: sessionId, columns, rows });
  }

  close(sessionId: string): void {
    const waiter = this.openWaiters.get(sessionId);
    if (waiter) {
      this.openWaiters.delete(sessionId);
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('Serial connection closed while connecting.'));
    }
    if (this.process && !this.process.killed) {
      try {
        this.write({ type: 'close', session_id: sessionId });
      } catch {
        // The controller may exit between the state check and the write.
      }
    }
  }

  requestSnapshots(): void {
    for (const sessionId of this.activeSessions) {
      try {
        this.write({ type: 'snapshot', session_id: sessionId });
      } catch {
        return;
      }
    }
  }

  dispose(): void {
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('Serial service stopped.'));
    }
    this.openWaiters.clear();
    this.activeSessions.clear();
    this.lineReader?.close();
    this.lineReader = undefined;
    const child = this.process;
    this.process = undefined;
    if (!child || child.killed) return;
    child.stdin.end();
    child.kill();
  }

  private async ensureProcess(): Promise<void> {
    if (this.process && !this.process.killed) return;
    if (this.starting) return this.starting;

    this.starting = new Promise<void>((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(this.options.executable, this.options.args, {
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
        return;
      }

      this.process = child;
      const lineReader = createInterface({ input: child.stdout, crlfDelay: Infinity });
      this.lineReader = lineReader;
      lineReader.on('line', (line) => {
        if (this.process === child) this.handleLine(line);
      });
      child.stdin.on('error', (error) => {
        if (this.process !== child) return;
        this.failOpenWaiters(new Error(`Serial service connection failed: ${error.message}`));
      });
      child.stderr.on('data', () => {
        // Native diagnostics stay outside the renderer boundary.
      });
      child.once('error', (error) => {
        if (this.process !== child) return;
        this.process = undefined;
        this.failOpenWaiters(new Error(`Serial service failed: ${error.message}`));
        reject(error);
      });
      child.once('spawn', () => resolve());
      child.once('exit', () => {
        lineReader.close();
        if (this.process !== child) return;
        this.process = undefined;
        if (this.lineReader === lineReader) this.lineReader = undefined;
        const closedSessions = [...this.activeSessions];
        this.activeSessions.clear();
        for (const sessionId of closedSessions) {
          this.broadcast({ type: 'closed', sessionId });
        }
        this.failOpenWaiters(new Error('Serial service stopped.'));
      });
    }).finally(() => {
      this.starting = undefined;
    });

    return this.starting;
  }

  private write(command: Record<string, unknown>): void {
    const child = this.process;
    if (!child || child.killed || child.stdin.destroyed) {
      throw new Error('Serial service is not running.');
    }
    child.stdin.write(`${JSON.stringify(command)}\n`, 'utf8');
  }

  private handleLine(line: string): void {
    const event = parseSerialBackendEvent(line);
    if (!event) return;
    if (event.type === 'connected') {
      this.activeSessions.add(event.sessionId);
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.resolve(event);
      }
    } else if (event.type === 'error') {
      const waiter = this.openWaiters.get(event.sessionId);
      if (waiter) {
        this.openWaiters.delete(event.sessionId);
        clearTimeout(waiter.timeout);
        waiter.reject(new Error(event.error || 'Serial connection failed.'));
      }
    } else if (event.type === 'closed') {
      this.activeSessions.delete(event.sessionId);
    }
    this.broadcast(event);
  }

  private broadcast(event: SerialBackendEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  private failOpenWaiters(error: Error): void {
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.openWaiters.clear();
  }
}
