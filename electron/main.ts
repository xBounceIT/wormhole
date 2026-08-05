import { app, BrowserWindow, ipcMain, screen } from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { AuthSession } from './auth-session.js';
import { RdpBackendClient } from './rdp.js';
import type {
  RdpBackendEvent,
  RdpCommandRequest,
  RdpProfile,
  RdpStartRequest,
  RdpSurfaceRect,
} from './rdp-contract.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rendererUrl = process.env.VITE_DEV_SERVER_URL;
const nativeTitlebarColor = '#0a0a0a00';
const nativeTitlebarSymbolColor = '#ffffff';
const nativeTitlebarHeight = 48;
const wormholeDataDirectoryName = 'Wormhole';
const backendTimeoutMs = 30_000;
const backendMaxBuffer = 16 * 1024 * 1024;
const backendMaxRequestBytes = 64 * 1024;
const nativeBackendLineLimit = 32 * 1024 * 1024;
const nativeBackendCommandTimeoutMs = 15_000;
let rdpClient: RdpBackendClient | undefined;

type BackendOperation =
  | 'workspace'
  | 'migrate'
  | 'auth-status'
  | 'auth-verify'
  | 'auth-set-secret'
  | 'auth-update-settings'
  | 'auth-hello-status'
  | 'auth-hello-verify'
  | 'auth-system-idle'
  | 'ssh-trust-host-key';
type VncAction = 'vnc.connect' | 'vnc.disconnect' | 'vnc.pointer' | 'vnc.key';
type VncCommand = {
  action: VncAction;
  sessionId: string;
  nodeId?: string;
  credentialId?: string;
  host?: string;
  port?: number;
  password?: string;
  x?: number;
  y?: number;
  buttons?: number;
  down?: boolean;
  keysym?: number;
};
type BackendResponse = {
  id: string;
  ok: boolean;
  error?: string;
};
type BackendEvent = {
  type: string;
  sessionId: string;
  status?: string;
  message?: string;
  passwordRequired?: boolean;
  width?: number;
  height?: number;
  image?: string;
};
type MigrationResponse = {
  status: 'completed' | 'already-completed' | 'skipped-non-windows';
  migrated: number;
  missing: number;
};
type WorkspaceResponse = {
  tree: unknown[];
  credentials: unknown[];
  tunnels: unknown[];
};
type AuthStateResponse = {
  mode: string;
  configured: boolean;
};

const authSession = new AuthSession();
let authOperationQueue: Promise<void> = Promise.resolve();

type SshConnectedResponse = {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
};

type SshTerminalCell = {
  character: string;
  foreground: number;
  background: number;
};

type SshTerminalCellChange = SshTerminalCell & {
  index: number;
};

type SshTerminalFrame = {
  columns: number;
  rows: number;
  full: boolean;
  cells?: SshTerminalCell[];
  changes: SshTerminalCellChange[];
  scrollbackReset: boolean;
  scrollback?: string[];
  cursorX: number;
  cursorY: number;
  cursorVisible: boolean;
  applicationCursor: boolean;
  title?: string;
  sequence: number;
};

type SshBackendEvent =
  | {
      type: 'connected';
      sessionId: string;
      host: string;
      port: number;
      username: string;
      fingerprint: string;
    }
  | { type: 'screen'; sessionId: string; frame: SshTerminalFrame }
  | { type: 'closed'; sessionId: string }
  | {
      type: 'error';
      sessionId: string;
      error: string;
      hostKeyExpected?: string;
      hostKeyReceived?: string;
    };

type SshOpenRequest = {
  sessionId: string;
  nodeId: string;
  columns: number;
  rows: number;
};

type SshHostKeyTrustRequest = {
  nodeId: string;
  expected: string;
  received: string;
};

const sshMaxSessionIdLength = 128;
const sshMaxInputLength = 1_500_000;
const sshMaxTerminalCells = 500 * 500;
const sshMaxTerminalScrollbackLines = 5000;
const sshMaxTerminalScrollbackLineLength = 2048;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isSshSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= sshMaxSessionIdLength &&
    value.trim() === value
  );
}

function isSshOpenRequest(value: unknown): value is SshOpenRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.sessionId) &&
    isSshSessionId(value.nodeId) &&
    typeof value.columns === 'number' &&
    Number.isInteger(value.columns) &&
    value.columns >= 0 &&
    value.columns <= 500 &&
    typeof value.rows === 'number' &&
    Number.isInteger(value.rows) &&
    value.rows >= 0 &&
    value.rows <= 500
  );
}

function isSshInput(value: unknown): value is string {
  return typeof value === 'string' && value.length <= sshMaxInputLength;
}

function isSshFingerprint(value: unknown): value is string {
  return typeof value === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value);
}

function isSshHostKeyTrustRequest(value: unknown): value is SshHostKeyTrustRequest {
  return (
    isRecord(value) &&
    isSshSessionId(value.nodeId) &&
    isSshFingerprint(value.expected) &&
    isSshFingerprint(value.received) &&
    value.expected !== value.received
  );
}

function isSshTerminalCell(value: unknown): value is SshTerminalCell {
  return (
    isRecord(value) &&
    typeof value.character === 'string' &&
    value.character.length <= 8 &&
    typeof value.foreground === 'number' &&
    Number.isInteger(value.foreground) &&
    value.foreground >= 0 &&
    value.foreground <= 0xffff &&
    typeof value.background === 'number' &&
    Number.isInteger(value.background) &&
    value.background >= 0 &&
    value.background <= 0xffff
  );
}

function parseSshTerminalFrame(value: unknown): SshTerminalFrame | undefined {
  if (
    !isRecord(value) ||
    typeof value.columns !== 'number' ||
    !Number.isInteger(value.columns) ||
    value.columns < 1 ||
    value.columns > 500 ||
    typeof value.rows !== 'number' ||
    !Number.isInteger(value.rows) ||
    value.rows < 1 ||
    value.rows > 500 ||
    (value.full !== undefined && typeof value.full !== 'boolean') ||
    (value.scrollback_reset !== undefined && typeof value.scrollback_reset !== 'boolean') ||
    typeof value.cursor_x !== 'number' ||
    !Number.isInteger(value.cursor_x) ||
    value.cursor_x < 0 ||
    value.cursor_x >= value.columns ||
    typeof value.cursor_y !== 'number' ||
    !Number.isInteger(value.cursor_y) ||
    value.cursor_y < 0 ||
    value.cursor_y >= value.rows ||
    typeof value.cursor_visible !== 'boolean' ||
    typeof value.application_cursor !== 'boolean' ||
    typeof value.sequence !== 'number' ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 1
  ) {
    return undefined;
  }

  const cellCount = value.columns * value.rows;
  let cells: SshTerminalCell[] | undefined;
  if (value.cells !== undefined) {
    if (
      !Array.isArray(value.cells) ||
      value.cells.length > sshMaxTerminalCells ||
      !value.cells.every(isSshTerminalCell)
    ) {
      return undefined;
    }
    cells = value.cells;
  }
  const full = value.full === true;
  if (full && (!cells || cells.length !== cellCount)) return undefined;

  const changes: SshTerminalCellChange[] = [];
  if (value.changes !== undefined) {
    if (!Array.isArray(value.changes) || value.changes.length > cellCount) return undefined;
    for (const change of value.changes) {
      const index = isRecord(change) ? change.index : undefined;
      if (
        !isRecord(change) ||
        typeof index !== 'number' ||
        !Number.isInteger(index) ||
        index < 0 ||
        index >= cellCount ||
        !isSshTerminalCell(change)
      ) {
        return undefined;
      }
      changes.push({ ...change, index });
    }
  }

  let scrollback: string[] | undefined;
  if (value.scrollback !== undefined) {
    if (
      !Array.isArray(value.scrollback) ||
      value.scrollback.length > sshMaxTerminalScrollbackLines ||
      !value.scrollback.every(
        (line) => typeof line === 'string' && line.length <= sshMaxTerminalScrollbackLineLength,
      )
    ) {
      return undefined;
    }
    scrollback = value.scrollback.slice();
  }

  return {
    columns: value.columns,
    rows: value.rows,
    full,
    cells,
    changes,
    scrollbackReset: value.scrollback_reset === true,
    scrollback,
    cursorX: value.cursor_x,
    cursorY: value.cursor_y,
    cursorVisible: value.cursor_visible,
    applicationCursor: value.application_cursor,
    title: typeof value.title === 'string' ? value.title.slice(0, 2048) : undefined,
    sequence: value.sequence,
  };
}

function parseSshBackendEvent(line: string): SshBackendEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || typeof value.type !== 'string' || !isSshSessionId(value.session_id)) {
    return undefined;
  }

  if (
    value.type === 'connected' &&
    typeof value.host === 'string' &&
    typeof value.port === 'number' &&
    Number.isInteger(value.port) &&
    value.port > 0 &&
    value.port <= 65535 &&
    typeof value.username === 'string' &&
    typeof value.fingerprint === 'string'
  ) {
    return {
      type: 'connected',
      sessionId: value.session_id,
      host: value.host,
      port: value.port,
      username: value.username,
      fingerprint: value.fingerprint,
    };
  }
  if (value.type === 'screen') {
    const frame = parseSshTerminalFrame(value.frame);
    return frame ? { type: 'screen', sessionId: value.session_id, frame } : undefined;
  }
  if (value.type === 'closed') {
    return { type: 'closed', sessionId: value.session_id };
  }
  if (value.type === 'error' && typeof value.error === 'string') {
    const hostKeyExpected = isSshFingerprint(value.host_key_expected)
      ? value.host_key_expected
      : undefined;
    const hostKeyReceived = isSshFingerprint(value.host_key_received)
      ? value.host_key_received
      : undefined;
    return {
      type: 'error',
      sessionId: value.session_id,
      error: value.error,
      hostKeyExpected,
      hostKeyReceived,
    };
  }
  return undefined;
}

class NativeBackendProcess {
  private child: ReturnType<typeof spawn> | undefined;
  private startPromise: Promise<void> | undefined;
  private outputBuffer = '';
  private requestSequence = 0;
  private readonly pending = new Map<
    string,
    { resolve: (response: BackendResponse) => void; reject: (error: Error) => void }
  >();

  async send(command: VncCommand): Promise<BackendResponse> {
    await this.start();
    const child = this.child;
    if (!child?.stdin || child.stdin.destroyed) {
      throw new Error('Native backend is not available.');
    }

    const id = `electron-${++this.requestSequence}`;
    const payload = JSON.stringify({ id, ...command }) + '\n';
    const response = new Promise<BackendResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    try {
      child.stdin.write(payload);
    } catch (error) {
      this.pending.delete(id);
      throw error instanceof Error ? error : new Error(String(error));
    }

    const timeout = setTimeout(() => {
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);
      pending.reject(new Error('Native backend command timed out.'));
    }, nativeBackendCommandTimeoutMs);

    return response.finally(() => clearTimeout(timeout));
  }

  stop(): void {
    const child = this.child;
    this.child = undefined;
    this.outputBuffer = '';
    if (!child) return;

    const error = new Error('Native backend stopped.');
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    child.stdin?.end();
    setTimeout(() => {
      if (!child.killed) child.kill();
    }, 1_000);
  }

  private async start(): Promise<void> {
    if (this.child) return;
    if (this.startPromise) return this.startPromise;

    this.startPromise = new Promise<void>((resolve, reject) => {
      let settled = false;
      const child = spawn(
        backendPath(),
        [
          '--operation',
          'serve',
          '--database',
          wormholeDatabasePath(),
          '--electron-user-data',
          electronUserDataPath(),
        ],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] },
      );
      this.child = child;
      child.stdout?.setEncoding('utf8');
      child.stdout?.on('data', (chunk: string | Buffer) => this.readOutput(String(chunk)));
      child.stdout?.once('error', (error) => {
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        this.stop();
      });
      child.stdin?.once('error', (error) => {
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('spawn', () => {
        settled = true;
        resolve();
      });
      child.once('error', (error) => {
        this.child = undefined;
        this.rejectAll(error instanceof Error ? error : new Error(String(error)));
        if (!settled) reject(error instanceof Error ? error : new Error(String(error)));
      });
      child.once('close', (code) => {
        this.child = undefined;
        this.outputBuffer = '';
        const error = new Error(
          code === null ? 'Native backend stopped.' : `Native backend exited (${code}).`,
        );
        this.rejectAll(error);
        if (!settled) reject(error);
      });
    }).finally(() => {
      this.startPromise = undefined;
    });

    return this.startPromise;
  }

  private readOutput(chunk: string): void {
    this.outputBuffer += chunk;
    if (this.outputBuffer.length > nativeBackendLineLimit) {
      this.stop();
      return;
    }

    while (true) {
      const newline = this.outputBuffer.indexOf('\n');
      if (newline < 0) return;
      const line = this.outputBuffer.slice(0, newline).trim();
      this.outputBuffer = this.outputBuffer.slice(newline + 1);
      if (!line) continue;

      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (!message || typeof message !== 'object') continue;
      if ('id' in message && typeof message.id === 'string') {
        const pending = this.pending.get(message.id);
        if (pending) {
          this.pending.delete(message.id);
          pending.resolve(message as BackendResponse);
        }
        continue;
      }
      if ('type' in message && typeof message.type === 'string') {
        if (!authSession.isAccessAllowed) continue;
        for (const window of BrowserWindow.getAllWindows()) {
          if (window.isDestroyed()) continue;
          try {
            window.webContents.send('backend:event', message as BackendEvent);
          } catch {
            // The window may be destroyed between isDestroyed() and send().
          }
        }
      }
    }
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

let nativeBackend: NativeBackendProcess | undefined;
let isQuitting = false;

function parseVncCommand(value: unknown): VncCommand {
  if (!value || typeof value !== 'object') throw new Error('Invalid VNC command.');
  const input = value as Record<string, unknown>;
  const action = input.action;
  const sessionId = input.sessionId;
  if (
    (action !== 'vnc.connect' &&
      action !== 'vnc.disconnect' &&
      action !== 'vnc.pointer' &&
      action !== 'vnc.key') ||
    typeof sessionId !== 'string' ||
    sessionId.length === 0 ||
    sessionId.length > 128
  ) {
    throw new Error('Invalid VNC command.');
  }

  const command: VncCommand = { action, sessionId };
  const stringField = (name: string, maxLength: number): string | undefined => {
    const field = input[name];
    if (field === undefined) return undefined;
    if (typeof field !== 'string' || field.length > maxLength)
      throw new Error(`Invalid VNC ${name}.`);
    return field;
  };
  const numberField = (name: string, max: number): number | undefined => {
    const field = input[name];
    if (field === undefined) return undefined;
    if (typeof field !== 'number' || !Number.isInteger(field) || field < 0 || field > max) {
      throw new Error(`Invalid VNC ${name}.`);
    }
    return field;
  };

  if (action === 'vnc.connect') {
    command.nodeId = stringField('nodeId', 128);
    command.credentialId = stringField('credentialId', 128);
    command.host = stringField('host', 1024);
    command.password = stringField('password', 16 * 1024);
    command.port = numberField('port', 65535);
    return command;
  }
  if (action === 'vnc.pointer') {
    command.x = numberField('x', 65535);
    command.y = numberField('y', 65535);
    command.buttons = numberField('buttons', 255);
    if (command.x === undefined || command.y === undefined || command.buttons === undefined) {
      throw new Error('Invalid VNC pointer command.');
    }
    return command;
  }
  if (action === 'vnc.key') {
    command.keysym = numberField('keysym', 0xffffffff);
    if (typeof input.down !== 'boolean' || command.keysym === undefined || command.keysym === 0) {
      throw new Error('Invalid VNC key command.');
    }
    command.down = input.down;
  }
  return command;
}

function wormholeDatabasePath(): string {
  const configured = process.env.WORMHOLE_DATABASE?.trim();
  if (configured) return configured;

  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData) return path.join(localAppData, wormholeDataDirectoryName, 'wormhole.db');

  // Linux/macOS do not have the Windows compatibility root. The Electron user-data directory
  // is deliberately kept separate from the renderer profile, while still giving the Go backend
  // one stable location for future cross-platform persistence.
  return path.join(app.getPath('userData'), wormholeDataDirectoryName, 'wormhole.db');
}

function electronUserDataPath(): string {
  return app.getPath('userData');
}

function findBundledExecutable(name: string): string | undefined {
  const candidates = [
    path.join(process.resourcesPath, name),
    path.join(__dirname, name),
    path.join(__dirname, '..', name),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

function backendPath(): string {
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  const executableName = `wormhole-backend-${architecture}${process.platform === 'win32' ? '.exe' : ''}`;
  const executablePath = findBundledExecutable(executableName);
  if (!executablePath) {
    throw new Error(`Electron Go backend is missing (${executableName}).`);
  }
  return executablePath;
}

function nativeRdpHostPath(): string | undefined {
  if (process.platform !== 'win32') return undefined;
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  return findBundledExecutable(`wormhole-rdp-host-${architecture}.exe`);
}

function credentialReaderPath(): string | undefined {
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  return findBundledExecutable(`wormhole-credential-reader-${architecture}.exe`);
}

async function runBackend<T>(operation: BackendOperation, request?: unknown): Promise<T> {
  const args = [
    '--operation',
    operation,
    '--database',
    wormholeDatabasePath(),
    '--electron-user-data',
    electronUserDataPath(),
  ];
  if (operation === 'migrate') {
    const reader = credentialReaderPath();
    if (reader) args.push('--credential-reader', reader);
  }
  let requestPayload: string | undefined;
  if (request !== undefined) {
    requestPayload = JSON.stringify(request);
    if (
      requestPayload === undefined ||
      Buffer.byteLength(requestPayload, 'utf8') > backendMaxRequestBytes
    ) {
      throw new Error('Electron Go backend request is too large.');
    }
  }

  const child = spawn(backendPath(), args, {
    stdio: 'pipe',
    windowsHide: true,
  });

  const output = await new Promise<string>((resolve, reject) => {
    let stdout = '';
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill();
      finishReject(new Error('Electron Go backend timed out.'));
    }, backendTimeoutMs);

    function finishReject(error: Error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    }

    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk;
      stdoutBytes += Buffer.byteLength(chunk, 'utf8');
      if (stdoutBytes > backendMaxBuffer) {
        child.kill();
        finishReject(new Error('Electron Go backend returned too much data.'));
      }
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
      if (stderr.length > backendMaxBuffer) stderr = stderr.slice(-backendMaxBuffer);
    });
    child.on('error', (error) => finishReject(error));
    child.stdin?.on('error', (error) => finishReject(error));
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(stderr.trim() || 'Electron Go backend failed.'));
        return;
      }
      resolve(stdout);
    });

    if (requestPayload === undefined) {
      child.stdin?.end();
    } else {
      child.stdin?.end(requestPayload);
    }
  });

  try {
    return JSON.parse(output) as T;
  } catch {
    throw new Error('Electron Go backend returned invalid data.');
  }
}

class NativeSshBackend {
  private child: ChildProcessWithoutNullStreams | undefined;
  private lineReader: Interface | undefined;
  private readonly activeSessions = new Set<string>();
  private readonly openWaiters = new Map<
    string,
    {
      resolve: (response: SshConnectedResponse) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
    }
  >();

  async open(request: SshOpenRequest): Promise<SshConnectedResponse> {
    if (this.openWaiters.has(request.sessionId) || this.activeSessions.has(request.sessionId)) {
      throw new Error('SSH session id is already in use.');
    }
    this.ensureStarted();

    return new Promise<SshConnectedResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const waiter = this.openWaiters.get(request.sessionId);
        if (!waiter || waiter.timeout !== timeout) return;
        this.openWaiters.delete(request.sessionId);
        reject(new Error('SSH connection timed out.'));
        try {
          this.write({ type: 'close', session_id: request.sessionId });
        } catch {
          // The backend may already have stopped; the timeout has released the renderer.
        }
      }, backendTimeoutMs);
      this.openWaiters.set(request.sessionId, { resolve, reject, timeout });
      try {
        this.write({
          type: 'open',
          session_id: request.sessionId,
          node_id: request.nodeId,
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
      waiter.reject(new Error('SSH connection closed while connecting.'));
    }
    if (this.child && !this.child.killed) {
      try {
        this.write({ type: 'close', session_id: sessionId });
      } catch {
        // The backend may exit between the state check and the write. The renderer is already
        // removing this tab, so there is no useful recovery action here.
      }
    }
  }

  requestSnapshots(): void {
    if (!authSession.isAccessAllowed || !this.child || this.child.killed) return;
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
      waiter.reject(new Error('SSH backend stopped.'));
    }
    this.openWaiters.clear();
    this.activeSessions.clear();
    this.lineReader?.close();
    this.lineReader = undefined;
    const child = this.child;
    this.child = undefined;
    if (!child || child.killed) return;
    child.stdin.end();
    child.kill();
  }

  private ensureStarted(): void {
    if (process.platform !== 'win32') {
      throw new Error('Native SSH sessions are currently available on Windows only.');
    }
    if (this.child && !this.child.killed) return;

    const child = spawn(
      backendPath(),
      [
        '--operation',
        'ssh',
        '--database',
        wormholeDatabasePath(),
        '--electron-user-data',
        electronUserDataPath(),
      ],
      { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    this.child = child;
    const lineReader = createInterface({ input: child.stdout, crlfDelay: Infinity });
    this.lineReader = lineReader;
    lineReader.on('line', (line) => {
      if (this.child === child) this.handleLine(line);
    });
    child.stdin.on('error', (error) => {
      if (this.child !== child) return;
      this.failOpenWaiters(new Error(`Native SSH backend input failed: ${error.message}`));
    });
    child.stderr.on('data', () => {
      // The backend deliberately keeps protocol events on stdout. Drain stderr so a native
      // failure cannot block the session pipe; do not mirror raw backend text into the UI.
    });
    child.on('error', (error) => {
      if (this.child !== child) return;
      this.failOpenWaiters(new Error(`Native SSH backend failed: ${error.message}`));
    });
    child.on('exit', () => {
      lineReader.close();
      if (this.child !== child) return;
      this.child = undefined;
      if (this.lineReader === lineReader) this.lineReader = undefined;
      const closedSessions = [...this.activeSessions];
      this.activeSessions.clear();
      for (const sessionId of closedSessions) {
        this.broadcast({ type: 'closed', sessionId });
      }
      this.failOpenWaiters(new Error('Native SSH backend stopped.'));
    });
  }

  private write(command: Record<string, unknown>): void {
    const child = this.child;
    if (!child || child.killed || child.stdin.destroyed) {
      throw new Error('Native SSH backend is not running.');
    }
    child.stdin.write(`${JSON.stringify(command)}\n`, 'utf8');
  }

  private handleLine(line: string): void {
    const event = parseSshBackendEvent(line);
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
        waiter.reject(new Error(event.error || 'SSH connection failed.'));
      }
    } else if (event.type === 'closed') {
      this.activeSessions.delete(event.sessionId);
    }

    this.broadcast(event);
  }

  private broadcast(event: SshBackendEvent): void {
    // Lifecycle notifications let the locked renderer settle pending tabs, but terminal frames
    // must never cross the native authentication boundary until the session is unlocked again.
    if (event.type === 'screen' && !authSession.isAccessAllowed) return;
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('ssh:event', event);
    }
  }

  private failOpenWaiters(error: Error): void {
    for (const waiter of this.openWaiters.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.openWaiters.clear();
  }
}

function serializeAuthOperation<T>(operation: () => Promise<T>): Promise<T> {
  const result = authOperationQueue.then(operation, operation);
  authOperationQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function rememberAuthState(state: AuthStateResponse, assumeUnlocked: boolean): AuthStateResponse {
  authSession.remember(state, assumeUnlocked);
  return state;
}

async function refreshAuthSession(): Promise<AuthStateResponse> {
  const state = await runBackend<AuthStateResponse>('auth-status');
  return rememberAuthState(state, false);
}

async function ensureAuthSession(): Promise<void> {
  if (!authSession.isInitialized) await refreshAuthSession();
}

async function requireNativeAuth(): Promise<void> {
  if (process.platform !== 'win32') return;
  await ensureAuthSession();
  authSession.requireUnlocked();
}

async function runFirstLaunchMigrations(): Promise<void> {
  // The legacy Credential Manager is a Windows-only source. Keeping this guard in the Electron
  // main process also prevents the Windows backend/helper from being loaded on other platforms.
  if (process.platform !== 'win32') return;

  const result = await runBackend<MigrationResponse>('migrate');
  if (result.status === 'completed') {
    console.info(
      `[Wormhole] Credential Manager migration completed: ${result.migrated} migrated, ${result.missing} missing.`,
    );
  } else if (result.status === 'already-completed') {
    console.info('[Wormhole] Credential Manager migration already completed.');
  }
}

function registerIpcHandlers(sshBackend: NativeSshBackend): void {
  ipcMain.handle('workspace:load', async () => {
    if (process.platform !== 'win32') {
      return { tree: [], credentials: [], tunnels: [] };
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const workspace = await runBackend<WorkspaceResponse>('workspace');
      console.info(
        `[Wormhole] Workspace loaded: ${workspace.tree.length} roots, ${workspace.credentials.length} credentials, ${workspace.tunnels.length} tunnels.`,
      );
      return workspace;
    });
  });

  ipcMain.handle('auth:status', async () => {
    if (process.platform !== 'win32') {
      return {
        mode: 'disabled',
        fallback: 'pin',
        idleTimeoutMinutes: 15,
        hasPin: false,
        hasPassword: false,
        isCorrupted: false,
        configured: false,
        windowsHello: {
          available: false,
          message: 'Windows Hello is only available on Windows.',
        },
      };
    }
    return serializeAuthOperation(refreshAuthSession);
  });

  ipcMain.handle('auth:verify', async (_event, request: unknown) => {
    if (process.platform !== 'win32')
      return { succeeded: false, message: 'Authentication is unavailable.' };
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const result = await runBackend<{ succeeded: boolean }>('auth-verify', request);
      if (result.succeeded) authSession.markUnlocked();
      return result;
    });
  });

  ipcMain.handle('auth:set-secret', async (_event, request: unknown) => {
    if (process.platform !== 'win32') throw new Error('Authentication is unavailable.');
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-set-secret', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:update-settings', async (_event, request: unknown) => {
    if (process.platform !== 'win32') throw new Error('Authentication is unavailable.');
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.requireUnlocked();
      const state = await runBackend<AuthStateResponse>('auth-update-settings', request);
      return rememberAuthState(state, true);
    });
  });

  ipcMain.handle('auth:lock', async (event) => {
    if (process.platform !== 'win32') return;
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      authSession.lock();
      const ownerWindow = BrowserWindow.fromWebContents(event.sender);
      if (!ownerWindow || ownerWindow.isDestroyed()) return;
      try {
        await rdpClient?.hideAll(nativeWindowHandle(ownerWindow));
      } catch {
        // Authentication remains locked even if a native RDP surface has already exited.
      }
    });
  });

  ipcMain.handle('auth:hello-status', async () => {
    if (process.platform !== 'win32') {
      return { available: false, message: 'Windows Hello is only available on Windows.' };
    }
    return runBackend('auth-hello-status');
  });

  ipcMain.handle('auth:hello-verify', async () => {
    if (process.platform !== 'win32') {
      return { succeeded: false, message: 'Windows Hello is only available on Windows.' };
    }
    return serializeAuthOperation(async () => {
      await ensureAuthSession();
      const state = await refreshAuthSession();
      if (state.mode !== 'windowsHello' || !state.configured) {
        return {
          succeeded: false,
          message: 'Windows Hello is not the configured unlock method.',
        };
      }
      const result = await runBackend<{ succeeded: boolean }>('auth-hello-verify');
      if (result.succeeded) authSession.markUnlocked();
      return result;
    });
  });

  ipcMain.handle('auth:system-idle', async () => {
    if (process.platform !== 'win32') return { seconds: 0 };
    return runBackend('auth-system-idle');
  });
  ipcMain.handle('ssh:open', async (_event, request: unknown) => {
    if (!isSshOpenRequest(request)) throw new Error('SSH open request is invalid.');
    let connection: Promise<SshConnectedResponse> | undefined;
    await serializeAuthOperation(async () => {
      await requireNativeAuth();
      // Start the long-lived connection inside the authorization queue, but do not make the
      // queue wait for the remote handshake. This keeps a lock request responsive while a host
      // is unreachable or still negotiating.
      connection = sshBackend.open(request);
    });
    return connection!;
  });
  ipcMain.handle('ssh:trust-host-key', async (_event, request: unknown) => {
    if (!isSshHostKeyTrustRequest(request)) {
      throw new Error('SSH host-key trust request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      return runBackend('ssh-trust-host-key', request);
    });
  });
  ipcMain.handle('ssh:input', async (_event, sessionId: unknown, data: unknown) => {
    if (!isSshSessionId(sessionId) || !isSshInput(data)) {
      throw new Error('SSH input request is invalid.');
    }
    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      sshBackend.sendInput(sessionId, data);
    });
  });
  ipcMain.handle(
    'ssh:resize',
    async (_event, sessionId: unknown, columns: unknown, rows: unknown) => {
      if (
        !isSshSessionId(sessionId) ||
        typeof columns !== 'number' ||
        !Number.isInteger(columns) ||
        columns < 0 ||
        columns > 500 ||
        typeof rows !== 'number' ||
        !Number.isInteger(rows) ||
        rows < 0 ||
        rows > 500
      ) {
        throw new Error('SSH resize request is invalid.');
      }
      return serializeAuthOperation(async () => {
        await requireNativeAuth();
        sshBackend.resize(sessionId, columns, rows);
      });
    },
  );
  ipcMain.handle('ssh:close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH close request is invalid.');
    sshBackend.close(sessionId);
  });
  ipcMain.handle('vnc:command', async (_event, input: unknown) => {
    if (isQuitting) {
      return { id: '', ok: false, error: 'Native backend is stopping.' };
    }
    if (process.platform !== 'win32') {
      return { id: '', ok: false, error: 'Native VNC sessions are available on Windows builds.' };
    }

    let command: VncCommand;
    try {
      command = parseVncCommand(input);
    } catch (error) {
      return {
        id: '',
        ok: false,
        error: error instanceof Error ? error.message : 'Invalid VNC command.',
      };
    }
    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      nativeBackend ??= new NativeBackendProcess();
      return nativeBackend.send(command);
    });
  });

  ipcMain.handle('rdp:start', async (event, value: unknown) => {
    const request = parseRdpStartRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');

    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      const client = getRdpClient();
      const bounds = toScreenBounds(ownerWindow, request.bounds);
      return client.start(request, nativeWindowHandle(ownerWindow), bounds);
    });
  });

  ipcMain.handle('rdp:resize', async (event, value: unknown) => {
    const request = parseRdpCommandRequest(value);
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');

    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      const client = getRdpClient();
      const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
      return client.resize({ ...request, bounds }, nativeWindowHandle(ownerWindow));
    });
  });

  ipcMain.handle('rdp:command', async (event, value: unknown) => {
    const request = parseRdpCommandRequest(value);
    const operation = valueAsString(value, 'operation');
    if (
      operation !== 'show' &&
      operation !== 'hide' &&
      operation !== 'focus' &&
      operation !== 'disconnect'
    ) {
      throw new Error('Unsupported RDP command.');
    }
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    if (!ownerWindow) throw new Error('RDP owner window is unavailable.');
    const bounds = request.bounds ? toScreenBounds(ownerWindow, request.bounds) : undefined;
    const command = () =>
      getRdpClient().command(operation, request.sessionId, nativeWindowHandle(ownerWindow), bounds);
    if (operation === 'hide' || operation === 'disconnect') return command();
    return serializeAuthOperation(async () => {
      await requireNativeAuth();
      return command();
    });
  });
}

function getRdpClient(): RdpBackendClient {
  if (rdpClient) return rdpClient;

  const args = ['--operation', 'rdp', '--database', wormholeDatabasePath()];
  const hostPath = nativeRdpHostPath();
  if (hostPath) args.push('--rdp-host', hostPath);
  const configuredFreeRdp = process.env.WORMHOLE_FREERDP_PATH?.trim();
  if (configuredFreeRdp) args.push('--freerdp', configuredFreeRdp);

  rdpClient = new RdpBackendClient({ executable: backendPath(), args });
  rdpClient.onEvent((event: RdpBackendEvent) => {
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send('rdp:event', event);
    }
  });
  return rdpClient;
}

function nativeWindowHandle(window: BrowserWindow): string {
  const handle = window.getNativeWindowHandle();
  if (handle.length >= 8) return handle.readBigUInt64LE(0).toString();
  if (handle.length >= 4) return handle.readUInt32LE(0).toString();
  throw new Error('RDP native owner window handle is unavailable.');
}

function toScreenBounds(window: BrowserWindow, rect?: RdpSurfaceRect): RdpSurfaceRect | undefined {
  if (!rect) return undefined;
  const content = window.getContentBounds();
  const dipRect = {
    x: content.x + rect.x,
    y: content.y + rect.y,
    width: rect.width,
    height: rect.height,
  };
  if (process.platform === 'win32') {
    // The renderer and Electron window bounds are DIP coordinates, while SetWindowPos in the
    // ActiveX helper needs physical pixels. Electron's conversion handles negative monitor
    // origins and per-monitor DPI correctly, including a window moved between displays.
    const physical = screen.dipToScreenRect(window, dipRect);
    return {
      x: physical.x,
      y: physical.y,
      width: Math.max(1, physical.width),
      height: Math.max(1, physical.height),
    };
  }

  const display = screen.getDisplayNearestPoint({ x: dipRect.x, y: dipRect.y });
  const scale = display.scaleFactor > 0 ? display.scaleFactor : 1;
  return {
    x: Math.round(dipRect.x),
    y: Math.round(dipRect.y),
    width: Math.max(1, Math.round(rect.width * scale)),
    height: Math.max(1, Math.round(rect.height * scale)),
  };
}

function parseRdpStartRequest(value: unknown): RdpStartRequest {
  if (!value || typeof value !== 'object') throw new Error('Invalid RDP start request.');
  const sessionId = valueAsString(value, 'sessionId');
  const profile = valueAsObject(value, 'profile') as RdpProfile;
  const host = typeof profile.host === 'string' ? profile.host.trim() : '';
  if (!sessionId || sessionId.length > 128 || !host || host.length > 253) {
    throw new Error('RDP session or host is invalid.');
  }
  if (
    profile.port !== undefined &&
    (typeof profile.port !== 'number' ||
      !Number.isInteger(profile.port) ||
      profile.port < 0 ||
      profile.port > 65535)
  ) {
    throw new Error('RDP port is invalid.');
  }
  if (typeof profile.password === 'string' && profile.password.length > 4096) {
    throw new Error('RDP password is too long.');
  }
  if (typeof profile.gatewayPassword === 'string' && profile.gatewayPassword.length > 4096) {
    throw new Error('RDP gateway password is too long.');
  }
  return {
    sessionId,
    profile: { ...profile, host },
    bounds: parseOptionalBounds(valueAsUnknown(value, 'bounds')),
  };
}

function parseRdpCommandRequest(value: unknown): RdpCommandRequest {
  if (!value || typeof value !== 'object') throw new Error('Invalid RDP command request.');
  const sessionId = valueAsString(value, 'sessionId');
  if (!sessionId || sessionId.length > 128) throw new Error('RDP session ID is invalid.');
  return {
    sessionId,
    bounds: parseOptionalBounds(valueAsUnknown(value, 'bounds')),
  };
}

function parseOptionalBounds(value: unknown): RdpSurfaceRect | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object') throw new Error('RDP surface bounds are invalid.');
  const bounds = value as Record<string, unknown>;
  const numbers = ['x', 'y', 'width', 'height'].map((key) => bounds[key]);
  if (!numbers.every((number) => typeof number === 'number' && Number.isFinite(number))) {
    throw new Error('RDP surface bounds are invalid.');
  }
  return {
    x: numbers[0] as number,
    y: numbers[1] as number,
    width: numbers[2] as number,
    height: numbers[3] as number,
  };
}

function valueAsUnknown(value: unknown, key: string): unknown {
  return valueAsRecord(value)[key];
}

function valueAsString(value: unknown, key: string): string {
  const result = valueAsRecord(value)[key];
  return typeof result === 'string' ? result.trim() : '';
}

function valueAsObject(value: unknown, key: string): Record<string, unknown> {
  const result = valueAsRecord(value)[key];
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error(`RDP ${key} is invalid.`);
  }
  return result as Record<string, unknown>;
}

function valueAsRecord(value: unknown): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid RDP request.');
  }
  return value as Record<string, any>;
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: '#000000',
    icon: path.join(__dirname, '..', 'Assets', 'Wormhole.ico'),
    title: 'Wormhole',
    titleBarStyle: 'hidden',
    ...(process.platform !== 'darwin'
      ? {
          titleBarOverlay: {
            color: nativeTitlebarColor,
            symbolColor: nativeTitlebarSymbolColor,
            height: nativeTitlebarHeight,
          },
        }
      : {}),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  window.webContents.on('did-start-loading', () => {
    if (process.platform !== 'win32') return;
    void serializeAuthOperation(async () => {
      // A renderer reload creates a fresh UI process context. Do not let a previous renderer's
      // native unlock survive into the new context before it proves possession of the secret.
      authSession.lock();
      await rdpClient?.dispose();
    }).catch((error) => {
      console.error('[Wormhole] Could not reset native authentication for the renderer.', error);
    });
  });

  window.webContents.on('preload-error', (_event, preloadPath, error) => {
    console.error(`[Wormhole] Preload failed (${path.basename(preloadPath)}).`, error.message);
  });

  if (rendererUrl) {
    void window.loadURL(rendererUrl);
  } else {
    void window.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
}

const sshBackend = new NativeSshBackend();
authSession.onUnlocked(() => sshBackend.requestSnapshots());

app.whenReady().then(async () => {
  registerIpcHandlers(sshBackend);
  try {
    await runFirstLaunchMigrations();
  } catch (error) {
    // A failed first attempt remains retryable because no completion marker is written. The app
    // still opens so a missing native dependency or a temporarily locked DB cannot prevent the
    // user from launching Electron and fixing the environment.
    const message = error instanceof Error ? error.message : String(error);
    console.error('[Wormhole] Credential Manager migration failed.', message);
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  isQuitting = true;
  nativeBackend?.stop();
  nativeBackend = undefined;
});

app.on('window-all-closed', () => {
  void rdpClient?.dispose();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  sshBackend.dispose();
  void rdpClient?.dispose();
});
