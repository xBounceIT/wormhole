import { app, BrowserWindow, ipcMain } from 'electron';
import { execFile, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rendererUrl = process.env.VITE_DEV_SERVER_URL;
const nativeTitlebarColor = '#0a0a0a00';
const nativeTitlebarSymbolColor = '#ffffff';
const nativeTitlebarHeight = 48;
const wormholeDataDirectoryName = 'Wormhole';
const backendTimeoutMs = 30_000;
const backendMaxBuffer = 16 * 1024 * 1024;

type BackendOperation = 'workspace' | 'migrate';
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

type SshConnectedResponse = {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
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
  | { type: 'data'; sessionId: string; data: string }
  | { type: 'closed'; sessionId: string }
  | { type: 'error'; sessionId: string; error: string };

type SshOpenRequest = {
  sessionId: string;
  nodeId: string;
  columns: number;
  rows: number;
};

const sshMaxSessionIdLength = 128;
const sshMaxInputLength = 1_500_000;

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
  if (value.type === 'data' && typeof value.data === 'string') {
    return { type: 'data', sessionId: value.session_id, data: value.data };
  }
  if (value.type === 'closed') {
    return { type: 'closed', sessionId: value.session_id };
  }
  if (value.type === 'error' && typeof value.error === 'string') {
    return { type: 'error', sessionId: value.session_id, error: value.error };
  }
  return undefined;
}

function wormholeDatabasePath(): string {
  const localAppData = process.env.LOCALAPPDATA;
  if (!localAppData) {
    throw new Error('LOCALAPPDATA is not set; cannot locate the Wormhole database.');
  }

  return path.join(localAppData, wormholeDataDirectoryName, 'wormhole.db');
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
  const executableName = `wormhole-backend-${architecture}.exe`;
  const executablePath = findBundledExecutable(executableName);
  if (!executablePath) {
    throw new Error(`Electron Go backend is missing (${executableName}).`);
  }
  return executablePath;
}

function credentialReaderPath(): string | undefined {
  const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
  return findBundledExecutable(`wormhole-credential-reader-${architecture}.exe`);
}

async function runBackend<T>(operation: BackendOperation): Promise<T> {
  const args = ['--operation', operation, '--database', wormholeDatabasePath()];
  if (operation === 'migrate') {
    const reader = credentialReaderPath();
    if (reader) args.push('--credential-reader', reader);
  }

  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(backendPath(), args, {
      windowsHide: true,
      maxBuffer: backendMaxBuffer,
      timeout: backendTimeoutMs,
      encoding: 'utf8',
    }));
  } catch (error) {
    const stderr =
      typeof error === 'object' &&
      error !== null &&
      'stderr' in error &&
      typeof error.stderr === 'string'
        ? error.stderr.trim()
        : '';
    throw new Error(stderr || 'Electron Go backend failed.');
  }
  const output = stdout;
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
      ['--operation', 'ssh', '--database', wormholeDatabasePath()],
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
    const workspace = await runBackend<WorkspaceResponse>('workspace');
    console.info(
      `[Wormhole] Workspace loaded: ${workspace.tree.length} roots, ${workspace.credentials.length} credentials, ${workspace.tunnels.length} tunnels.`,
    );
    return workspace;
  });
  ipcMain.handle('ssh:open', async (_event, request: unknown) => {
    if (!isSshOpenRequest(request)) throw new Error('SSH open request is invalid.');
    return sshBackend.open(request);
  });
  ipcMain.handle('ssh:input', async (_event, sessionId: unknown, data: unknown) => {
    if (!isSshSessionId(sessionId) || !isSshInput(data)) {
      throw new Error('SSH input request is invalid.');
    }
    sshBackend.sendInput(sessionId, data);
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
      sshBackend.resize(sessionId, columns, rows);
    },
  );
  ipcMain.handle('ssh:close', async (_event, sessionId: unknown) => {
    if (!isSshSessionId(sessionId)) throw new Error('SSH close request is invalid.');
    sshBackend.close(sessionId);
  });
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

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  sshBackend.dispose();
});
