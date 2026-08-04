import { app, BrowserWindow, ipcMain } from 'electron';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
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

function registerIpcHandlers(): void {
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

app.whenReady().then(async () => {
  registerIpcHandlers();
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
