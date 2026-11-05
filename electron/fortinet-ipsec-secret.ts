import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainEvent,
} from 'electron';
import type { TunnelWriteRequest } from './tunnel-test-contract.js';

export const fortinetIPsecSecretChannel = 'fortinet-ipsec:secret-response';

const secretPage = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<style>body{font:14px system-ui;margin:28px;color-scheme:light dark}input{box-sizing:border-box;width:100%;margin:12px 0;padding:8px}footer{display:flex;justify-content:flex-end;gap:8px}button{padding:7px 16px}</style>
</head><body><form><h2>Fortinet IPsec gateway key</h2>
<label for="secret">Gateway pre-shared key (PSK)</label>
<input id="secret" type="password" autocomplete="off" spellcheck="false" maxlength="4096" autofocus required>
<p>The key is stored securely and is never returned to the connection editor.</p>
<footer><button id="cancel" type="button">Cancel</button><button type="submit">Save key</button></footer>
</form></body></html>`;

export function validFortinetIPsecSecret(value: unknown): value is string {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value, 'utf8') > 4096)
    return false;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

export async function prepareFortinetIPsecWrite(
  request: TunnelWriteRequest,
  prompt: () => Promise<string>,
): Promise<TunnelWriteRequest> {
  if (request.kind !== 9) return request;
  const { HasPreSharedKey, ReplacePreSharedKey, ...settings } = request.settings;
  if (request.id && HasPreSharedKey === true && ReplacePreSharedKey !== true) {
    return { ...request, settings: { ...settings, HasPreSharedKey: true } };
  }
  const key = await prompt();
  if (!validFortinetIPsecSecret(key)) throw new Error('The Fortinet IPsec gateway key is invalid.');
  return { ...request, settings: { ...settings, PreSharedKey: key } };
}

// This isolated native input owns only an uncontrolled DOM field. The application
// renderer never sees a PSK in React state, IPC responses, navigation URLs or logs.
export function promptFortinetIPsecSecret(options: {
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  ipc: Pick<IpcMain, 'on' | 'removeListener'>;
  preload: string;
  parent?: BrowserWindow;
  isAuthorized: () => boolean;
  present: (window: BrowserWindow) => void;
  forget: (window: BrowserWindow) => void;
}): Promise<string> {
  if (!options.isAuthorized()) return Promise.reject(new Error('Authentication is required.'));
  const window = options.createWindow({
    width: 480,
    height: 330,
    resizable: false,
    show: false,
    parent: options.parent,
    modal: !!options.parent,
    title: 'Fortinet IPsec gateway key',
    autoHideMenuBar: true,
    webPreferences: {
      preload: options.preload,
      partition: `wormhole-ipsec-key-${randomUUID()}`,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      devTools: false,
    },
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, value = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearInterval(authorizationCheck);
      options.ipc.removeListener(fortinetIPsecSecretChannel, receive);
      options.forget(window);
      if (!window.isDestroyed()) window.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const cancel = () => finish(new Error('Fortinet IPsec gateway key entry was cancelled.'));
    const receive = (event: IpcMainEvent, message: unknown) => {
      if (event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame)
        return;
      if (!options.isAuthorized()) {
        cancel();
        return;
      }
      const input =
        message && typeof message === 'object' ? (message as Record<string, unknown>) : {};
      if (input.cancelled === true) {
        cancel();
        return;
      }
      if (!validFortinetIPsecSecret(input.value)) {
        finish(new Error('The Fortinet IPsec gateway key is invalid.'));
        return;
      }
      finish(undefined, input.value);
    };
    const timeout = setTimeout(cancel, 120_000);
    const authorizationCheck = setInterval(() => {
      if (!options.isAuthorized()) cancel();
    }, 250);
    options.ipc.on(fortinetIPsecSecretChannel, receive);
    try {
      window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) =>
        callback(false),
      );
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event) => event.preventDefault());
      window.webContents.once('render-process-gone', cancel);
      window.once('closed', cancel);
      window.once('ready-to-show', () => {
        if (!settled) options.present(window);
      });
      void window
        .loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(secretPage)}`)
        .catch(() => finish(new Error('Could not open the secure key window.')));
    } catch {
      finish(new Error('Could not open the secure key window.'));
    }
  });
}
