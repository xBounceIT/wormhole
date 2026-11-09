import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainEvent,
} from 'electron';
import type { TunnelWriteRequest } from './tunnel-test-contract.js';
const fortinetIPsecSecrets = [
  'PreSharedKey',
  'Password',
  'ClientCert',
  'ClientKey',
  'CaCert',
] as const;

export const fortinetIPsecSecretChannel = 'fortinet-ipsec:secret-response';

function secretPage(kind: string): string {
  const label = (
    {
      PreSharedKey: 'Gateway pre-shared key (PSK)',
      Password: 'VPN user password',
      ClientCert: 'Client certificate chain (PEM)',
      ClientKey: 'Client private key (PEM, unencrypted)',
      CaCert: 'Trusted CA certificates (PEM; leave blank for system trust)',
    } as Record<string, string>
  )[kind];
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<style>body{font:14px system-ui;margin:28px;color-scheme:light dark}input{box-sizing:border-box;width:100%;margin:12px 0;padding:8px}footer{display:flex;justify-content:flex-end;gap:8px}button{padding:7px 16px}</style>
</head><body><form><h2>Fortinet IPsec credentials</h2>
<label for="secret">${label}</label>
${kind.endsWith('Cert') || kind === 'ClientKey' ? `<textarea id="secret" autocomplete="off" spellcheck="false" maxlength="131072" autofocus ${kind === 'CaCert' ? '' : 'required'} style="width:100%;height:150px"></textarea>` : '<input id="secret" type="password" autocomplete="off" spellcheck="false" maxlength="4096" autofocus required>'}
<p>Credentials are stored securely and are never returned to the connection editor.</p>
<footer><button id="cancel" type="button">Cancel</button><button type="submit">Save</button></footer>
</form></body></html>`;
}

export function validFortinetIPsecSecret(value: unknown, kind = 'PreSharedKey'): value is string {
  if (kind === 'ClientCert' || kind === 'ClientKey' || kind === 'CaCert')
    return (
      typeof value === 'string' &&
      Buffer.byteLength(value, 'utf8') <= 131072 &&
      ((kind === 'CaCert' && value === '') || value.includes('-----BEGIN '))
    );
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
  prompt: (kind?: string) => Promise<string>,
): Promise<TunnelWriteRequest> {
  if (request.kind !== 9) return request;
  const settings = { ...request.settings };
  const required =
    request.settings.AuthMethod === 1 ? ['ClientCert', 'ClientKey', 'CaCert'] : ['PreSharedKey'];
  if (request.settings.UserAuth === 2) required.push('Password');
  for (const secret of fortinetIPsecSecrets) {
    const preserve =
      request.id && settings[`Has${secret}`] === true && settings[`Replace${secret}`] !== true;
    delete settings[`Has${secret}`];
    delete settings[`Replace${secret}`];
    if (!required.includes(secret)) continue;
    if (
      secret === 'CaCert' &&
      request.id &&
      request.settings.HasClientCert === true &&
      request.settings.HasCaCert !== true &&
      request.settings.ReplaceCaCert !== true
    ) {
      settings.CaCert = '';
      continue;
    }
    if (preserve) settings[`Has${secret}`] = true;
    else {
      const key = await prompt(secret);
      if (!validFortinetIPsecSecret(key, secret))
        throw new Error('The Fortinet IPsec credential is invalid.');
      settings[secret] = key;
    }
  }
  return { ...request, settings };
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
  kind?: string;
}): Promise<string> {
  if (!options.isAuthorized()) return Promise.reject(new Error('Authentication is required.'));
  const window = options.createWindow({
    width: 480,
    height: options.kind?.endsWith('Cert') || options.kind === 'ClientKey' ? 560 : 420,
    resizable: false,
    show: false,
    parent: options.parent,
    modal: !!options.parent,
    title: 'Fortinet IPsec credentials',
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
      if (!validFortinetIPsecSecret(input.value, options.kind)) {
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
        .loadURL(
          `data:text/html;charset=utf-8,${encodeURIComponent(secretPage(options.kind ?? 'PreSharedKey'))}`,
        )
        .catch(() => finish(new Error('Could not open the secure key window.')));
    } catch {
      finish(new Error('Could not open the secure key window.'));
    }
  });
}
