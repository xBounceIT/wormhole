import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainEvent,
  WebContents,
} from 'electron';
import type { TunnelWriteRequest } from './tunnel-test-contract.js';
const fortinetIPsecSecrets = [
  'PreSharedKey',
  'Password',
  'ClientCert',
  'ClientKey',
  'CaCert',
] as const;

const fortinetIPsecSecretChannel = 'fortinet-ipsec:secret-response';
export type FortinetIPsecEditableSecret = 'PreSharedKey' | 'Password';
type FortinetIPsecCredentials = Partial<Record<FortinetIPsecEditableSecret, string>>;
const certificateLabels = {
  ClientCert: 'Client certificate chain (PEM)',
  ClientKey: 'Client private key (PEM, unencrypted)',
  CaCert: 'Trusted CA certificates (PEM; leave blank for system trust)',
};
export type FortinetIPsecCertificate = keyof typeof certificateLabels;
type FortinetIPsecSecret = FortinetIPsecEditableSecret | FortinetIPsecCertificate;

export function isFortinetIPsecEditableSecret(
  value: unknown,
): value is FortinetIPsecEditableSecret {
  return value === 'PreSharedKey' || value === 'Password';
}

export class FortinetIPsecEntryCancelled extends Error {}

type CredentialDraft = {
  id: string;
  epoch: number;
  pending: boolean;
  credentials: FortinetIPsecCredentials;
};

export class FortinetIPsecCredentialDrafts {
  private drafts = new WeakMap<WebContents, CredentialDraft>();

  async enter(
    owner: WebContents,
    id: string,
    epoch: number,
    key: FortinetIPsecEditableSecret,
    prompt: (isCurrent: () => boolean) => Promise<string>,
  ): Promise<boolean> {
    const current = this.drafts.get(owner);
    if (current?.pending) throw new Error('A Fortinet IPsec credential window is already open.');
    const draft =
      current?.id === id && current.epoch === epoch
        ? current
        : { id, epoch, pending: false, credentials: {} };
    this.drafts.set(owner, draft);
    draft.pending = true;
    const isCurrent = () => this.drafts.get(owner) === draft;
    try {
      const value = await prompt(isCurrent);
      if (!isCurrent()) return false;
      draft.credentials[key] = value;
      return true;
    } catch (error) {
      if (error instanceof FortinetIPsecEntryCancelled) return false;
      throw error;
    } finally {
      draft.pending = false;
    }
  }

  read(owner: WebContents, id: string | undefined, epoch: number): FortinetIPsecCredentials {
    if (!id) return {};
    const draft = this.drafts.get(owner);
    if (draft?.id !== id || draft.epoch !== epoch)
      throw new Error('The Fortinet IPsec credential draft expired. Enter the credentials again.');
    if (draft.pending)
      throw new Error('Finish entering the Fortinet IPsec credential before saving.');
    return { ...draft.credentials };
  }

  discard(owner: WebContents, id?: string): void {
    if (id === undefined || this.drafts.get(owner)?.id === id) this.drafts.delete(owner);
  }

  clear(): void {
    this.drafts = new WeakMap();
  }
}

function secretPage(kind: FortinetIPsecSecret): string {
  const password = isFortinetIPsecEditableSecret(kind);
  const label =
    kind === 'PreSharedKey'
      ? 'Gateway pre-shared key (PSK)'
      : kind === 'Password'
        ? 'VPN user password'
        : certificateLabels[kind];
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<style>body{font:14px system-ui;margin:28px;color-scheme:light dark}input{box-sizing:border-box;width:100%;margin:12px 0;padding:8px}footer{display:flex;justify-content:flex-end;gap:8px}button{padding:7px 16px}</style>
</head><body><form><h2>Fortinet IPsec credentials</h2>
<label for="secret">${label}</label>
${password ? '<input id="secret" type="password" autocomplete="off" spellcheck="false" maxlength="4096" autofocus required>' : `<textarea id="secret" autocomplete="off" spellcheck="false" maxlength="131072" autofocus ${kind === 'CaCert' ? '' : 'required'} style="width:100%;height:150px"></textarea>`}
<p>${password ? 'This value will be applied when you save the VPN tunnel.' : 'Certificate material is stored securely.'}</p>
<footer><button id="cancel" type="button">Cancel</button><button type="submit">Continue</button></footer>
</form></body></html>`;
}

function validFortinetIPsecSecret(value: unknown, kind: FortinetIPsecSecret): value is string {
  if (kind === 'ClientCert' || kind === 'ClientKey' || kind === 'CaCert')
    return (
      typeof value === 'string' &&
      Buffer.byteLength(value, 'utf8') <= 131072 &&
      ((kind === 'CaCert' && value === '') || value.includes('-----BEGIN '))
    );
  if (
    typeof value !== 'string' ||
    value.length > 4096 ||
    Buffer.byteLength(value, 'utf8') > 4096 ||
    !/\P{White_Space}/u.test(value) ||
    /[\uD800-\uDFFF]/u.test(value)
  )
    return false;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

export async function prepareFortinetIPsecWrite(
  request: TunnelWriteRequest,
  prompt: (kind: FortinetIPsecCertificate) => Promise<string>,
  credentials: FortinetIPsecCredentials = {},
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
    const entered =
      secret === 'PreSharedKey' || secret === 'Password' ? credentials[secret] : undefined;
    if (entered !== undefined) {
      settings[secret] = entered;
      continue;
    }
    if (preserve) {
      settings[`Has${secret}`] = true;
      continue;
    }
    if (secret === 'PreSharedKey') throw new Error('Enter the gateway PSK in the editor.');
    if (secret === 'Password') throw new Error('Enter the VPN user password in the editor.');
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
    const pem = await prompt(secret);
    if (!validFortinetIPsecSecret(pem, secret))
      throw new Error('The Fortinet IPsec credential is invalid.');
    settings[secret] = pem;
  }
  return { ...request, settings };
}

// Only this isolated window handles input. The workspace gets a draft reference and status.
export function promptFortinetIPsecSecret(options: {
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  ipc: Pick<IpcMain, 'on' | 'removeListener'>;
  preload: string;
  parent?: BrowserWindow;
  isAuthorized: () => boolean;
  present: (window: BrowserWindow) => void;
  forget: (window: BrowserWindow) => void;
  kind: FortinetIPsecSecret;
}): Promise<string> {
  if (!options.isAuthorized()) return Promise.reject(new Error('Authentication is required.'));
  const window = options.createWindow({
    width: 480,
    height: isFortinetIPsecEditableSecret(options.kind) ? 360 : 560,
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
    const cancel = () =>
      finish(new FortinetIPsecEntryCancelled('Fortinet IPsec credential entry was cancelled.'));
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
        finish(new Error('The Fortinet IPsec credential is invalid.'));
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
        .loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(secretPage(options.kind))}`)
        .catch(() => finish(new Error('Could not open the secure key window.')));
    } catch {
      finish(new Error('Could not open the secure key window.'));
    }
  });
}
