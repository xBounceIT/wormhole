import {
  parseVaultTunnelAuthenticationContext,
  maxTunnelAuthenticationField,
  type VaultTunnelAuthenticationContext,
  type VaultTunnelAuthenticationEnvelope,
} from '../electron/vault-tunnel-authentication.ts';
import { sealTunnelAuthentication } from './vault-tunnel-authentication-sender.ts';
export type VaultTunnelAuthenticationApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  submit(value: VaultTunnelAuthenticationEnvelope): Promise<unknown>;
  cancel(): Promise<void>;
};

export function mountVaultTunnelAuthenticationScreen(
  card: HTMLElement,
  api: VaultTunnelAuthenticationApi,
) {
  const heading = document.createElement('h1');
  heading.textContent = 'Fortinet IPsec sign-in';
  const explanation = document.createElement('p');
  explanation.textContent = 'Loading…';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const field = (text: string, type: string) => {
    const label = document.createElement('label'),
      input = document.createElement('input');
    label.textContent = text;
    input.type = type;
    input.autocomplete = 'off';
    input.maxLength = maxTunnelAuthenticationField;
    input.disabled = true;
    input.spellcheck = false;
    label.append(input);
    form.append(label);
    return { label, input };
  };
  const username = field('VPN username', 'text'),
    password = field('VPN password', 'password');
  username.label.hidden = true;
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Connect';
  submit.disabled = true;
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'startup-button startup-button-secondary';
  cancel.textContent = 'Cancel';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  form.append(submit, cancel);
  card.replaceChildren(heading, explanation, form, status);
  if (!api.contentProtectionAvailable) {
    const notice = document.createElement('p');
    notice.textContent = 'Screen capture protection is unavailable on this platform.';
    card.append(notice);
  }
  const controller = new AbortController();
  let disposed = false,
    busy = false,
    context: VaultTunnelAuthenticationContext | undefined;
  const clear = () => {
    username.input.value = password.input.value = '';
  };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    clear();
    username.input.disabled = password.input.disabled = submit.disabled = true;
    form.onsubmit = null;
    cancel.onclick = null;
    window.removeEventListener('pagehide', dispose);
  };
  cancel.onclick = () => {
    dispose();
    void api.cancel().catch(() => undefined);
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || busy || !context) return;
    const name = new TextEncoder().encode(username.input.value),
      secret = new TextEncoder().encode(password.input.value);
    clear();
    busy = true;
    username.input.disabled = password.input.disabled = submit.disabled = true;
    void (async () => {
      try {
        const envelope = await sealTunnelAuthentication(context, name, secret, controller.signal);
        if (disposed) return;
        if ((await api.submit(envelope)) !== true) throw Error('VPN entry unavailable.');
        dispose();
      } catch {
        if (!disposed)
          status.textContent = 'The credentials could not be submitted. Check them or cancel.';
      } finally {
        name.fill(0);
        secret.fill(0);
        busy = false;
        if (!disposed) {
          username.input.disabled = !context?.usernameRequired;
          password.input.disabled = submit.disabled = false;
          (context?.usernameRequired ? username.input : password.input).focus();
        }
      }
    })();
  };
  window.addEventListener('pagehide', dispose);
  void api
    .context()
    .then((value) => {
      if (disposed) return;
      context = parseVaultTunnelAuthenticationContext(value);
      if (!context) throw Error('Invalid context.');
      username.label.hidden = !context.usernameRequired;
      username.input.disabled = !context.usernameRequired;
      password.input.disabled = submit.disabled = false;
      explanation.textContent = context.usernameRequired
        ? 'Enter credentials for this VPN connection. They are not saved.'
        : 'The saved VPN username will be used. This password is not saved.';
      (context.usernameRequired ? username.input : password.input).focus();
    })
    .catch(() => {
      if (!disposed)
        status.textContent = 'VPN authentication is unavailable. Cancel and try again.';
    });
  return dispose;
}
