import {
  parseVaultRdpCredentialsContext,
  maxRdpTemporaryPasswordBytes,
  type VaultRdpCredentialsContext,
  type VaultRdpCredentialsEnvelope,
} from '../electron/vault-rdp-credentials.ts';
import { sealRdpTemporaryCredentials } from './vault-rdp-credentials-sender.ts';

export type VaultRdpCredentialsApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  submit(envelope: VaultRdpCredentialsEnvelope): Promise<unknown>;
  cancel(): Promise<void>;
};
export function mountVaultRdpCredentialsScreen(card: HTMLElement, api: VaultRdpCredentialsApi) {
  card.classList.add('vault-rdp-credentials-card');
  const heading = document.createElement('h1');
  heading.textContent = 'RDP credentials';
  const target = document.createElement('p');
  target.className = 'startup-subtitle vault-rdp-credentials-target';
  target.textContent = 'Loading…';
  const explanation = document.createElement('p');
  explanation.textContent =
    'This account is used once and is not saved. Gateway settings come from this connection.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.textContent = 'Password';
  const input = document.createElement('input');
  input.type = 'password';
  input.autocomplete = 'off';
  input.maxLength = maxRdpTemporaryPasswordBytes;
  input.setAttribute('aria-label', 'RDP password');
  input.disabled = true;
  label.append(input);
  const username = document.createElement('input');
  username.type = 'text';
  username.autocomplete = 'off';
  username.maxLength = 1026;
  username.disabled = true;
  username.required = true;
  username.setAttribute('aria-label', 'RDP username');
  const usernameLabel = document.createElement('label');
  usernameLabel.textContent = 'Username';
  usernameLabel.append(username);
  const domain = document.createElement('input');
  domain.type = 'text';
  domain.autocomplete = 'off';
  domain.maxLength = 1026;
  domain.disabled = true;
  domain.setAttribute('aria-label', 'RDP domain');
  const domainLabel = document.createElement('label');
  domainLabel.textContent = 'Domain (optional)';
  domainLabel.append(domain);
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
  status.className = 'startup-status';
  const actions = document.createElement('div');
  actions.className = 'vault-rdp-credentials-actions';
  actions.append(submit, cancel);
  form.append(usernameLabel, domainLabel, label, actions);
  card.replaceChildren(heading, target, explanation, form, status);
  if (!api.contentProtectionAvailable) {
    const limitation = document.createElement('p');
    limitation.textContent = 'Screen capture protection is unavailable on this platform.';
    card.append(limitation);
  }
  const controller = new AbortController();
  let context: VaultRdpCredentialsContext | undefined,
    disposed = false,
    busy = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    input.value = '';
    username.value = domain.value = '';
    username.disabled = domain.disabled = true;
    input.disabled = true;
    submit.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  cancel.onclick = () => {
    dispose();
    void api.cancel().catch(() => {});
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || busy || !context) return;
    const encoder = new TextEncoder();
    const inputBytes = {
      username: encoder.encode(username.value),
      domain: encoder.encode(domain.value),
      password: encoder.encode(input.value),
    };
    username.value = domain.value = input.value = '';
    if (
      inputBytes.username.length === 0 ||
      inputBytes.username.length > 2048 ||
      inputBytes.domain.length > 2048 ||
      inputBytes.password.length > maxRdpTemporaryPasswordBytes
    ) {
      Object.values(inputBytes).forEach((f) => f.fill(0));
      status.textContent = 'The account fields are empty or too long.';
      return;
    }
    busy = true;
    input.disabled = true;
    username.disabled = domain.disabled = true;
    submit.disabled = true;
    status.textContent = 'Connecting…';
    void (async () => {
      try {
        const envelope = await sealRdpTemporaryCredentials(context, inputBytes, controller.signal);
        if (disposed) return;
        if ((await api.submit(envelope)) !== true) throw Error('Credential entry unavailable.');
        if (!disposed) {
          status.textContent = 'Credentials submitted.';
          dispose();
        }
      } catch {
        if (!disposed)
          status.textContent = 'The credentials could not be submitted. Cancel and try again.';
      } finally {
        Object.values(inputBytes).forEach((f) => f.fill(0));
        busy = false;
        if (!disposed) {
          username.disabled = domain.disabled = false;
          input.disabled = false;
          submit.disabled = false;
          input.focus();
        }
      }
    })();
  };
  window.addEventListener('pagehide', dispose);
  void api
    .context()
    .then((value) => {
      if (disposed) return;
      context = parseVaultRdpCredentialsContext(value);
      if (!context) throw Error('Invalid context.');
      target.textContent = `${context.binding.host}:${context.binding.port}`;
      username.disabled = domain.disabled = false;
      input.disabled = false;
      submit.disabled = false;
      username.focus();
    })
    .catch(() => {
      if (!disposed) status.textContent = 'Credential entry is unavailable. Cancel and try again.';
    });
  return dispose;
}
