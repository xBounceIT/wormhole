import {
  parseVaultVncPasswordContext,
  maxVncTemporaryPasswordBytes,
  type VaultVncPasswordContext,
  type VaultVncPasswordEnvelope,
} from '../electron/vault-vnc-password.ts';
import { sealVncTemporaryPassword } from './vault-vnc-password-sender.ts';

export type VaultVncPasswordApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  submit(envelope: VaultVncPasswordEnvelope): Promise<unknown>;
  cancel(): Promise<void>;
};
export function mountVaultVncPasswordScreen(card: HTMLElement, api: VaultVncPasswordApi) {
  const heading = document.createElement('h1');
  heading.textContent = 'VNC password';
  const target = document.createElement('p');
  target.className = 'startup-subtitle vault-vnc-password-target';
  target.textContent = 'Loading…';
  const explanation = document.createElement('p');
  explanation.textContent = 'This password is used once and is not saved.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.textContent = 'VNC password';
  const input = document.createElement('input');
  input.type = 'password';
  input.autocomplete = 'off';
  input.maxLength = maxVncTemporaryPasswordBytes;
  input.setAttribute('aria-label', 'VNC password');
  input.disabled = true;
  label.append(input);
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
  actions.className = 'vault-dialog-actions';
  actions.append(submit, cancel);
  form.append(label, actions);
  card.replaceChildren(heading, target, explanation, form, status);
  if (!api.contentProtectionAvailable) {
    const limitation = document.createElement('p');
    limitation.textContent = 'Screen capture protection is unavailable on this platform.';
    card.append(limitation);
  }
  const controller = new AbortController();
  let context: VaultVncPasswordContext | undefined,
    disposed = false,
    busy = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    input.value = '';
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
    const inputBytes = new TextEncoder().encode(input.value);
    input.value = '';
    if (inputBytes.length > maxVncTemporaryPasswordBytes) {
      inputBytes.fill(0);
      status.textContent = 'The password is too long.';
      return;
    }
    busy = true;
    input.disabled = true;
    submit.disabled = true;
    status.textContent = 'Connecting…';
    void (async () => {
      try {
        const envelope = await sealVncTemporaryPassword(context, inputBytes, controller.signal);
        if (disposed) return;
        if ((await api.submit(envelope)) !== true) throw Error('Password entry unavailable.');
        if (!disposed) {
          status.textContent = 'Password submitted.';
          dispose();
        }
      } catch {
        if (!disposed)
          status.textContent = 'The password could not be submitted. Cancel and try again.';
      } finally {
        inputBytes.fill(0);
        busy = false;
        if (!disposed) {
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
      context = parseVaultVncPasswordContext(value);
      if (!context) throw Error('Invalid context.');
      target.textContent = `${context.binding.host}:${context.binding.port}`;
      input.disabled = false;
      submit.disabled = false;
      input.focus();
    })
    .catch(() => {
      if (!disposed) status.textContent = 'Password entry is unavailable. Cancel and try again.';
    });
  return dispose;
}
