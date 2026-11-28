import {
  maxBitwardenCLIPassword,
  parseVaultBitwardenCLIUnlockContext,
  type VaultBitwardenCLIEnvelope,
} from '../electron/vault-bitwarden-cli-unlock.ts';
import { sealBitwardenCLIPassword } from './vault-bitwarden-cli-unlock-sender.ts';

export type VaultBitwardenCLIUnlockApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  submit(envelope: VaultBitwardenCLIEnvelope): Promise<unknown>;
  cancel(): Promise<void>;
};

export async function mountVaultBitwardenCLIUnlock(
  form: HTMLFormElement,
  api: VaultBitwardenCLIUnlockApi,
) {
  const input = form.querySelector<HTMLInputElement>('input')!;
  const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
  const cancel = form.querySelector<HTMLButtonElement>('button[type="button"]')!;
  const status = form.querySelector<HTMLElement>('[role="status"]')!;
  const limitation = form.parentElement?.querySelector<HTMLElement>('[data-capture-limitation]');
  if (limitation) limitation.hidden = api.contentProtectionAvailable;
  const lifecycle = new AbortController();
  const signal = lifecycle.signal;
  const stop = () => {
    lifecycle.abort();
    input.value = '';
    input.disabled = true;
    submit.disabled = true;
  };
  window.addEventListener('pagehide', stop, { once: true });
  cancel.onclick = () => {
    stop();
    void api.cancel().catch(() => {});
  };
  try {
    const context = parseVaultBitwardenCLIUnlockContext(await api.context());
    if (!context) throw Error('Invalid context.');
    if (signal.aborted) return;
    input.disabled = false;
    submit.disabled = false;
    input.focus();
    form.onsubmit = async (event) => {
      event.preventDefault();
      if (signal.aborted || submit.disabled) return;
      const password = new TextEncoder().encode(input.value);
      input.value = '';
      if (!password.length || password.length > maxBitwardenCLIPassword) {
        password.fill(0);
        status.textContent = 'Enter a master password of up to 4096 UTF-8 bytes.';
        return;
      }
      input.disabled = true;
      submit.disabled = true;
      status.textContent = 'Submitting…';
      try {
        const envelope = await sealBitwardenCLIPassword(context, password, signal);
        signal.throwIfAborted();
        if ((await api.submit(envelope)) !== true) throw Error('Password entry unavailable.');
        stop();
      } catch {
        if (!signal.aborted) {
          status.textContent = 'The password could not be submitted. Try again.';
          input.disabled = false;
          submit.disabled = false;
          input.focus();
        }
      }
    };
  } catch {
    if (!signal.aborted) status.textContent = 'Password entry is unavailable.';
  }
}

if (typeof window !== 'undefined') {
  const api = (window as unknown as { vaultBitwardenCLIUnlock?: VaultBitwardenCLIUnlockApi })
    .vaultBitwardenCLIUnlock;
  const form = document.querySelector('form');
  if (api && form) void mountVaultBitwardenCLIUnlock(form, api);
}
