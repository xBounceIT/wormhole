import type { VaultDescriptor, VaultUnlockResult } from '../electron/vault-contract.js';
import type {
  VaultPresenceSelection,
  VaultPresenceUnlockResult,
} from '../electron/vault-presence.js';
import type { VaultUnlockInput } from '../electron/vault-unlock.js';

type UnlockApi = {
  platform?: string;
  unlockVault(input: VaultUnlockInput): Promise<VaultUnlockResult>;
  unlockVaultPresence?(selection: VaultPresenceSelection): Promise<VaultPresenceUnlockResult>;
};

// The input stays in its DOM control only until submission. No factor is placed
// in React/app state, persisted, logged or retained across an asynchronous call.
export function mountVaultUnlockScreen(
  card: HTMLElement,
  descriptor: VaultDescriptor,
  api: UnlockApi,
  onUnlocked: () => Promise<void>,
): () => void {
  const title = document.createElement('h1');
  title.textContent = 'Wormhole is locked';
  const detail = document.createElement('p');
  detail.textContent = 'Unlock your vault to load your connections.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const slotLabel = document.createElement('label');
  slotLabel.textContent = 'Unlock method';
  const select = document.createElement('select');
  select.setAttribute('aria-label', 'Unlock method');
  const counts = { password: 0, recovery: 0 };
  const methods = descriptor.slots.filter(
    (slot) => slot.kind === 'password' || slot.kind === 'recovery',
  );
  for (const slot of methods) {
    const option = document.createElement('option');
    option.value = slot.id;
    const number = ++counts[slot.kind];
    option.textContent =
      (slot.kind === 'password' ? 'Password' : 'Recovery code') + (number > 1 ? ` ${number}` : '');
    select.append(option);
  }
  // A password is the ordinary unlock even when recovery happens to be listed first.
  select.value = methods.find((slot) => slot.kind === 'password')?.id ?? methods[0]?.id ?? '';
  slotLabel.append(select);
  const factorLabel = document.createElement('label');
  const caption = document.createElement('span');
  const input = document.createElement('input');
  input.type = 'password';
  input.spellcheck = false;
  input.autocapitalize = 'off';
  input.maxLength = 1024;
  factorLabel.append(caption, input);
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  const submit = document.createElement('button');
  submit.className = 'startup-button';
  submit.type = 'submit';
  submit.textContent = 'Unlock';
  const kind = api.platform === 'win32' ? 'hello' : api.platform === 'darwin' ? 'touch-id' : null;
  const presenceSlot = kind && descriptor.slots.find((slot) => slot.kind === kind);
  const label = kind === 'touch-id' ? 'Touch ID' : 'Windows Hello';
  const biometric = document.createElement('button');
  biometric.className = 'startup-button startup-button-secondary';
  biometric.type = 'button';
  biometric.textContent = `Unlock with ${label}`;
  biometric.hidden = !presenceSlot || !api.unlockVaultPresence;
  let busy = false;
  let disposed = false;
  let unlocked = false;
  const selected = () => methods.find((slot) => slot.id === select.value);
  const update = () => {
    submit.disabled = disposed || busy || (!unlocked && (!selected() || input.value.length === 0));
    biometric.disabled = disposed || busy || unlocked;
  };
  const changeMethod = () => {
    input.value = '';
    const recovery = selected()?.kind === 'recovery';
    caption.textContent = recovery ? 'Recovery code' : 'Wormhole password';
    input.autocomplete = recovery ? 'off' : 'current-password';
    input.placeholder = recovery ? 'WHREC1-…' : 'Enter your password';
    status.textContent = recovery ? 'Enter the recovery code exactly as saved.' : '';
    update();
  };
  const unlock = async (authenticate: () => Promise<VaultPresenceUnlockResult>, native = false) => {
    if (disposed || busy) return;
    busy = true;
    select.disabled = input.disabled = true;
    update();
    submit.textContent = 'Unlocking…';
    status.textContent = 'Unlocking…';
    try {
      if (!unlocked) {
        const result = await authenticate();
        if (disposed) return;
        if ('status' in result) {
          status.textContent =
            result.status === 'remote-desktop'
              ? 'Windows Hello is unavailable in Remote Desktop. Use your password or recovery code.'
              : result.status === 'canceled'
                ? `${label} was canceled. Try again or use your password or recovery code.`
                : `${label} is unavailable. Use your password or recovery code.`;
          return;
        }
        if (!result.unlocked || typeof result.lockedMemory !== 'boolean')
          throw new Error('Invalid unlock result');
        unlocked = true;
        slotLabel.hidden = factorLabel.hidden = biometric.hidden = true;
      }
      status.textContent = 'Loading your workspace…';
      await onUnlocked();
    } catch {
      if (!disposed)
        status.textContent = unlocked
          ? "Your vault is unlocked, but Wormhole couldn't load the workspace. Try again."
          : native
            ? `Wormhole couldn't unlock your vault with ${label}. Use your password or recovery code.`
            : "Wormhole couldn't unlock your vault. Check your password or recovery code and try again.";
    } finally {
      if (!disposed) {
        busy = false;
        select.disabled = input.disabled = unlocked;
        submit.textContent = unlocked ? 'Load workspace' : 'Unlock';
        update();
        if (unlocked) submit.focus();
        else input.focus();
      }
    }
  };
  const send = (event: SubmitEvent) => {
    event.preventDefault();
    const slot = selected();
    if (!slot || (!unlocked && input.value.length === 0)) return;
    void unlock(() => {
      const factor = new TextEncoder().encode(input.value);
      input.value = '';
      try {
        if (slot.kind === 'password' ? factor.length > 1024 : factor.length !== 76)
          throw new Error('Invalid factor length');
        return api.unlockVault({
          vaultId: descriptor.vaultId,
          slotId: slot.id,
          kind: slot.kind === 'password' ? 'password' : 'recovery-code',
          factor,
        });
      } finally {
        factor.fill(0);
      }
    });
  };
  const sendPresence = () => {
    const authenticate = api.unlockVaultPresence?.bind(api);
    if (biometric.hidden || biometric.disabled || !presenceSlot || !authenticate) return;
    input.value = '';
    void unlock(() => authenticate({ vaultId: descriptor.vaultId, slotId: presenceSlot.id }), true);
  };
  form.addEventListener('submit', send);
  biometric.addEventListener('click', sendPresence);
  input.addEventListener('input', update);
  select.addEventListener('change', changeMethod);
  form.append(slotLabel, factorLabel, status, submit, biometric);
  card.replaceChildren(title, detail, form);
  changeMethod();
  input.focus();
  const dispose = () => {
    disposed = true;
    input.value = '';
    input.disabled = select.disabled = submit.disabled = biometric.disabled = true;
    form.removeEventListener('submit', send);
    biometric.removeEventListener('click', sendPresence);
    input.removeEventListener('input', update);
    select.removeEventListener('change', changeMethod);
    window.removeEventListener('pagehide', dispose);
  };
  window.addEventListener('pagehide', dispose);
  return dispose;
}
