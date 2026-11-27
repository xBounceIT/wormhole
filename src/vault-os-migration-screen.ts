import type { VaultMigrationContext } from '../electron/vault-migration-setup';
import type { VaultOSMigrationPrepare } from '../electron/vault-os-migration-contract';

export type VaultOSMigrationApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<VaultMigrationContext>;
  prepare(input: VaultOSMigrationPrepare): Promise<unknown>;
  cancel(): Promise<unknown>;
};

export function mountVaultOSMigrationScreen(
  card: HTMLElement,
  api: VaultOSMigrationApi,
  context: VaultMigrationContext,
): () => void {
  const heading = document.createElement('h1');
  heading.textContent = 'Continue without a Wormhole password';
  const detail = document.createElement('p');
  detail.textContent =
    'Wormhole will move your saved secrets into its native store and restart. This workspace will open without an app password. Any existing Wormhole PIN or password will be removed. You can add protection later in Settings.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const method = document.createElement('select');
  method.setAttribute('aria-label', 'Existing app lock');
  for (const value of context.methods) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent =
      value === 'none'
        ? 'No existing app lock'
        : value === 'pin'
          ? 'Existing Wormhole PIN'
          : 'Existing Wormhole password';
    method.append(option);
  }
  const label = document.createElement('label'),
    field = document.createElement('input');
  label.textContent = 'Verify your existing app lock';
  field.type = 'password';
  field.autocomplete = 'current-password';
  field.maxLength = 1024;
  field.spellcheck = false;
  field.autocapitalize = 'off';
  label.append(field);
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  const submit = document.createElement('button'),
    cancel = document.createElement('button');
  submit.type = 'submit';
  submit.className = cancel.className = 'startup-button';
  submit.textContent = 'Continue and restart';
  cancel.type = 'button';
  cancel.textContent = 'Cancel';
  form.append(method, label, status, submit, cancel);
  card.replaceChildren(heading, detail, form);
  if (!api.contentProtectionAvailable) {
    const warning = document.createElement('p');
    warning.textContent = 'Screen capture protection is unavailable on this platform.';
    card.append(warning);
  }
  let busy = false,
    disposed = false,
    prepared = false;
  const update = () => {
    label.hidden = method.value === 'none';
    field.inputMode = method.value === 'pin' ? 'numeric' : 'text';
    field.disabled = method.disabled = busy || disposed || prepared;
    submit.disabled =
      busy || disposed || prepared || (method.value !== 'none' && !field.value.length);
    cancel.disabled = disposed || prepared;
  };
  const change = () => {
    field.value = '';
    update();
  };
  const run = async (event: Event) => {
    event.preventDefault();
    if (busy || disposed || prepared || submit.disabled) return;
    busy = true;
    const factor = new TextEncoder().encode(field.value);
    field.value = '';
    update();
    status.textContent = 'Preparing your workspace…';
    try {
      if (factor.length > 1024) throw Error('Input too long.');
      await api.prepare({
        legacyMethod: method.value as VaultOSMigrationPrepare['legacyMethod'],
        legacyFactor: factor,
      });
      prepared = true;
      if (!disposed) status.textContent = 'Restarting Wormhole…';
    } catch {
      if (!disposed)
        status.textContent = 'Preparation failed. Verify your existing app lock and try again.';
    } finally {
      factor.fill(0);
      busy = false;
      update();
    }
  };
  const close = () => {
    field.value = '';
    void api.cancel().catch(() => {
      if (!disposed) status.textContent = 'Cancellation could not be confirmed. Close this window.';
    });
  };
  method.addEventListener('change', change);
  field.addEventListener('input', update);
  form.addEventListener('submit', run);
  cancel.addEventListener('click', close);
  update();
  return () => {
    disposed = true;
    field.value = '';
    update();
    method.removeEventListener('change', change);
    field.removeEventListener('input', update);
    form.removeEventListener('submit', run);
    cancel.removeEventListener('click', close);
  };
}
