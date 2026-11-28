import { parseVaultDescriptor, type VaultDescriptor } from '../electron/vault-contract.ts';

type Input = {
  vaultId: string;
  slotId: string;
  kind: 'password' | 'recovery-code';
  factor: Uint8Array;
};
export type VaultReauthenticationApi = {
  context(): Promise<unknown>;
  submit(input: Input): Promise<unknown>;
  cancel(): Promise<void>;
};
const actions: Record<string, string> = {
  'tighten-local-profile': 'Use Standard protection and lock this vault',
  'bitwarden-cleanup': 'Clean old Bitwarden extension packages',
  'bitwarden-install-zip': 'Import Bitwarden extension ZIP',
  'bitwarden-install-folder': 'Install Bitwarden extension',
  'ssh-host-trust': 'Trust SSH host key',
  'tunnel-edit': 'Save tunnel',
  'tunnel-delete': 'Delete tunnel',
  'credential-edit': 'Save credential',
  'credential-delete': 'Delete credential',
  'connection-save': 'Save connection',
  'folder-save': 'Save folder',
  'credential-copy': 'Copy credential',
  'credential-display': 'Show credentials',
  'local-backup-export': 'Export encrypted vault backup',
  'hello-enroll': 'Set up Windows Hello for this vault',
  'hello-remove': 'Remove Windows Hello from this vault',
  'touch-id-enroll': 'Set up Touch ID for this vault',
  'touch-id-remove': 'Remove Touch ID from this vault',
  'local-backup-install': 'Restore encrypted vault backup',
  'node-duplicate': 'Duplicate connection',
  'node-move': 'Move selected items',
  'node-delete-trees': 'Delete selected items',
  'migration-decide': 'Change credential resolution',
  'migration-resume': 'Migrate and protect this workspace',
  'rotation-resume': 'Finish updating vault protection',
};

export function mountVaultReauthenticationScreen(card: HTMLElement, api: VaultReauthenticationApi) {
  const heading = document.createElement('h1');
  heading.textContent = 'Confirm your identity';
  const action = document.createElement('p');
  action.className = 'startup-subtitle';
  action.textContent = 'Loading…';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const method = document.createElement('select');
  method.setAttribute('aria-label', 'Authentication method');
  const label = document.createElement('label');
  const labelText = document.createElement('span');
  labelText.textContent = 'Wormhole password';
  label.append(labelText);
  const input = document.createElement('input');
  input.type = 'password';
  input.autocomplete = 'current-password';
  input.maxLength = 1024;
  input.required = true;
  label.append(input);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Confirm';
  submit.disabled = true;
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.textContent = 'Cancel';
  cancel.className = 'startup-button startup-button-secondary';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.className = 'startup-status';
  const controls = document.createElement('div');
  controls.className = 'vault-dialog-actions';
  controls.append(submit, cancel);
  form.append(method, label, controls);
  card.replaceChildren(heading, action, form, status);
  let descriptor: VaultDescriptor | undefined,
    restoringBackup = false,
    disposed = false,
    busy = false;
  let pendingFactor: Uint8Array | undefined;
  const clear = () => {
    input.value = '';
  };
  const dispose = () => {
    disposed = true;
    clear();
    pendingFactor?.fill(0);
    input.disabled = true;
    submit.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  const updateMethod = () => {
    clear();
    const recovery =
      descriptor?.slots.find((slot) => slot.id === method.value)?.kind === 'recovery';
    labelText.textContent = recovery ? 'Recovery key' : 'Wormhole password';
    input.autocomplete = recovery ? 'off' : 'current-password';
    input.maxLength = recovery ? 76 : 1024;
    input.setAttribute('aria-label', recovery ? 'Recovery key' : 'Wormhole password');
    input.focus();
  };
  method.onchange = updateMethod;
  cancel.onclick = () => {
    dispose();
    void api.cancel().catch(() => undefined);
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || busy || !descriptor) return;
    const currentDescriptor = descriptor;
    const slot = descriptor.slots.find((slot) => slot.id === method.value);
    if (!slot || (slot.kind !== 'password' && slot.kind !== 'recovery')) return;
    const factor = new TextEncoder().encode(input.value);
    clear();
    if (
      !factor.length ||
      (slot.kind === 'password' ? factor.length > 1024 : factor.length !== 76)
    ) {
      factor.fill(0);
      status.textContent = 'Enter a valid password or recovery key.';
      return;
    }
    busy = true;
    pendingFactor = factor;
    input.disabled = true;
    submit.disabled = true;
    method.disabled = true;
    if (restoringBackup) status.textContent = 'Restoring your encrypted vault…';
    void (async () => {
      try {
        const accepted = await api.submit({
          vaultId: currentDescriptor.vaultId,
          slotId: slot.id,
          kind: slot.kind === 'password' ? 'password' : 'recovery-code',
          factor,
        });
        if (!disposed && accepted !== true)
          status.textContent = restoringBackup
            ? 'Could not restore the backup. Check your recovery key or cancel to choose another file.'
            : 'Could not confirm the operation. Check your password, or cancel and refresh the item.';
      } catch {
        if (!disposed) status.textContent = 'Authentication is unavailable. Cancel and try again.';
      } finally {
        factor.fill(0);
        pendingFactor = undefined;
        busy = false;
        if (!disposed) {
          submit.disabled = false;
          input.disabled = false;
          method.disabled = false;
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
      if (typeof value !== 'object' || value === null || Array.isArray(value))
        throw Error('Invalid context');
      const context = value as Record<string, unknown>;
      const slots = parseVaultDescriptor(context.slots);
      if (
        Object.keys(context).length !== 2 ||
        typeof context.operation !== 'string' ||
        !Object.hasOwn(actions, context.operation) ||
        !slots
      )
        throw Error('Invalid context');
      descriptor = slots;
      restoringBackup = context.operation === 'local-backup-install';
      action.textContent = actions[context.operation];
      for (const slot of slots.slots) {
        if (slot.kind !== 'password' && slot.kind !== 'recovery') continue;
        const option = document.createElement('option');
        option.value = slot.id;
        option.textContent = slot.kind === 'password' ? 'Wormhole password' : 'Recovery key';
        method.append(option);
      }
      if (!method.options.length) throw Error('No supported factor');
      method.hidden = method.options.length === 1;
      submit.disabled = false;
      updateMethod();
    })
    .catch(() => {
      if (!disposed) status.textContent = 'Authentication is unavailable. Cancel and try again.';
    });
  return dispose;
}
