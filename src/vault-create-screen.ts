import type { VaultMigrationContext, VaultLegacyMethod } from '../electron/vault-migration-setup';
import type { VaultRootEnrollmentContext } from '../electron/vault-root-enrollment-contract';
import type { VaultUnlockInput } from '../electron/vault-unlock';
import type { VaultUpgradeContext } from '../electron/vault-upgrade-contract';
import { createRecoveryRecipient, type RecoveryRecipient } from './vault-recovery-recipient.ts';
import type {
  VaultEnrollment,
  VaultEnrollmentBegin,
  VaultEnrollmentConfirm,
} from '../electron/vault-enrollment-contract';

export type VaultCreateApi = {
  contentProtectionAvailable: boolean;
  begin(
    input: VaultEnrollmentBegin,
    legacy?: { legacyMethod: VaultLegacyMethod; legacyFactor: Uint8Array },
    authentication?: VaultUnlockInput,
  ): Promise<VaultEnrollment>;
  migrationContext?(): Promise<VaultMigrationContext>;
  rotationContext?(): Promise<VaultRootEnrollmentContext>;
  upgradeContext?(): Promise<VaultUpgradeContext>;
  confirm(input: VaultEnrollmentConfirm): Promise<unknown>;
  cancel(): Promise<unknown>;
};

export function mountVaultCreateScreen(
  card: HTMLElement,
  api: VaultCreateApi,
  migration?: VaultMigrationContext,
  rotation?: VaultRootEnrollmentContext,
  upgrade?: VaultUpgradeContext,
): () => void {
  const heading = document.createElement('h1');
  heading.textContent = rotation?.encryptDatabase
    ? 'Encrypt the vault database'
    : rotation
      ? 'Update vault protection'
      : 'Protect your workspace';
  const detail = document.createElement('p');
  detail.textContent = upgrade
    ? 'Choose a password and save your new recovery code. Wormhole will restart before opening your protected workspace.'
    : 'Choose a Wormhole password. You will also receive a recovery code to keep somewhere safe.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const input = (caption: string, autocomplete: HTMLInputElement['autocomplete']) => {
    const label = document.createElement('label');
    const text = document.createElement('span');
    text.textContent = caption;
    const field = document.createElement('input');
    field.type = 'password';
    field.autocomplete = autocomplete;
    field.maxLength = 1024;
    field.spellcheck = false;
    field.autocapitalize = 'off';
    label.append(text, field);
    form.append(label);
    return { label, text, field };
  };
  const legacyMethods = document.createElement('select');
  legacyMethods.setAttribute('aria-label', 'Existing app lock');
  const legacyLabel = document.createElement('label');
  legacyLabel.textContent = 'Existing app lock';
  legacyLabel.append(legacyMethods);
  if (migration) {
    for (const method of migration.methods) {
      const option = document.createElement('option');
      option.value = method;
      option.textContent =
        method === 'none' ? 'No existing PIN or password' : method === 'pin' ? 'PIN' : 'Password';
      legacyMethods.append(option);
    }
    legacyLabel.hidden = migration.methods.length <= 1;
    form.append(legacyLabel);
    detail.textContent =
      'Confirm your existing app lock, then choose a Wormhole password. Save the recovery code before Wormhole restarts.';
  }
  if (rotation) {
    legacyMethods.setAttribute('aria-label', 'Current vault unlock method');
    legacyLabel.textContent = 'Current vault unlock method';
    legacyLabel.append(legacyMethods);
    for (const slot of rotation.slots.slots) {
      if (slot.kind !== 'password' && slot.kind !== 'recovery') continue;
      const option = document.createElement('option');
      option.value = slot.id;
      option.textContent = slot.kind === 'password' ? 'Current password' : 'Current recovery code';
      legacyMethods.append(option);
    }
    legacyMethods.value =
      rotation.slots.slots.find((s) => s.kind === 'password')?.id ??
      rotation.slots.slots.find((s) => s.kind === 'recovery')?.id ??
      '';
    form.append(legacyLabel);
    detail.textContent = rotation.encryptDatabase
      ? 'Encrypt the entire local database, including connection names and hosts. Confirm your current unlock method, choose a new password, and save the replacement recovery code before Wormhole restarts.'
      : 'Confirm your current password or recovery code, then choose a new password. Save the replacement recovery code before Wormhole restarts.';
    if (rotation.slots.slots.some(({ kind }) => kind === 'hello' || kind === 'touch-id')) {
      detail.textContent += ' Set up biometric unlock again after Wormhole restarts.';
    }
  }
  const old = migration || rotation ? input('Current password', 'current-password') : undefined;
  const updateLegacy = () => {
    if (old) {
      old.field.value = '';
      const recovery =
        rotation?.slots.slots.find((slot) => slot.id === legacyMethods.value)?.kind === 'recovery';
      old.label.hidden = !rotation && legacyMethods.value === 'none';
      old.text.textContent = recovery
        ? 'Current recovery code'
        : legacyMethods.value === 'pin'
          ? 'Current PIN'
          : 'Current password';
      old.field.autocomplete = recovery ? 'off' : 'current-password';
      old.field.maxLength = recovery ? 76 : 1024;
    }
  };
  updateLegacy();
  const first = input('Password', 'new-password'),
    second = input('Confirm password', 'new-password');
  const recovery = document.createElement('pre');
  recovery.className = 'vault-recovery-code';
  recovery.hidden = true;
  const saved = document.createElement('button');
  saved.type = 'button';
  saved.className = 'startup-button';
  saved.textContent = "I've saved my recovery code";
  saved.hidden = true;
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Continue';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'startup-button startup-button-secondary';
  cancel.textContent = 'Cancel';
  const captureNotice = document.createElement('p');
  captureNotice.className = 'startup-status';
  captureNotice.hidden = api.contentProtectionAvailable !== false;
  captureNotice.textContent =
    'Screen capture protection is unavailable on this system. Keep your recovery code private when sharing your screen.';
  const actions = document.createElement('div');
  actions.className = 'vault-dialog-actions';
  actions.append(submit, saved, cancel);
  form.append(status, actions);
  card.replaceChildren(heading, detail, captureNotice, form, recovery);
  let busy = false,
    disposed = false,
    step: 'password' | 'display' | 'confirm' | 'done' = 'password';
  let enrollment: VaultEnrollment | undefined,
    recipient: RecoveryRecipient | undefined,
    code: Uint8Array | undefined;
  const update = () => {
    legacyMethods.disabled = busy || step !== 'password';
    if (old) old.field.disabled = busy || step !== 'password';
    submit.disabled =
      disposed ||
      busy ||
      step === 'display' ||
      step === 'done' ||
      !first.field.value ||
      !second.field.value ||
      (step === 'password' && !!old && legacyMethods.value !== 'none' && !old.field.value);
  };
  const clear = () => {
    first.field.value = second.field.value = '';
    if (old) old.field.value = '';
    recovery.textContent = '';
    code?.fill(0);
    code = undefined;
  };
  const preventCopy = (event: Event) => event.preventDefault();
  card.addEventListener('copy', preventCopy);
  card.addEventListener('cut', preventCopy);
  card.addEventListener('dragstart', preventCopy);
  const cancelFlow = () => {
    dispose();
    void api.cancel().catch(() => undefined);
  };
  const acknowledge = () => {
    if (disposed || busy || step !== 'display' || !enrollment) return;
    clear();
    step = 'confirm';
    recovery.hidden = saved.hidden = true;
    form.hidden = false;
    submit.hidden = false;
    form.append(actions);
    heading.textContent = 'Confirm your recovery code';
    detail.textContent = 'Enter the two groups below from your saved code. Do not include hyphens.';
    for (const [index, control] of [first, second].entries()) {
      control.label.hidden = false;
      control.text.textContent = `Group ${enrollment.groups[index]}`;
      control.field.autocomplete = 'off';
      control.field.maxLength = 5;
      control.field.disabled = false;
    }
    submit.textContent =
      migration || rotation || upgrade ? 'Prepare and restart' : 'Create workspace';
    update();
    first.field.focus();
  };
  const send = async (event: SubmitEvent) => {
    event.preventDefault();
    if (
      disposed ||
      busy ||
      step === 'display' ||
      step === 'done' ||
      !first.field.value ||
      !second.field.value ||
      (step === 'password' && !!old && legacyMethods.value !== 'none' && !old.field.value)
    )
      return;
    busy = true;
    first.field.disabled = second.field.disabled = true;
    update();
    status.textContent = '';
    try {
      if (step === 'password') {
        if (first.field.value !== second.field.value) {
          status.textContent = 'The passwords do not match.';
          return;
        }
        recipient = await createRecoveryRecipient();
        if (disposed) {
          recipient.dispose();
          return;
        }
        const password = new TextEncoder().encode(first.field.value);
        const legacyFactor = new TextEncoder().encode(old?.field.value ?? '');
        if (old) old.field.value = '';
        first.field.value = second.field.value = '';
        let pending: Promise<VaultEnrollment>;
        try {
          if (password.length > 1024) throw Error('Password too long.');
          if (legacyFactor.length > 1024) throw Error('Existing factor too long.');
          pending = api.begin(
            { password, publicKey: new Uint8Array(recipient.publicKey) },
            migration
              ? { legacyMethod: legacyMethods.value as VaultLegacyMethod, legacyFactor }
              : undefined,
            rotation
              ? {
                  vaultId: rotation.slots.vaultId,
                  slotId: legacyMethods.value,
                  kind:
                    rotation.slots.slots.find((slot) => slot.id === legacyMethods.value)?.kind ===
                    'password'
                      ? 'password'
                      : 'recovery-code',
                  factor: legacyFactor,
                }
              : undefined,
          );
        } finally {
          password.fill(0);
          legacyFactor.fill(0);
        }
        const response = await pending;
        if (disposed) return;
        const opened = await recipient.open(response);
        if (disposed) {
          opened.fill(0);
          return;
        }
        code = opened;
        enrollment = response;
        step = 'display';
        legacyLabel.hidden = true;
        if (old) old.label.hidden = true;
        form.hidden = true;
        submit.hidden = true;
        recovery.hidden = saved.hidden = false;
        card.append(actions);
        heading.textContent = 'Save your recovery code';
        detail.textContent =
          'This code is shown only once. Write it down and store it safely. Anyone with it can open your workspace.';
        recovery.textContent = new TextDecoder().decode(code);
        saved.focus();
      } else {
        const groups = new TextEncoder().encode(first.field.value + second.field.value);
        first.field.value = second.field.value = '';
        try {
          if (groups.length !== 10 || !enrollment) throw Error('Invalid confirmation.');
          const pending = api.confirm({ enrollmentId: enrollment.enrollmentId, groups });
          groups.fill(0);
          await pending;
          step = 'done';
          clear();
        } finally {
          groups.fill(0);
        }
      }
    } catch {
      if (step === 'password') {
        first.field.value = second.field.value = '';
        if (old) old.field.value = '';
      }
      if (!disposed)
        status.textContent =
          step === 'password'
            ? "Wormhole couldn't prepare your workspace. Cancel and try again."
            : 'Those groups could not be confirmed. Check your saved code or cancel and start again.';
    } finally {
      if (!disposed) {
        busy = false;
        first.field.disabled = second.field.disabled = false;
        update();
        if (step !== 'display') first.field.focus();
      }
      recipient?.dispose();
      recipient = undefined;
    }
  };
  function dispose() {
    disposed = true;
    legacyMethods.disabled = true;
    if (old) old.field.disabled = true;
    card.removeEventListener('copy', preventCopy);
    card.removeEventListener('cut', preventCopy);
    card.removeEventListener('dragstart', preventCopy);
    clear();
    recipient?.dispose();
    recipient = undefined;
    submit.disabled =
      first.field.disabled =
      second.field.disabled =
      saved.disabled =
      cancel.disabled =
        true;
    form.removeEventListener('submit', send);
    first.field.removeEventListener('input', update);
    second.field.removeEventListener('input', update);
    saved.removeEventListener('click', acknowledge);
    cancel.removeEventListener('click', cancelFlow);
    legacyMethods.removeEventListener('change', changeLegacy);
    old?.field.removeEventListener('input', update);
    window.removeEventListener('pagehide', dispose);
  }
  const changeLegacy = () => {
    updateLegacy();
    update();
  };
  legacyMethods.addEventListener('change', changeLegacy);
  old?.field.addEventListener('input', update);
  form.addEventListener('submit', send);
  first.field.addEventListener('input', update);
  second.field.addEventListener('input', update);
  saved.addEventListener('click', acknowledge);
  cancel.addEventListener('click', cancelFlow);
  window.addEventListener('pagehide', dispose);
  update();
  first.field.focus();
  return dispose;
}
