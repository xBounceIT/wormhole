import { parseVaultStartup, type VaultStartupMetadata } from '../electron/vault-contract.ts';
import { isSharedInitialStartup } from '../electron/vault-shared-invitation.ts';
import { mountSharedInitialJoinScreen } from './vault-shared-initial-screen.ts';
import type { SharedInitialJoinInput } from '../electron/vault-shared-initial-join.ts';
import type { SharedAccountResetInput } from '../electron/vault-shared-account-reset.ts';

export type SharedAuthenticationApi = {
  context(): Promise<unknown>;
  submit(
    input:
      | {
          vaultId: string;
          slotId: string;
          password: Uint8Array;
          ask?: Uint8Array;
          code?: Uint8Array;
          acknowledgeTLSOff?: boolean;
        }
      | SharedInitialJoinInput
      | SharedAccountResetInput,
  ): Promise<unknown>;
  inspectInvitation?(invitation: string): Promise<unknown>;
  openInvitation?(): Promise<unknown>;
  openResetOffer?(): Promise<unknown>;
  selectTLSUpdate?(action: 'choose' | 'clear'): Promise<unknown>;
  cancel(): Promise<void>;
};

export function mountSharedAuthenticationScreen(card: HTMLElement, api: SharedAuthenticationApi) {
  let disposeInitial: (() => void) | undefined;
  const title = document.createElement('h1');
  title.textContent = 'Sign in to shared workspace';
  const detail = document.createElement('p');
  detail.textContent = 'Loading…';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const method = document.createElement('select');
  method.setAttribute('aria-label', 'Password slot');
  const field = (caption: string, autocomplete: string, maxLength: number) => {
    const label = document.createElement('label');
    label.textContent = caption;
    const input = document.createElement('input');
    input.type = 'password';
    input.setAttribute('autocomplete', autocomplete);
    input.maxLength = maxLength;
    input.spellcheck = false;
    input.autocapitalize = 'off';
    label.append(input);
    form.append(label);
    return input;
  };
  form.append(method);
  const password = field('Wormhole password', 'current-password', 1024);
  const ask = field(
    'Account secret key, if your account uses one (64 hexadecimal characters)',
    'off',
    64,
  );
  const continuationLabel = document.createElement('label');
  continuationLabel.hidden = true;
  const continuation = document.createElement('input');
  continuation.type = 'checkbox';
  continuation.name = 'continue-enrollment';
  const continuationCaption = document.createTextNode('Finish joining with my invitation code');
  continuationLabel.append(continuation, continuationCaption);
  form.append(continuationLabel);
  const code = field('Invitation code (32 hexadecimal characters)', 'off', 32);
  code.name = 'code';
  const codeLabel = code.parentElement!;
  codeLabel.hidden = true;
  const tlsLabel = document.createElement('label');
  tlsLabel.hidden = true;
  const tls = document.createElement('input');
  tls.type = 'checkbox';
  tls.name = 'acknowledge-tls-off';
  tlsLabel.append(
    tls,
    document.createTextNode(
      'Allow joining without TLS only if the signed workspace policy permits it',
    ),
  );
  form.append(tlsLabel);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Sign in';
  submit.disabled = true;
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'startup-button startup-button-secondary';
  cancel.textContent = 'Cancel';
  const trustUpdate = document.createElement('button');
  trustUpdate.type = 'button';
  trustUpdate.className = cancel.className;
  trustUpdate.textContent = 'Choose signed trust update…';
  trustUpdate.hidden = true;
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  form.append(submit, cancel, trustUpdate);
  card.replaceChildren(title, detail, form, status);
  let startup: VaultStartupMetadata | undefined,
    disposed = false,
    busy = false,
    updateSelected = false;
  let pending: Uint8Array[] = [];
  let failureFeedback = 'Could not sign in. Check your details or cancel and try again.';
  const clear = () => {
    password.value = ask.value = code.value = '';
    tls.checked = false;
  };
  const disable = (value: boolean) => {
    password.disabled = ask.disabled = method.disabled = submit.disabled = value;
    continuation.disabled = code.disabled = tls.disabled = value;
    trustUpdate.disabled = value;
  };
  continuation.onchange = () => {
    clear();
    codeLabel.hidden = !continuation.checked;
    tlsLabel.hidden = !continuation.checked || startup?.sharedJoin?.accountReset === true;
  };
  const dispose = () => {
    disposed = true;
    clear();
    pending.forEach((bytes) => bytes.fill(0));
    disable(true);
    window.removeEventListener('pagehide', dispose);
  };
  cancel.onclick = () => {
    dispose();
    void api.cancel().catch(() => undefined);
  };
  trustUpdate.onclick = async () => {
    if (disposed || busy || trustUpdate.hidden || !api.selectTLSUpdate) return;
    busy = true;
    clear();
    disable(true);
    try {
      const selected = await api.selectTLSUpdate(updateSelected ? 'clear' : 'choose');
      if (disposed) return;
      if (typeof selected !== 'boolean') throw Error('Invalid trust update selection.');
      updateSelected = selected;
      trustUpdate.textContent = selected
        ? 'Remove signed trust update'
        : 'Choose signed trust update…';
      status.textContent = selected ? 'Trust update selected. Sign in to verify it.' : '';
    } catch {
      if (!disposed) status.textContent = 'Could not select a signed trust update.';
    } finally {
      busy = false;
      if (!disposed) {
        disable(false);
        password.focus();
      }
    }
  };
  method.onchange = clear;
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || busy || !startup?.slots) return;
    const slot = startup.slots.slots.find(
      (slot) => slot.id === method.value && slot.kind === 'password',
    );
    if (!slot) {
      clear();
      return;
    }
    const bytes = new TextEncoder().encode(password.value);
    let askBytes: Uint8Array | undefined;
    let codeBytes: Uint8Array | undefined;
    const continuing = !continuationLabel.hidden && continuation.checked;
    const resetting = startup.sharedJoin?.accountReset === true;
    const acknowledgeTLSOff = !tlsLabel.hidden && tls.checked;
    const valid =
      bytes.length > 0 &&
      bytes.length <= 1024 &&
      (!resetting || !!ask.value) &&
      (!ask.value || /^[0-9a-fA-F]{64}$/.test(ask.value)) &&
      (!continuing || /^[0-9a-fA-F]{32}$/.test(code.value));
    if (valid && ask.value) {
      askBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) askBytes[i] = parseInt(ask.value.slice(i * 2, i * 2 + 2), 16);
    }
    if (valid && continuing) {
      codeBytes = new Uint8Array(16);
      for (let i = 0; i < 16; i++) codeBytes[i] = parseInt(code.value.slice(i * 2, i * 2 + 2), 16);
    }
    clear();
    if (!valid) {
      bytes.fill(0);
      status.textContent = resetting
        ? 'Enter the new password and account secret key, and the reset code if requested.'
        : 'Enter a valid password, account secret key and invitation code if requested.';
      return;
    }
    pending = [bytes, ...(askBytes ? [askBytes] : []), ...(codeBytes ? [codeBytes] : [])];
    busy = true;
    disable(true);
    status.textContent = 'Checking your account…';
    let request: Promise<unknown>;
    try {
      request = api.submit({
        vaultId: startup.slots.vaultId,
        slotId: slot.id,
        password: bytes,
        ...(askBytes ? { ask: askBytes } : {}),
        ...(codeBytes ? { code: codeBytes, acknowledgeTLSOff } : {}),
      });
    } catch {
      request = Promise.reject(Error('Authentication unavailable.'));
    }
    // The preload invokes IPC synchronously before returning its promise.
    pending.forEach((value) => value.fill(0));
    pending = [];
    void request
      .then((result) => {
        if (!disposed && result !== true) {
          if (resetting && result === 'awaiting-activation') {
            status.textContent =
              'This device is registered. Try again after your administrator restores your personal keys and re-enables the account.';
          } else {
            status.textContent = updateSelected
              ? 'Could not sign in. Check your account details and the selected trust update.'
              : failureFeedback;
          }
        }
        if (result === true) dispose();
      })
      .catch(() => {
        if (!disposed) status.textContent = 'Authentication unavailable. Cancel and try again.';
      })
      .finally(() => {
        busy = false;
        if (!disposed) {
          disable(false);
          password.focus();
        }
      });
  };
  window.addEventListener('pagehide', dispose);
  void api
    .context()
    .then((value) => {
      if (disposed) return;
      if (!value || typeof value !== 'object' || Array.isArray(value))
        throw Error('Invalid context');
      const context = value as Record<string, unknown>;
      const metadata = parseVaultStartup(context.startup);
      if (
        context.mode === 'join-initial' &&
        Object.keys(context).length === 2 &&
        metadata &&
        isSharedInitialStartup(metadata) &&
        api.inspectInvitation &&
        api.openInvitation
      ) {
        dispose();
        disposeInitial = mountSharedInitialJoinScreen(card, {
          inspectInvitation: (value) => api.inspectInvitation!(value),
          openInvitation: () => api.openInvitation!(),
          openResetOffer: api.openResetOffer && (() => api.openResetOffer!()),
          submit: (value) => api.submit(value),
          cancel: () => api.cancel(),
        });
        return;
      }
      if (
        Object.keys(context).length !== 2 ||
        !(context.mode === 'recover-enrollment' ? metadata?.sharedJoin : metadata?.shared) ||
        !metadata?.slots ||
        (context.mode !== 'admit' &&
          context.mode !== 'recover-password' &&
          context.mode !== 'recover-enrollment' &&
          context.mode !== 'refresh-recovery-kit' &&
          context.mode !== 'trust-ssh-host' &&
          context.mode !== 'edit-shared-node' &&
          context.mode !== 'tighten-profile')
      )
        throw Error('Invalid context');
      startup = metadata;
      trustUpdate.hidden = context.mode !== 'admit' || !api.selectTLSUpdate;
      const hint = context.mode === 'recover-enrollment' ? metadata.sharedJoin! : metadata.shared!;
      detail.textContent = `${hint.lastLoginName} · ${hint.serverDisplayName}`;
      if (context.mode === 'refresh-recovery-kit') {
        title.textContent = 'Confirm recovery kit update';
        submit.textContent = 'Confirm update';
        failureFeedback =
          'Could not confirm the update. Check your details or cancel and try again.';
      }
      if (context.mode === 'tighten-profile') {
        title.textContent = 'Use Standard protection on this device';
        submit.textContent = 'Confirm and lock workspace';
        status.textContent =
          'Confirm your password to apply Standard to this workspace on this device.';
        failureFeedback =
          'Could not confirm Standard protection. Check your details or cancel and try again.';
      }
      if (context.mode === 'edit-shared-node') {
        title.textContent = 'Confirm shared catalog edit';
        submit.textContent = 'Save changes';
        status.textContent =
          'Confirm your account credentials to change these connection settings.';
        failureFeedback =
          'Could not confirm the change. Check your account details or reopen the editor.';
      }
      if (context.mode === 'trust-ssh-host') {
        title.textContent = 'Confirm SSH host key';
        submit.textContent = 'Save verified key';
        failureFeedback = 'Could not save the host key. Check your password and workspace access.';
      }
      if (context.mode === 'recover-password') {
        title.textContent = 'Finish a password change';
        submit.textContent = 'Continue';
        status.textContent = 'Enter the new password from the interrupted change on this computer.';
      }
      if (context.mode === 'recover-enrollment') {
        title.textContent = 'Continue joining your workspace';
        submit.textContent = 'Continue';
        status.textContent = 'Enter the password chosen when joining this workspace.';
        if (metadata.sharedJoin?.accountReset) {
          title.textContent = 'Continue resetting your account';
          status.textContent = 'Enter the new password and account secret key.';
          continuationCaption.textContent = 'Resume with my reset code';
          codeLabel.firstChild!.textContent = 'Reset code (32 hexadecimal characters)';
          ask.parentElement!.firstChild!.textContent =
            'New account secret key (64 hexadecimal characters)';
        }
        continuationLabel.hidden = metadata.sharedJoin?.canContinue !== true;
      }
      for (const slot of metadata.slots.slots.filter((slot) => slot.kind === 'password')) {
        const option = document.createElement('option');
        option.value = slot.id;
        option.textContent = `Password ${method.options.length + 1}`;
        method.append(option);
      }
      if (!method.options.length) throw Error('No password slot');
      submit.disabled = false;
      password.focus();
    })
    .catch(() => {
      if (!disposed) {
        disable(true);
        status.textContent = 'Authentication unavailable. Cancel and try again.';
      }
    });
  return () => {
    disposeInitial?.();
    dispose();
  };
}
