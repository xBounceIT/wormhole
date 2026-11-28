import type { SharedInitialJoinInput } from '../electron/vault-shared-initial-join.ts';
import type { SharedAccountResetInput } from '../electron/vault-shared-account-reset.ts';
import {
  maxSharedInvitationBytes,
  parseSharedInvitation,
  type SharedInvitation,
} from '../electron/vault-shared-invitation.ts';

export type SharedInitialJoinApi = {
  inspectInvitation(invitation: string): Promise<unknown>;
  openInvitation(): Promise<unknown>;
  openResetOffer?(): Promise<unknown>;
  submit(input: SharedInitialJoinInput | SharedAccountResetInput): Promise<unknown>;
  cancel(): Promise<void>;
};

// This form runs only in the protected authentication document. It formats
// transient input; Go validates invitations, policy, identities and credentials.
export function mountSharedInitialJoinScreen(card: HTMLElement, api: SharedInitialJoinApi) {
  const title = document.createElement('h1');
  title.textContent = 'Join a shared workspace';
  const detail = document.createElement('p');
  detail.textContent = 'Paste the invitation or open the file sent by your administrator.';
  const form = document.createElement('form');
  form.className = 'startup-form shared-invitation-form';
  const factors = document.createElement('div');
  factors.className = 'shared-invitation-factors';
  factors.hidden = true;
  const label = (caption: string, control: HTMLElement) => {
    const row = document.createElement('label');
    row.textContent = caption;
    row.append(control);
    return row;
  };
  const token = document.createElement('textarea');
  token.rows = 3;
  token.maxLength = maxSharedInvitationBytes;
  token.spellcheck = false;
  token.autocapitalize = 'off';
  token.setAttribute('autocomplete', 'off');
  const tokenLabel = label('Workspace invitation', token);
  form.append(tokenLabel);
  const button = (caption: string) => {
    const value = document.createElement('button');
    value.type = 'button';
    value.textContent = caption;
    value.className = 'startup-button startup-button-secondary';
    return value;
  };
  const open = button('Open invite file…'),
    check = button('Check invitation');
  const sourceActions = document.createElement('div');
  sourceActions.className = 'vault-dialog-actions';
  sourceActions.append(open, check);
  form.append(sourceActions);
  const hint = document.createElement('p');
  hint.className = 'shared-invitation-account';
  hint.setAttribute('role', 'status');
  form.insertBefore(hint, sourceActions);
  form.append(factors);
  const field = (caption: string, name: string, maximum: number, secret = true) => {
    const value = document.createElement('input');
    value.type = secret ? 'password' : 'text';
    value.name = name;
    value.maxLength = maximum;
    value.spellcheck = false;
    value.autocapitalize = 'off';
    value.autocomplete = name.startsWith('password') ? 'new-password' : 'off';
    factors.append(label(caption, value));
    return value;
  };
  const code = field('One-time code (32 hexadecimal characters)', 'code', 32);
  const password = field('New Wormhole password', 'password', 1024);
  const confirm = field('Confirm password', 'password-confirm', 1024);
  const device = field('Device name', 'device-name', 4096, false);
  const ask = field('Account secret key, if required (64 hexadecimal characters)', 'ask', 64);
  const askCaption = ask.parentElement!.firstChild!;
  const off = document.createElement('input');
  off.type = 'checkbox';
  const offLabel = label(
    'I understand that TLS Off exposes connection metadata and permits session hijacking.',
    off,
  );
  offLabel.className = 'shared-invitation-off';
  offLabel.prepend(off);
  factors.append(offLabel);
  offLabel.hidden = true;
  const submit = button('Join workspace');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.disabled = true;
  const cancel = button('Cancel');
  const switchMethod = api.openResetOffer ? button('Use an account reset file') : undefined;
  const actions = document.createElement('div');
  actions.className = 'vault-dialog-actions';
  actions.append(submit, cancel);
  form.append(actions);
  if (switchMethod) {
    switchMethod.classList.add('vault-dialog-link');
    form.append(switchMethod);
  }
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  form.insertBefore(status, actions);
  card.replaceChildren(title, detail, form);
  const controls = [token, open, check, code, password, confirm, device, ask, off, submit];
  let disposed = false,
    busy = false,
    generation = 0;
  let invitation: SharedInvitation | undefined;
  let reset = false,
    resetFileSelected = false,
    awaitingActivation = false;
  let pending: Uint8Array[] = [];
  const clearFactors = () => {
    code.value = password.value = confirm.value = ask.value = '';
    pending.forEach((bytes) => bytes.fill(0));
    pending = [];
  };
  const disable = (value: boolean) => {
    controls.forEach((control) => {
      control.disabled = value;
    });
    if (switchMethod) switchMethod.disabled = value;
    submit.disabled = value || (reset ? !resetFileSelected : !invitation);
  };
  const showSelection = () => {
    factors.hidden = reset ? !resetFileSelected : !invitation;
    tokenLabel.hidden = reset || !!invitation;
    check.hidden = reset;
    check.textContent = invitation ? 'Change invitation' : 'Check invitation';
    check.classList.toggle('startup-button-secondary', !!invitation);
    if (!reset)
      detail.textContent = invitation
        ? 'Set up your account on this device.'
        : 'Paste the invitation or open the file sent by your administrator.';
    submit.hidden = factors.hidden;
  };
  showSelection();
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    generation++;
    clearFactors();
    token.value = device.value = '';
    invitation = undefined;
    resetFileSelected = false;
    disable(true);
    cancel.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  const invalidate = () => {
    generation++;
    invitation = undefined;
    hint.textContent = '';
    off.checked = false;
    offLabel.hidden = true;
    submit.disabled = true;
    clearFactors();
    showSelection();
  };
  token.oninput = invalidate;
  if (switchMethod)
    switchMethod.onclick = () => {
      if (busy || disposed || awaitingActivation) return;
      reset = !reset;
      resetFileSelected = false;
      invalidate();
      title.textContent = reset ? 'Reset your shared account' : 'Join a shared workspace';
      detail.textContent = reset
        ? 'Open the reset file from your administrator and enter the separately delivered code and account secret key.'
        : 'Paste the invitation or open the file sent by your administrator.';
      open.textContent = reset ? 'Open reset file…' : 'Open invite file…';
      askCaption.textContent = reset
        ? 'New account secret key (64 hexadecimal characters)'
        : 'Account secret key, if required (64 hexadecimal characters)';
      submit.textContent = reset ? 'Reset account' : 'Join workspace';
      switchMethod.textContent = reset ? 'Use an invitation' : 'Use an account reset file';
      status.textContent = '';
      (reset ? open : token).focus();
    };
  const inspect = async (file: boolean) => {
    if (disposed || busy || awaitingActivation || (reset && !file)) return;
    const requested = token.value,
      version = ++generation;
    clearFactors();
    invitation = undefined;
    resetFileSelected = false;
    off.checked = false;
    offLabel.hidden = true;
    hint.textContent = '';
    busy = true;
    disable(true);
    status.textContent = reset ? 'Selecting reset file…' : 'Checking invitation…';
    try {
      if (reset) {
        const result = await api.openResetOffer?.();
        if (disposed || version !== generation) return;
        resetFileSelected = result === true;
        status.textContent = resetFileSelected ? 'Reset file selected.' : 'Choose a reset file.';
        return;
      }
      const result = file ? await api.openInvitation() : await api.inspectInvitation(requested);
      if (disposed || version !== generation) return;
      if (result === null && file) {
        status.textContent = '';
        return;
      }
      const parsed = parseSharedInvitation(result);
      if (!parsed || (!file && token.value !== requested)) throw Error('Invalid invitation');
      invitation = parsed;
      token.value = parsed.invitation;
      const account = document.createElement('strong');
      account.textContent = parsed.loginName;
      const workspace = document.createElement('span');
      workspace.textContent = 'Workspace ' + parsed.workspaceId;
      hint.replaceChildren(account, workspace);
      offLabel.hidden = parsed.tls !== 'off';
      status.textContent =
        'Invitation format checked. Enter the code sent through a separate channel.';
    } catch {
      if (!disposed && version === generation)
        status.textContent = reset
          ? 'Could not select the reset file.'
          : 'Could not read the invitation. Check the token or choose another file.';
    } finally {
      busy = false;
      if (!disposed) {
        showSelection();
        disable(false);
        if (!factors.hidden) code.focus();
      }
    }
  };
  open.onclick = () => {
    void inspect(true);
  };
  check.onclick = () => {
    if (invitation) {
      invalidate();
      token.value = '';
      status.textContent = '';
      token.focus();
    } else void inspect(false);
  };
  cancel.onclick = () => {
    dispose();
    void Promise.resolve()
      .then(() => api.cancel())
      .catch(() => undefined);
  };
  const hex = (value: string, length: number) => {
    if (value.length !== length * 2 || !/^[0-9a-fA-F]+$/.test(value)) return undefined;
    return Uint8Array.from({ length }, (_, index) =>
      parseInt(value.slice(index * 2, index * 2 + 2), 16),
    );
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (awaitingActivation) {
      clearFactors();
      return;
    }
    if (disposed || busy || (reset ? !resetFileSelected : !invitation)) return;
    if (!reset && token.value !== invitation?.invitation) {
      invalidate();
      return;
    }
    const codeBytes = hex(code.value, 16),
      bytes = new TextEncoder().encode(password.value);
    const askBytes = ask.value ? hex(ask.value, 32) : undefined;
    pending = [...(codeBytes ? [codeBytes] : []), bytes, ...(askBytes ? [askBytes] : [])];
    const valid =
      !!codeBytes &&
      bytes.length > 0 &&
      bytes.length <= 1024 &&
      password.value === confirm.value &&
      (!reset || !!askBytes) &&
      (!ask.value || !!askBytes) &&
      device.value.length > 0 &&
      new TextEncoder().encode(device.value).length <= 4096 &&
      !/\p{Cc}/u.test(device.value) &&
      (invitation?.tls !== 'off' || off.checked);
    // Keep owned byte views until the synchronous preload invocation has copied
    // them. DOM factor values never survive a submission, including validation.
    code.value = password.value = confirm.value = ask.value = '';
    if (!valid || !codeBytes) {
      pending.forEach((value) => value.fill(0));
      pending = [];
      status.textContent = reset
        ? 'Enter matching passwords, a reset code, a device name and the new account secret key.'
        : 'Enter matching passwords, a valid code, device name and account secret key. Acknowledge TLS Off if shown.';
      return;
    }
    busy = true;
    disable(true);
    status.textContent = reset ? 'Resetting account…' : 'Joining workspace…';
    let request: Promise<unknown>;
    try {
      const factors = {
        code: codeBytes,
        password: bytes,
        deviceName: device.value,
      };
      request =
        reset && askBytes
          ? api.submit({ ...factors, kind: 'account-reset', ask: askBytes })
          : api.submit({
              ...factors,
              invitation: invitation!.invitation,
              ...(askBytes ? { ask: askBytes } : {}),
              acknowledgeTLSOff: off.checked,
            });
    } catch {
      request = Promise.reject(Error('Join unavailable.'));
    }
    pending.forEach((value) => value.fill(0));
    pending = [];
    void request
      .then((result) => {
        if (!disposed && result === 'connection-limit') {
          status.textContent =
            'The workspace server is at its connection limit. Try again after a connection closes.';
        } else if (!disposed && reset && result === 'awaiting-activation') {
          awaitingActivation = true;
          status.textContent =
            'This device is registered. Close this window and continue after your administrator restores your personal keys and re-enables the account.';
          cancel.textContent = 'Close';
          cancel.focus();
        } else if (result === true) dispose();
        else if (!disposed)
          status.textContent = reset
            ? 'Could not reset the account. Check the file and your details.'
            : 'Could not join. Check your details or cancel and try again.';
      })
      .catch(() => {
        if (!disposed)
          status.textContent = reset
            ? 'Account reset is unavailable. Cancel and try again.'
            : 'Joining is unavailable. Cancel and try again.';
      })
      .finally(() => {
        busy = false;
        if (!disposed) disable(awaitingActivation);
      });
  };
  window.addEventListener('pagehide', dispose);
  token.focus();
  return dispose;
}
