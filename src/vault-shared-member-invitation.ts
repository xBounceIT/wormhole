import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import {
  memberInvitationEnvelope,
  parseMemberInvitationReply,
  parseMemberInvitationRequest,
  type MemberInvitationPort,
} from '../electron/vault-shared-member-invitation.ts';

const messages = {
  unavailable: 'Your account cannot issue invitations in this workspace.',
  unsupported: 'Update the workspace schema to add members.',
  'invalid-login': 'Use a lowercase Wormhole login name.',
  'invalid-authentication': 'Check your password and Account Secret Key.',
  'invalid-recipient': 'Reopen this window to prepare the protected display.',
  'publication-disabled':
    'PostgreSQL parameter logging must be disabled before issuing an invitation.',
  changed: 'The login or workspace has changed. Check the accounts list.',
  busy: 'The workspace is busy. Try again.',
};

export function mountMemberInvitation(
  panel: HTMLElement,
  api: {
    issue: MemberInvitationPort;
    copyCode: (requestId: string) => Promise<{ expiresInSeconds: 20 | 30 }>;
    finish: (requestId: string) => Promise<unknown>;
  },
  close: (issued: boolean) => void,
) {
  const heading = document.createElement('h2');
  heading.textContent = 'Add member';
  const form = document.createElement('form');
  form.className = 'startup-form member-invitation';
  const fields = document.createElement('fieldset');
  const field = (caption: string, type: 'text' | 'password', limit: number, required = true) => {
    const label = document.createElement('label');
    label.textContent = caption;
    const input = document.createElement('input');
    input.type = type;
    input.required = required;
    input.maxLength = limit;
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.autocapitalize = 'off';
    label.append(input);
    fields.append(label);
    return input;
  };
  const login = field('Wormhole login', 'text', 256);
  const name = field('Display name (optional)', 'text', 4096, false);
  const password = field('Your Wormhole password', 'password', 1024);
  const ask = field('Your Account Secret Key, if required', 'password', 64, false);
  const scope = document.createElement('p');
  scope.textContent = 'This account starts with no group memberships.';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const deliver = document.createElement('section');
  deliver.className = 'member-invitation-delivery';
  deliver.hidden = true;
  const preview = document.createElement('textarea');
  preview.readOnly = true;
  preview.rows = 2;
  preview.setAttribute('aria-label', 'Invitation token');
  const code = document.createElement('code');
  code.className = 'vault-recovery-code';
  code.setAttribute('aria-label', 'One-time code');
  const button = (caption: string, primary = false) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = caption;
    button.className = primary ? 'startup-button' : 'startup-button startup-button-secondary';
    return button;
  };
  const copyInvite = button('Copy invitation');
  const copyCode = button('Copy one-time code');
  const codeLabel = document.createElement('p');
  codeLabel.textContent = 'One-time code';
  deliver.append(preview, copyInvite, codeLabel, code, copyCode);
  const back = button('Cancel');
  const submit = button('Create invitation', true);
  submit.type = 'submit';
  const actions = document.createElement('div');
  actions.className = 'shared-setup-actions';
  actions.append(back, submit);
  form.append(scope, fields, status, deliver, actions);
  panel.replaceChildren(heading, form);
  login.focus();
  let active = true,
    issued = false;
  let recipient: Awaited<ReturnType<typeof createVaultDisplayRecipient>> | undefined;
  let pending: Uint8Array[] = [];
  const events = new AbortController();
  const wipe = () => {
    password.value = ask.value = '';
    for (const bytes of pending) bytes.fill(0);
    pending = [];
  };
  let currentRequest: string | undefined;
  const dispose = () => {
    active = false;
    if (currentRequest) void api.finish(currentRequest).catch(() => {});
    wipe();
    recipient?.dispose();
    preview.value = code.textContent = '';
    events.abort();
  };
  for (const kind of ['copy', 'cut', 'dragstart']) {
    document.addEventListener(
      kind,
      (event) => {
        if (!deliver.hidden && event.target !== preview) event.preventDefault();
      },
      { capture: true, signal: events.signal },
    );
  }
  back.onclick = () => {
    if (active && !back.disabled) close(issued);
  };
  copyCode.onclick = async () => {
    if (!active || !issued || !currentRequest || copyCode.disabled) return;
    copyCode.disabled = true;
    try {
      const { expiresInSeconds } = await api.copyCode(currentRequest);
      if (active)
        status.textContent = `Code copied. The clipboard clears after ${expiresInSeconds} seconds.`;
    } catch {
      if (active)
        status.textContent = 'Secure copy is unavailable. Read the code from this window.';
    } finally {
      if (active) copyCode.disabled = false;
    }
  };
  copyInvite.onclick = async () => {
    if (!active || !issued || !preview.value) return;
    try {
      await navigator.clipboard.writeText(preview.value);
      if (active)
        status.textContent =
          'Invitation copied. Send the one-time code through a different channel.';
    } catch {
      if (active) {
        preview.focus();
        preview.select();
        status.textContent = 'Copy the selected invitation.';
      }
    }
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!active || submit.disabled || issued) return;
    const loginName = login.value;
    const displayName = name.value;
    const pass = new TextEncoder().encode(password.value);
    const askText = ask.value;
    password.value = ask.value = '';
    if (!pass.length || pass.length > 1024 || (askText && !/^[0-9a-f]{64}$/i.test(askText))) {
      pass.fill(0);
      status.textContent = 'Check your password and Account Secret Key.';
      return;
    }
    const askBytes = askText
      ? Uint8Array.from(askText.match(/../g)!, (pair) => parseInt(pair, 16))
      : undefined;
    pending = askBytes ? [pass, askBytes] : [pass];
    fields.disabled = back.disabled = submit.disabled = true;
    status.textContent = 'Creating invitation…';
    try {
      const requestId = crypto.randomUUID();
      currentRequest = requestId;
      recipient = await createVaultDisplayRecipient(
        'wormhole/v1/member-invitation-display',
        [requestId, loginName],
        memberInvitationEnvelope,
      );
      if (!active) return;
      const request = parseMemberInvitationRequest({
        requestId,
        recipient: recipient.publicKey,
        login: loginName,
        name: displayName,
      });
      if (!request) {
        status.textContent = 'Check the login and display name.';
        return;
      }
      let response: ReturnType<MemberInvitationPort>;
      try {
        response = api.issue(request, { password: pass, ...(askBytes ? { ask: askBytes } : {}) });
      } finally {
        wipe();
      }
      const reply = parseMemberInvitationReply(await response);
      if (!active) return;
      if (!reply) throw Error('Invalid invitation response.');
      if (reply.status !== 'issued') {
        status.textContent = messages[reply.status];
        return;
      }
      issued = true;
      const receipt = reply.handover;
      if (receipt.requestId !== requestId) throw Error('Invitation request changed.');
      const rawDigest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(receipt.token)),
      );
      const hex = (value: Uint8Array) =>
        Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
      const secret = await recipient.open(receipt.bundle, [
        receipt.workspaceId,
        receipt.inviteId,
        hex(rawDigest),
      ]);
      try {
        if (!active) return;
        if (secret.length !== 16) throw Error('Invalid invitation code.');
        heading.textContent = 'Invitation for ' + loginName;
        code.textContent = hex(secret);
        preview.value = receipt.token;
        scope.hidden = fields.hidden = submit.hidden = true;
        deliver.hidden = false;
        back.textContent = 'Done';
        status.textContent =
          'Send the invitation and one-time code through different channels. The code is shown once.';
        copyInvite.focus();
      } finally {
        secret.fill(0);
      }
    } catch {
      if (active)
        status.textContent = issued
          ? 'The invitation was issued but the code could not be displayed.'
          : 'Could not confirm issuance. Check Invitations before trying again.';
    } finally {
      wipe();
      recipient?.dispose();
      if (active) {
        back.disabled = false;
        fields.disabled = submit.disabled = issued;
      }
    }
  };
  return dispose;
}
