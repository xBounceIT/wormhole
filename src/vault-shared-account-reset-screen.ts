import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import { enrollmentBytes, enrollmentID } from '../electron/vault-enrollment-contract.ts';
import {
  accountResetDisplayEnvelope,
  parseSharedAccountResetIssue,
  type SharedAccountResetIssueInput,
} from '../electron/vault-shared-account-reset-issue.ts';
import {
  parseAccountResetMarkResult,
  type AccountResetMark,
  type AccountResetTarget,
} from '../electron/vault-shared-account-reset-queue.ts';
import {
  createAccountResetQueue,
  type AccountResetQueueApi,
} from './vault-shared-account-reset-queue.ts';

export type SharedAccountResetIssueApi = Partial<AccountResetQueueApi> & {
  contentProtectionAvailable?: boolean;
  resetContext(): Promise<unknown>;
  issueReset(input: SharedAccountResetIssueInput): Promise<unknown>;
  close(): Promise<true>;
};

type ReenrollmentOfferScope = Required<
  Pick<SharedAccountResetIssueInput, 'targetUserId' | 'targetLogin' | 'suspension'>
> & { signal: AbortSignal };

const failures = {
  unavailable: 'Account reset is unavailable for this login or workspace.',
  'invalid-login': 'Enter the exact Wormhole login name.',
  'invalid-authentication': 'Check your password and Account Secret Key.',
  'invalid-recipient': 'Could not prepare the protected display. Try again.',
  'publication-disabled': 'PostgreSQL logging settings prevent issuing a reset.',
  'save-failed': 'Could not save the offer. Choose a new file in a writable folder.',
};

export async function mountSharedAccountResetIssue(
  card: HTMLElement,
  api: SharedAccountResetIssueApi,
  scope?: ReenrollmentOfferScope,
) {
  const workspace = await api.resetContext();
  if (scope?.signal.aborted) return;
  if (!enrollmentID(workspace)) throw Error('Account reset is unavailable.');
  const title = document.createElement(scope ? 'h2' : 'h1');
  title.textContent = scope ? 'Issue re-enrollment offer' : 'Issue account reset';
  const detail = document.createElement('p');
  detail.textContent = scope
    ? 'The recipient will register new account keys, a password and an Account Secret Key. The account stays suspended until you restore its personal keys and re-enable it.'
    : 'When the recipient redeems the offer, Wormhole replaces their password and Account Secret Key and revokes their previous devices.';
  const protection = document.createElement('p');
  protection.textContent = 'Screen capture protection is unavailable on this computer.';
  protection.hidden = api.contentProtectionAvailable === true;
  const form = document.createElement('form');
  form.className = 'startup-form';
  const field = (caption: string, name: string, maxLength: number, required = true) => {
    const label = document.createElement('label');
    label.textContent = caption;
    const input = document.createElement('input');
    input.name = name;
    input.type = name === 'target-login' ? 'text' : 'password';
    input.autocomplete = 'off';
    input.autocapitalize = 'off';
    input.spellcheck = false;
    input.maxLength = maxLength;
    input.required = required;
    label.append(input);
    form.append(label);
    return input;
  };
  const login = field('Recipient’s Wormhole login', 'target-login', 256);
  if (scope) {
    login.value = scope.targetLogin;
    login.readOnly = true;
  }
  const password = field('Your Wormhole password', 'password', 1024);
  const ask = field(
    'Your Account Secret Key, if required (64 hexadecimal characters)',
    'ask',
    64,
    false,
  );
  const issue = document.createElement('button');
  issue.type = 'submit';
  issue.className = 'startup-button';
  issue.textContent = 'Choose offer destination…';
  form.append(issue);
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  const handover = document.createElement('section');
  handover.hidden = true;
  const recipientLabel = document.createElement('h2');
  handover.append(recipientLabel);
  const output = (caption: string) => {
    const label = document.createElement('p');
    label.textContent = caption;
    const code = document.createElement('code');
    code.className = 'vault-recovery-code';
    code.setAttribute('aria-label', caption);
    handover.append(label, code);
    return code;
  };
  const code = output('Reset code');
  const key = output('New Account Secret Key');
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'startup-button startup-button-secondary';
  close.textContent = scope ? 'Back to suspension' : 'Close';
  const queuePanel = document.createElement('section');
  queuePanel.hidden = true;

  let disposed = false;
  let issued = false;
  let pending: Uint8Array[] = [];
  let recipient: Awaited<ReturnType<typeof createVaultDisplayRecipient>> | undefined;
  let remaining: AccountResetTarget[] = [];
  let target: AccountResetTarget | undefined;
  let transfer: AccountResetMark | undefined;

  const queueActions = document.createElement('div');
  queueActions.className = 'shared-reset-actions';
  queueActions.hidden = true;
  const action = (label: string) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = close.className;
    button.textContent = label;
    queueActions.append(button);
    return button;
  };
  const mark = action('Mark handed over and continue');
  const leave = action('Leave pending and continue');
  const skip = action('Skip this account');
  mark.hidden = leave.hidden = skip.hidden = true;
  card.replaceChildren(
    title,
    detail,
    protection,
    queuePanel,
    form,
    status,
    handover,
    queueActions,
    close,
  );

  const queueApi =
    !scope && api.resetTargets && api.markResetHandover && api.leaveResetPending
      ? {
          resetTargets: api.resetTargets,
          markResetHandover: api.markResetHandover,
          leaveResetPending: api.leaveResetPending,
        }
      : undefined;
  const queue =
    queueApi &&
    createAccountResetQueue(queuePanel, status, queueApi, (choices) => {
      remaining = choices;
      void showNext();
    });
  const clear = () => {
    password.value = ask.value = '';
    pending.forEach((factor) => factor.fill(0));
    pending = [];
  };
  const clearHandover = () => {
    handover.hidden = true;
    recipientLabel.textContent = '';
    code.textContent = key.textContent = '';
  };
  const showNext = async () => {
    clear();
    clearHandover();
    issued = false;
    transfer = undefined;
    target = remaining.shift();
    mark.hidden = leave.hidden = true;
    skip.hidden = !target;
    form.hidden = !target;
    queueActions.hidden = !target;
    queuePanel.hidden = Boolean(target);
    issue.disabled = login.disabled = skip.disabled = false;
    if (!target) {
      await queue?.load();
      return;
    }
    login.value = target.loginName;
    login.readOnly = true;
    const replacing = target.status === 'awaiting-handover' || target.status === 'handed-over';
    issue.textContent = replacing
      ? 'Choose replacement offer destination…'
      : 'Choose offer destination…';
    const message = replacing
      ? 'Issuing a replacement retires this account’s current offer.'
      : 'Confirm your factors to issue this account’s reset.';
    status.textContent = `${message} ${remaining.length} remaining after this account.`;
    password.focus();
  };
  const finishHandover = async (record: boolean) => {
    if (!queueApi || !transfer || mark.disabled || leave.disabled || disposed) return;
    mark.disabled = leave.disabled = close.disabled = true;
    try {
      if (record) {
        const reply = parseAccountResetMarkResult(await queueApi.markResetHandover(transfer));
        if (reply?.status !== 'handed-over' && reply?.status !== 'redeemed') {
          if (!disposed)
            status.textContent = 'Could not confirm handover. Try again or leave it pending.';
          return;
        }
      } else if ((await queueApi.leaveResetPending(transfer.offerId)) !== true) {
        throw Error('Could not leave handover pending.');
      }
      if (!disposed) await showNext();
    } catch {
      if (!disposed) status.textContent = 'Could not finish this account’s handover.';
    } finally {
      if (!disposed) mark.disabled = leave.disabled = close.disabled = false;
    }
  };
  mark.onclick = () => void finishHandover(true);
  leave.onclick = () => void finishHandover(false);
  skip.onclick = () => {
    if (!skip.disabled && target) void showNext();
  };
  const events = new AbortController();
  for (const kind of ['copy', 'cut', 'dragstart']) {
    document.addEventListener(
      kind,
      (event) => {
        if (!handover.hidden) event.preventDefault();
      },
      { capture: true, signal: events.signal },
    );
  }
  const dispose = () => {
    disposed = true;
    queue?.dispose();
    remaining = [];
    recipient?.dispose();
    clear();
    clearHandover();
    events.abort();
  };
  window.addEventListener('pagehide', dispose, { once: true, signal: events.signal });
  scope?.signal.addEventListener('abort', dispose, { once: true, signal: events.signal });
  close.onclick = () => {
    clear();
    clearHandover();
    void api.close().catch(() => {
      if (!disposed) status.textContent = 'Could not close account reset.';
    });
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (disposed || issue.disabled || issued) return;
    const targetLogin = scope?.targetLogin ?? target?.loginName ?? login.value.trim();
    const pass = new TextEncoder().encode(password.value);
    const askText = ask.value;
    password.value = ask.value = '';
    if (
      !targetLogin ||
      targetLogin.length > 256 ||
      new TextEncoder().encode(targetLogin).length > 256 ||
      /\p{Cc}/u.test(targetLogin) ||
      pass.length === 0 ||
      pass.length > 1024 ||
      (askText && !/^[0-9a-f]{64}$/i.test(askText))
    ) {
      pass.fill(0);
      status.textContent = 'Check the login, password and Account Secret Key.';
      return;
    }
    const askBytes = askText
      ? Uint8Array.from(askText.match(/../g)!, (part) => parseInt(part, 16))
      : undefined;
    pending = askBytes ? [pass, askBytes] : [pass];
    issue.disabled = close.disabled = login.disabled = skip.disabled = true;
    status.textContent = 'Preparing account reset…';
    try {
      const requestId = crypto.randomUUID();
      recipient = await createVaultDisplayRecipient(
        'wormhole/v1/account-reset-display',
        [workspace, requestId, targetLogin],
        accountResetDisplayEnvelope,
      );
      if (disposed) return;
      const recipientBytes = enrollmentBytes(recipient.publicKey, 32);
      if (!recipientBytes) throw Error('Invalid display recipient.');
      pending.push(recipientBytes);
      let request: Promise<unknown>;
      try {
        request = api.issueReset({
          targetLogin,
          ...(scope
            ? { targetUserId: scope.targetUserId, suspension: scope.suspension }
            : target
              ? { targetUserId: target.userId }
              : {}),
          requestId,
          recipient: recipientBytes,
          password: pass,
          ...(askBytes ? { ask: askBytes } : {}),
        });
      } finally {
        clear();
      }
      const value = await request;
      if (disposed) return;
      if (value === null) {
        status.textContent = 'File selection cancelled.';
        return;
      }
      const result = parseSharedAccountResetIssue(value);
      if (!result) throw Error('Invalid account reset response.');
      if (result.status !== 'issued') {
        status.textContent = failures[result.status];
        return;
      }
      issued = true;
      form.hidden = true;
      const receipt = result.handover;
      if (receipt.workspaceId !== workspace || receipt.requestId !== requestId)
        throw Error('Account reset response did not match.');
      if (target) {
        transfer = { userId: target.userId, offerId: receipt.offerId };
        leave.hidden = false;
        skip.hidden = true;
      }
      const factors = await recipient.open(receipt.bundle);
      try {
        if (factors.length !== 48) throw Error('Invalid handover length.');
        if (disposed) return;
        const hex = (bytes: Uint8Array) =>
          Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
        recipientLabel.textContent = `Deliver to ${targetLogin}`;
        code.textContent = hex(factors.subarray(0, 16));
        key.textContent = hex(factors.subarray(16));
        handover.hidden = false;
        mark.hidden = !transfer;
        status.textContent =
          'Offer issued. Deliver the file, reset code and new Account Secret Key separately. The code and key are displayed once.';
      } finally {
        factors.fill(0);
      }
    } catch {
      if (!disposed)
        status.textContent = issued
          ? 'The offer was issued but the factors could not be displayed. Issue a replacement before handover.'
          : 'Could not confirm the reset. A saved file may require a replacement offer.';
    } finally {
      recipient?.dispose();
      recipient = undefined;
      clear();
      if (!disposed) {
        issue.disabled = login.disabled = issued;
        skip.disabled = issued;
        close.disabled = false;
      }
    }
  };
  if (queue) {
    form.hidden = true;
    queuePanel.hidden = false;
    if (await queue.load()) {
      title.textContent = 'Account reset handover';
      return;
    }
    if (disposed) return;
    queuePanel.hidden = true;
    form.hidden = false;
  }
  (scope ? password : login).focus();
}
