import {
  confirmedSlotDefault,
  type SlotDefaultPort,
  type SlotDefaultReply,
} from '../electron/vault-shared-slot-default.ts';

export function credentialReviewRow(choice: {
  credentialName: string;
  credentialId: string;
  protocol: string;
  provider?: string;
}) {
  const row = document.createElement('div');
  row.className = 'slot-credential';
  const icon = document.createElement('span');
  icon.className = 'slot-credential-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.innerHTML =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v4h4v-3h3v-3h2l2.1-2.1a6.5 6.5 0 1 0-3-3Z"/><circle cx="16.5" cy="7.5" r="1"/></svg>';
  const selected = document.createElement('strong');
  selected.textContent = choice.credentialName;
  const protocol = document.createElement('span');
  protocol.className = 'slot-protocol';
  protocol.textContent =
    choice.protocol.toUpperCase() + (choice.provider === 'bitwarden' ? ' · Bitwarden' : '');
  const identifier = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Credential ID';
  const id = document.createElement('code');
  id.textContent = choice.credentialId;
  identifier.append(summary, id);
  const accountDetails = document.createElement('div');
  accountDetails.append(selected, identifier);
  row.append(icon, accountDetails, protocol);
  return row;
}

export function mountSlotDefault(
  panel: HTMLElement,
  slotId: string,
  slotName: string,
  change: SlotDefaultPort,
  close: (message?: string) => void,
  personal = false,
) {
  const title = document.createElement('h2');
  title.textContent = slotName;
  const context = document.createElement('p');
  context.className = 'slot-context';
  context.textContent = personal ? 'My credential' : 'Shared default';
  const form = document.createElement('form'),
    fields = document.createElement('fieldset');
  form.className = 'startup-form shared-slot-default';
  const label = (caption: string, input: HTMLInputElement) => {
    const parent = document.createElement('label');
    parent.textContent = caption;
    parent.append(input);
    return parent;
  };
  const account = document.createElement('input'),
    remove = document.createElement('input');
  account.required = true;
  account.maxLength = 1024;
  remove.type = 'checkbox';
  remove.onchange = () => {
    account.disabled = remove.checked;
  };
  const password = document.createElement('input'),
    ask = document.createElement('input');
  for (const input of [password, ask]) {
    input.type = 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
  }
  password.maxLength = 1024;
  ask.maxLength = 64;
  const auth = document.createElement('div');
  auth.append(
    label('Your Wormhole password', password),
    label('Account Secret Key, if required (64 hexadecimal characters)', ask),
  );
  auth.hidden = true;
  const detail = document.createElement('div'),
    notice = document.createElement('p');
  detail.className = 'slot-selection';
  notice.setAttribute('role', 'status');
  const back = document.createElement('button'),
    submit = document.createElement('button');
  back.type = 'button';
  back.textContent = 'Back to slots';
  back.className = 'startup-button startup-button-secondary';
  submit.type = 'submit';
  submit.className = 'startup-button';
  const reviewLabel = personal ? 'Review assignment' : 'Review default';
  submit.textContent = reviewLabel;
  const nameLabel = label(
    personal ? 'Exact name of your credential' : 'Exact name of the shared credential',
    account,
  );
  const removeLabel = label(
    personal ? 'Use the shared default' : 'Remove the shared default',
    remove,
  );
  removeLabel.className = 'shared-slot-default-remove';
  const actions = document.createElement('div');
  actions.className = 'shared-setup-actions';
  actions.append(back, submit);
  fields.append(nameLabel, removeLabel, detail, auth, notice, actions);
  form.append(fields);
  panel.replaceChildren(context, title, form);
  account.focus();
  let active = true,
    review: Extract<SlotDefaultReply, { status: 'review' }> | undefined;
  const clear = () => {
    password.value = '';
    ask.value = '';
  };
  const reset = (message: string) => {
    clear();
    review = undefined;
    account.disabled = remove.checked;
    remove.disabled = false;
    nameLabel.hidden = removeLabel.hidden = false;
    auth.hidden = true;
    password.required = false;
    detail.textContent = '';
    submit.textContent = reviewLabel;
    notice.textContent = message;
  };
  back.onclick = () => {
    if (active && !fields.disabled) {
      clear();
      close();
    }
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!active || fields.disabled || !form.reportValidity()) return;
    let pass: Uint8Array | undefined, key: Uint8Array | undefined;
    try {
      if (review?.authenticationRequired) {
        pass = new TextEncoder().encode(password.value);
        if (
          pass.length === 0 ||
          pass.length > 1024 ||
          (ask.value !== '' && !/^[0-9a-f]{64}$/i.test(ask.value))
        ) {
          clear();
          notice.textContent = 'Check your password and the Account Secret Key format.';
          password.focus();
          return;
        }
        if (ask.value) key = Uint8Array.from(ask.value.match(/../g)!, (pair) => parseInt(pair, 16));
        clear();
      }
      fields.disabled = true;
      notice.textContent = review ? 'Saving the change…' : 'Checking the credential…';
      const request = review
        ? confirmedSlotDefault(review)
        : { slotId, credentialName: remove.checked ? '' : account.value };
      let pending: ReturnType<SlotDefaultPort>;
      try {
        pending = pass
          ? change(request, { password: pass, ...(key ? { ask: key } : {}) })
          : change(request);
      } finally {
        pass?.fill(0);
        key?.fill(0);
      }
      const result = await pending;
      if (!active) return;
      if (result.status === 'review') {
        review = result;
        account.disabled = remove.disabled = true;
        nameLabel.hidden = removeLabel.hidden = true;
        const choice = result.choice;
        title.textContent = choice.slotName;
        const explanation = document.createElement('p');
        if (choice.credentialId) {
          const row = credentialReviewRow(choice);
          explanation.textContent = personal
            ? 'Your connections using this slot will use this credential.'
            : 'Users without a personal assignment will use this credential.';
          detail.replaceChildren(explanation, row);
        } else {
          explanation.textContent = personal
            ? choice.hasDefault
              ? 'Your connections will use the shared default.'
              : 'This slot has no shared default. Your connections will have no credential for it.'
            : 'Users without a personal assignment will have no credential for this slot.';
          detail.replaceChildren(explanation);
        }
        submit.textContent = personal
          ? choice.credentialId
            ? 'Set my credential'
            : 'Clear my assignment'
          : choice.credentialId
            ? 'Set shared default'
            : 'Remove shared default';
        auth.hidden = !result.authenticationRequired;
        password.required = !!result.authenticationRequired;
        notice.textContent = '';
        fields.disabled = false;
        (auth.hidden ? submit : password).focus();
      } else if (result.status === 'saved') {
        close(
          (personal ? 'Updated your credential for “' : 'Updated the shared default for “') +
            slotName +
            '”.',
        );
      } else if (result.status === 'unchanged') {
        reset(
          personal
            ? 'Your assignment already matches this selection.'
            : 'This is already the shared default.',
        );
      } else {
        reset(
          {
            stale: 'The selection changed. Review the current credential again.',
            busy: 'The workspace is busy. Try again.',
            unsupported: personal
              ? 'Update the workspace schema to manage personal assignments.'
              : 'Update the workspace schema to manage slot defaults.',
            unavailable: personal
              ? 'The slot or matching personal credential is unavailable.'
              : 'The slot or matching shared credential is unavailable.',
            'authentication-required':
              'The account now requires fresh authentication. Review the change again.',
          }[result.status],
        );
      }
    } catch {
      if (active) reset('Could not confirm the change. Review your selection again.');
    } finally {
      pass?.fill(0);
      key?.fill(0);
      if (active) fields.disabled = false;
    }
  };
  return () => {
    active = false;
    clear();
    panel.replaceChildren();
  };
}
