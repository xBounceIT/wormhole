import {
  confirmedSlotDefault,
  type SlotDefaultPort,
  type SlotDefaultReply,
} from '../electron/vault-shared-slot-default.ts';

export function mountSlotDefault(
  panel: HTMLElement,
  slotId: string,
  slotName: string,
  change: SlotDefaultPort,
  close: (message?: string) => void,
) {
  const title = document.createElement('h2');
  title.textContent = 'Shared default · ' + slotName;
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
  notice.setAttribute('role', 'status');
  const back = document.createElement('button'),
    submit = document.createElement('button');
  back.type = 'button';
  back.textContent = 'Back to slots';
  back.className = 'startup-button startup-button-secondary';
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Review default';
  const nameLabel = label('Exact name of the shared credential', account);
  const removeLabel = label('Remove the shared default', remove);
  removeLabel.className = 'shared-slot-default-remove';
  const actions = document.createElement('div');
  actions.className = 'shared-setup-actions';
  actions.append(back, submit);
  fields.append(nameLabel, removeLabel, detail, auth, actions);
  form.append(fields, notice);
  panel.replaceChildren(title, form);
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
    submit.textContent = 'Review default';
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
      notice.textContent = review ? 'Saving the default…' : 'Checking the credential…';
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
        title.textContent = 'Shared default · ' + choice.slotName;
        const explanation = document.createElement('p');
        if (choice.credentialId) {
          const selected = document.createElement('strong');
          selected.textContent = choice.credentialName;
          const id = document.createElement('code');
          id.textContent = choice.credentialId;
          explanation.textContent = 'Users without a personal assignment will use this credential.';
          detail.replaceChildren(
            selected,
            document.createTextNode(' · ' + choice.protocol.toUpperCase()),
            id,
            explanation,
          );
        } else {
          explanation.textContent =
            'Users without a personal assignment will have no credential for this slot.';
          detail.replaceChildren(explanation);
        }
        submit.textContent = choice.credentialId ? 'Set shared default' : 'Remove shared default';
        auth.hidden = !result.authenticationRequired;
        password.required = !!result.authenticationRequired;
        notice.textContent = '';
        fields.disabled = false;
        (auth.hidden ? submit : password).focus();
      } else if (result.status === 'saved') {
        close('Updated the shared default for “' + slotName + '”.');
      } else if (result.status === 'unchanged') {
        reset('This is already the shared default.');
      } else {
        reset(
          {
            stale: 'The selection changed. Review the current credential again.',
            busy: 'The workspace is busy. Try again.',
            unsupported: 'Update the workspace schema to manage slot defaults.',
            unavailable: 'The slot or matching shared credential is unavailable.',
            'authentication-required':
              'The account now requires fresh authentication. Review the change again.',
          }[result.status],
        );
      }
    } catch {
      if (active) reset('Could not confirm the change. Review the current default again.');
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
