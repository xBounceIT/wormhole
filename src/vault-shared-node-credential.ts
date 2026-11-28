import type {
  NodeCredentialPort,
  NodeCredentialReply,
  NodeCredentialSelection,
} from '../electron/vault-shared-node-credential.ts';
import { credentialReviewRow } from './vault-shared-slot-default.ts';

export function mountNodeCredential(
  card: HTMLElement,
  change: NodeCredentialPort,
  close: () => void,
) {
  card.classList.add('workspace-admin');
  card.innerHTML = `<header class="workspace-admin-header"><h1>My workspace</h1><span class="workspace-admin-location">Connection credential</span><button class="workspace-admin-close" type="button" aria-label="Close"></button></header>
    <p class="slot-context">Personal selection</p><h2>Credential for this connection</h2>
    <form class="shared-slot-default startup-form"><fieldset>
      <label>Credential source<select name="scope"><option value="personal">My credentials</option><option value="shared">Shared credentials</option><option value="inherit">Use the connection settings</option></select></label>
      <label>Exact credential name<input name="account" maxlength="1024" required autocomplete="off" spellcheck="false"></label>
      <div class="slot-selection"></div>
      <div class="credential-factors" hidden>
        <label>Your Wormhole password<input name="password" type="password" maxlength="1024" autocomplete="off"></label>
        <label>Account Secret Key, if required (64 hexadecimal characters)<input name="ask" type="password" maxlength="64" autocomplete="off" spellcheck="false"></label>
      </div>
      <p role="status"></p><div class="shared-setup-actions"><button type="button" class="startup-button startup-button-secondary">Cancel</button><button type="submit" class="startup-button">Review selection</button></div>
    </fieldset></form>`;
  const form = card.querySelector('form')!,
    fields = card.querySelector('fieldset')!,
    scope = card.querySelector('select')!;
  const account = card.querySelector<HTMLInputElement>('[name="account"]')!,
    password = card.querySelector<HTMLInputElement>('[name="password"]')!,
    ask = card.querySelector<HTMLInputElement>('[name="ask"]')!;
  const auth = card.querySelector<HTMLElement>('.credential-factors')!,
    detail = card.querySelector<HTMLElement>('.slot-selection')!;
  const submit = card.querySelector<HTMLButtonElement>('[type="submit"]')!,
    back = card.querySelector<HTMLButtonElement>('.startup-button-secondary')!;
  const heading = card.querySelector('h2')!,
    status = card.querySelector<HTMLElement>('[role="status"]')!;
  const clear = () => {
    password.value = '';
    ask.value = '';
  };
  let review: Extract<NodeCredentialReply, { status: 'review' }> | undefined;
  const edit = (message: string) => {
    review = undefined;
    clear();
    scope.parentElement!.hidden = false;
    account.disabled = scope.value === 'inherit';
    account.parentElement!.hidden = account.disabled;
    auth.hidden = true;
    password.required = false;
    detail.replaceChildren();
    heading.textContent = 'Credential for this connection';
    submit.textContent = 'Review selection';
    back.textContent = 'Cancel';
    status.textContent = message;
  };
  scope.onchange = () => edit('');
  back.onclick = () => {
    if (review) {
      edit('');
      scope.focus();
    } else close();
  };
  card.querySelector<HTMLButtonElement>('.workspace-admin-close')!.onclick = close;
  window.addEventListener('pagehide', clear, { once: true });
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (fields.disabled || !form.reportValidity()) return;
    const source = scope.value as NodeCredentialSelection['scope'];
    const credentialName = source === 'inherit' ? '' : account.value;
    let pass: Uint8Array | undefined, key: Uint8Array | undefined;
    try {
      if (review?.authenticationRequired) {
        pass = new TextEncoder().encode(password.value);
        if (
          !pass.length ||
          pass.length > 1024 ||
          (ask.value !== '' && !/^[0-9a-f]{64}$/i.test(ask.value))
        ) {
          clear();
          status.textContent = 'Check your password and the Account Secret Key format.';
          password.focus();
          return;
        }
        if (ask.value) key = Uint8Array.from(ask.value.match(/../g)!, (pair) => parseInt(pair, 16));
        clear();
      }
      fields.disabled = true;
      const action = {
        scope: source,
        credentialName,
        ...(review ? { confirmation: review.review } : {}),
      };
      let pending: ReturnType<NodeCredentialPort>;
      try {
        pending = change(
          action,
          pass ? { password: pass, ...(key ? { ask: key } : {}) } : undefined,
        );
      } finally {
        pass?.fill(0);
        key?.fill(0);
      }
      const result = await pending;
      if (!card.isConnected) return;
      if (result.status === 'saved') {
        close();
        return;
      }
      if (result.status === 'review') {
        review = result;
        heading.textContent = result.nodeName;
        scope.parentElement!.hidden = account.parentElement!.hidden = true;
        const explanation = document.createElement('p');
        explanation.textContent =
          source === 'inherit'
            ? 'Your account will use the credential configured for this connection.'
            : 'Only your sessions on this connection will use this credential.';
        detail.replaceChildren(explanation);
        if (result.credentialId)
          detail.append(
            credentialReviewRow({
              credentialId: result.credentialId,
              credentialName,
              protocol: result.protocol,
              provider: result.provider,
            }),
          );
        auth.hidden = !result.authenticationRequired;
        password.required = result.authenticationRequired;
        back.textContent = 'Back';
        submit.textContent = source === 'inherit' ? 'Use connection settings' : 'Set my credential';
        status.textContent = '';
        fields.disabled = false;
        (auth.hidden ? submit : password).focus();
      } else {
        edit(
          {
            busy: 'The workspace is busy. Try again.',
            stale: 'The connection changed. Review the selection again.',
            unsupported: 'Update the workspace schema to set a connection credential.',
            unchanged: 'This is already your selection.',
            unavailable: 'This selection is unavailable. Check the name and your access.',
            'authentication-required': 'Review the selection again to confirm your credentials.',
          }[result.status],
        );
      }
    } catch {
      edit('Could not confirm this selection. Review the credential and try again.');
    } finally {
      fields.disabled = false;
      pass?.fill(0);
      key?.fill(0);
    }
  };
  scope.focus();
}
