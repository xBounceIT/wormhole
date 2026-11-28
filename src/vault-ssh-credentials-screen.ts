import {
  parseVaultSshManualContext,
  type VaultSshManualContext,
  type VaultSshManualEnvelope,
} from '../electron/vault-ssh-manual.ts';
import { sealSshTemporaryCredentials } from './vault-ssh-credentials-sender.ts';

export type VaultSshCredentialsApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  submit(envelope: VaultSshManualEnvelope): Promise<unknown>;
  cancel(): Promise<void>;
};

export function mountVaultSshCredentialsScreen(card: HTMLElement, api: VaultSshCredentialsApi) {
  const heading = document.createElement('h1');
  heading.textContent = 'SSH credentials';
  const target = document.createElement('p');
  target.className = 'startup-subtitle vault-ssh-credentials-target';
  target.textContent = 'Loading…';
  const fingerprint = document.createElement('p');
  fingerprint.className = 'startup-subtitle vault-ssh-credentials-target';
  const explanation = document.createElement('p');
  explanation.textContent = 'These credentials are used once and are not saved.';
  const form = document.createElement('form');
  form.className = 'startup-form vault-ssh-credentials-form';
  const authLabel = document.createElement('label');
  authLabel.textContent = 'Authentication';
  const authentication = document.createElement('select');
  authentication.setAttribute('aria-label', 'Authentication');
  for (const [value, name] of [
    ['password', 'Password'],
    ['key', 'SSH key'],
    ['certificate', 'Certificate'],
  ]) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = name;
    authentication.append(option);
  }
  authLabel.append(authentication);
  const field = (name: string, multiline = false) => {
    const label = document.createElement('label');
    label.textContent = name;
    const input = multiline ? document.createElement('textarea') : document.createElement('input');
    if (input instanceof HTMLInputElement) input.type = name === 'Username' ? 'text' : 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.setAttribute('aria-label', name);
    input.maxLength = multiline ? 1024 * 1024 : name === 'Username' ? 2048 : 16384;
    label.append(input);
    return { label, input };
  };
  const username = field('Username'),
    password = field('Password'),
    key = field('Private key', true),
    passphrase = field('Key passphrase'),
    certificate = field('Certificate', true);
  const all = [username, password, key, passphrase, certificate];
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button';
  submit.textContent = 'Connect';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'startup-button startup-button-secondary';
  cancel.textContent = 'Cancel';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.className = 'startup-status';
  form.append(authLabel, ...all.map((f) => f.label), submit, cancel);
  card.replaceChildren(heading, target, fingerprint, explanation, form, status);
  if (!api.contentProtectionAvailable) {
    const warning = document.createElement('p');
    warning.textContent = 'Screen capture protection is unavailable on this platform.';
    card.append(warning);
  }
  const abort = new AbortController();
  let context: VaultSshManualContext | undefined,
    disposed = false,
    busy = false;
  const clear = () => {
    for (const f of all) f.input.value = '';
  };
  const update = () => {
    const passOnly = context?.plan.mode === 'passphrase',
      useKey = authentication.value !== 'password';
    authLabel.hidden = Boolean(passOnly);
    username.label.hidden = Boolean(passOnly);
    password.label.hidden = Boolean(passOnly || useKey);
    key.label.hidden = Boolean(passOnly || !useKey);
    passphrase.label.hidden = !passOnly && !useKey;
    certificate.label.hidden = Boolean(passOnly || authentication.value !== 'certificate');
    for (const control of [authentication, ...all.map((f) => f.input), submit])
      control.disabled = disposed || busy || !context;
  };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    abort.abort();
    clear();
    update();
    window.removeEventListener('pagehide', dispose);
  };
  authentication.onchange = () => {
    clear();
    update();
  };
  cancel.onclick = () => {
    dispose();
    void api.cancel().catch(() => {});
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || busy || !context) return;
    const onlyPassphrase = context.plan.mode === 'passphrase',
      useKey = authentication.value !== 'password';
    const encoder = new TextEncoder();
    const input = {
      username: encoder.encode(onlyPassphrase ? '' : username.input.value.trim()),
      password: encoder.encode(!onlyPassphrase && !useKey ? password.input.value : ''),
      privateKey: encoder.encode(!onlyPassphrase && useKey ? key.input.value : ''),
      passphrase: encoder.encode(onlyPassphrase || useKey ? passphrase.input.value : ''),
      certificate: encoder.encode(
        !onlyPassphrase && authentication.value === 'certificate' ? certificate.input.value : '',
      ),
    };
    clear();
    if (!onlyPassphrase && authentication.value === 'certificate' && !input.certificate.length) {
      for (const bytes of Object.values(input)) bytes.fill(0);
      status.textContent = 'Enter a certificate and its private key.';
      return;
    }
    busy = true;
    update();
    status.textContent = 'Connecting…';
    void (async () => {
      try {
        const envelope = await sealSshTemporaryCredentials(context, input, abort.signal);
        if (disposed) return;
        if ((await api.submit(envelope)) !== true) throw Error('Credential entry unavailable.');
        dispose();
      } catch {
        if (!disposed)
          status.textContent = 'Credentials could not be submitted. Enter them again or cancel.';
      } finally {
        for (const bytes of Object.values(input)) bytes.fill(0);
        busy = false;
        update();
      }
    })();
  };
  update();
  window.addEventListener('pagehide', dispose);
  void api
    .context()
    .then((value) => {
      if (disposed) return;
      context = parseVaultSshManualContext(value);
      if (!context) throw Error('Invalid context.');
      target.textContent = `${context.plan.host.binding.host}:${context.plan.host.binding.port}`;
      fingerprint.textContent = context.plan.host.fingerprint;
      if (context.plan.mode === 'passphrase') {
        heading.textContent = 'SSH key passphrase';
        explanation.textContent =
          'This passphrase replaces the saved value for this connection only. Leave empty to use an empty passphrase.';
      }
      update();
      (context.plan.mode === 'passphrase' ? passphrase : username).input.focus();
    })
    .catch(() => {
      if (!disposed) status.textContent = 'Credential entry is unavailable. Cancel and try again.';
    });
  return dispose;
}
