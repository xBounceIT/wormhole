import type {
  SharedRecoveryBackupInput,
  SharedRecoveryBackupResult,
} from '../electron/vault-shared-recovery-backup.ts';
import { createRecoveryRecipient, type RecoveryRecipient } from './vault-recovery-recipient.ts';

export type SharedBackupApi = {
  contentProtectionAvailable?: boolean;
  backupContext(): Promise<boolean>;
  exportBackup(input: SharedRecoveryBackupInput): Promise<SharedRecoveryBackupResult | null>;
  close(): Promise<true>;
};

const failureMessages = {
  unavailable: 'Backup export is unavailable for this workspace or account.',
  'authentication-required':
    'The workspace now requires fresh authentication. Close and reopen export.',
  'invalid-authentication': 'Check your Wormhole password and Account Secret Key, then retry.',
  'too-large': 'This workspace exceeds the maximum backup size.',
  'save-failed': 'Could not save the backup. Choose a new file in a writable folder.',
};

export async function mountSharedBackup(card: HTMLElement, api: SharedBackupApi): Promise<void> {
  const authentication = await api.backupContext();
  if (typeof authentication !== 'boolean') throw Error('Invalid workspace backup context.');
  const title = document.createElement('h1');
  title.textContent = 'Export workspace recovery backup';
  const instructions = document.createElement('p');
  instructions.textContent =
    'Save the encrypted backup somewhere offline. Store its recovery password separately.';
  const protection = document.createElement('p');
  protection.textContent = 'Screen capture protection is unavailable on this computer.';
  protection.hidden = api.contentProtectionAvailable === true;
  const form = document.createElement('form');
  form.className = 'startup-form';
  const factor = (text: string, name: string, maxLength: number, required: boolean) => {
    const label = document.createElement('label');
    label.textContent = text;
    const input = document.createElement('input');
    input.name = name;
    input.type = 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.maxLength = maxLength;
    input.required = required;
    label.append(input);
    form.append(label);
    return input;
  };
  const password = authentication ? factor('Wormhole password', 'password', 1024, true) : undefined;
  const ask = authentication
    ? factor('Account Secret Key (64 hexadecimal characters, when required)', 'ask', 64, false)
    : undefined;
  const save = document.createElement('button');
  save.type = 'submit';
  save.className = 'startup-button';
  save.textContent = 'Choose backup destination…';
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'startup-button startup-button-secondary';
  close.textContent = 'Close';
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  const code = document.createElement('code');
  code.className = 'vault-recovery-code';
  code.dataset.recovery = '';
  code.setAttribute('aria-label', 'Backup recovery password');
  code.hidden = true;
  form.append(save);
  card.replaceChildren(title, instructions, protection, form, status, code, close);

  let recipient: RecoveryRecipient | undefined;
  let factors: Pick<SharedRecoveryBackupInput, 'password' | 'ask'> | undefined;
  let disposed = false;
  let exported = false;
  const clearFactors = () => {
    if (password) password.value = '';
    if (ask) ask.value = '';
  };
  const clearDisplay = () => {
    code.textContent = '';
    code.hidden = true;
  };
  const releaseFactors = () => {
    factors?.password?.fill(0);
    factors?.ask?.fill(0);
    factors = undefined;
  };
  const events = new AbortController();
  for (const kind of ['copy', 'cut', 'dragstart']) {
    document.addEventListener(
      kind,
      (event) => {
        if (!code.hidden) event.preventDefault();
      },
      {
        capture: true,
        signal: events.signal,
      },
    );
  }
  window.addEventListener(
    'pagehide',
    () => {
      disposed = true;
      events.abort();
      recipient?.dispose();
      releaseFactors();
      clearDisplay();
      clearFactors();
    },
    { once: true },
  );
  close.onclick = () => {
    clearDisplay();
    clearFactors();
    void api.close().catch(() => {
      if (!disposed) status.textContent = 'Could not close workspace backup.';
    });
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (disposed || save.disabled || exported) return;
    const askValue = ask?.value ?? '';
    if ((password && !password.value) || (askValue && !/^[0-9a-f]{64}$/i.test(askValue))) {
      clearFactors();
      status.textContent = 'Enter your password and check the Account Secret Key format.';
      return;
    }
    factors = {
      ...(password ? { password: new TextEncoder().encode(password.value) } : {}),
      ...(askValue
        ? { ask: Uint8Array.from(askValue.match(/../g)!, (pair) => parseInt(pair, 16)) }
        : {}),
    };
    clearFactors();
    save.disabled = close.disabled = true;
    status.textContent = 'Preparing workspace backup…';
    try {
      recipient = await createRecoveryRecipient();
      if (disposed) return;
      let pending: ReturnType<SharedBackupApi['exportBackup']>;
      try {
        pending = api.exportBackup({
          recipient: recipient.publicKey,
          ...factors,
        });
      } finally {
        releaseFactors();
      }
      const result = await pending;
      if (disposed) return;
      if (result === null) {
        status.textContent = 'File selection cancelled.';
      } else if (result.status !== 'exported') {
        status.textContent = failureMessages[result.status];
      } else {
        exported = true;
        form.hidden = true;
        const secret = await recipient.open(result.receipt);
        try {
          if (disposed) return;
          status.textContent =
            'Backup saved. Record this recovery password now. It is displayed once.';
          code.textContent = new TextDecoder().decode(secret);
          code.hidden = false;
        } finally {
          secret.fill(0);
        }
      }
    } catch {
      if (!disposed)
        status.textContent = exported
          ? 'Backup saved, but the recovery password could not be displayed.'
          : 'Could not export the workspace backup.';
    } finally {
      recipient?.dispose();
      recipient = undefined;
      releaseFactors();
      if (!disposed) {
        save.disabled = exported;
        close.disabled = false;
      }
    }
  };
}
