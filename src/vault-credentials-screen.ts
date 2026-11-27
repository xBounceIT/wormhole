import {
  parseVaultClipboardResult,
  type VaultClipboardField,
} from '../electron/vault-clipboard.ts';
import {
  createCredentialsRecipient,
  decodeCredentialDisplay,
} from './vault-credentials-recipient.ts';
import { parseVaultNotesContext } from '../electron/vault-notes.ts';
import type { VaultNotesApi } from './vault-notes-screen.ts';

export type VaultCredentialsApi = VaultNotesApi & {
  copyAvailable: boolean;
  copy(field: VaultClipboardField): Promise<unknown>;
};
export function mountVaultCredentialsScreen(card: HTMLElement, api: VaultCredentialsApi) {
  const heading = document.createElement('h1');
  heading.textContent = 'Connection credentials';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Opening encrypted credentials…';
  const fields = document.createElement('dl');
  fields.hidden = true;
  const notice = document.createElement('p');
  notice.className = 'startup-subtitle';
  notice.textContent = api.contentProtectionAvailable
    ? 'This view closes when Wormhole locks or after five minutes.'
    : 'Screen capture protection is unavailable on Linux. This view closes when Wormhole locks or after five minutes.';
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'startup-button';
  close.textContent = 'Close';
  card.replaceChildren(heading, status, fields, notice, close);
  const copyButtons: HTMLButtonElement[] = [];
  let copying = false;
  let disposed = false,
    recipient: Awaited<ReturnType<typeof createCredentialsRecipient>> | undefined;
  const preventCopy = (event: Event) => event.preventDefault();
  const dispose = () => {
    disposed = true;
    recipient?.dispose();
    recipient = undefined;
    for (const button of copyButtons) {
      button.disabled = true;
      button.onclick = null;
    }
    copyButtons.length = 0;
    fields.replaceChildren();
    fields.hidden = true;
    close.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  close.onclick = () => {
    dispose();
    void api.close().catch(() => undefined);
  };
  // Clipboard release has its own native history-exclusion and expiry policy.
  card.addEventListener('copy', preventCopy);
  card.addEventListener('cut', preventCopy);
  window.addEventListener('pagehide', dispose);
  void (async () => {
    let bytes: Uint8Array | undefined;
    try {
      const context = parseVaultNotesContext(await api.context());
      if (disposed) return;
      if (!context) throw Error('Invalid context.');
      const generated = await createCredentialsRecipient(context);
      if (disposed) {
        generated.dispose();
        return;
      }
      recipient = generated;
      const result = await api.read(recipient.publicKey);
      if (disposed) return;
      bytes = await recipient.open(result);
      if (disposed) return;
      const value = decodeCredentialDisplay(bytes);
      for (const [label, text, field] of [
        ['Username', value.username, 'username'],
        ['Domain', value.domain, 'domain'],
        [value.label, value.secret, 'secret'],
      ] as const) {
        const term = document.createElement('dt'),
          detail = document.createElement('dd');
        term.textContent = label;
        detail.textContent = text || (label === value.label ? 'No stored secret.' : '—');
        detail.className = 'vault-stored-notes';
        fields.append(term, detail);
        if (api.copyAvailable && text) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'startup-button';
          button.textContent = `Copy ${label.toLowerCase()}`;
          button.onclick = async () => {
            if (disposed || copying) return;
            copying = true;
            for (const other of copyButtons) other.disabled = true;
            status.textContent = 'Copying…';
            try {
              const result = parseVaultClipboardResult(await api.copy(field));
              if (!result) throw Error('Invalid clipboard response.');
              if (!disposed)
                status.textContent = `Copied. Clipboard expires after ${result.expiresInSeconds} seconds.`;
            } catch {
              if (!disposed) status.textContent = 'Secure copy is unavailable. Try again.';
            } finally {
              copying = false;
              if (!disposed) for (const other of copyButtons) other.disabled = false;
            }
          };
          copyButtons.push(button);
          detail.append(button);
        }
      }
      fields.hidden = false;
      status.textContent = '';
    } catch {
      if (!disposed)
        status.textContent =
          'Credentials are unavailable. Close this view, refresh the connection and try again.';
    } finally {
      bytes?.fill(0);
      recipient?.dispose();
      recipient = undefined;
    }
  })();
  return dispose;
}
