import { createNotesRecipient } from './vault-notes-recipient.ts';
import { parseVaultNotesContext, type VaultNotesContext } from '../electron/vault-notes.ts';

export type VaultNotesApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<VaultNotesContext>;
  read(publicKey: string): Promise<unknown>;
  close(): Promise<void>;
};
export function mountVaultNotesScreen(card: HTMLElement, api: VaultNotesApi) {
  const heading = document.createElement('h1');
  heading.textContent = 'Stored notes';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Opening encrypted notes…';
  const notes = document.createElement('pre');
  notes.className = 'vault-stored-notes';
  notes.hidden = true;
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'startup-button';
  close.textContent = 'Close';
  const notice = document.createElement('p');
  notice.className = 'startup-subtitle';
  notice.textContent = api.contentProtectionAvailable
    ? 'This view closes when Wormhole locks or after five minutes.'
    : 'Screen capture protection is unavailable on Linux. This view closes when Wormhole locks or after five minutes.';
  card.replaceChildren(heading, status, notes, notice, close);
  let disposed = false,
    recipient: Awaited<ReturnType<typeof createNotesRecipient>> | undefined;
  const dispose = () => {
    disposed = true;
    recipient?.dispose();
    recipient = undefined;
    notes.textContent = '';
    notes.hidden = true;
    close.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  close.onclick = () => {
    dispose();
    void api.close().catch(() => undefined);
  };
  // Clipboard writes need their own vault-owned expiry flow; no implicit copy.
  card.addEventListener('copy', (event) => event.preventDefault());
  card.addEventListener('cut', (event) => event.preventDefault());
  window.addEventListener('pagehide', dispose);
  void (async () => {
    let bytes: Uint8Array | undefined;
    try {
      const context = parseVaultNotesContext(await api.context());
      if (disposed) return;
      if (!context) throw Error('Invalid notes context.');
      const generated = await createNotesRecipient(context);
      if (disposed) {
        generated.dispose();
        return;
      }
      recipient = generated;
      const result = await api.read(recipient.publicKey);
      if (disposed) return;
      bytes = await recipient.open(result);
      if (disposed) return;
      notes.textContent = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      notes.hidden = false;
      status.textContent = bytes.length ? '' : 'No stored note text.';
    } catch {
      if (!disposed)
        status.textContent =
          'Stored notes are unavailable. Close this view, refresh the connection and try again.';
    } finally {
      bytes?.fill(0);
      recipient?.dispose();
      recipient = undefined;
    }
  })();
  return dispose;
}
