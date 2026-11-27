import { randomUUID } from 'node:crypto';
import type { Clipboard, ClipboardItem } from 'electron';
import type { VaultBackendHost, VaultFreshAuthentication } from './vault-host.ts';
import { parseVaultClipboardRequest, type VaultClipboardResult } from './vault-clipboard.ts';
import { createClipboardRecipient, decodeClipboardRelease } from './vault-clipboard-release.ts';

type ClipboardIO = {
  write(value: Uint8Array, marker: string): Promise<void>;
  has(marker: string): Promise<boolean>;
  clear(): void;
};
const rawFormat = (format: string) => `electron application/osclipboard;format="${format}"`;
export function linuxClipboardIO(
  clipboard: Pick<Clipboard, 'write' | 'has' | 'clear'>,
  Item: typeof ClipboardItem,
): ClipboardIO {
  return {
    write(value, marker) {
      const text = new Blob([value as Uint8Array<ArrayBuffer>]);
      // Raw formats avoid Chromium's automatic text mirroring into PRIMARY,
      // which would publish a second copy without the exclusion marker.
      return clipboard.write([
        new Item({
          [rawFormat('text/plain')]: text,
          [rawFormat('text/plain;charset=utf-8')]: text,
          [rawFormat('UTF8_STRING')]: text,
          [rawFormat('x-kde-passwordManagerHint')]: new Blob(['secret']),
          [rawFormat(marker)]: new Blob(['1']),
        }),
      ]);
    },
    has: (marker) => clipboard.has(rawFormat(marker)),
    clear: () => clipboard.clear(),
  };
}

type Ticket = { marker: string; stop?: () => void };
type Options = {
  host: Pick<VaultBackendHost, 'unlockedWorkspaceId' | 'releaseClipboard'>;
  io: ClipboardIO;
  recipient?: typeof createClipboardRecipient;
  now?: () => number;
  timer?: (callback: () => void, milliseconds: number) => () => void;
};
// One main-owned clipboard lifecycle. Retain only a random marker after writing;
// never read back clipboard plaintext to determine whether it is ours.
export class LinuxVaultClipboard {
  private generation = 0;
  private busy = false;
  private queue: Promise<unknown> = Promise.resolve();
  private ticket: Ticket | undefined;
  private recipient: Awaited<ReturnType<typeof createClipboardRecipient>> | undefined;
  private plaintext: Uint8Array | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
  }
  private serialize<T>(action: () => Promise<T>): Promise<T> {
    const pending = this.queue.then(action);
    this.queue = pending.catch(() => undefined);
    return pending;
  }
  private schedule(ticket: Ticket, milliseconds: number): void {
    ticket.stop?.();
    const timer =
      this.options.timer ??
      ((callback, milliseconds) => {
        const handle = setTimeout(callback, milliseconds);
        handle.unref();
        return () => clearTimeout(handle);
      });
    ticket.stop = timer(() => {
      if (this.ticket !== ticket) return;
      void this.serialize(() => this.erase(ticket)).catch(() => {});
    }, milliseconds);
  }
  private async erase(expected?: Ticket): Promise<void> {
    const ticket = this.ticket;
    if (!ticket || (expected && ticket !== expected)) return;
    ticket.stop?.();
    try {
      // Electron offers no compare-and-clear primitive. This avoids clearing an
      // observed replacement, but an external writer can race the final clear.
      if (await this.options.io.has(ticket.marker)) this.options.io.clear();
      this.ticket = undefined;
    } catch {
      this.schedule(ticket, 1000);
      throw Error('Clipboard cleanup could not be confirmed.');
    }
  }
  reset(): Promise<void> {
    this.generation++;
    this.recipient?.dispose();
    this.plaintext?.fill(0);
    return this.serialize(() => this.erase());
  }
  async copy(
    value: unknown,
    confirm?: VaultFreshAuthentication,
    accepted: () => boolean = () => true,
  ): Promise<VaultClipboardResult> {
    const request = parseVaultClipboardRequest(value);
    if (!request || this.busy) throw Error('Invalid clipboard request.');
    const generation = this.generation;
    const current = () =>
      generation === this.generation &&
      accepted() &&
      this.options.host.unlockedWorkspaceId === request.workspaceId;
    if (!current()) throw Error('Vault is locked.');
    this.busy = true;
    let raw: Uint8Array | undefined;
    let recipient: Awaited<ReturnType<typeof createClipboardRecipient>> | undefined;
    try {
      const context = { ...request, requestId: randomUUID() };
      recipient = await (this.options.recipient ?? createClipboardRecipient)(context);
      this.recipient = recipient;
      if (!current()) throw Error('Vault is locked.');
      const result = await this.options.host.releaseClipboard(
        { ...context, publicKey: recipient.publicKey },
        confirm,
        current,
      );
      if (!current()) throw Error('Vault is locked.');
      raw = await recipient.open(result);
      this.plaintext = raw;
      if (!current()) throw Error('Vault is locked.');
      const payload = decodeClipboardRelease(raw);
      const now = this.options.now ?? (() => performance.now());
      const deadline = now() + payload.expiresInSeconds * 1000;
      await this.serialize(async () => {
        if (!current()) throw Error('Vault is locked.');
        await this.erase();
        if (!current()) throw Error('Vault is locked.');
        const ticket = { marker: 'application/x-wormhole-clipboard-' + randomUUID() };
        this.ticket = ticket;
        try {
          await this.options.io.write(payload.value, ticket.marker);
          if (!current() || now() >= deadline) throw Error('Clipboard request expired.');
          this.schedule(ticket, Math.max(1, deadline - now()));
        } catch {
          await this.erase();
          throw Error('Clipboard write could not be confirmed.');
        }
      });
      return { expiresInSeconds: payload.expiresInSeconds };
    } catch {
      throw Error('Secure copy is unavailable.');
    } finally {
      raw?.fill(0);
      recipient?.dispose();
      this.recipient = undefined;
      this.plaintext = undefined;
      this.busy = false;
    }
  }
}
