import type { BrowserWindow } from 'electron';
import {
  VaultProtectedEntryDialog,
  type ProtectedEntryOptions,
} from './vault-protected-entry-dialog.ts';
import {
  parseVaultTunnelAuthenticationContext,
  parseVaultTunnelAuthenticationEnvelope,
  type VaultTunnelAuthenticationContext,
  type VaultTunnelAuthenticationEnvelope,
} from './vault-tunnel-authentication.ts';

type Pending = {
  parent: BrowserWindow;
  accepted: () => boolean;
  context: VaultTunnelAuthenticationContext;
  signal: AbortSignal;
  resolve: (value: VaultTunnelAuthenticationEnvelope) => void;
  reject: (e: Error) => void;
  abort: () => void;
};

// Serialize protected prompts without letting a cancelled queued attempt hold
// cleanup behind another window. The base actor retains failed-close quarantine.
export class VaultTunnelAuthenticationDialog extends VaultProtectedEntryDialog<
  VaultTunnelAuthenticationContext,
  VaultTunnelAuthenticationEnvelope
> {
  private readonly pending: Pending[] = [];
  private running?: Pending;
  constructor(options: ProtectedEntryOptions) {
    super({
      ...options,
      channel: 'vault-tunnel-authentication',
      title: 'Fortinet IPsec sign-in',
      height: 500,
      parseContext: parseVaultTunnelAuthenticationContext,
      parseEnvelope: parseVaultTunnelAuthenticationEnvelope,
    });
  }
  override open(
    parent: BrowserWindow,
    accepted: () => boolean,
    value: unknown,
    signal: AbortSignal,
  ): Promise<VaultTunnelAuthenticationEnvelope> {
    const context = parseVaultTunnelAuthenticationContext(value);
    if (!context || signal.aborted || parent.isDestroyed() || this.pending.length >= 128)
      return Promise.reject(Error('VPN authentication unavailable.'));
    return new Promise((resolve, reject) => {
      const entry: Pending = {
        parent,
        accepted,
        context,
        signal,
        resolve,
        reject,
        abort: () => {
          void this.cancelChallenge(context).catch(() => undefined);
        },
      };
      this.pending.push(entry);
      signal.addEventListener('abort', entry.abort, { once: true });
      this.next();
    });
  }
  private next() {
    if (this.running) return;
    const entry = this.pending.shift();
    if (!entry) return;
    this.running = entry;
    let opened: Promise<VaultTunnelAuthenticationEnvelope>;
    try {
      // Install the base actor synchronously so cancellation cannot miss a
      // selected entry between dequeuing it and creating its window.
      opened = super.open(entry.parent, entry.accepted, entry.context, entry.signal);
    } catch {
      opened = Promise.reject(Error('VPN authentication unavailable.'));
    }
    void opened.then(entry.resolve, entry.reject).finally(() => {
      entry.signal.removeEventListener('abort', entry.abort);
      if (this.running === entry) this.running = undefined;
      this.next();
    });
  }
  async cancelChallenge(context: VaultTunnelAuthenticationContext): Promise<void> {
    const expected = parseVaultTunnelAuthenticationContext(context);
    if (!expected) throw Error('VPN authentication context unavailable.');
    const matches = (c: VaultTunnelAuthenticationContext) =>
      c.challengeId === expected.challengeId &&
      JSON.stringify(c.binding) === JSON.stringify(expected.binding);
    for (let i = this.pending.length - 1; i >= 0; i--) {
      const entry = this.pending[i];
      if (matches(entry.context)) {
        this.pending.splice(i, 1);
        entry.signal.removeEventListener('abort', entry.abort);
        entry.reject(Error('VPN authentication cancelled.'));
      }
    }
    await this.cancelMatching(matches);
  }
  override async cancel(): Promise<void> {
    for (const entry of this.pending.splice(0)) {
      entry.signal.removeEventListener('abort', entry.abort);
      entry.reject(Error('VPN authentication cancelled.'));
    }
    await super.cancel();
  }
}
