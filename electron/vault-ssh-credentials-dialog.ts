import {
  VaultProtectedEntryDialog,
  type ProtectedEntryOptions,
} from './vault-protected-entry-dialog.ts';
import {
  parseVaultSshManualContext,
  parseVaultSshManualEnvelope,
  type VaultSshManualContext,
  type VaultSshManualEnvelope,
} from './vault-ssh-manual.ts';

export class VaultSshCredentialsDialog extends VaultProtectedEntryDialog<
  VaultSshManualContext,
  VaultSshManualEnvelope
> {
  cancelSession(sessionId: string): Promise<void> {
    return this.cancelMatching((context) => context.plan.host.binding.sessionId === sessionId);
  }
  constructor(options: ProtectedEntryOptions) {
    super({
      ...options,
      channel: 'vault-ssh-credentials',
      title: 'SSH credentials',
      height: 720,
      parseContext: parseVaultSshManualContext,
      parseEnvelope: parseVaultSshManualEnvelope,
    });
  }
}
