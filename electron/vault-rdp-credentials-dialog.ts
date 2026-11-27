import {
  VaultProtectedEntryDialog,
  type ProtectedEntryOptions,
} from './vault-protected-entry-dialog.ts';
import {
  parseVaultRdpCredentialsContext,
  parseVaultRdpCredentialsEnvelope,
  type VaultRdpCredentialsContext,
  type VaultRdpCredentialsEnvelope,
} from './vault-rdp-credentials.ts';
export class VaultRdpCredentialsDialog extends VaultProtectedEntryDialog<
  VaultRdpCredentialsContext,
  VaultRdpCredentialsEnvelope
> {
  constructor(options: ProtectedEntryOptions) {
    super({
      ...options,
      channel: 'vault-rdp-credentials',
      title: 'RDP credentials',
      height: 600,
      parseContext: parseVaultRdpCredentialsContext,
      parseEnvelope: parseVaultRdpCredentialsEnvelope,
    });
  }
}
