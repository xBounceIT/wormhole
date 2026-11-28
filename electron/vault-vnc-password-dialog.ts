import {
  VaultProtectedEntryDialog,
  type ProtectedEntryOptions,
} from './vault-protected-entry-dialog.ts';
import {
  parseVaultVncPasswordContext,
  parseVaultVncPasswordEnvelope,
  type VaultVncPasswordContext,
  type VaultVncPasswordEnvelope,
} from './vault-vnc-password.ts';
export class VaultVncPasswordDialog extends VaultProtectedEntryDialog<
  VaultVncPasswordContext,
  VaultVncPasswordEnvelope
> {
  constructor(options: ProtectedEntryOptions) {
    super({
      ...options,
      channel: 'vault-vnc-password',
      title: 'VNC password',
      height: 410,
      parseContext: parseVaultVncPasswordContext,
      parseEnvelope: parseVaultVncPasswordEnvelope,
    });
  }
}
