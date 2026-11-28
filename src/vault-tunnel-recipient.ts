import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import {
  parseVaultTunnelEditorContext,
  parseVaultTunnelEditorDisplay,
  tunnelEditorCiphertext,
  type VaultTunnelEditorContext,
} from '../electron/vault-tunnel.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';

// Only the main-owned editor document imports this module. Go never sends stored
// factors to this recipient; the plaintext is its redacted settings projection.
export async function createTunnelEditorRecipient(context: VaultTunnelEditorContext) {
  const expected = parseVaultTunnelEditorContext(context);
  if (!expected) throw Error('Invalid tunnel editor context.');
  return createVaultDisplayRecipient(
    'wormhole/v1/tunnel-editor',
    [expected.workspaceId, expected.tunnelId, expected.requestId, expected.rowVersion],
    (value) => {
      const result = parseVaultTunnelEditorDisplay(value, expected);
      return result
        ? {
            enc: enrollmentBytes(result.bundle.enc, 32)!,
            ciphertext: tunnelEditorCiphertext(result.bundle.ciphertext)!,
          }
        : undefined;
    },
  );
}
