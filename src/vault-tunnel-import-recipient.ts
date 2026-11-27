import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import {
  parseTunnelImportContext,
  parseTunnelImportDisplay,
  type VaultTunnelImportContext,
} from '../electron/vault-tunnel-import.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import { tunnelEditorCiphertext } from '../electron/vault-tunnel.ts';

export async function createTunnelImportRecipient(context: VaultTunnelImportContext) {
  const expected = parseTunnelImportContext(context);
  if (!expected) throw Error('Invalid tunnel import context.');
  return createVaultDisplayRecipient(
    'wormhole/v1/tunnel-import',
    [expected.workspaceId, expected.editorId, expected.importId, String(expected.kind)],
    (value) => {
      const result = parseTunnelImportDisplay(value, expected);
      return result
        ? {
            enc: enrollmentBytes(result.bundle.enc, 32)!,
            ciphertext: tunnelEditorCiphertext(result.bundle.ciphertext)!,
          }
        : undefined;
    },
  );
}
