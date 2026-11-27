import type { VaultCredentialInput, VaultCredentialRequest } from './vault-credential.js';

type Selection = { id: string; path: string; authorizationEpoch: number };

// Only main's picker registries can turn opaque renderer IDs into native paths.
// Both selections are checked before either is consumed; retries within the
// same fresh-auth dialog retain the captured paths, never a reusable picker ID.
export function prepareVaultCredentialSelections<T>(
  input: VaultCredentialRequest,
  sender: T,
  keys: Pick<Map<T, Selection>, 'get' | 'delete'>,
  certificates: Pick<Map<T, Selection>, 'get' | 'delete'>,
  requireEpoch: (epoch: number) => void,
): VaultCredentialInput {
  const { privateKeySelectionId, certificateSelectionId, ...metadata } = input.metadata;
  const key = privateKeySelectionId ? keys.get(sender) : undefined;
  const certificate = certificateSelectionId ? certificates.get(sender) : undefined;
  if (
    (privateKeySelectionId && key?.id !== privateKeySelectionId) ||
    (certificateSelectionId && certificate?.id !== certificateSelectionId)
  )
    throw Error('Select the SSH files again.');
  if (key) requireEpoch(key.authorizationEpoch);
  if (certificate) requireEpoch(certificate.authorizationEpoch);
  if (key) keys.delete(sender);
  if (certificate) certificates.delete(sender);
  return {
    ...input,
    metadata: {
      ...metadata,
      privateKeyPath: key?.path ?? '',
      certificatePath: certificate?.path ?? '',
    },
  };
}
