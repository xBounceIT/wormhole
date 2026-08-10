export const maxCredentialSecretRunes = 4096;

export function hasValidCredentialSecretLength(value: string): boolean {
  // A Unicode code point occupies at most two UTF-16 code units. The cheap bound avoids
  // allocating an iterator result for an already-invalid IPC payload.
  return (
    value.length <= maxCredentialSecretRunes * 2 &&
    Array.from(value).length <= maxCredentialSecretRunes
  );
}
