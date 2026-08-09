type NamedCredential = {
  id: string;
  name: string;
};

export type CredentialKind = 'password' | 'sshKey' | 'unsupported';
export type CredentialProtocol = 'ssh' | 'rdp' | 'vnc';
export type SshAutoSudoMode = 'inherit' | 'on' | 'off';

export function credentialCanUseProtocol(
  kind: CredentialKind,
  protocol: CredentialProtocol,
): boolean {
  return kind === 'password' || (protocol === 'ssh' && kind === 'sshKey');
}

export function sshAutoSudoAvailable(
  useSavedCredentials: boolean,
  selectedCredentialKind?: CredentialKind,
): boolean {
  return (
    !useSavedCredentials ||
    selectedCredentialKind === undefined ||
    selectedCredentialKind === 'password'
  );
}

export function effectiveSshAutoSudoMode(
  protocol: string,
  available: boolean,
  requested: SshAutoSudoMode,
  hiddenFallback: SshAutoSudoMode,
): SshAutoSudoMode {
  if (protocol !== 'ssh') return 'inherit';
  return available ? requested : hiddenFallback;
}

const textEncoder = new TextEncoder();

function compareBytes(leftBytes: Uint8Array, rightBytes: Uint8Array): number {
  const sharedLength = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < sharedLength; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
  }
  return leftBytes.length - rightBytes.length;
}

export function mergeCredential<T extends NamedCredential>(current: T[], saved: T): T[] {
  // Workspace credentials arrive in SQLite BINARY order; every merge preserves that invariant.
  const next = current.filter((credential) => credential.id !== saved.id);
  const savedName = textEncoder.encode(saved.name);
  const savedID = textEncoder.encode(saved.id);
  const insertionIndex = next.findIndex((credential) => {
    const nameOrder = compareBytes(savedName, textEncoder.encode(credential.name));
    return (
      nameOrder < 0 ||
      (nameOrder === 0 && compareBytes(savedID, textEncoder.encode(credential.id)) < 0)
    );
  });
  if (insertionIndex < 0) next.push(saved);
  else next.splice(insertionIndex, 0, saved);
  return next;
}
