type NamedCredential = {
  id: string;
  name: string;
};

type SavedCredential = NamedCredential & {
  provider: string;
};

type CredentialSelectionOption = {
  value: string;
  label: string;
};

export type CredentialKind = 'password' | 'sshKey' | 'unsupported';
export type CredentialProtocol = 'ssh' | 'rdp' | 'vnc';
export type SshAutoSudoMode = 'inherit' | 'on' | 'off';

export function buildConnectionCredentialSelectionOptions(
  credentials: SavedCredential[],
  includeInheritance: boolean,
): CredentialSelectionOption[] {
  return [
    ...(includeInheritance ? [{ value: 'inherit', label: 'Inherit from folder' }] : []),
    ...credentials.map((credential) => ({
      value: credential.id,
      label: `${credential.name} · ${credential.provider}`,
    })),
  ];
}

export function connectionUsesSavedCredentials(
  credentialMode: number | undefined,
  hasInlineCredential: boolean | undefined,
): boolean {
  return credentialMode !== 1 && hasInlineCredential !== true;
}

export function connectionCredentialSelectionAfterSavedToggle(
  useSavedCredentials: boolean,
  editorMode: 'saved' | 'quick',
  currentSelection: string,
): string {
  if (useSavedCredentials && editorMode === 'saved' && currentSelection === 'none') {
    return 'inherit';
  }
  return currentSelection;
}

export function connectionInlinePasswordAction(
  useSavedCredentials: boolean,
  protocol: string,
  inlinePassword: string,
  hasInlineCredential: boolean | undefined,
): 'preserve' | 'set' | 'clear' {
  const supportsInlineCredentials = protocol === 'ssh' || protocol === 'rdp';
  if (useSavedCredentials || !supportsInlineCredentials) return 'clear';
  if (inlinePassword) return 'set';
  return hasInlineCredential ? 'preserve' : 'clear';
}

export function connectionInlinePasswordPlaceholder(
  hasInlineCredential: boolean | undefined,
): string {
  return hasInlineCredential ? 'Leave blank to keep stored password' : '(optional)';
}

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
