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
export type CredentialSourceFilter = 'all' | 'Local' | 'Bitwarden';
export type SshAutoSudoMode = 'inherit' | 'on' | 'off';

export function isCredentialProtocol(protocol: string): protocol is CredentialProtocol {
  return protocol === 'ssh' || protocol === 'rdp' || protocol === 'vnc';
}

type CredentialListItem = {
  id: string;
  name: string;
  username: string;
  domain?: string;
  provider: string;
  kind: CredentialKind;
  privateKeyFileName?: string;
};

type CredentialListProjection<T> = {
  credentials: ReadonlyArray<T>;
  emptyState: 'empty' | 'noMatches' | null;
  resetKey: string;
};

function normalizeCredentialSelectionID(value: string): string {
  return value.trim().toLowerCase();
}

function credentialListSearchText(credential: CredentialListItem): string {
  return [
    credential.name,
    credential.username,
    credential.domain,
    credential.provider,
    credential.kind === 'sshKey' ? 'SSH key' : 'Password',
    credential.privateKeyFileName,
  ]
    .filter(Boolean)
    .join('\u0000')
    .toLowerCase();
}

export function filterCredentialsBySource<T extends { provider: string }>(
  credentials: ReadonlyArray<T>,
  source: CredentialSourceFilter,
): ReadonlyArray<T> {
  return source === 'all'
    ? credentials
    : credentials.filter((credential) => credential.provider === source);
}

export function buildCredentialListProjection<T extends CredentialListItem>(
  credentials: ReadonlyArray<T>,
  source: CredentialSourceFilter,
  normalizedSearch: string,
): CredentialListProjection<T> {
  const sourceCredentials = filterCredentialsBySource(credentials, source);
  const visibleCredentials = normalizedSearch
    ? sourceCredentials.filter(
        (credential) => credentialListSearchText(credential).includes(normalizedSearch), // react-doctor-disable-line react-doctor/js-set-map-lookups -- String lookup, not an array scan.
      )
    : sourceCredentials;

  return {
    credentials: visibleCredentials,
    emptyState:
      visibleCredentials.length > 0 ? null : credentials.length === 0 ? 'empty' : 'noMatches',
    resetKey: `${source}\u0000${normalizedSearch}`,
  };
}

export function credentialSelectionAfterSelectAll<T extends { id: string }>(
  visibleCredentials: ReadonlyArray<T>,
  selectedCredentials: ReadonlySet<string>,
): Set<string> {
  const allVisibleSelected =
    visibleCredentials.length > 0 &&
    visibleCredentials.every((credential) => selectedCredentials.has(credential.id));
  return allVisibleSelected
    ? new Set()
    : new Set(visibleCredentials.map((credential) => credential.id));
}

export function buildConnectionCredentialSelectionOptions(
  credentials: SavedCredential[],
  includeInheritance: boolean,
): CredentialSelectionOption[] {
  return [
    ...(includeInheritance ? [{ value: 'inherit', label: 'Inherit from folder' }] : []),
    ...credentials.map((credential) => ({
      value: normalizeCredentialSelectionID(credential.id),
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

export function connectionEditorCredentialSelectionIsValid(
  editorMode: 'saved' | 'quick',
  protocol: string,
  useSavedCredentials: boolean,
  selection: string,
  availableCredentials: ReadonlyArray<{ id: string }>,
): boolean {
  if (editorMode === 'quick') return true;
  if (!isCredentialProtocol(protocol) || !useSavedCredentials) return true;
  if (selection === 'inherit') return true;
  const normalizedSelection = normalizeCredentialSelectionID(selection);
  if (!normalizedSelection || normalizedSelection === 'none') return false;
  return availableCredentials.some(
    (credential) => normalizeCredentialSelectionID(credential.id) === normalizedSelection,
  );
}

export function connectionInlinePasswordAction(
  useSavedCredentials: boolean,
  protocol: string,
  inlinePassword: string,
  hasInlineCredential: boolean | undefined,
  removeInlinePassword: boolean,
): 'preserve' | 'set' | 'clear' {
  const supportsInlineCredentials = protocol === 'ssh' || protocol === 'rdp';
  if (useSavedCredentials || !supportsInlineCredentials) return 'clear';
  if (removeInlinePassword) return 'clear';
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
    selectedCredentialKind === 'password' ||
    selectedCredentialKind === 'sshKey'
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
