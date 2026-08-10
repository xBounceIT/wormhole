export function backupExportPasswordsMatch(password: string, confirmation: string): boolean {
  return password.length === 0 || password.normalize('NFC') === confirmation.normalize('NFC');
}

export function backupExportRequiresEncryption(
  credentials: ReadonlyArray<{ kind: string; provider: string }>,
): boolean {
  return credentials.some(
    (credential) => credential.kind === 'sshKey' && credential.provider === 'Local',
  );
}

export function backupExportPasswordIsValid(
  password: string,
  confirmation: string,
  encryptionRequired: boolean,
): boolean {
  return (
    (!encryptionRequired || password.length > 0) &&
    backupExportPasswordsMatch(password, confirmation)
  );
}
