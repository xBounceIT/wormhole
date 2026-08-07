export function backupExportPasswordsMatch(password: string, confirmation: string): boolean {
  return password.length === 0 || password.normalize('NFC') === confirmation.normalize('NFC');
}
