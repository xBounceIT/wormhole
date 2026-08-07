export function isBitwardenUnlockError(message: string | undefined): boolean {
  const value = message?.toLowerCase() ?? '';
  return (
    (value.includes('bitwarden') || value.includes('vault')) &&
    (value.includes('locked') || value.includes('unlock') || value.includes('session'))
  );
}

export function isBitwardenCredentialError(message: string): boolean {
  const value = message.toLowerCase();
  return value.includes('bitwarden') || value.includes('vault');
}

export function requiresSshCredentialPrompt(message: string): boolean {
  const value = message.toLowerCase();
  if (value.includes('bitwarden credential was rejected by the ssh server')) return false;
  return (
    isBitwardenCredentialError(value) ||
    value.includes('ssh credential was not found') ||
    value.includes('wormhole database has no ssh credentials') ||
    value.includes('ssh connection has no username') ||
    value.includes('connection has no usable ssh credential') ||
    value.includes('selected credential is not an ssh credential') ||
    value.includes('stored ssh secret is missing')
  );
}
