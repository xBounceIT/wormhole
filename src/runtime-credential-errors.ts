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

export function requiresRdpCredentialPrompt(message: string): boolean {
  if (message.toLowerCase().includes('rdp gateway credential is unavailable')) return false;
  return isBitwardenCredentialError(message) || /credential|password/i.test(message);
}

export function sshCredentialPromptTarget(
  request: { nodeId?: string; credentialId?: string; manualCredentials?: boolean },
  message: string,
): 'saved' | 'quick' | null {
  if (request.manualCredentials || !requiresSshCredentialPrompt(message)) return null;
  if (request.nodeId) return 'saved';
  return request.credentialId ? 'quick' : null;
}
