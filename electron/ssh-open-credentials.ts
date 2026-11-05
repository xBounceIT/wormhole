type SshCredentialRequest = {
  mode?: 'terminal' | 'sftp' | 'smb';
  nodeId?: string;
  credentialId?: string;
  manualCredentials?: boolean;
  username?: string;
  password?: string;
};

type SshVaultCredential = {
  bitwarden: boolean;
  username?: string;
  password?: string;
  domain?: string;
};

// Map the resolved Go credential to the SSH process's direct or saved wire format.
// Secrets are transient process input and must never be logged or persisted here.
export function sshOpenCredentialFields(request: SshCredentialRequest, vault: SshVaultCredential) {
  const username =
    request.mode === 'smb' && vault.domain && !/[\\@]/.test(vault.username ?? '')
      ? `${vault.domain}\\${vault.username ?? ''}`
      : vault.username;
  const saved = request.nodeId !== undefined;
  if (
    vault.bitwarden &&
    !vault.username?.trim() &&
    (!saved || request.credentialId !== undefined)
  ) {
    throw new Error('Bitwarden credential is unavailable: the SSH username is missing.');
  }
  return {
    credential_id: vault.bitwarden ? undefined : request.credentialId,
    username: saved ? undefined : vault.bitwarden ? username : request.username,
    password: saved ? undefined : vault.bitwarden ? vault.password : request.password,
    username_override: saved
      ? request.manualCredentials
        ? request.username?.trim()
        : vault.bitwarden
          ? username
          : undefined
      : undefined,
    username_override_authoritative:
      request.manualCredentials === true || request.credentialId !== undefined,
    password_override: saved
      ? request.manualCredentials
        ? request.password
        : vault.bitwarden
          ? vault.password
          : undefined
      : undefined,
    credential_override: saved && (request.manualCredentials === true || vault.bitwarden),
  };
}
