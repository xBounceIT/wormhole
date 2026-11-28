import { parseVaultQuickTarget, type VaultQuickTarget } from '../electron/vault-quick-target.ts';
import { parseVaultSshOpen } from '../electron/vault-ssh-open.ts';

export type SshStartRequest = Omit<
  Parameters<NonNullable<Window['wormhole']>['openSshSession']>[0],
  'columns' | 'rows'
> & { frontendSessionId?: string };

export function vaultSshQuickTarget(value: {
  protocol: string;
  host: string;
  port?: number;
  credentialId?: string;
  tunnelId?: string;
  sshAutoSudo?: boolean;
}): VaultQuickTarget {
  const target = parseVaultQuickTarget({
    protocol: value.protocol,
    host: value.host,
    port: value.port ?? 0,
    credentialId: value.credentialId ?? '',
    tunnelId: value.tunnelId ?? '',
    sshAutoSudo: value.sshAutoSudo === true,
    httpPath: '',
    ignoreCertificateErrors: false,
    rdp: null,
  });
  if (!target || (target.protocol !== 'ssh' && target.protocol !== 'sftp'))
    throw Error('The temporary SSH target is invalid.');
  return target;
}

// Rebuild the public intent instead of spreading legacy account/transport fields.
// Quick creation passes its target explicitly because React has not rendered its tab yet.
export function sshConnectRequest(
  request: SshStartRequest,
  source: { protocol: string; quickTarget?: VaultQuickTarget } | undefined,
  vault: boolean,
): Parameters<NonNullable<Window['wormhole']>['openSshSession']>[0] {
  const mode =
    request.mode ??
    (source?.protocol === 'sftp' ? 'sftp' : source?.protocol === 'smb' ? 'smb' : 'terminal');
  if (vault) {
    if ([request.username, request.password, request.keyPassphrase].some((v) => v !== undefined))
      throw Error('Use the protected credential prompt for this vault connection.');
    const quickTarget = request.quickTarget ?? source?.quickTarget;
    if (quickTarget && request.nodeId !== undefined)
      throw Error('The protected SSH target is invalid.');
    const q = parseVaultSshOpen({
      sessionId: request.sessionId,
      columns: 80,
      rows: 24,
      mode,
      ...(quickTarget
        ? {
            quickTarget: {
              ...quickTarget,
              credentialId: request.manualCredentials
                ? ''
                : (request.credentialId ?? quickTarget.credentialId),
            },
          }
        : {
            nodeId: request.nodeId,
            ...(!request.manualCredentials && request.credentialId
              ? { credentialId: request.credentialId }
              : {}),
          }),
      ...(request.manualCredentials ? { manualCredentials: true } : {}),
      ...(request.manualKeyPassphrase ? { manualKeyPassphrase: true } : {}),
    });
    if (!q) throw Error('The protected SSH target is invalid.');
    return q;
  }
  const { frontendSessionId: _, quickTarget: _target, ...legacy } = request;
  return { ...legacy, mode, columns: 80, rows: 24 };
}
