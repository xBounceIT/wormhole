import { parseVaultQuickTarget, type VaultQuickTarget } from '../electron/vault-quick-target.ts';
import { parseVaultVncCommand } from '../electron/vault-vnc-controller.ts';
export type VncConnectTarget = {
  id: string;
  nodeId?: string;
  quickTarget?: VaultQuickTarget;
  credentialId?: string;
  tunnelConfigId?: string;
  host: string;
  port?: number;
};
// Vault targets are resolved and authenticated in Go. Ordinary UI state cannot
// override their destination, route or credential bytes.
export function vncConnectRequest(
  session: VncConnectTarget,
  vault: boolean,
  providedPassword?: string,
  manualPassword = false,
): WormholeVncCommand {
  if (vault) {
    if (session.quickTarget && session.nodeId !== undefined)
      throw Error('The protected VNC target is invalid.');
    if (providedPassword !== undefined)
      throw Error('Use the protected password prompt for this vault connection.');
    const manual = manualPassword;
    const q = parseVaultVncCommand({
      action: 'vnc.connect',
      sessionId: session.id,
      ...(session.quickTarget
        ? {
            quickTarget: {
              ...session.quickTarget,
              credentialId: manual ? '' : session.quickTarget.credentialId,
            },
          }
        : {
            nodeId: session.nodeId,
            ...(session.credentialId ? { credentialId: session.credentialId } : {}),
          }),
      ...(manual ? { manualPassword: true } : {}),
    });
    if (!q) throw Error('The protected VNC target is invalid.');
    return q;
  }
  return {
    action: 'vnc.connect',
    sessionId: session.id,
    nodeId: session.nodeId,
    credentialId: session.credentialId,
    tunnelConfigId: session.tunnelConfigId,
    host: session.host,
    port: session.port,
    ...(providedPassword === undefined
      ? {}
      : { password: providedPassword, passwordProvided: true }),
  };
}

export function vaultVncQuickTarget(value: {
  host: string;
  port?: number;
  credentialId?: string;
  tunnelId?: string;
}): VaultQuickTarget {
  const target = parseVaultQuickTarget({
    protocol: 'vnc',
    host: value.host,
    port: value.port ?? 0,
    credentialId: value.credentialId ?? '',
    tunnelId: value.tunnelId ?? '',
    sshAutoSudo: false,
    httpPath: '',
    ignoreCertificateErrors: false,
    rdp: null,
  });
  if (!target) throw Error('The temporary VNC target is invalid.');
  return target;
}
