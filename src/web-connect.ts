import { parseVaultQuickTarget, type VaultQuickTarget } from '../electron/vault-quick-target.ts';
import { parseVaultWebRequest } from '../electron/vault-web-open.ts';

export function vaultWebQuickTarget(value: {
  protocol: string;
  host: string;
  port?: number;
  tunnelId?: string;
  ignoreCertificateErrors?: boolean;
}): VaultQuickTarget {
  const target = parseVaultQuickTarget({
    protocol: value.protocol,
    host: value.host,
    port: value.port ?? 0,
    tunnelId: value.tunnelId ?? '',
    credentialId: '',
    sshAutoSudo: false,
    httpPath: '',
    ignoreCertificateErrors: value.ignoreCertificateErrors === true,
    rdp: null,
  });
  if (!target || (target.protocol !== 'http' && target.protocol !== 'https'))
    throw Error('The protected browser target is invalid.');
  return target;
}

export function webConnectRequest(
  session: {
    id: string;
    webTargetNodeId?: string;
    quickTarget?: VaultQuickTarget;
    host: string;
    port?: number;
    protocol: string;
    webIgnoreCertErrors?: boolean;
    tunnelConfigId?: string;
  },
  attempt: number,
  vault: boolean,
): Parameters<NonNullable<Window['wormhole']>['openWebSession']>[0] {
  if (vault) {
    if (session.webTargetNodeId !== undefined && session.quickTarget !== undefined)
      throw Error('The protected browser target is invalid.');
    const request = parseVaultWebRequest({
      sessionId: session.id,
      attempt,
      ...(session.quickTarget
        ? { quickTarget: session.quickTarget }
        : { nodeId: session.webTargetNodeId }),
    });
    if (!request) throw Error('The protected browser target is invalid.');
    return request;
  }
  return session.webTargetNodeId
    ? { sessionId: session.id, attempt, nodeId: session.webTargetNodeId }
    : {
        sessionId: session.id,
        attempt,
        address: session.host,
        port: session.port,
        protocol: session.protocol as 'http' | 'https',
        ignoreCertErrors: session.webIgnoreCertErrors === true,
        tunnelConfigId: session.tunnelConfigId,
      };
}
