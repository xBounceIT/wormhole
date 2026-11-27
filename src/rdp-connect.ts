import { parseVaultQuickTarget, type VaultQuickTarget } from '../electron/vault-quick-target.ts';
import type { WorkspaceRdpSettings } from '../electron/workspace-rdp-contract.ts';
import { vaultID } from '../electron/vault-contract.ts';
import { isRdpSurfaceRectWithinNativeBounds } from '../electron/rdp-contract.ts';
import type { VaultRdpOpenRequest } from '../electron/vault-rdp-ipc.ts';
import type { RdpSurfaceRect } from '../electron/rdp-contract.ts';

// The UI supplies saved identity or public quick metadata. Go owns admission and secret use.
export function vaultRdpConnectRequest(
  value: {
    sessionId: string;
    nodeId?: string;
    credentialId?: string;
    quickTarget?: VaultQuickTarget;
    bounds?: RdpSurfaceRect;
  },
  manualCredentials = false,
): VaultRdpOpenRequest {
  if (manualCredentials && value.credentialId !== undefined)
    throw Error('A temporary account cannot select saved credentials.');
  const quickTarget =
    value.quickTarget === undefined ? undefined : parseVaultQuickTarget(value.quickTarget);
  if (
    value.quickTarget !== undefined &&
    (!quickTarget ||
      quickTarget.protocol !== 'rdp' ||
      value.nodeId !== undefined ||
      value.credentialId !== undefined ||
      (manualCredentials && quickTarget.credentialId !== ''))
  )
    throw Error('The temporary RDP target is invalid.');
  if (!vaultID(value.sessionId) || (!quickTarget && !vaultID(value.nodeId)))
    throw Error('Save this RDP connection before connecting from the protected workspace.');
  if (
    !value.bounds ||
    !isRdpSurfaceRectWithinNativeBounds(value.bounds) ||
    (value.credentialId !== undefined && !vaultID(value.credentialId))
  )
    throw Error('The RDP surface or credential selection is unavailable.');
  return {
    sessionId: value.sessionId,
    ...(quickTarget
      ? { quickTarget }
      : {
          nodeId: value.nodeId!,
          ...(value.credentialId !== undefined ? { credentialId: value.credentialId } : {}),
        }),
    bounds: { ...value.bounds },

    ...(manualCredentials ? { manualCredentials: true } : {}),
  };
}

export function vaultRdpQuickTarget(value: {
  host: string;
  port?: number;
  credentialId?: string;
  tunnelId?: string;
  rdp: WorkspaceRdpSettings;
}): VaultQuickTarget {
  const target = parseVaultQuickTarget({
    protocol: 'rdp',
    host: value.host,
    port: value.port ?? 0,
    credentialId: value.credentialId ?? '',
    tunnelId: value.tunnelId ?? '',
    sshAutoSudo: false,
    httpPath: '',
    ignoreCertificateErrors: false,
    rdp: { ...value.rdp, domain: '' },
  });
  if (!target) throw Error('The temporary RDP target is invalid.');
  return target;
}
