import {
  parseVaultSshHostTrust,
  parseVaultSshHostPlan,
  type VaultSshHostPlan,
} from './vault-ssh-host.ts';
import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { parseWorkspaceRdpSettings, type WorkspaceRdpSettings } from './workspace-rdp-contract.ts';

export type VaultQuickTarget = {
  protocol: 'ssh' | 'sftp' | 'rdp' | 'vnc' | 'http' | 'https';
  host: string;
  port: number;
  credentialId: string;
  tunnelId: string;
  sshAutoSudo: boolean;
  httpPath: string;
  ignoreCertificateErrors: boolean;
  rdp: WorkspaceRdpSettings | null;
};
export type VaultQuickTargetRequest = {
  workspaceId: string;
  sessionId: string;
  epoch: number;
  target: VaultQuickTarget;
};
export type VaultQuickTargetRef = {
  workspaceId: string;
  id: string;
  sessionId: string;
  epoch: number;
};
export type VaultQuickTargetLease = {
  readonly reference: Readonly<VaultQuickTargetRef>;
  release(): Promise<void>;
};

const protocols = ['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https'];
function epoch(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}
function quickHost(value: unknown): value is string {
  if (!vaultMetadataText(value, 1024, true)) return false;
  return (
    !/[\p{White_Space}\p{Cc}]/u.test(value) &&
    !['/', '?', '#', '@', String.fromCharCode(92)].some((c) => value.includes(c))
  );
}
function quickWebAddress(value: unknown): value is string {
  if (!vaultMetadataText(value, 4096, true) || /[\p{White_Space}\p{Cc}\\]/u.test(value))
    return false;
  // This field is public metadata. Reject URL userinfo before crossing IPC;
  // Go alone resolves the address and the selected protocol/port.
  return !value
    .replace(/^https?:\/\//i, '')
    .split(/[/?#]/, 1)[0]
    .includes('@');
}
export function parseVaultQuickTarget(value: unknown): VaultQuickTarget | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'protocol',
      'host',
      'port',
      'credentialId',
      'tunnelId',
      'sshAutoSudo',
      'httpPath',
      'ignoreCertificateErrors',
      'rdp',
    ]) ||
    !protocols.includes(value.protocol as string) ||
    typeof value.host !== 'string' ||
    !((value.protocol === 'http' || value.protocol === 'https') && value.httpPath === ''
      ? quickWebAddress(value.host)
      : quickHost(value.host)) ||
    !Number.isInteger(value.port) ||
    (value.port as number) < 0 ||
    (value.port as number) > 65535 ||
    !(value.credentialId === '' || vaultID(value.credentialId)) ||
    !(value.tunnelId === '' || vaultID(value.tunnelId)) ||
    typeof value.sshAutoSudo !== 'boolean' ||
    !vaultMetadataText(value.httpPath, 16384) ||
    typeof value.ignoreCertificateErrors !== 'boolean'
  )
    return undefined;
  const protocol = value.protocol as VaultQuickTarget['protocol'];
  if (
    (protocol !== 'ssh' && protocol !== 'sftp' && value.sshAutoSudo) ||
    (protocol !== 'http' && protocol !== 'https' && value.httpPath !== '') ||
    (protocol !== 'https' && value.ignoreCertificateErrors) ||
    ((protocol === 'http' || protocol === 'https') && value.credentialId !== '') ||
    (protocol !== 'rdp' && value.rdp !== null) ||
    (protocol === 'rdp' && Array.from(value.host).length > 253)
  )
    return undefined;
  let rdp: WorkspaceRdpSettings | null = null;
  if (value.rdp !== null) {
    try {
      rdp = parseWorkspaceRdpSettings(value.rdp);
      if (
        !vaultRecord(value.rdp) ||
        !vaultFields(value.rdp, Object.keys(rdp)) ||
        value.rdp.domain !== '' ||
        (rdp.gatewayCredentialId !== '' && !vaultID(rdp.gatewayCredentialId))
      )
        return undefined;
    } catch {
      return undefined;
    }
  }
  return {
    protocol,
    host: value.host,
    port: value.port as number,
    credentialId: value.credentialId,
    tunnelId: value.tunnelId,
    sshAutoSudo: value.sshAutoSudo,
    httpPath: value.httpPath,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
    rdp,
  };
}
export function parseVaultQuickTargetRequest(value: unknown): VaultQuickTargetRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'sessionId', 'epoch', 'target']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.sessionId) ||
    !epoch(value.epoch)
  )
    return undefined;
  const target = parseVaultQuickTarget(value.target);
  return target
    ? { workspaceId: value.workspaceId, sessionId: value.sessionId, epoch: value.epoch, target }
    : undefined;
}
export function parseVaultQuickTargetRef(
  value: unknown,
  request?: VaultQuickTargetRequest,
): VaultQuickTargetRef | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'id', 'sessionId', 'epoch']) ||
    ![value.workspaceId, value.id, value.sessionId].every(vaultID) ||
    !epoch(value.epoch) ||
    (request &&
      (value.workspaceId !== request.workspaceId ||
        value.sessionId !== request.sessionId ||
        value.epoch !== request.epoch))
  )
    return undefined;
  return {
    workspaceId: value.workspaceId as string,
    id: value.id as string,
    sessionId: value.sessionId as string,
    epoch: value.epoch,
  };
}
export function parseVaultQuickTargetReleased(value: unknown): true | undefined {
  return vaultRecord(value) && vaultFields(value, ['released']) && value.released === true
    ? true
    : undefined;
}
export function vaultQuickTargetPayload(q: VaultQuickTargetRequest) {
  return { sessionId: q.sessionId, epoch: String(q.epoch), target: q.target };
}

export function parseVaultQuickSshHostReceipt(
  value: unknown,
  request: unknown,
): VaultSshHostPlan | undefined {
  const q = parseVaultSshHostTrust(request);
  if (!q || q.credentialOverride !== '') return undefined;
  const { expected, received, ...context } = q;
  const plan = parseVaultSshHostPlan(value, context);
  return plan &&
    plan.fileId === expected.fileId &&
    plan.fingerprint === received &&
    plan.revision !== expected.revision &&
    Object.entries(expected.binding).every(
      ([key, value]) => plan.binding[key as keyof typeof plan.binding] === value,
    )
    ? plan
    : undefined;
}
