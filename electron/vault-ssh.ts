import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';

// Main-only native relay types. Never export these through preload/renderer IPC.
export type VaultSshRequest = {
  sftpOnly?: true;
  workspaceId: string;
  nodeId: string;
  credentialOverride: string;
  sessionId: string;
  requestId: string;
  epoch: number;
  publicKey: string;
};
export type VaultSshBundle = {
  sftpOnly?: true;
  binding: {
    workspaceId: string;
    nodeId: string;
    sessionId: string;
    requestId: string;
    protocol: 'ssh' | 'sftp';
    host: string;
    port: number;
    epoch: number;
    tunnelConfigId: '';
    useExternalClient: false;
  };
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};

export function canonicalBase64(value: unknown, minimum: number, maximum: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length > 4 * Math.ceil(maximum / 3) ||
    value.length % 4 !== 0
  )
    return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= minimum && bytes.length <= maximum && bytes.toString('base64') === value;
}

export function validVaultSshRequest(q: VaultSshRequest): boolean {
  return (
    (q.sftpOnly === undefined || q.sftpOnly === true) &&
    [q.workspaceId, q.nodeId, q.sessionId, q.requestId].every(vaultID) &&
    (q.credentialOverride === '' || vaultID(q.credentialOverride)) &&
    Number.isSafeInteger(q.epoch) &&
    q.epoch > 0 &&
    canonicalBase64(q.publicKey, 32, 32)
  );
}

export function parseVaultSshBundle(
  value: unknown,
  q: VaultSshRequest,
): VaultSshBundle | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'bundle', ...(q.sftpOnly ? ['sftpOnly'] : [])]) ||
    value.sftpOnly !== q.sftpOnly
  )
    return undefined;
  const b = value.binding,
    s = value.bundle;
  if (
    !vaultRecord(b) ||
    !vaultFields(b, [
      'workspaceId',
      'nodeId',
      'sessionId',
      'requestId',
      'protocol',
      'host',
      'port',
      'epoch',
      'tunnelConfigId',
      'useExternalClient',
    ]) ||
    !vaultRecord(s) ||
    !vaultFields(s, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    !validVaultSshRequest(q) ||
    b.workspaceId !== q.workspaceId ||
    b.nodeId !== q.nodeId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.epoch !== q.epoch ||
    (b.protocol !== 'ssh' && b.protocol !== 'sftp') ||
    b.tunnelConfigId !== '' ||
    b.useExternalClient !== false ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    typeof b.port !== 'number' ||
    !Number.isInteger(b.port) ||
    b.port < 1 ||
    b.port > 65535 ||
    s.formatVersion !== 1 ||
    s.suiteId !== 2 ||
    !canonicalBase64(s.enc, 32, 32) ||
    !canonicalBase64(s.ciphertext, 16, 4 * 1024 * 1024 + 16)
  )
    return undefined;
  return {
    ...(q.sftpOnly ? { sftpOnly: true as const } : {}),
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: b.protocol,
      host: b.host,
      port: b.port,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: { formatVersion: 1, suiteId: 2, enc: s.enc, ciphertext: s.ciphertext },
  };
}
