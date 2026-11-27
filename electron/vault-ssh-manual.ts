import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  parseVaultSshHostPlan,
  parseVaultSshHostRequest,
  validVaultSshFingerprint,
  vaultSshHostPayload,
  type VaultSshHostPlan,
  type VaultSshHostRequest,
} from './vault-ssh-host.ts';
import { validVaultRouteEndpoint, type VaultRouteBinding } from './vault-route.ts';
import { parseVaultSshBundle, type VaultSshBundle } from './vault-ssh.ts';
import { parseVaultRoutedSshBundle, type VaultRoutedSshBundle } from './vault-ssh-route.ts';

export type VaultSshManualMode = 'account' | 'passphrase';
export type VaultSshManualPlanRequest = VaultSshHostRequest & {
  mode: VaultSshManualMode;
  sftpOnly: boolean;
};
export type VaultSshManualPlan = {
  host: VaultSshHostPlan;
  mode: VaultSshManualMode;
  autoSudo: boolean;
  sftpOnly: boolean;
};
export type VaultSshManualContext = {
  plan: VaultSshManualPlan;
  route: VaultRouteBinding | null;
  endpoint: string;
  publicKey: string;
};
export type VaultSshManualEnvelope = VaultSshBundle['bundle'];
export type VaultSshManualRequest = {
  context: VaultSshManualContext;
  credentialOverride: string;
  manual: VaultSshManualEnvelope;
};
export const maxSshManualCiphertext = 2 * 1024 * 1024 + 40 * 1024 + 256;

export function parseVaultSshManualPlanRequest(
  value: unknown,
): VaultSshManualPlanRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { mode, sftpOnly, ...base } = value;
  const request = parseVaultSshHostRequest(base);
  return request &&
    (mode === 'account' || mode === 'passphrase') &&
    typeof sftpOnly === 'boolean' &&
    !(mode === 'account' && request.credentialOverride !== '')
    ? { ...request, mode, sftpOnly }
    : undefined;
}
export function parseVaultSshManualPlan(
  value: unknown,
  request: unknown,
): VaultSshManualPlan | undefined {
  const q = parseVaultSshManualPlanRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['host', 'mode', 'autoSudo', 'sftpOnly']) ||
    value.mode !== q.mode ||
    value.sftpOnly !== q.sftpOnly ||
    typeof value.autoSudo !== 'boolean'
  )
    return undefined;
  const { mode: _, sftpOnly: _file, ...base } = q;
  const host = parseVaultSshHostPlan(value.host, base);
  return host &&
    validVaultSshFingerprint(host.fingerprint) &&
    !(value.autoSudo && (q.sftpOnly || host.binding.protocol === 'sftp'))
    ? { host, mode: q.mode, autoSudo: value.autoSudo, sftpOnly: q.sftpOnly }
    : undefined;
}
export function parseVaultSshManualContext(value: unknown): VaultSshManualContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['plan', 'route', 'endpoint', 'publicKey']) ||
    !vaultRecord(value.plan) ||
    !vaultRecord(value.plan.host) ||
    !vaultRecord(value.plan.host.binding) ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  const b = value.plan.host.binding;
  const request = parseVaultSshManualPlanRequest({
    workspaceId: b.workspaceId,
    nodeId: b.nodeId,
    sessionId: b.sessionId,
    requestId: b.requestId,
    epoch: b.epoch,
    credentialOverride: '',
    route: value.route,
    mode: value.plan.mode,
    sftpOnly: value.plan.sftpOnly,
  });
  const plan = request && parseVaultSshManualPlan(value.plan, request);
  return plan &&
    request &&
    (request.route ? validVaultRouteEndpoint(value.endpoint) : value.endpoint === '')
    ? {
        plan,
        route: request.route,
        endpoint: value.endpoint as string,
        publicKey: value.publicKey as string,
      }
    : undefined;
}
export function parseVaultSshManualEnvelope(value: unknown): VaultSshManualEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length % 4 !== 0 ||
    value.ciphertext.length > 4 * Math.ceil(maxSshManualCiphertext / 3)
  )
    return undefined;
  const size =
    (value.ciphertext.length / 4) * 3 -
    (value.ciphertext.endsWith('==') ? 2 : value.ciphertext.endsWith('=') ? 1 : 0);
  return size >= 22 && size <= maxSshManualCiphertext && enrollmentBytes(value.ciphertext, size)
    ? { formatVersion: 1, suiteId: 2, enc: value.enc as string, ciphertext: value.ciphertext }
    : undefined;
}
export function parseVaultSshManualRequest(value: unknown): VaultSshManualRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['context', 'credentialOverride', 'manual']) ||
    (value.credentialOverride !== '' && !vaultID(value.credentialOverride))
  )
    return undefined;
  const context = parseVaultSshManualContext(value.context),
    manual = parseVaultSshManualEnvelope(value.manual);
  return context && manual && !(context.plan.mode === 'account' && value.credentialOverride !== '')
    ? { context, manual, credentialOverride: value.credentialOverride as string }
    : undefined;
}
export function sshManualPlanPayload(q: VaultSshManualPlanRequest) {
  return { ...vaultSshHostPayload(q), mode: q.mode, sftpOnly: q.sftpOnly };
}
export function sshManualPayload(q: VaultSshManualRequest) {
  const { context: c } = q,
    b = c.plan.host.binding;
  return {
    ...sshManualPlanPayload({
      workspaceId: b.workspaceId,
      nodeId: b.nodeId,
      sessionId: b.sessionId,
      requestId: b.requestId,
      epoch: b.epoch,
      credentialOverride: q.credentialOverride,
      route: c.route,
      mode: c.plan.mode,
      sftpOnly: c.plan.sftpOnly,
    }),
    publicKey: c.publicKey,
    expected: c.plan,
    manual: q.manual,
    endpoint: c.endpoint,
  };
}
export function parseVaultSshManualBundle(
  value: unknown,
  q: VaultSshManualRequest,
): VaultSshBundle | VaultRoutedSshBundle | undefined {
  const c = q.context,
    b = c.plan.host.binding;
  const base = {
    workspaceId: b.workspaceId,
    nodeId: b.nodeId,
    sessionId: b.sessionId,
    requestId: b.requestId,
    epoch: b.epoch,
    credentialOverride: q.credentialOverride,
    publicKey: c.publicKey,
    ...(c.plan.sftpOnly ? { sftpOnly: true as const } : {}),
  };
  const result = c.route
    ? parseVaultRoutedSshBundle(value, { ...base, route: c.route, endpoint: c.endpoint })
    : parseVaultSshBundle(value, base);
  return result &&
    Object.entries(b).every(([key, item]) => result.binding[key as keyof typeof b] === item)
    ? result
    : undefined;
}

// Shared with Go's SSHManualContext.info; used only by the isolated document.
export function sshManualInfo(value: unknown): Uint8Array {
  const c = parseVaultSshManualContext(value);
  if (!c) throw Error('Invalid SSH credential context.');
  const { plan: p, route: r } = c,
    b = p.host.binding,
    encoder = new TextEncoder();
  const fields = [
    b.workspaceId,
    b.nodeId,
    b.sessionId,
    b.requestId,
    b.protocol,
    b.host,
    String(b.port),
    b.tunnelConfigId,
    String(b.epoch),
    r?.fileId ?? '',
    r ? String(r.kind) : '',
    r?.rowVersion ?? '',
    r?.configurationVersion ?? '',
    c.endpoint,
    p.mode,
    p.host.fileId,
    p.host.revision,
    p.host.fingerprint,
    String(p.autoSudo),
    String(p.sftpOnly),
  ].map((v) => encoder.encode(v));
  const prefix = encoder.encode('wormhole/v1/ssh-manual-credentials');
  const info = new Uint8Array(
    prefix.length + fields.reduce((size, field) => size + 4 + field.length, 0),
  );
  info.set(prefix);
  let offset = prefix.length;
  for (const field of fields) {
    new DataView(info.buffer).setUint32(offset, field.length);
    info.set(field, offset + 4);
    offset += 4 + field.length;
  }
  return info;
}
