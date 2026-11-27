import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { parseVaultTunnelSelection, parseTunnelDisplayBundle } from './vault-tunnel.ts';

export type VaultTunnelImportFormat =
  | 'openvpn'
  | 'watchguard'
  | 'azure'
  | 'cisco'
  | 'ipsec-cert'
  | 'ipsec-key'
  | 'ipsec-ca';
export type VaultTunnelImportContext = {
  workspaceId: string;
  editorId: string;
  importId: string;
  kind: number;
};
export type VaultTunnelImportChoice = {
  importId: string;
  kind: number;
  format: VaultTunnelImportFormat;
  publicKey: string;
};
export type VaultTunnelImportRequest = VaultTunnelImportContext &
  VaultTunnelImportChoice & {
    tunnelId: string;
    rowVersion: string;
    path: string;
  };
export type VaultTunnelImportDisplay = VaultTunnelImportContext & {
  bundle: NonNullable<ReturnType<typeof parseTunnelDisplayBundle>>;
};
export type VaultTunnelImportDiscard = { workspaceId: string; editorId: string; importId: string };

export function tunnelImportFormats(kind: number): VaultTunnelImportFormat[] {
  switch (kind) {
    case 1:
    case 4:
      return ['openvpn'];
    case 3:
      return ['openvpn', 'watchguard'];
    case 5:
      return ['azure'];
    case 6:
      return ['cisco'];
    case 9:
      return ['ipsec-cert', 'ipsec-key', 'ipsec-ca'];
    default:
      return [];
  }
}
export function parseTunnelImportChoice(value: unknown): VaultTunnelImportChoice | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['importId', 'kind', 'format', 'publicKey']) ||
    !vaultID(value.importId) ||
    !Number.isInteger(value.kind) ||
    !tunnelImportFormats(value.kind as number).includes(value.format as VaultTunnelImportFormat) ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  return {
    importId: value.importId,
    kind: value.kind as number,
    format: value.format as VaultTunnelImportFormat,
    publicKey: value.publicKey as string,
  };
}
export function parseTunnelImportContext(value: unknown): VaultTunnelImportContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'editorId', 'importId', 'kind']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.editorId) ||
    !vaultID(value.importId) ||
    !Number.isInteger(value.kind) ||
    !tunnelImportFormats(value.kind as number).length
  )
    return undefined;
  return {
    workspaceId: value.workspaceId,
    editorId: value.editorId,
    importId: value.importId,
    kind: value.kind as number,
  };
}
export function parseTunnelImportRequest(value: unknown): VaultTunnelImportRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'workspaceId',
      'editorId',
      'importId',
      'kind',
      'format',
      'publicKey',
      'tunnelId',
      'rowVersion',
      'path',
    ])
  )
    return undefined;
  const context = parseTunnelImportContext({
    workspaceId: value.workspaceId,
    editorId: value.editorId,
    importId: value.importId,
    kind: value.kind,
  });
  const choice = parseTunnelImportChoice({
    importId: value.importId,
    kind: value.kind,
    format: value.format,
    publicKey: value.publicKey,
  });
  if (
    !context ||
    !choice ||
    !(
      (value.tunnelId === '' && value.rowVersion === '0') ||
      parseVaultTunnelSelection({ id: value.tunnelId, rowVersion: value.rowVersion })
    ) ||
    typeof value.path !== 'string' ||
    !value.path.length ||
    new TextEncoder().encode(value.path).length > 8192 ||
    value.path.includes('\0')
  )
    return undefined;
  // Only main obtains paths from the native picker. Go enforces absolute, regular,
  // bounded files on the owning OS; this contract is also browser-importable.
  return {
    ...context,
    ...choice,
    tunnelId: value.tunnelId as string,
    rowVersion: value.rowVersion as string,
    path: value.path,
  };
}
export function parseTunnelImportDisplay(
  value: unknown,
  expected: VaultTunnelImportContext,
): VaultTunnelImportDisplay | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'editorId', 'importId', 'kind', 'bundle']) ||
    value.workspaceId !== expected.workspaceId ||
    value.editorId !== expected.editorId ||
    value.importId !== expected.importId ||
    value.kind !== expected.kind
  )
    return undefined;
  const bundle = parseTunnelDisplayBundle(value.bundle);
  return bundle
    ? {
        workspaceId: expected.workspaceId,
        editorId: expected.editorId,
        importId: expected.importId,
        kind: expected.kind,
        bundle,
      }
    : undefined;
}
export function parseTunnelImportDiscard(value: unknown): VaultTunnelImportDiscard | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'editorId', 'importId']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.editorId) ||
    !(value.importId === '' || vaultID(value.importId))
  )
    return undefined;
  return { workspaceId: value.workspaceId, editorId: value.editorId, importId: value.importId };
}
export function parseTunnelImportDiscarded(value: unknown): { discarded: true } | undefined {
  return vaultRecord(value) && vaultFields(value, ['discarded']) && value.discarded === true
    ? { discarded: true }
    : undefined;
}
