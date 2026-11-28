import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';

export type VaultTunnelSelection = { id: string; rowVersion: string };
export type VaultTunnelInput = {
  metadata: { id: string; name: string; kind: number };
  rowVersion: string;
  forgetHostKey: boolean;
  patch: Uint8Array;
  editorId?: string;
  importId?: string;
};
export type VaultTunnelResult = VaultTunnelSelection & { updated: true };
export type VaultTunnelDeleteResult = VaultTunnelSelection & { deleted: true };
export type VaultTunnelEditorContext = {
  workspaceId: string;
  tunnelId: string;
  requestId: string;
  rowVersion: string;
};
export type VaultTunnelEditorRequest = VaultTunnelEditorContext & { publicKey: string };
export type VaultTunnelEditorDisplay = VaultTunnelEditorContext & {
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};

export function parseVaultTunnelSelection(value: unknown): VaultTunnelSelection | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.rowVersion === '9223372036854775807'
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion };
}

// Consume bytes without decoding the patch: settings and factors belong to Go.
export function consumeVaultTunnelInput(value: unknown): VaultTunnelInput {
  const object = vaultRecord(value) ? value : undefined;
  const patch = object?.patch,
    m = object?.metadata;
  try {
    if (
      !object ||
      !vaultFields(object, [
        'metadata',
        'rowVersion',
        'forgetHostKey',
        'patch',
        ...(object.editorId === undefined ? [] : ['editorId', 'importId']),
      ]) ||
      !(
        (object.editorId === undefined && object.importId === undefined) ||
        (vaultID(object.editorId) && vaultID(object.importId))
      ) ||
      !vaultRecord(m) ||
      !vaultFields(m, ['id', 'name', 'kind']) ||
      !(
        (m.id === '' && object.rowVersion === '0') ||
        parseVaultTunnelSelection({ id: m.id, rowVersion: object.rowVersion })
      ) ||
      !vaultMetadataText(m.name, 512, true) ||
      [...m.name.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '')].length > 128 ||
      !Number.isInteger(m.kind) ||
      (m.kind as number) < 0 ||
      (m.kind as number) > 9 ||
      typeof object.forgetHostKey !== 'boolean' ||
      !(patch instanceof Uint8Array) ||
      !(patch.buffer instanceof ArrayBuffer) ||
      patch.length < 2 ||
      patch.length > 4 * 1024 * 1024
    )
      throw Error('Invalid vault tunnel request.');
    return {
      metadata: { id: m.id as string, name: m.name, kind: m.kind as number },
      rowVersion: object.rowVersion as string,
      forgetHostKey: object.forgetHostKey,
      patch: new Uint8Array(patch),
      ...(object.editorId === undefined
        ? {}
        : { editorId: object.editorId as string, importId: object.importId as string }),
    };
  } finally {
    if (patch instanceof Uint8Array) patch.fill(0);
  }
}

export function parseVaultTunnelResult(value: unknown): VaultTunnelResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion', 'updated']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.updated !== true
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion, updated: true };
}
export function parseVaultTunnelDeleteResult(value: unknown): VaultTunnelDeleteResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion', 'deleted']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.deleted !== true
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion, deleted: true };
}
export function parseVaultTunnelEditorContext(
  value: unknown,
): VaultTunnelEditorContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'tunnelId', 'requestId', 'rowVersion']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.tunnelId) ||
    !vaultID(value.requestId) ||
    !vaultRevision(value.rowVersion)
  )
    return undefined;
  return {
    workspaceId: value.workspaceId,
    tunnelId: value.tunnelId,
    requestId: value.requestId,
    rowVersion: value.rowVersion,
  };
}
export function parseVaultTunnelEditorRequest(
  value: unknown,
): VaultTunnelEditorRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'tunnelId', 'requestId', 'rowVersion', 'publicKey']) ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  const context = parseVaultTunnelEditorContext({
    workspaceId: value.workspaceId,
    tunnelId: value.tunnelId,
    requestId: value.requestId,
    rowVersion: value.rowVersion,
  });
  return context ? { ...context, publicKey: value.publicKey as string } : undefined;
}
export function tunnelEditorCiphertext(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string' || value.length < 24 || value.length > 699072) return undefined;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const size = (value.length / 4) * 3 - padding;
  return size >= 16 && size <= 512 * 1024 + 16 ? enrollmentBytes(value, size) : undefined;
}
export function parseVaultTunnelEditorDisplay(
  value: unknown,
  expected: VaultTunnelEditorContext,
): VaultTunnelEditorDisplay | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'tunnelId', 'requestId', 'rowVersion', 'bundle']) ||
    value.workspaceId !== expected.workspaceId ||
    value.tunnelId !== expected.tunnelId ||
    value.requestId !== expected.requestId ||
    value.rowVersion !== expected.rowVersion
  )
    return undefined;
  const bundle = parseTunnelDisplayBundle(value.bundle);
  if (!bundle) return undefined;
  return {
    workspaceId: expected.workspaceId,
    tunnelId: expected.tunnelId,
    requestId: expected.requestId,
    rowVersion: expected.rowVersion,
    bundle,
  };
}

export function parseTunnelDisplayBundle(
  value: unknown,
): VaultTunnelEditorDisplay['bundle'] | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    !tunnelEditorCiphertext(value.ciphertext)
  )
    return undefined;
  return {
    formatVersion: 1,
    suiteId: 2,
    enc: value.enc as string,
    ciphertext: value.ciphertext as string,
  };
}
