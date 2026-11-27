import { isAbsolute } from 'node:path';
import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { browserTransferDecimal } from './vault-bitwarden-transfer.ts';

export type BitwardenInstallationRequest = { workspaceId: string; minimumRevision: string };
export type BitwardenInstallationPlan = {
  workspaceId: string;
  revision: string;
  installation: null | {
    id: string;
    extensionId: string;
    version: string;
    popup: string;
    background: string;
  };
};

export function parseBitwardenInstallationRequest(
  value: unknown,
): BitwardenInstallationRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'minimumRevision']) ||
    !vaultID(value.workspaceId) ||
    !browserTransferDecimal(value.minimumRevision)
  )
    return undefined;
  return { workspaceId: value.workspaceId as string, minimumRevision: value.minimumRevision };
}
function packagePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > 1024 ||
    /[\\:%?#]/.test(value) ||
    value.split('/').some((p) => !p || p === '.' || p === '..')
  )
    return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 32 || code === 127) return false;
  }
  const bytes = new TextEncoder().encode(value);
  return bytes.length <= 1024 && new TextDecoder().decode(bytes) === value;
}
function packageVersion(value: unknown): value is string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$/.test(value))
    return false;
  const parts = value.split('.').map(Number);
  return parts.every((p) => p <= 65535) && parts.some((p) => p > 0);
}

// Main-only plan contract. This validates metadata, never reads extension storage
// or constructs an installation path from renderer input.
export function parseBitwardenInstallationPlan(
  value: unknown,
  request: BitwardenInstallationRequest,
): BitwardenInstallationPlan | undefined {
  const q = parseBitwardenInstallationRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'revision', 'installation']) ||
    value.workspaceId !== q.workspaceId ||
    !browserTransferDecimal(value.revision) ||
    BigInt(value.revision) < BigInt(q.minimumRevision)
  )
    return undefined;
  if (value.installation === null)
    return { workspaceId: q.workspaceId, revision: value.revision, installation: null };
  const p = value.installation;
  if (
    value.revision === '0' ||
    !vaultRecord(p) ||
    !vaultFields(p, ['id', 'extensionId', 'version', 'popup', 'background']) ||
    !vaultID(p.id) ||
    typeof p.extensionId !== 'string' ||
    !/^[a-p]{32}$/.test(p.extensionId) ||
    !packageVersion(p.version) ||
    !packagePath(p.popup) ||
    !packagePath(p.background)
  )
    return undefined;
  return {
    workspaceId: q.workspaceId,
    revision: value.revision,
    installation: {
      id: p.id as string,
      extensionId: p.extensionId,
      version: p.version,
      popup: p.popup,
      background: p.background,
    },
  };
}

export type BitwardenFolderInstallRequest = {
  workspaceId: string;
  sourceDirectory: string;
  expectedRevision: string;
};
export type BitwardenFolderInstallResult = { workspaceId: string; revision: string };

// Only a trusted main-process picker may supply this path. Never expose this
// operation through generic renderer IPC.
export function parseBitwardenFolderInstallRequest(
  value: unknown,
): BitwardenFolderInstallRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'sourceDirectory', 'expectedRevision']) ||
    !vaultID(value.workspaceId) ||
    !browserTransferDecimal(value.expectedRevision) ||
    value.expectedRevision === '9223372036854775807' ||
    typeof value.sourceDirectory !== 'string' ||
    value.sourceDirectory.length > 4096 ||
    value.sourceDirectory.includes('\0') ||
    !isAbsolute(value.sourceDirectory)
  )
    return undefined;
  const bytes = new TextEncoder().encode(value.sourceDirectory);
  if (bytes.length > 4096 || new TextDecoder().decode(bytes) !== value.sourceDirectory)
    return undefined;
  return {
    workspaceId: value.workspaceId as string,
    sourceDirectory: value.sourceDirectory,
    expectedRevision: value.expectedRevision,
  };
}
export function parseBitwardenFolderInstallResult(
  value: unknown,
  request: BitwardenFolderInstallRequest,
): BitwardenFolderInstallResult | undefined {
  const q = parseBitwardenFolderInstallRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'revision']) ||
    value.workspaceId !== q.workspaceId ||
    !browserTransferDecimal(value.revision) ||
    BigInt(value.revision) !== BigInt(q.expectedRevision) + 1n
  )
    return undefined;
  return { workspaceId: q.workspaceId, revision: value.revision };
}

export type BitwardenZipInstallRequest = {
  workspaceId: string;
  sourceFile: string;
  expectedRevision: string;
};
export function parseBitwardenZipInstallRequest(
  value: unknown,
): BitwardenZipInstallRequest | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['workspaceId', 'sourceFile', 'expectedRevision']))
    return undefined;
  const q = parseBitwardenFolderInstallRequest({
    workspaceId: value.workspaceId,
    sourceDirectory: value.sourceFile,
    expectedRevision: value.expectedRevision,
  });
  return q
    ? {
        workspaceId: q.workspaceId,
        sourceFile: q.sourceDirectory,
        expectedRevision: q.expectedRevision,
      }
    : undefined;
}
export function parseBitwardenZipInstallResult(
  value: unknown,
  request: BitwardenZipInstallRequest,
): BitwardenFolderInstallResult | undefined {
  const q = parseBitwardenZipInstallRequest(request);
  return q
    ? parseBitwardenFolderInstallResult(value, {
        workspaceId: q.workspaceId,
        sourceDirectory: q.sourceFile,
        expectedRevision: q.expectedRevision,
      })
    : undefined;
}

export type BitwardenInstallationRevision = { workspaceId: string; revision: string };
export function parseBitwardenInstallationRevision(
  value: unknown,
  request: BitwardenInstallationRequest,
): BitwardenInstallationRevision | undefined {
  const q = parseBitwardenInstallationRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'revision']) ||
    value.workspaceId !== q.workspaceId ||
    !browserTransferDecimal(value.revision) ||
    BigInt(value.revision) < BigInt(q.minimumRevision)
  )
    return undefined;
  return { workspaceId: q.workspaceId, revision: value.revision };
}

export type BitwardenCleanupRequest = { workspaceId: string; expectedRevision: string };
export function parseBitwardenCleanupRequest(value: unknown): BitwardenCleanupRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'expectedRevision']) ||
    !vaultID(value.workspaceId) ||
    !browserTransferDecimal(value.expectedRevision) ||
    value.expectedRevision === '9223372036854775807'
  )
    return undefined;
  return { workspaceId: value.workspaceId as string, expectedRevision: value.expectedRevision };
}
export function parseBitwardenCleanupResult(
  value: unknown,
  request: BitwardenCleanupRequest,
): BitwardenInstallationRevision | undefined {
  const q = parseBitwardenCleanupRequest(request);
  if (!q) return undefined;
  const next = (BigInt(q.expectedRevision) + 1n).toString();
  const result = parseBitwardenInstallationRevision(value, {
    workspaceId: q.workspaceId,
    minimumRevision: next,
  });
  return result?.revision === next ? result : undefined;
}
