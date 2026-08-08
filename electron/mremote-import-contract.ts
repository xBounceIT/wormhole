export type MRemoteImportInspection = {
  fileName: string;
  fileSize: number;
  confVersion: string;
  passwordRequired: boolean;
  fullFileEncrypted: boolean;
};

export type MRemoteImportPreviewNode = {
  name: string;
  kind: 'folder' | 'connection';
  protocol?: 'ssh' | 'rdp' | 'vnc';
  depth: number;
};

export type MRemoteImportPlan = {
  planToken: string;
  folders: number;
  connections: number;
  credentials: number;
  skippedUnsupported: number;
  skippedUnsupportedSamples: string[];
  warnings: string[];
  droppedWarnings: number;
  preview: MRemoteImportPreviewNode[];
  previewTruncated: boolean;
};

export type MRemoteImportResult = {
  foldersCreated: number;
  connectionsCreated: number;
  credentialsCreated: number;
  skippedUnsupported: number;
  warnings: string[];
  droppedWarnings: number;
};

export type MRemoteImportOptions = { password: string; structureOnly: boolean };

const maxPasswordBytes = 16 * 1024;
const maxListLength = 250;

export function parseMRemoteImportOptions(value: unknown): MRemoteImportOptions {
  if (!value || typeof value !== 'object') throw new Error('mRemoteNG import options are invalid.');
  const record = value as Record<string, unknown>;
  if (
    typeof record.password !== 'string' ||
    Buffer.byteLength(record.password, 'utf8') > maxPasswordBytes ||
    typeof record.structureOnly !== 'boolean'
  ) {
    throw new Error('mRemoteNG import options are invalid.');
  }
  return { password: record.password, structureOnly: record.structureOnly };
}

export function parseMRemoteImportInspection(
  value: unknown,
  fileName: string,
): MRemoteImportInspection {
  if (!value || typeof value !== 'object')
    throw new Error('The mRemoteNG inspector returned invalid data.');
  const record = value as Record<string, unknown>;
  if (
    !Number.isSafeInteger(record.fileSize) ||
    (record.fileSize as number) <= 0 ||
    typeof record.confVersion !== 'string' ||
    record.confVersion.length > 64 ||
    typeof record.passwordRequired !== 'boolean' ||
    typeof record.fullFileEncrypted !== 'boolean'
  )
    throw new Error('The mRemoteNG inspector returned invalid data.');
  return {
    fileName,
    fileSize: record.fileSize as number,
    confVersion: record.confVersion,
    passwordRequired: record.passwordRequired,
    fullFileEncrypted: record.fullFileEncrypted,
  };
}

function safeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 50_000;
}

function safeStrings(value: unknown, limit: number): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= limit &&
    value.every((item) => typeof item === 'string' && item.length <= 1024)
  );
}

function hasOnlyKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

export function parseMRemoteImportPlan(value: unknown): MRemoteImportPlan {
  if (!value || typeof value !== 'object')
    throw new Error('The mRemoteNG analyzer returned invalid data.');
  const record = value as Record<string, unknown>;
  const preview = record.preview;
  if (
    !hasOnlyKeys(record, [
      'planToken',
      'folders',
      'connections',
      'credentials',
      'skippedUnsupported',
      'skippedUnsupportedSamples',
      'warnings',
      'droppedWarnings',
      'preview',
      'previewTruncated',
    ]) ||
    typeof record.planToken !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(record.planToken) ||
    !safeCount(record.folders) ||
    !safeCount(record.connections) ||
    !safeCount(record.credentials) ||
    !safeCount(record.skippedUnsupported) ||
    !safeCount(record.droppedWarnings) ||
    !safeStrings(record.skippedUnsupportedSamples, 5) ||
    !safeStrings(record.warnings, 50) ||
    typeof record.previewTruncated !== 'boolean' ||
    !Array.isArray(preview) ||
    preview.length > maxListLength ||
    !preview.every((item) => {
      if (!item || typeof item !== 'object') return false;
      const node = item as Record<string, unknown>;
      return (
        hasOnlyKeys(node, ['name', 'kind', 'protocol', 'depth']) &&
        typeof node.name === 'string' &&
        node.name.length > 0 &&
        node.name.length <= 256 &&
        (node.kind === 'folder' || node.kind === 'connection') &&
        (node.protocol === undefined ||
          node.protocol === 'ssh' ||
          node.protocol === 'rdp' ||
          node.protocol === 'vnc') &&
        Number.isSafeInteger(node.depth) &&
        (node.depth as number) > 0 &&
        (node.depth as number) <= 4096
      );
    })
  )
    throw new Error('The mRemoteNG analyzer returned invalid data.');
  return record as MRemoteImportPlan;
}

export function parseMRemoteImportResult(value: unknown): MRemoteImportResult {
  if (!value || typeof value !== 'object')
    throw new Error('The mRemoteNG importer returned invalid data.');
  const record = value as Record<string, unknown>;
  if (
    !hasOnlyKeys(record, [
      'foldersCreated',
      'connectionsCreated',
      'credentialsCreated',
      'skippedUnsupported',
      'warnings',
      'droppedWarnings',
    ]) ||
    !safeCount(record.foldersCreated) ||
    !safeCount(record.connectionsCreated) ||
    !safeCount(record.credentialsCreated) ||
    !safeCount(record.skippedUnsupported) ||
    !safeCount(record.droppedWarnings) ||
    !safeStrings(record.warnings, 50)
  ) {
    throw new Error('The mRemoteNG importer returned invalid data.');
  }
  return {
    foldersCreated: record.foldersCreated,
    connectionsCreated: record.connectionsCreated,
    credentialsCreated: record.credentialsCreated,
    skippedUnsupported: record.skippedUnsupported,
    warnings: record.warnings,
    droppedWarnings: record.droppedWarnings,
  };
}
