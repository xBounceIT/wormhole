import { isSftpEditRequest } from './sftp-contract.ts';
import { vaultID, vaultFields, vaultRecord } from './vault-contract.ts';

export type VaultFileEditSettings = {
  editors: {
    id: string;
    name: string;
    executable: string;
    arguments: string[];
    patterns: string;
  }[];
  defaultEditor: string;
  maxFileSize: number;
  swapPanels: boolean;
};

export function parseVaultFileEditSettings(value: unknown): VaultFileEditSettings | undefined {
  const text = (v: unknown, max: number) =>
    typeof v === 'string' && Buffer.byteLength(v) <= max && !v.includes('\0');
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['editors', 'defaultEditor', 'maxFileSize', 'swapPanels']) ||
    !Array.isArray(value.editors) ||
    value.editors.length > 32 ||
    !text(value.defaultEditor, 128) ||
    !Number.isSafeInteger(value.maxFileSize) ||
    (value.maxFileSize as number) < 1 ||
    (value.maxFileSize as number) > 1024 * 1024 * 1024 ||
    typeof value.swapPanels !== 'boolean'
  )
    return undefined;
  const ids = new Set(['auto', 'system']);
  const editors: VaultFileEditSettings['editors'] = [];
  for (const e of value.editors) {
    if (
      !vaultRecord(e) ||
      !vaultFields(e, ['id', 'name', 'executable', 'arguments', 'patterns']) ||
      !text(e.id, 128) ||
      !e.id ||
      ids.has(e.id as string) ||
      !text(e.name, 256) ||
      !(e.name as string).trim() ||
      !text(e.executable, 4096) ||
      !e.executable ||
      [e.id, e.name, e.executable].some((v) => /[\r\n]/.test(v as string)) ||
      !text(e.patterns, 4096) ||
      !Array.isArray(e.arguments) ||
      e.arguments.length > 64 ||
      !e.arguments.every((v) => text(v, 4096))
    )
      return undefined;
    ids.add(e.id as string);
    editors.push({
      id: e.id as string,
      name: e.name as string,
      executable: e.executable as string,
      arguments: [...e.arguments] as string[],
      patterns: e.patterns as string,
    });
  }
  if (!ids.has(value.defaultEditor as string)) return undefined;
  const result = {
    editors,
    defaultEditor: value.defaultEditor as string,
    maxFileSize: value.maxFileSize as number,
    swapPanels: value.swapPanels,
  };
  return Buffer.byteLength(JSON.stringify(result)) <= 64 * 1024 ? result : undefined;
}

const fields: Record<string, readonly string[]> = {
  list: [],
  'prepare-close': [],
  'finish-close': ['decision'],
  start: ['pane', 'path', 'editor_id', 'allow_binary'],
  recover: ['edit_id'],
  reveal: ['edit_id'],
  reload: ['edit_id', 'decision'],
  discard: ['edit_id', 'decision'],
  upload: ['edit_id', 'decision', 'destination_path'],
  stop: ['edit_id', 'decision', 'destination_path'],
};

// Match the native per-operation contract before writing to the sealed child.
// Optional undefined fields from the shared legacy call site are not wire fields.
export function sealedSftpEditCommand(input: Record<string, unknown>): Record<string, unknown> {
  const q = Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined));
  const operation = typeof q.operation === 'string' ? q.operation : '';
  const allowed = Object.hasOwn(fields, operation) ? fields[operation] : undefined;
  const identifier = (value: unknown, empty = false) =>
    typeof value === 'string' &&
    (empty || value.length > 0) &&
    Buffer.byteLength(value) <= 128 &&
    !/\p{Cc}/u.test(value);
  if (
    !allowed ||
    q.type !== 'sftp-edit' ||
    !identifier(q.request_id) ||
    !vaultID(q.session_id) ||
    Object.keys(q).some(
      (key) => !['type', 'session_id', 'request_id', 'operation', ...allowed].includes(key),
    ) ||
    !isSftpEditRequest({
      operation,
      pane: q.pane,
      path: q.path,
      editId: q.edit_id,
      editorId: q.editor_id,
      allowBinary: q.allow_binary,
      decision: q.decision,
      destinationPath: q.destination_path === '' ? undefined : q.destination_path,
    }) ||
    (q.editor_id !== undefined && !identifier(q.editor_id, true)) ||
    (allowed.includes('edit_id') && !vaultID(q.edit_id)) ||
    (operation === 'finish-close' && q.decision !== 'keep') ||
    (['reload', 'discard'].includes(operation) && q.decision !== 'discard') ||
    (['upload', 'stop'].includes(operation) &&
      q.decision !== undefined &&
      q.decision !== 'overwrite')
  )
    throw Error('Invalid vault file edit request.');
  return q;
}
