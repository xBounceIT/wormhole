export const sshMaxSftpPathLength = 16 * 1024;
export const sshMaxSftpEntryNameLength = 4 * 1024;

export type SftpEditView = {
  id: string;
  sessionId: string;
  nodeId: string;
  name: string;
  remotePath: string;
  editor: string;
  state: string;
  pending: boolean;
  recovered: boolean;
  error?: string;
  uploadedAt?: string;
};
export type SftpEditRequest = {
  operation:
    | 'list'
    | 'start'
    | 'upload'
    | 'stop'
    | 'reload'
    | 'reveal'
    | 'recover'
    | 'discard'
    | 'prepare-close'
    | 'finish-close';
  pane?: 'local' | 'remote';
  path?: string;
  editId?: string;
  editorId?: string;
  allowBinary?: boolean;
  decision?: 'overwrite' | 'discard' | 'keep';
  destinationPath?: string;
};
export type SftpEditEvent = {
  type: 'sftp.edit';
  sessionId: string;
  requestId?: string;
  edits: SftpEditView[];
  error?: string;
};

function boundedText(value: unknown, limit: number): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= limit &&
    !value.includes('\u0000')
  );
}

export function isSftpEditRequest(
  value: unknown,
  platform: NodeJS.Platform = process.platform,
): value is SftpEditRequest {
  if (!value || typeof value !== 'object') return false;
  const request = value as SftpEditRequest;
  if (
    ![
      'list',
      'start',
      'upload',
      'stop',
      'reload',
      'reveal',
      'recover',
      'discard',
      'prepare-close',
      'finish-close',
    ].includes(request.operation)
  )
    return false;
  if (request.allowBinary !== undefined && typeof request.allowBinary !== 'boolean') return false;
  if (request.editorId !== undefined && !boundedText(request.editorId, 128)) return false;
  if (
    request.decision !== undefined &&
    !['overwrite', 'discard', 'keep'].includes(request.decision)
  )
    return false;
  if (
    request.destinationPath !== undefined &&
    (!boundedText(request.destinationPath, sshMaxSftpPathLength) ||
      !request.destinationPath.startsWith('/'))
  )
    return false;
  if (request.operation === 'start')
    return request.pane === 'local'
      ? isLocalSftpPath(request.path, false, platform)
      : request.pane === 'remote' &&
          boundedText(request.path, sshMaxSftpPathLength) &&
          request.path.startsWith('/');
  if (['list', 'prepare-close', 'finish-close'].includes(request.operation)) return true;
  return boundedText(request.editId, 128) && /^[a-fA-F0-9-]{36}$/.test(request.editId);
}

export function parseSftpEditEvent(value: Record<string, unknown>): SftpEditEvent | undefined {
  if (
    value.type !== 'sftp.edit' ||
    !boundedText(value.session_id, 128) ||
    !value.session_id ||
    (value.request_id !== undefined && !boundedText(value.request_id, 128)) ||
    (value.error !== undefined && !boundedText(value.error, 8192))
  )
    return undefined;
  const edits = value.edits ?? [];
  if (
    !Array.isArray(edits) ||
    edits.length > 256 ||
    !edits.every((entry: unknown) => {
      if (!entry || typeof entry !== 'object') return false;
      const edit = entry as SftpEditView;
      return (
        boundedText(edit.id, 128) &&
        boundedText(edit.sessionId, 128) &&
        boundedText(edit.nodeId, 128) &&
        boundedText(edit.name, sshMaxSftpEntryNameLength) &&
        boundedText(edit.remotePath, sshMaxSftpPathLength) &&
        boundedText(edit.editor, 256) &&
        boundedText(edit.state, 128) &&
        typeof edit.pending === 'boolean' &&
        typeof edit.recovered === 'boolean' &&
        (edit.error === undefined || boundedText(edit.error, 8192)) &&
        (edit.uploadedAt === undefined || boundedText(edit.uploadedAt, 128))
      );
    })
  )
    return undefined;
  return {
    type: 'sftp.edit',
    sessionId: value.session_id,
    requestId: value.request_id as string | undefined,
    edits,
    error: value.error as string | undefined,
  };
}

export type SftpNameDestination = 'local' | 'remote';

export function isSftpName(
  value: unknown,
  destination: SftpNameDestination,
  platform: NodeJS.Platform = process.platform,
): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    Buffer.byteLength(value, 'utf8') > sshMaxSftpEntryNameLength ||
    value.includes('/') ||
    value.includes('\u0000')
  ) {
    return false;
  }
  if (destination === 'local' && platform !== 'win32') return true;
  if (value.includes('\\')) return false;
  return destination === 'remote' || !value.includes(':');
}

export function isLocalSftpPath(
  value: unknown,
  allowEmpty = false,
  platform: NodeJS.Platform = process.platform,
): value is string {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') > sshMaxSftpPathLength ||
    value.includes('\u0000')
  ) {
    return false;
  }
  if (value.length === 0) return allowEmpty;
  return platform === 'win32' ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(value) : value.startsWith('/');
}
