export const sftpDragDataType = 'application/x-wormhole-sftp-items';

export function hasSftpDragPayload(types: readonly string[]): boolean {
  return types.includes(sftpDragDataType) || types.includes('Files');
}
