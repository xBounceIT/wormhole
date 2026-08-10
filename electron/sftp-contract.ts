export const sshMaxSftpPathLength = 16 * 1024;
export const sshMaxSftpEntryNameLength = 4 * 1024;

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
