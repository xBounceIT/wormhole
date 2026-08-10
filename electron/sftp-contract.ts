export const sshMaxSftpPathLength = 16 * 1024;

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
