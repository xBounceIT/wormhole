/** Standalone file tabs share browsing and transfer behavior across transports. */
export function isFileBrowserProtocol(protocol: string | undefined): boolean {
  return protocol === 'sftp' || protocol === 'smb';
}

export function fileSessionMode(protocol: string | undefined): 'terminal' | 'sftp' | 'smb' {
  return protocol === 'smb' ? 'smb' : protocol === 'sftp' ? 'sftp' : 'terminal';
}
