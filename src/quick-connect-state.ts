export type QuickConnectProtocol = 'ssh' | 'sftp' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';

export function connectionProtocolSupportsTunnel(protocol: QuickConnectProtocol): boolean {
  return (
    protocol === 'ssh' ||
    protocol === 'sftp' ||
    protocol === 'rdp' ||
    protocol === 'http' ||
    protocol === 'https' ||
    protocol === 'vnc'
  );
}

export function quickConnectTunnelId(
  protocol: QuickConnectProtocol,
  tunnelMode: string | undefined,
): string | undefined {
  if (!connectionProtocolSupportsTunnel(protocol) || !tunnelMode || tunnelMode === 'off')
    return undefined;
  return tunnelMode;
}

export function quickConnectStartsImmediately(
  protocol: QuickConnectProtocol,
  useSavedCredentials: boolean,
  credentialId: string | undefined,
): boolean {
  if (protocol !== 'ssh' && protocol !== 'sftp') return protocol !== 'rdp';
  return !useSavedCredentials || Boolean(credentialId);
}
