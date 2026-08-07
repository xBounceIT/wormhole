export type QuickConnectProtocol = 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';

export function quickConnectSupportsTunnel(protocol: QuickConnectProtocol): boolean {
  return protocol === 'rdp' || protocol === 'http' || protocol === 'https' || protocol === 'vnc';
}

export function quickConnectTunnelId(
  protocol: QuickConnectProtocol,
  tunnelMode: string | undefined,
): string | undefined {
  if (!quickConnectSupportsTunnel(protocol) || !tunnelMode || tunnelMode === 'off')
    return undefined;
  return tunnelMode;
}
