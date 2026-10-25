export type QuickConnectProtocol = 'ssh' | 'sftp' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
export type ConnectionType = Exclude<QuickConnectProtocol, 'http' | 'https'> | 'browser';

export function connectionTypeForProtocol(protocol: QuickConnectProtocol): ConnectionType {
  return protocol === 'http' || protocol === 'https' ? 'browser' : protocol;
}

export function connectionProtocolForType(
  type: ConnectionType,
  current: QuickConnectProtocol,
  address = '',
): QuickConnectProtocol {
  return type === 'browser'
    ? connectionTypeForProtocol(current) === 'browser'
      ? current
      : connectionProtocolForAddress('https', address)
    : type;
}

/** The Browser form defaults to HTTPS; an explicit HTTP home page selects HTTP. */
export function connectionProtocolForAddress(
  current: QuickConnectProtocol,
  address: string,
): QuickConnectProtocol {
  return connectionTypeForProtocol(current) === 'browser'
    ? /^\s*http:\/\//i.test(address)
      ? 'http'
      : 'https'
    : current;
}

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
