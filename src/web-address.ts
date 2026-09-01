export function savedConnectionAddressForEditor(
  protocol: string,
  host: string,
  httpPath?: string,
): string {
  return (protocol === 'http' || protocol === 'https') && httpPath ? `${host}${httpPath}` : host;
}

function isWebProtocol(protocol: string): boolean {
  return protocol === 'http' || protocol === 'https';
}

export function connectionAddressForProtocolChange(
  currentProtocol: string,
  nextProtocol: string,
  address: string,
): string {
  if (!isWebProtocol(currentProtocol) || isWebProtocol(nextProtocol)) return address;

  let endpoint = address.trim().replace(/^https?:\/\//i, '');
  const contextStart = endpoint.search(/[/?#]/);
  if (contextStart >= 0) endpoint = endpoint.slice(0, contextStart);

  if (endpoint.startsWith('[')) {
    const bracketEnd = endpoint.indexOf(']');
    if (bracketEnd > 0) return endpoint.slice(1, bracketEnd);
  }

  const portSeparator = endpoint.lastIndexOf(':');
  if (
    portSeparator > 0 &&
    endpoint.indexOf(':') === portSeparator &&
    /^\d+$/.test(endpoint.slice(portSeparator + 1))
  ) {
    return endpoint.slice(0, portSeparator);
  }
  return endpoint;
}
