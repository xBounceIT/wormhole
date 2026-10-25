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

/** Include the scheme in the editable home page so legacy HTTP connections remain explicit. */
export function browserHomePageForEditor(
  protocol: string,
  host: string,
  httpPath?: string,
): string {
  const address = savedConnectionAddressForEditor(protocol, host, httpPath);
  if (!isWebProtocol(protocol) || !host) return address;
  if (/^https?:\/\//i.test(address)) return address.replace(/^https?:/i, `${protocol}:`);
  const endpoint =
    !host.startsWith('[') && host.indexOf(':') !== host.lastIndexOf(':') ? `[${host}]` : host;
  return `${protocol}://${savedConnectionAddressForEditor(protocol, endpoint, httpPath)}`;
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
