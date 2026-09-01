export function savedConnectionAddressForEditor(
  protocol: string,
  host: string,
  httpPath?: string,
): string {
  return (protocol === 'http' || protocol === 'https') && httpPath ? `${host}${httpPath}` : host;
}
