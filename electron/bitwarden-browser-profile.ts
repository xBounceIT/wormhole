import { createHash } from 'node:crypto';

export type BitwardenRouteKind = 'socks5' | 'forwarder';

export function buildBitwardenPersistentRouteKey(
  tunnelConfigId: string,
  routeKind: BitwardenRouteKind,
  targetUrl: string,
): string {
  const normalizedTunnelId = tunnelConfigId.trim().replaceAll('-', '').toLowerCase();
  const targetOrigin = new URL(targetUrl).origin.toLowerCase();
  return createHash('sha256')
    .update(`${normalizedTunnelId}\0${routeKind}\0${targetOrigin}`)
    .digest('hex');
}

export function buildBitwardenBrowserContext(
  proxyUrl: string | undefined,
  persistentRouteKey: string,
): string {
  const proxyContext = proxyUrl ? `proxy=${proxyUrl}` : '';
  if (!persistentRouteKey) return proxyContext;
  return proxyContext
    ? `${proxyContext}\0route-key=${persistentRouteKey}`
    : `route-key=${persistentRouteKey}`;
}

export function getBitwardenBrowserPartition(context: string, ignoreCertErrors: boolean): string {
  const material = `${context}\0cert=${ignoreCertErrors ? '1' : '0'}`;
  const hash = createHash('sha256').update(material).digest('hex').slice(0, 16);
  return `persist:wormhole-web-ext-${hash}`;
}
