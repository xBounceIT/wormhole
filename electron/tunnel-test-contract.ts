import { isIP } from 'node:net';

export type TunnelTestRequest = {
  id: string;
  targetHost?: string;
  targetPort?: number;
};

export function isTunnelIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  );
}

export function isTunnelTestHost(value: string): boolean {
  if (!value || value.length > 1024 || /[\\/?#@%\s\p{Cc}]/u.test(value)) return false;
  if (value.startsWith('[') || value.endsWith(']')) {
    return value.startsWith('[') && value.endsWith(']') && isIP(value.slice(1, -1)) === 6;
  }
  return !value.includes(':') || isIP(value) !== 0;
}

export function parseTunnelTestRequest(value: unknown): TunnelTestRequest {
  if (!value || typeof value !== 'object') throw new Error('VPN tunnel id is invalid.');
  const input = value as Record<string, unknown>;
  if (!isTunnelIdentifier(input.id)) throw new Error('VPN tunnel id is invalid.');

  const hasHost = Object.hasOwn(input, 'targetHost');
  const hasPort = Object.hasOwn(input, 'targetPort');
  if (!hasHost && !hasPort) return { id: input.id };
  if (typeof input.targetHost !== 'string') {
    throw new Error('VPN tunnel test target is invalid.');
  }
  const targetHost = input.targetHost.trim();
  const targetPort = input.targetPort;
  if (
    !isTunnelTestHost(targetHost) ||
    !Number.isInteger(targetPort) ||
    (targetPort as number) < 1 ||
    (targetPort as number) > 65535
  ) {
    throw new Error('VPN tunnel test target is invalid.');
  }
  return { id: input.id, targetHost, targetPort: targetPort as number };
}
