import { isIP } from 'node:net';

export type TunnelTestRequest = {
  id: string;
  attempt: number;
  targetHost?: string;
  targetPort?: number;
};

export type TunnelDetailsResponse = {
  id: string;
  name: string;
  kind: number;
  endpoint?: string;
  settings: Record<string, unknown>;
};

export type TunnelSummaryResponse = Omit<TunnelDetailsResponse, 'kind' | 'settings'> & {
  kind: string;
};

export function isTunnelIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseTunnelEndpoint(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > 512 ||
    /\p{Cc}/u.test(value)
  ) {
    throw new Error('The VPN service returned an invalid endpoint.');
  }
  return value;
}

function hasValidTunnelIdentity(value: unknown): value is Record<string, unknown> & {
  id: string;
  name: string;
} {
  return (
    isRecord(value) &&
    isTunnelIdentifier(value.id) &&
    typeof value.name === 'string' &&
    value.name.trim().length > 0 &&
    [...value.name].length <= 128
  );
}

export function parseTunnelDetailsResponse(value: unknown): TunnelDetailsResponse {
  if (
    !hasValidTunnelIdentity(value) ||
    typeof value.kind !== 'number' ||
    !Number.isInteger(value.kind) ||
    value.kind < 0 ||
    value.kind > 6 ||
    !isRecord(value.settings)
  ) {
    throw new Error('The VPN service returned invalid tunnel details.');
  }
  return {
    id: value.id,
    name: value.name,
    kind: value.kind,
    endpoint: parseTunnelEndpoint(value.endpoint),
    settings: value.settings,
  };
}

function parseTunnelSummaryResponse(value: unknown): TunnelSummaryResponse {
  if (
    !hasValidTunnelIdentity(value) ||
    typeof value.kind !== 'string' ||
    value.kind.length === 0 ||
    value.kind.length > 64
  ) {
    throw new Error('The VPN service returned an invalid tunnel summary.');
  }
  return {
    id: value.id,
    name: value.name,
    kind: value.kind,
    endpoint: parseTunnelEndpoint(value.endpoint),
  };
}

export function parseTunnelSummaryList(value: unknown): TunnelSummaryResponse[] {
  if (!Array.isArray(value)) throw new Error('The VPN service returned an invalid tunnel list.');
  return value.map(parseTunnelSummaryResponse);
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
  if (!Number.isSafeInteger(input.attempt) || (input.attempt as number) < 1) {
    throw new Error('VPN tunnel test attempt is invalid.');
  }

  const hasHost = Object.hasOwn(input, 'targetHost');
  const hasPort = Object.hasOwn(input, 'targetPort');
  if (!hasHost && !hasPort) return { id: input.id, attempt: input.attempt as number };
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
  return {
    id: input.id,
    attempt: input.attempt as number,
    targetHost,
    targetPort: targetPort as number,
  };
}
