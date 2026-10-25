import { isIP } from 'node:net';

export type TunnelTestRequest = {
  id: string;
  attempt: number;
  targetHost?: string;
  targetPort?: number;
};

export type TunnelDetailsResponse = {
  jumpHostKeySha256?: string;
  id: string;
  name: string;
  kind: number;
  endpoint?: string;
  settings: Record<string, unknown>;
};

export type TunnelWriteRequest = {
  forgetJumpHostKeySha256?: string;
  id?: string;
  name: string;
  kind: number;
  settings: Record<string, unknown>;
};
export function parseTunnelWriteRequest(value: unknown, requiresID: boolean): TunnelWriteRequest {
  if (!value || typeof value !== 'object') throw new Error('VPN tunnel settings are invalid.');
  const input = value as Record<string, unknown>;
  if (
    typeof input.name !== 'string' ||
    input.name.trim().length === 0 ||
    input.name.length > 128 ||
    typeof input.kind !== 'number' ||
    !Number.isInteger(input.kind) ||
    input.kind < 0 ||
    input.kind > 8 ||
    !isRecord(input.settings)
  ) {
    throw new Error('VPN tunnel settings are invalid.');
  }
  if (requiresID && !isTunnelIdentifier(input.id)) throw new Error('VPN tunnel id is invalid.');
  if (input.kind === 8) parseSSHJumpSettings(input.settings);
  if (
    input.forgetJumpHostKeySha256 !== undefined &&
    (input.kind !== 8 ||
      !requiresID ||
      typeof input.forgetJumpHostKeySha256 !== 'string' ||
      !/^SHA256:[A-Za-z0-9+/]{43}$/.test(input.forgetJumpHostKeySha256))
  )
    throw new Error('SSH tunnel pin reset is invalid.');
  return {
    ...(input.forgetJumpHostKeySha256
      ? { forgetJumpHostKeySha256: input.forgetJumpHostKeySha256 as string }
      : {}),
    ...(isTunnelIdentifier(input.id) ? { id: input.id } : {}),
    name: input.name,
    kind: input.kind,
    settings: input.settings,
  };
}

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
    value.kind > 8 ||
    !isRecord(value.settings)
  ) {
    throw new Error('The VPN service returned invalid tunnel details.');
  }
  if (value.kind === 8) parseSSHJumpSettings(value.settings);
  if (
    value.jumpHostKeySha256 !== undefined &&
    (typeof value.jumpHostKeySha256 !== 'string' ||
      !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value.jumpHostKeySha256))
  ) {
    throw new Error('The SSH tunnel service returned an invalid host-key fingerprint.');
  }
  return {
    ...(value.jumpHostKeySha256 ? { jumpHostKeySha256: value.jumpHostKeySha256 as string } : {}),
    id: value.id,
    name: value.name,
    kind: value.kind,
    endpoint: parseTunnelEndpoint(value.endpoint),
    settings: value.settings,
  };
}

export function parseSSHJumpSettings(value: unknown): Record<string, unknown> {
  if (!isRecord(value) || Buffer.byteLength(JSON.stringify(value), 'utf8') > 8192)
    throw new Error('SSH tunnel settings are invalid.');
  const allowed = new Set([
    'Mode',
    'JumpConnectionId',
    'Host',
    'Port',
    'Username',
    'CredentialId',
    'HostKeySha256',
    'KeepaliveSeconds',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)))
    throw new Error('SSH tunnel settings must contain references only.');
  if (
    value.KeepaliveSeconds !== undefined &&
    (!Number.isInteger(value.KeepaliveSeconds) ||
      (value.KeepaliveSeconds as number) < 1 ||
      (value.KeepaliveSeconds as number) > 3600)
  )
    throw new Error('SSH tunnel keepalive is invalid.');
  if (value.Mode === 'connection') {
    if (
      !isTunnelIdentifier(value.JumpConnectionId) ||
      ['Host', 'Port', 'Username', 'CredentialId', 'HostKeySha256'].some((key) =>
        Object.hasOwn(value, key),
      )
    )
      throw new Error('SSH jump connection is invalid.');
  } else if (value.Mode === 'manual') {
    if (
      Object.hasOwn(value, 'JumpConnectionId') ||
      typeof value.Host !== 'string' ||
      !isTunnelTestHost(value.Host) ||
      typeof value.Username !== 'string' ||
      !value.Username.trim() ||
      value.Username.length > 512 ||
      /\p{Cc}/u.test(value.Username) ||
      !isTunnelIdentifier(value.CredentialId) ||
      !Number.isInteger(value.Port) ||
      (value.Port as number) < 1 ||
      (value.Port as number) > 65535 ||
      (value.HostKeySha256 !== undefined &&
        (typeof value.HostKeySha256 !== 'string' ||
          !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value.HostKeySha256)))
    )
      throw new Error('SSH tunnel endpoint or credential is invalid.');
  } else throw new Error('SSH tunnel mode is invalid.');
  return value;
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
