import { createHash } from 'node:crypto';

export type TunnelBrowserCompletion = 'query-token' | 'oauth-code' | 'cookie';
export const tunnelPromptValueMaxBytes = 16 * 1024;
export type TunnelAuthPartitionRequest =
  | { completion: 'cookie' | 'oauth-code' }
  | {
      completion: 'query-token';
      origin: string;
      ignoreCertificateErrors: boolean;
    };

// Persisting each provider partition keeps its IdP session between connects. WatchGuard also
// isolates the Firebox origin and certificate policy because Chromium caches certificate verify
// results inside the network service; an explicit trust opt-in must never affect another gateway
// or a later connection that restores normal verification.
export function tunnelAuthPartition(request: TunnelAuthPartitionRequest): string {
  switch (request.completion) {
    case 'cookie':
      return 'persist:wormhole-tunnel-auth-fortinet';
    case 'oauth-code':
      return 'persist:wormhole-tunnel-auth-azure';
    case 'query-token': {
      const origin = new URL(request.origin).origin.toLowerCase();
      const material = `${origin}\0cert=${request.ignoreCertificateErrors ? '1' : '0'}`;
      const hash = createHash('sha256').update(material).digest('hex').slice(0, 16);
      return `persist:wormhole-tunnel-auth-watchguard-${hash}`;
    }
  }
}

function normalizeCertificateHostname(hostname: string): string {
  const normalized = hostname.toLowerCase();
  if (normalized.startsWith('[') && normalized.endsWith(']')) {
    return normalized.slice(1, -1);
  }
  return normalized.endsWith('.') ? normalized.slice(0, -1) : normalized;
}

export function isSameCertificateHostname(candidate: string, expected: string): boolean {
  return normalizeCertificateHostname(candidate) === normalizeCertificateHostname(expected);
}

export function isMatchingOAuthRedirect(candidate: URL, expectedRaw: string): boolean {
  const expected = new URL(expectedRaw);
  return (
    candidate.protocol === expected.protocol &&
    candidate.hostname === expected.hostname &&
    candidate.port === expected.port &&
    candidate.pathname === expected.pathname &&
    !candidate.username &&
    !candidate.password
  );
}

export function encodeTunnelOAuthCallback(candidate: URL): string | undefined {
  const value = JSON.stringify({
    code: candidate.searchParams.get('code') ?? '',
    state: candidate.searchParams.get('state') ?? '',
    error: candidate.searchParams.get('error') ?? '',
    description: candidate.searchParams.get('error_description') ?? '',
  });
  return Buffer.byteLength(value, 'utf8') <= tunnelPromptValueMaxBytes ? value : undefined;
}
