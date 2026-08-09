export type TunnelBrowserCompletion = 'query-token' | 'oauth-code' | 'cookie';

// Each provider gets the same dedicated, persistent browser profile as its WinUI/WebView2
// counterpart. Persisting the partition keeps the IdP session between connects without mixing
// cookies across Fortinet, WatchGuard, and Microsoft Entra. Provider-specific completion modes
// are part of the native broker contract, so they are a stable discriminator here.
export function tunnelAuthPartition(completion: TunnelBrowserCompletion): string {
  switch (completion) {
    case 'cookie':
      return 'persist:wormhole-tunnel-auth-fortinet';
    case 'query-token':
      return 'persist:wormhole-tunnel-auth-watchguard';
    case 'oauth-code':
      return 'persist:wormhole-tunnel-auth-azure';
  }
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
