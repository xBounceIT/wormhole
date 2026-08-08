export type BitwardenCliStatusName = 'Unauthenticated' | 'Locked' | 'Unlocked' | 'Unknown';

export function bitwardenCliIsLoggedIn(status: BitwardenCliStatusName | null | undefined): boolean {
  return status === 'Locked' || status === 'Unlocked';
}

export function formatBitwardenLoginStatus(
  status: BitwardenCliStatusName | null | undefined,
): string {
  if (bitwardenCliIsLoggedIn(status)) return 'Logged in';
  if (status === 'Unauthenticated') return 'Not logged in';
  return 'Unknown';
}

export function formatBitwardenVaultStatus(status: BitwardenCliStatusName): string {
  switch (status) {
    case 'Unlocked':
      return 'Unlocked';
    case 'Locked':
      return 'Locked';
    case 'Unauthenticated':
      return 'Unavailable';
    default:
      return 'Unknown';
  }
}

export function bitwardenCliServerRegionCode(
  serverUrl: string | null | undefined,
): 'US' | 'EU' | null {
  // Bitwarden represents its default US cloud with a null serverUrl.
  if (!serverUrl) return 'US';
  try {
    const hostname = new URL(serverUrl).hostname.toLowerCase();
    if (hostname === 'bitwarden.eu' || hostname.endsWith('.bitwarden.eu')) return 'EU';
    if (hostname === 'bitwarden.com' || hostname.endsWith('.bitwarden.com')) return 'US';
  } catch {
    // A custom or malformed CLI server URL has no US/EU shorthand.
  }
  return null;
}

export function formatBitwardenCurrentServerLabel(region: 'US' | 'EU' | null): string {
  return `Current Server${region ? ` (${region})` : ''}`;
}

export function formatBitwardenSyncResult(result: {
  availableCount: number;
  lastSyncStatus: string;
  usedCache: boolean;
  lastSyncError?: string;
}): { status: 'success' | 'warning'; message: string } {
  if (!result.usedCache) {
    return {
      status: 'success',
      message: result.lastSyncStatus || 'Bitwarden vault synced successfully.',
    };
  }

  const credentials = `${result.availableCount} cached credential${result.availableCount === 1 ? '' : 's'}`;
  return {
    status: 'warning',
    message: `Bitwarden could not be synchronized. Wormhole will continue using ${credentials}.${
      result.lastSyncError ? ` ${result.lastSyncError}` : ''
    }`,
  };
}
