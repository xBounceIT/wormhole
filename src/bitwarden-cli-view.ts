export type BitwardenCliStatusName = 'Unauthenticated' | 'Locked' | 'Unlocked' | 'Unknown';

export function bitwardenCliAuthMode(status: {
  status: BitwardenCliStatusName;
  hasSessionKey?: boolean;
}): 'login' | 'unlock' | null {
  if (status.status === 'Unauthenticated') return 'login';
  // The CLI status command has no session key. A locked CLI can still have an unlocked
  // vault in the Go service, which is the session Wormhole actually uses.
  if (status.hasSessionKey) return null;
  if (status.status === 'Locked' || status.status === 'Unlocked') return 'unlock';
  return null;
}

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

export function formatBitwardenAuthenticationError(
  error: unknown,
  mode: 'login' | 'unlock',
): string {
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();

  if (message.includes('credential vault is disabled')) {
    return 'Bitwarden is disabled. Enable it in Settings and try again.';
  }
  if (message.includes('cli is not installed')) {
    return "The Bitwarden CLI isn't installed. Install it from Settings and try again.";
  }
  if (
    mode === 'unlock' &&
    (message.includes('not logged in') || message.includes('unauthenticated'))
  ) {
    return 'Bitwarden is logged out. Log in again from Settings.';
  }
  if (message.includes('timeout') || message.includes('timed out')) {
    return 'Bitwarden took too long to respond. Check your connection and try again.';
  }
  if (
    mode === 'login' &&
    (message.includes('two-step login is required') ||
      message.includes('two-step token is invalid') ||
      message.includes('two-factor authentication is required'))
  ) {
    return 'Enter a valid two-step login code and try again.';
  }

  const credentialsWereRejected = [
    'invalid master password',
    'master password is invalid',
    'master password is incorrect',
    'invalid credentials',
    'invalid password',
    'password is incorrect',
    'decryption operation failed',
    'cryptography error',
    'two-step code',
    'two factor',
    'two-factor',
  ].some((fragment) => message.includes(fragment));

  if (credentialsWereRejected) {
    return mode === 'unlock'
      ? "That master password didn't work. Check it and try again."
      : 'Check your email, master password, and two-step login code, then try again.';
  }

  const serviceIsUnreachable = [
    'could not be reached',
    'cannot reach',
    'could not connect',
    'network',
    'offline',
    'econn',
    'enotfound',
  ].some((fragment) => message.includes(fragment));
  if (serviceIsUnreachable) {
    return "Bitwarden couldn't be reached. Check your connection and try again.";
  }

  return mode === 'unlock'
    ? "Bitwarden couldn't unlock the vault. Please try again."
    : "Bitwarden couldn't log in. Please try again.";
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
