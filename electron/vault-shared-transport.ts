export type SharedVaultTransport = 'off' | 'encrypted' | 'verified';

export function parseSharedVaultTransport(value: unknown): SharedVaultTransport | undefined {
  return value === 'off' || value === 'encrypted' || value === 'verified' ? value : undefined;
}
