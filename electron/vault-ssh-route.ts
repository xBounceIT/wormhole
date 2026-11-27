import { vaultFields, vaultRecord } from './vault-contract.ts';
import {
  parseVaultRouteRequest,
  parseVaultRouteBinding,
  parseVaultRouteBundle,
  validVaultRouteEndpoint,
  type VaultRouteRequest,
  type VaultRouteBinding,
  type VaultRouteBundle,
} from './vault-route.ts';

export type VaultRoutedSshRequest = VaultRouteRequest & {
  sftpOnly?: true;
  route: VaultRouteBinding;
  endpoint: string;
};
export type VaultRoutedSshBundle = VaultRouteBundle & { endpoint: string; sftpOnly?: true };

export function parseVaultRoutedSshRequest(value: unknown): VaultRoutedSshRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { route: rawRoute, endpoint, sftpOnly, ...base } = value;
  if (sftpOnly !== undefined && sftpOnly !== true) return undefined;
  const q = parseVaultRouteRequest(base);
  if (!q || !validVaultRouteEndpoint(endpoint)) return undefined;
  const { publicKey: _, ...context } = q;
  const route = parseVaultRouteBinding(rawRoute, context);
  if (!route || (route.protocol !== 'ssh' && route.protocol !== 'sftp')) return undefined;
  return { ...q, route, endpoint, ...(sftpOnly ? { sftpOnly: true } : {}) };
}
export function parseVaultRoutedSshBundle(
  value: unknown,
  request: VaultRoutedSshRequest,
): VaultRoutedSshBundle | undefined {
  const q = parseVaultRoutedSshRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'bundle', 'endpoint', ...(q.sftpOnly ? ['sftpOnly'] : [])]) ||
    value.sftpOnly !== q.sftpOnly ||
    value.endpoint !== q.endpoint
  )
    return undefined;
  const { route, endpoint, sftpOnly, ...base } = q;
  const result = parseVaultRouteBundle({ binding: value.binding, bundle: value.bundle }, base);
  if (!result || JSON.stringify(result.binding) !== JSON.stringify(route)) return undefined;
  return { ...result, endpoint, ...(sftpOnly ? { sftpOnly: true } : {}) };
}
