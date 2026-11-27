import { tunnelAuthenticationContext } from './vault-tunnel-authentication.ts';
import type { VaultTunnelCookieContext } from '../../electron/vault-tunnel-cookie.ts';
export function tunnelCookieContext(): Extract<VaultTunnelCookieContext, { cookieName: string }> {
  const { usernameRequired: _, ...base } = tunnelAuthenticationContext();
  return {
    ...base,
    binding: { ...base.binding, kind: 2 },
    startURL: 'https://vpn.test/remote/saml/start?realm=staff',
    ignoreCertificateErrors: true,
    cookieName: 'SVPNCOOKIE',
  };
}
