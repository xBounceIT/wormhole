import { tunnelAuthenticationContext } from './vault-tunnel-authentication.ts';
import type { VaultTunnelBrowserContext } from '../../electron/vault-tunnel-browser.ts';
export function tunnelBrowserContext(): VaultTunnelBrowserContext {
  const { usernameRequired: _, ...base } = tunnelAuthenticationContext();
  return {
    ...base,
    startURL: 'https://vpn.test:1001/saml?state=public',
    callbackURL: 'http://127.0.0.1:12345/',
    ignoreCertificateErrors: true,
  };
}
