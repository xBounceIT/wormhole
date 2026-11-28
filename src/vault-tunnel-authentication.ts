import {
  mountVaultTunnelAuthenticationScreen,
  type VaultTunnelAuthenticationApi,
} from './vault-tunnel-authentication-screen';
const api = (window as unknown as { vaultTunnelAuthentication: VaultTunnelAuthenticationApi })
  .vaultTunnelAuthentication;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultTunnelAuthenticationScreen(card, api);
