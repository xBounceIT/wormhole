import { mountVaultTunnelScreen, type VaultTunnelApi } from './vault-tunnel-screen';
import { applyTheme, isTheme } from './theme';
const api = (window as unknown as { vaultTunnel?: VaultTunnelApi & { appearance?: string } })
  .vaultTunnel;
applyTheme(isTheme(api?.appearance) ? api.appearance : 'system');
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultTunnelScreen(card, api);
