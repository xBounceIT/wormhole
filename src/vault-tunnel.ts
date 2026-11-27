import { mountVaultTunnelScreen, type VaultTunnelApi } from './vault-tunnel-screen';
const api = (window as unknown as { vaultTunnel: VaultTunnelApi }).vaultTunnel;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultTunnelScreen(card, api);
