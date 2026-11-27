import {
  mountVaultRdpCredentialsScreen,
  type VaultRdpCredentialsApi,
} from './vault-rdp-credentials-screen';
const api = (window as unknown as { vaultRdpCredentials: VaultRdpCredentialsApi })
  .vaultRdpCredentials;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultRdpCredentialsScreen(card, api);
