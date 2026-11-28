import {
  mountVaultReauthenticationScreen,
  type VaultReauthenticationApi,
} from './vault-reauth-screen';
const api = (window as unknown as { vaultReauthentication: VaultReauthenticationApi })
  .vaultReauthentication;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultReauthenticationScreen(card, api);
