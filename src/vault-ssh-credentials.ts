import {
  mountVaultSshCredentialsScreen,
  type VaultSshCredentialsApi,
} from './vault-ssh-credentials-screen';
const api = (window as unknown as { vaultSshCredentials: VaultSshCredentialsApi })
  .vaultSshCredentials;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultSshCredentialsScreen(card, api);
