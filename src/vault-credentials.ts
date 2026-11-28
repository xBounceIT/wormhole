import { mountVaultCredentialsScreen } from './vault-credentials-screen';
import type { VaultCredentialsApi } from './vault-credentials-screen';
const api = (window as unknown as { vaultCredentials: VaultCredentialsApi }).vaultCredentials;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultCredentialsScreen(card, api);
