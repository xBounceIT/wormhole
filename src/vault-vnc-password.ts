import { mountVaultVncPasswordScreen, type VaultVncPasswordApi } from './vault-vnc-password-screen';
const api = (window as unknown as { vaultVncPassword: VaultVncPasswordApi }).vaultVncPassword;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultVncPasswordScreen(card, api);
