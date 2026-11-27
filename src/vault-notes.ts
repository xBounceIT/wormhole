import { mountVaultNotesScreen, type VaultNotesApi } from './vault-notes-screen';
const api = (window as unknown as { vaultNotes: VaultNotesApi }).vaultNotes;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountVaultNotesScreen(card, api);
