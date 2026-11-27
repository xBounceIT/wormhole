import {
  mountSharedAuthenticationScreen,
  type SharedAuthenticationApi,
} from './vault-shared-screen';
const api = (window as unknown as { vaultSharedAuthentication: SharedAuthenticationApi })
  .vaultSharedAuthentication;
const card = document.querySelector<HTMLElement>('.startup-card');
if (api && card) mountSharedAuthenticationScreen(card, api);
