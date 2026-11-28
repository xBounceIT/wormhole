import { parseVaultMigrationContext } from '../electron/vault-migration-setup';
import { parseVaultRootEnrollmentContext } from '../electron/vault-root-enrollment-contract';
import { parseVaultUpgradeContext } from '../electron/vault-upgrade-contract';
import { mountVaultCreateScreen, type VaultCreateApi } from './vault-create-screen';
import { mountVaultOSMigrationScreen, type VaultOSMigrationApi } from './vault-os-migration-screen';
const api = (window as unknown as { vaultCreate: VaultCreateApi }).vaultCreate;
const osApi = (window as unknown as { vaultOSMigration?: VaultOSMigrationApi }).vaultOSMigration;
const card = document.querySelector<HTMLElement>('.startup-card');
if (osApi && card) {
  void osApi
    .context()
    .then((value) => {
      const context = parseVaultMigrationContext(value);
      if (!context) throw Error('Invalid migration context.');
      const dispose = mountVaultOSMigrationScreen(card, osApi, context);
      window.addEventListener('pagehide', dispose, { once: true });
    })
    .catch(() => {
      const status = document.createElement('p'),
        cancel = document.createElement('button');
      status.textContent = 'Existing authentication is unavailable. Cancel and try again.';
      cancel.textContent = 'Cancel';
      cancel.className = 'startup-button';
      cancel.addEventListener('click', () => {
        void osApi.cancel().catch(() => undefined);
      });
      card.replaceChildren(status, cancel);
    });
} else if (api && card) {
  if (!api.migrationContext && !api.rotationContext && !api.upgradeContext)
    mountVaultCreateScreen(card, api);
  else
    void (
      api.upgradeContext
        ? api.upgradeContext()
        : api.rotationContext
          ? api.rotationContext()
          : api.migrationContext!()
    )
      .then((value) => {
        if (api.upgradeContext) {
          const context = parseVaultUpgradeContext(value);
          if (!context) throw Error('Invalid vault upgrade context.');
          mountVaultCreateScreen(card, api, undefined, undefined, context);
          return;
        }
        if (api.rotationContext) {
          const context = parseVaultRootEnrollmentContext(value);
          if (!context) throw Error('Invalid vault protection context.');
          mountVaultCreateScreen(card, api, undefined, context);
          return;
        }
        const context = parseVaultMigrationContext(value);
        if (!context) throw Error('Invalid migration context.');
        mountVaultCreateScreen(card, api, context);
      })
      .catch(() => {
        const status = document.createElement('p');
        status.textContent = 'Existing authentication is unavailable. Cancel and try again.';
        const cancel = document.createElement('button');
        cancel.textContent = 'Cancel';
        cancel.className = 'startup-button';
        cancel.addEventListener('click', () => {
          void api.cancel().catch(() => undefined);
        });
        card.replaceChildren(status, cancel);
      });
}
