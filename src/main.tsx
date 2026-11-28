import {
  mountVaultMigrationStartup,
  mountVaultRootRotationStartup,
  mountVaultOSMigrationStartup,
} from './vault-migration-startup';
import { mountVaultUnlockScreen } from './vault-unlock-screen';
import { mountVaultUpgradeStartup } from './vault-upgrade-startup';
import { mountUnprotectedStartup } from './vault-unprotected-startup';
import { mountVaultLegacyStartup } from './vault-legacy-startup';
import { mountSharedStartup } from './vault-shared-startup';
import type { SharedVaultSessionAdmission } from '../electron/vault-shared-unlock';
import type { VaultDescriptor } from '../electron/vault-contract';
import startupLogo from '../Assets/wormhole-logo-transparent.png';
import { tooltipDarkColor, tooltipLightColor } from '../electron/tree-tooltip';
import { applyTheme, clearLegacyTheme, getInitialTheme, readLegacyTheme } from './theme';

window.addEventListener('error', () => window.wormhole?.reportRendererFailure('uncaught-error'));
window.addEventListener('unhandledrejection', () =>
  window.wormhole?.reportRendererFailure('unhandled-rejection'),
);

// Resolve the stored/system theme before React renders so the very first painted
// frame already has the correct background. Deferring this to a post-mount effect
// leaves a light-theme frame visible until the `.dark` class lands — the startup
// flash.
const legacyTheme = readLegacyTheme();
applyTheme(getInitialTheme(legacyTheme));

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Wormhole startup root is missing.');
const root: HTMLElement = rootElement;

let workspaceModulePromise: Promise<typeof import('./WorkspaceRoot')> | undefined;
let startupRequest: Promise<WormholeStartupSnapshot> | undefined;
let startupGeneration = 0;
let disposeWorkspace: (() => void) | undefined;
let disposeVaultUnlock: (() => void) | undefined;

function showVaultLock() {
  startupGeneration++;
  disposeWorkspace?.();
  disposeWorkspace = undefined;
  disposeVaultUnlock?.();
  disposeVaultUnlock = undefined;
  startupRequest = undefined;
  const card = renderCard('Wormhole is locked', 'Unlock to load your connections.', 'lock');
  const retry = document.createElement('button');
  retry.className = 'startup-button';
  retry.type = 'button';
  retry.textContent = 'Unlock';
  retry.addEventListener('click', () => {
    renderLoading();
    void bootstrap();
  });
  card.append(retry);
}
window.wormhole?.onVaultLocked(showVaultLock);

function loadWorkspaceModule() {
  workspaceModulePromise ??= import('./WorkspaceRoot').catch((error) => {
    workspaceModulePromise = undefined;
    throw error;
  });
  return workspaceModulePromise;
}

function renderLoading() {
  root.innerHTML = `
    <main class="startup-shell startup-loading-shell">
      <div class="startup-loading" role="status" aria-label="Wormhole is loading">
        <div class="startup-logo-stage" aria-label="Wormhole">
          <img class="startup-logo startup-logo-base" src="${startupLogo}" alt="" />
          <img class="startup-logo startup-logo-shine" src="${startupLogo}" alt="" aria-hidden="true" />
        </div>
      </div>
    </main>`;
}

function renderCard(title: string, detail: string, icon: 'key' | 'lock' = 'key'): HTMLElement {
  root.innerHTML = `
    <main class="startup-shell">
      <section class="startup-card">
        <div class="startup-heading">
          <span class="startup-mark-box">
            <svg aria-hidden="true" class="startup-mark startup-mark-${icon}" viewBox="0 0 24 24">
              ${
                icon === 'lock'
                  ? '<rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>'
                  : '<path d="M12 3a5 5 0 0 0-3.54 8.54L5 15v4h4v-2h2v-2h1.17A5 5 0 1 0 12 3Zm0 2a3 3 0 1 1 0 6 3 3 0 0 1 0-6Z"></path>'
              }
            </svg>
          </span>
          <span>
            <strong></strong>
            <small></small>
          </span>
        </div>
      </section>
    </main>`;
  root.querySelector('strong')!.textContent = title;
  root.querySelector('small')!.textContent = detail;
  return root.querySelector('.startup-card')!;
}

function showError(message: string) {
  window.wormhole?.markStartupReady();
  const card = renderCard("Wormhole couldn't open", message);
  const retry = document.createElement('button');
  retry.className = 'startup-button';
  retry.type = 'button';
  retry.textContent = 'Try again';
  retry.addEventListener('click', () => {
    startupRequest = undefined;
    renderLoading();
    void bootstrap();
  });
  card.append(retry);
}

async function mountWorkspace(
  startup: WormholeStartupSnapshot,
  workspace: WormholeWorkspaceSnapshot,
) {
  renderLoading();
  try {
    const { mountWorkspaceApp } = await loadWorkspaceModule();
    disposeWorkspace = mountWorkspaceApp(root, {
      initialAuthState: startup.auth,
      initialSettings: startup.settings,
      initialWorkspace: workspace,
    });
  } catch (error) {
    window.wormhole?.reportRendererFailure('workspace-mount');
    showError(error instanceof Error ? error.message : "Wormhole couldn't load the workspace.");
  }
}

function showUnlock(startup: WormholeStartupSnapshot) {
  const { auth } = startup;
  const method: WormholeAuthFallback =
    auth.mode === 'password' || (auth.mode === 'windowsHello' && auth.fallback === 'password')
      ? 'password'
      : 'pin';
  const isHelloMode = auth.mode === 'windowsHello';
  const fallbackName = method === 'pin' ? 'Wormhole PIN' : 'Wormhole password';
  const card = renderCard('Wormhole is locked', 'Unlock to load your connections.', 'lock');
  window.wormhole?.markStartupReady();
  let busy = false;

  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.htmlFor = 'startup-secret';
  label.textContent = fallbackName;
  const input = document.createElement('input');
  input.autocomplete = 'current-password';
  input.id = 'startup-secret';
  input.placeholder = `Enter your ${method === 'pin' ? 'Wormhole PIN' : 'password'}`;
  input.type = 'password';
  if (method === 'pin') input.inputMode = 'numeric';
  const passwordField = document.createElement('div');
  passwordField.className = 'startup-password-field';
  const visibility = document.createElement('button');
  visibility.className = 'startup-password-toggle';
  visibility.type = 'button';
  visibility.setAttribute('aria-controls', input.id);
  const tooltip = document.createElement('span');
  tooltip.className = 'startup-tooltip';
  tooltip.setAttribute('role', 'tooltip');
  tooltip.style.setProperty('--tooltip-dark', tooltipDarkColor);
  tooltip.style.setProperty('--tooltip-light', tooltipLightColor);
  function setPasswordVisible(visible: boolean) {
    input.type = visible ? 'text' : 'password';
    const label = visible ? 'Hide password' : 'Show password';
    visibility.innerHTML = `
      <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        ${
          visible
            ? '<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49M14.084 14.158a3 3 0 0 1-4.242-4.242M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143M2 2l20 20" />'
            : '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0" /><circle cx="12" cy="12" r="3" />'
        }
      </svg>`;
    visibility.setAttribute('aria-label', label);
    tooltip.textContent = label;
    visibility.setAttribute('aria-pressed', String(visible));
  }
  setPasswordVisible(false);
  visibility.addEventListener('click', () => {
    if (!busy) setPasswordVisible(input.type === 'password');
  });
  passwordField.append(input, visibility, tooltip);
  const status = document.createElement('p');
  status.className = 'startup-status';
  const submit = document.createElement('button');
  submit.className = 'startup-button';
  submit.disabled = true;
  submit.type = 'submit';
  submit.textContent = 'Unlock';
  input.addEventListener('input', () => {
    submit.disabled = busy || input.value.length === 0;
  });
  form.append(label, passwordField, status, submit);

  const hello = document.createElement('button');
  hello.className = 'startup-button startup-button-secondary';
  hello.type = 'button';
  hello.textContent = 'Use Windows Hello';
  hello.addEventListener('click', () => void tryWindowsHello());

  async function tryWindowsHello() {
    if (busy || !window.wormhole) return;
    const api = window.wormhole;
    busy = true;
    input.disabled = true;
    visibility.disabled = true;
    setPasswordVisible(false);
    submit.disabled = true;
    status.textContent = 'Waiting for Windows Hello…';
    const checkAvailability = async () => {
      const availability = await api.checkWindowsHello().catch((error: unknown) => {
        hello.remove();
        throw error;
      });
      if (!availability.available) {
        hello.remove();
        status.textContent = `${availability.message} You can use your ${fallbackName} instead.`;
      } else if (!hello.isConnected) {
        card.insertBefore(hello, form);
      }
      return availability.available;
    };
    try {
      if (!(await checkAvailability())) return;
      const result = await api.verifyWindowsHello().catch(() => ({
        succeeded: false,
        message: `Windows Hello couldn't verify you. Try again or use your ${fallbackName}.`,
      }));
      if (!result.succeeded) {
        status.textContent = result.message || `Windows Hello didn't recognize you.`;
        await checkAvailability();
        return;
      }
      try {
        const workspace = await api.loadWorkspace();
        await mountWorkspace(startup, workspace);
      } catch {
        status.textContent = "Wormhole couldn't load the workspace. Try again.";
      }
    } catch {
      status.textContent = `Windows Hello isn't available right now. Use your ${fallbackName}.`;
    } finally {
      busy = false;
      input.disabled = false;
      visibility.disabled = false;
      submit.disabled = input.value.length === 0;
      if (!hello.isConnected) input.focus();
    }
  }

  card.append(form);
  if (!isHelloMode) input.focus();

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const api = window.wormhole;
    if (busy || !input.value || !api) return;
    busy = true;
    input.disabled = true;
    visibility.disabled = true;
    setPasswordVisible(false);
    submit.disabled = true;
    submit.textContent = 'Checking…';
    status.textContent = 'Checking…';
    void api
      .unlockStartup({ method, secret: input.value })
      .then(async (result) => {
        if (!result.succeeded || !result.workspace) {
          input.value = '';
          status.textContent =
            result.message || (method === 'pin' ? 'Invalid PIN.' : 'Invalid password.');
          return;
        }
        input.value = '';
        await mountWorkspace(startup, result.workspace);
      })
      .catch(() => {
        status.textContent = "Wormhole couldn't unlock. Try again.";
      })
      .finally(() => {
        busy = false;
        input.disabled = false;
        visibility.disabled = false;
        submit.disabled = input.value.length === 0;
        submit.textContent = 'Unlock';
        input.focus();
      });
  });

  if (isHelloMode) void tryWindowsHello();
}

function showVaultUnlock(descriptor: VaultDescriptor) {
  const api = window.wormhole!;
  const generation = startupGeneration;
  const card = renderCard('Wormhole is locked', 'Unlock your encrypted workspace.', 'lock');
  api.markStartupReady();
  disposeVaultUnlock?.();
  disposeVaultUnlock = mountVaultUnlockScreen(card, descriptor, api, async () => {
    await loadNativeWorkspace(generation);
  });
}

async function loadNativeWorkspace(generation: number) {
  const api = window.wormhole!;
  const startup = await api.loadStartup();
  if (!startup.workspace || startup.auth.mode !== 'vault')
    throw new Error('Vault workspace unavailable.');
  const { mountWorkspaceApp } = await loadWorkspaceModule();
  if (generation !== startupGeneration) return;
  applyTheme(startup.settings.theme);
  disposeVaultUnlock?.();
  disposeVaultUnlock = undefined;
  disposeWorkspace = mountWorkspaceApp(root, {
    initialAuthState: startup.auth,
    initialSettings: startup.settings,
    initialWorkspace: startup.workspace,
  });
}

function showNewWorkspace(allowUnprotected = false) {
  const api = window.wormhole!;
  const generation = startupGeneration;
  const card = renderCard(
    'Welcome to Wormhole',
    'Create a workspace on this computer and protect it with a password.',
  );
  api.markStartupReady();
  const create = document.createElement('button');
  create.type = 'button';
  create.className = 'startup-button';
  create.textContent = 'Use on this computer';
  const join = document.createElement('button');
  join.type = 'button';
  join.className = 'startup-button';
  join.textContent = 'Join a shared workspace';
  const setup = document.createElement('button');
  setup.type = 'button';
  setup.className = 'startup-button startup-button-secondary';
  setup.textContent = 'Create a shared workspace';
  const recover = document.createElement('button');
  recover.type = 'button';
  recover.className = setup.className;
  recover.textContent = 'Recover shared workspace access';
  const restore = document.createElement('button');
  restore.type = 'button';
  restore.className = setup.className;
  restore.textContent = 'Restore a shared workspace';
  const restoreLocal = document.createElement('button');
  restoreLocal.type = 'button';
  restoreLocal.className = setup.className;
  restoreLocal.textContent = 'Restore an encrypted vault backup';
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  let created = false;
  const skip = document.createElement('button');
  skip.type = 'button';
  skip.className = 'startup-button-secondary';
  skip.textContent = 'Skip for now (Unprotected)';
  const actions = [create, join, setup, recover, restore, restoreLocal, skip];
  const disableActions = (disabled: boolean) => {
    for (const button of actions) button.disabled = disabled;
  };
  create.addEventListener('click', async () => {
    if (create.disabled) return;
    disableActions(true);
    status.textContent = '';
    try {
      if (!created) created = await api.createVault();
      if (generation !== startupGeneration) return;
      if (created) {
        startupRequest = undefined;
        await loadNativeWorkspace(generation);
      } else {
        await bootstrap();
      }
    } catch {
      if (generation === startupGeneration)
        status.textContent = "Wormhole couldn't create your workspace. Try again.";
    } finally {
      disableActions(false);
      if (created) create.textContent = 'Open workspace';
    }
  });
  skip.addEventListener('click', async () => {
    if (skip.disabled || create.disabled) return;
    disableActions(true);
    status.textContent = '';
    try {
      if (!created) created = await api.createUnprotectedVault();
      if (created && generation === startupGeneration) {
        startupRequest = undefined;
        await loadNativeWorkspace(generation);
      }
    } catch {
      if (generation === startupGeneration)
        status.textContent = 'Unprotected setup is unavailable. Set up a password or try again.';
    } finally {
      disableActions(false);
      if (created) create.textContent = skip.textContent = 'Open workspace';
    }
  });
  join.addEventListener('click', async () => {
    if (join.disabled || create.disabled || created) return;
    disableActions(true);
    status.textContent = '';
    try {
      const result = await api.authenticateSharedVault('join-initial');
      if (generation !== startupGeneration) return;
      startupRequest = undefined;
      await bootstrap(result && 'admitted' in result ? result : undefined);
    } catch {
      if (generation === startupGeneration) {
        // A commit or local stage can survive a lost reply. Re-read native
        // selection before offering another invitation or local creation.
        startupRequest = undefined;
        await bootstrap();
      }
    } finally {
      disableActions(created);
    }
  });
  setup.addEventListener('click', async () => {
    if (setup.disabled || create.disabled || created) return;
    disableActions(true);
    status.textContent = '';
    try {
      const result = await api.createSharedWorkspace();
      if (generation !== startupGeneration) return;
      startupRequest = undefined;
      await bootstrap(result && 'admitted' in result ? result : undefined);
    } catch {
      if (generation === startupGeneration) {
        // Join can leave durable recovery state even when its reply is lost.
        startupRequest = undefined;
        await bootstrap();
      }
    } finally {
      disableActions(created);
    }
  });
  recover.onclick = async () => {
    if (recover.disabled || create.disabled || created) return;
    disableActions(true);
    try {
      const result = await api.recoverSharedWorkspace();
      if (generation !== startupGeneration) return;
      startupRequest = undefined;
      await bootstrap(result ?? undefined);
    } catch {
      if (generation === startupGeneration) {
        startupRequest = undefined;
        await bootstrap();
      }
    } finally {
      disableActions(created);
    }
  };
  restore.onclick = async () => {
    if (restore.disabled || create.disabled || created) return;
    disableActions(true);
    status.textContent = '';
    try {
      await api.prepareSharedWorkspaceRestore();
    } catch {
      if (generation === startupGeneration)
        status.textContent = 'Could not open the workspace restore window.';
    } finally {
      disableActions(created);
    }
  };
  restoreLocal.onclick = async () => {
    if (restoreLocal.disabled || create.disabled || created) return;
    disableActions(true);
    status.textContent = '';
    let restored = false;
    try {
      restored = await api.restoreLocalVaultBackup();
      if (restored && generation === startupGeneration)
        status.textContent = 'Restarting to open your restored vault…';
    } catch {
      if (generation === startupGeneration)
        status.textContent = 'Could not restore the encrypted vault backup.';
    } finally {
      if (!restored) disableActions(created);
    }
  };
  card.append(status, create, join, setup, recover, restore, restoreLocal);
  if (allowUnprotected) card.append(skip);
}

async function bootstrap(initialShared?: SharedVaultSessionAdmission) {
  // The full React workspace is fetched only after the static frame can paint. Its parsing then
  // overlaps the single native bootstrap process instead of extending the blank-window phase.
  window.setTimeout(() => void loadWorkspaceModule().catch(() => undefined), 0);
  if (!window.wormhole) {
    showError('Wormhole could not start correctly.');
    return;
  }
  const generation = startupGeneration;
  try {
    const vault = await window.wormhole.loadVaultStartup();
    if (generation !== startupGeneration) return;
    applyTheme(vault.cosmetics.theme);
    if (vault.rotation?.pending) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountVaultRootRotationStartup(
        renderCard('Continue protection update', 'Finish updating your vault.', 'lock'),
        window.wormhole,
        async () => {
          await loadNativeWorkspace(generation);
        },
      );
      return;
    }
    if (vault.osMigration) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountVaultOSMigrationStartup(
        renderCard('Continue migration', 'Finish moving your saved secrets.', 'lock'),
        window.wormhole,
        async () => {
          await loadNativeWorkspace(generation);
        },
      );
      return;
    }
    if (vault.migration?.pending) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountVaultMigrationStartup(
        renderCard('Continue migration', 'Protect your workspace.', 'lock'),
        window.wormhole,
        async () => {
          await loadNativeWorkspace(generation);
        },
      );
      return;
    }
    if (vault.unprotected) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountUnprotectedStartup(
        renderCard('Open workspace', 'This computer', 'lock'),
        window.wormhole,
        async () => {
          await loadNativeWorkspace(generation);
        },
      );
      return;
    }
    if (vault.upgrade) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountVaultUpgradeStartup(
        renderCard('Protect workspace', 'Set up your vault protection.', 'lock'),
        window.wormhole,
      );
      return;
    }
    if (vault.shared || vault.sharedJoin) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountSharedStartup(
        renderCard('Shared workspace', 'Sign in to continue.', 'lock'),
        vault,
        window.wormhole,
        async (container, failed, tools) => {
          const { mountSharedWorkspace } = await import('./vault-shared-workspace');
          return mountSharedWorkspace(container, window.wormhole!, failed, tools);
        },
        initialShared,
      );
      window.wormhole.markStartupReady();
      return;
    }
    if (vault.slots) {
      showVaultUnlock(vault.slots);
      return;
    }
    if (vault.newWorkspace) {
      showNewWorkspace(vault.unprotectedAllowed === true);
      return;
    }
    if (vault.legacy) {
      disposeVaultUnlock?.();
      disposeVaultUnlock = mountVaultLegacyStartup(
        renderCard('Update workspace', 'Move your saved secrets.', 'lock'),
        window.wormhole,
        vault.legacy.unprotectedAllowed,
      );
      return;
    }
    startupRequest ??= window.wormhole.loadStartup(legacyTheme ?? undefined).then((startup) => {
      applyTheme(startup.settings.theme);
      if (startup.themeMigration.handled) clearLegacyTheme();
      return startup;
    });
    const startup = await startupRequest;
    if (generation !== startupGeneration) return;
    if (startup.auth.configured) {
      showUnlock(startup);
      return;
    }
    if (!startup.workspace) throw new Error('Wormhole could not load the workspace.');
    await mountWorkspace(startup, startup.workspace);
  } catch (error) {
    if (generation !== startupGeneration) return;
    if (initialShared) await window.wormhole?.lockAuthentication().catch(() => undefined);
    if (generation !== startupGeneration) return;
    startupRequest = undefined;
    showError(error instanceof Error ? error.message : "Wormhole couldn't start.");
  }
}

void bootstrap();
