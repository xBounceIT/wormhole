// This startup route never opens the application. The main process retires the
// isolated preparation process and restarts before new-factor recovery.
export function mountVaultUpgradeStartup(
  card: HTMLElement,
  api: { upgradeVaultProtection(): Promise<boolean>; markStartupReady(): void },
): () => void {
  const heading = document.createElement('h1');
  heading.textContent = 'Protect your workspace';
  const detail = document.createElement('p');
  detail.textContent =
    'Set a Wormhole password and save a recovery key to continue. Wormhole will restart after preparation.';
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'startup-button';
  button.textContent = 'Set up protection';
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  card.replaceChildren(heading, detail, status, button);
  let disposed = false,
    busy = false,
    restarting = false;
  const run = async () => {
    if (disposed || busy || restarting) return;
    busy = true;
    button.disabled = true;
    status.textContent = 'Continue in the protected window.';
    try {
      await api.upgradeVaultProtection();
      restarting = true;
      if (!disposed) status.textContent = 'Restarting Wormhole…';
    } catch {
      if (!disposed) status.textContent = 'Protection setup could not start. Try again.';
    } finally {
      busy = false;
      if (!disposed && !restarting) button.disabled = false;
    }
  };
  button.addEventListener('click', run);
  api.markStartupReady();
  return () => {
    disposed = true;
    button.disabled = true;
    button.removeEventListener('click', run);
  };
}
