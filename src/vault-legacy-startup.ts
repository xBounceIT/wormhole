// This screen offers a migration route before any legacy workspace data loads.
// Old-factor verification belongs exclusively to the main-owned native dialog.
export function mountVaultLegacyStartup(
  card: HTMLElement,
  api: {
    prepareLegacyVault(): Promise<boolean>;
    prepareLegacyUnprotectedVault(): Promise<boolean>;
    markStartupReady(): void;
  },
  allowUnprotected: boolean,
): () => void {
  const heading = document.createElement('h1'),
    detail = document.createElement('p'),
    status = document.createElement('p');
  heading.textContent = 'Update your saved workspace';
  detail.textContent =
    'Move your saved secrets into the native vault. Set a Wormhole password and save a recovery key, or continue without an app password when allowed on this computer. Wormhole will restart after preparation.';
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  const protect = document.createElement('button'),
    skip = document.createElement('button');
  protect.type = skip.type = 'button';
  protect.className = skip.className = 'startup-button';
  protect.textContent = 'Set up protection';
  skip.textContent = 'Skip for now';
  card.replaceChildren(heading, detail, status, protect);
  if (allowUnprotected) card.append(skip);
  let busy = false,
    disposed = false,
    restarting = false;
  const run = async (unprotected: boolean) => {
    if (busy || disposed || restarting || (unprotected && !allowUnprotected)) return;
    busy = true;
    protect.disabled = skip.disabled = true;
    status.textContent = 'Continue in the protected window.';
    try {
      restarting = await (unprotected
        ? api.prepareLegacyUnprotectedVault()
        : api.prepareLegacyVault());
      if (!disposed)
        status.textContent = restarting
          ? 'Restarting Wormhole…'
          : 'Preparation cancelled. Choose how to continue.';
    } catch {
      if (!disposed) status.textContent = 'Workspace preparation could not start. Try again.';
    } finally {
      busy = false;
      if (!disposed && !restarting) protect.disabled = skip.disabled = false;
    }
  };
  const protectClick = () => void run(false),
    skipClick = () => void run(true);
  protect.addEventListener('click', protectClick);
  skip.addEventListener('click', skipClick);
  api.markStartupReady();
  return () => {
    disposed = true;
    protect.disabled = skip.disabled = true;
    protect.removeEventListener('click', protectClick);
    skip.removeEventListener('click', skipClick);
  };
}
