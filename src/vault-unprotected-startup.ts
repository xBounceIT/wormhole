export function mountUnprotectedStartup(
  card: HTMLElement,
  api: {
    openUnprotectedVault(): Promise<boolean>;
    prepareUnprotectedVaultProtection(): Promise<boolean>;
    markStartupReady(): void;
  },
  opened: () => Promise<void>,
): () => void {
  const heading = document.createElement('h1');
  heading.textContent = 'Open your workspace';
  const detail = document.createElement('p');
  detail.textContent =
    'Open this workspace using your operating-system account, or add a Wormhole password and recovery key.';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.className = 'startup-status';
  const open = document.createElement('button');
  open.type = 'button';
  open.className = 'startup-button';
  open.textContent = 'Open workspace';
  const protect = document.createElement('button');
  protect.type = 'button';
  protect.className = 'startup-button-secondary';
  protect.textContent = 'Protect now';
  card.replaceChildren(heading, detail, status, open, protect);
  let disposed = false,
    busy = false,
    admitted = false,
    restarting = false;
  const run = async (prepare: boolean) => {
    if (disposed || busy || restarting) return;
    busy = true;
    open.disabled = protect.disabled = true;
    status.textContent = '';
    try {
      if (prepare) {
        if (await api.prepareUnprotectedVaultProtection()) {
          restarting = true;
          if (!disposed) status.textContent = 'Restarting Wormhole…';
        }
      } else {
        if (!admitted) admitted = await api.openUnprotectedVault();
        if (!disposed && admitted) await opened();
      }
    } catch {
      if (!disposed)
        status.textContent = 'The workspace could not be opened. Try again or choose Protect now.';
    } finally {
      busy = false;
      if (!disposed && !restarting) open.disabled = protect.disabled = false;
    }
  };
  const openClick = () => {
      void run(false);
    },
    protectClick = () => {
      void run(true);
    };
  open.addEventListener('click', openClick);
  protect.addEventListener('click', protectClick);
  api.markStartupReady();
  return () => {
    disposed = true;
    open.disabled = protect.disabled = true;
    open.removeEventListener('click', openClick);
    protect.removeEventListener('click', protectClick);
  };
}
