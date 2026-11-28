type Api = { resumeVaultMigration(): Promise<boolean>; markStartupReady(): void };

export function mountVaultMigrationStartup(
  card: HTMLElement,
  api: Api,
  opened: () => Promise<void>,
): () => void {
  return mountVaultContinuation(card, api, opened, false);
}

export function mountVaultRootRotationStartup(
  card: HTMLElement,
  api: { resumeVaultRootRotation(): Promise<boolean>; markStartupReady(): void },
  opened: () => Promise<void>,
): () => void {
  return mountVaultContinuation(
    card,
    {
      resumeVaultMigration: () => api.resumeVaultRootRotation(),
      markStartupReady: () => api.markStartupReady(),
    },
    opened,
    true,
  );
}

export function mountVaultOSMigrationStartup(
  card: HTMLElement,
  api: { resumeVaultOSMigration(): Promise<boolean>; markStartupReady(): void },
  opened: () => Promise<void>,
): () => void {
  return mountVaultContinuation(
    card,
    {
      resumeVaultMigration: () => api.resumeVaultOSMigration(),
      markStartupReady: () => api.markStartupReady(),
    },
    opened,
    false,
    true,
  );
}

function mountVaultContinuation(
  card: HTMLElement,
  api: Api,
  opened: () => Promise<void>,
  rotation: boolean,
  osMigration = false,
): () => void {
  const heading = document.createElement('h1');
  heading.textContent = osMigration
    ? 'Finish migrating your workspace'
    : rotation
      ? 'Finish updating vault protection'
      : 'Finish protecting your workspace';
  const detail = document.createElement('p');
  detail.textContent = osMigration
    ? 'Continue moving saved secrets into the vault using your operating-system account.'
    : rotation
      ? 'Use your new Wormhole password or recovery key to finish updating vault protection.'
      : 'Your migration is ready to continue. Use your new Wormhole password or recovery key to finish.';
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'startup-button';
  const continueLabel = rotation ? 'Continue protection update' : 'Continue migration';
  const unfinished = rotation
    ? 'The protection update was not completed.'
    : 'Migration was not completed.';
  button.textContent = continueLabel;
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  card.replaceChildren(heading, detail, status, button);
  let disposed = false,
    busy = false,
    completed = false;
  const run = async () => {
    if (disposed || busy) return;
    busy = true;
    button.disabled = true;
    status.textContent = osMigration
      ? 'Keep Wormhole open while migration finishes.'
      : rotation
        ? 'Confirm your identity in the protected window. Keep Wormhole open while protection is updated.'
        : 'Confirm your identity in the protected window. Keep Wormhole open while the migration finishes.';
    try {
      if (completed || (await api.resumeVaultMigration())) {
        completed = true;
        if (!disposed) await opened();
      } else if (!disposed) status.textContent = `${unfinished} You can try again.`;
    } catch {
      if (!disposed)
        status.textContent = completed
          ? rotation
            ? 'Protection was updated. Try opening your workspace again.'
            : 'Migration finished. Try opening your workspace again.'
          : osMigration
            ? `${unfinished} Try again to resume.`
            : `${unfinished} Your saved recovery key remains valid; try again to resume.`;
    } finally {
      busy = false;
      if (!disposed) {
        button.disabled = false;
        button.textContent = completed ? 'Open workspace' : continueLabel;
      }
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
