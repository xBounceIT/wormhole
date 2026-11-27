import type {
  SharedRecoveryInspection,
  SharedRecoveryInspectionRequest,
  SharedRecoveryRestoreRequest,
  SharedRecoveryRestoreStatus,
} from '../electron/vault-shared-restore.ts';

export function mountSharedRestore(
  card: HTMLElement,
  inspect: (input: SharedRecoveryInspectionRequest) => Promise<SharedRecoveryInspection | null>,
  close: () => Promise<true>,
  apply?: (input: SharedRecoveryRestoreRequest) => Promise<SharedRecoveryRestoreStatus>,
) {
  const title = document.createElement('h1');
  title.textContent = 'Restore a shared workspace';
  const description = document.createElement('p');
  description.textContent =
    'Open an encrypted workspace backup with its recovery password. Use the deployment SQL to prepare the new cluster with the original workspace ID and role tag.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.textContent = 'Backup recovery password';
  const password = document.createElement('input');
  password.type = 'password';
  password.autocomplete = 'off';
  password.spellcheck = false;
  password.required = true;
  password.maxLength = 76;
  label.append(password);
  const open = document.createElement('button');
  open.type = 'submit';
  open.formNoValidate = true;
  open.className = 'startup-button';
  open.textContent = 'Inspect backup…';
  const save = document.createElement('button');
  save.type = 'submit';
  save.formNoValidate = true;
  save.className = 'startup-button startup-button-secondary';
  save.textContent = 'Save deployment SQL…';
  const destination = document.createElement('fieldset');
  destination.hidden = true;
  const legend = document.createElement('legend');
  legend.textContent = 'Restore destination';
  const login = document.createElement('p');
  destination.append(legend, login);
  const targetField = (name: string, text: string, type: string, limit: number) => {
    const label = document.createElement('label');
    label.textContent = text;
    const field = document.createElement('input');
    field.name = name;
    field.type = type;
    field.maxLength = limit;
    field.autocomplete = 'off';
    field.spellcheck = false;
    label.append(field);
    destination.append(label);
    return field;
  };
  const host = targetField('host', 'Host approved by the backup TLS bundle', 'text', 253);
  const port = targetField('port', 'Port', 'number', 5);
  port.min = '1';
  port.max = '65535';
  port.value = '5432';
  const database = targetField('database', 'Database', 'text', 63);
  const deployer = targetField('deployerPassword', 'Deployer password', 'password', 1024);
  const confirmation = targetField(
    'confirmed',
    'I confirm this is the intended empty destination database.',
    'checkbox',
    0,
  );
  const restore = document.createElement('button');
  restore.type = 'submit';
  restore.className = 'startup-button';
  restore.textContent = 'Restore to PostgreSQL';
  destination.append(restore);
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = save.className;
  cancel.textContent = 'Close';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const details = document.createElement('ul');
  details.className = 'shared-setup-results';
  form.append(label, open, save, destination);
  card.replaceChildren(title, description, form, status, details, cancel);

  let disposed = false;
  window.addEventListener(
    'pagehide',
    () => {
      disposed = true;
      password.value = deployer.value = '';
      details.replaceChildren();
    },
    { once: true },
  );
  cancel.onclick = () => {
    password.value = deployer.value = '';
    details.replaceChildren();
    void close().catch(() => {
      if (!disposed) status.textContent = 'Could not close the restore window.';
    });
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (disposed || open.disabled) return;
    const applying = event.submitter === restore;
    if (
      applying &&
      (destination.hidden ||
        !apply ||
        !confirmation.checked ||
        !host.value.trim() ||
        !database.value.trim() ||
        !port.validity.valid ||
        !port.value ||
        !deployer.value)
    ) {
      status.textContent =
        'Enter the destination and deployer password, then confirm the database.';
      return;
    }
    const code = new TextEncoder().encode(password.value.trim());
    password.value = '';
    if (code.length !== 76) {
      code.fill(0);
      status.textContent = 'Enter the full backup recovery password.';
      return;
    }
    const deployerPassword = applying ? new TextEncoder().encode(deployer.value) : undefined;
    deployer.value = '';
    confirmation.checked = false;
    if (!applying) {
      details.replaceChildren();
      destination.hidden = true;
    }
    password.disabled =
      open.disabled =
      save.disabled =
      cancel.disabled =
      destination.disabled =
        true;
    status.textContent = applying
      ? 'Restoring the workspace in one PostgreSQL transaction…'
      : 'Inspecting the backup…';
    try {
      if (apply && deployerPassword) {
        let pending: ReturnType<typeof apply>;
        try {
          pending = apply({
            host: host.value.trim(),
            port: port.valueAsNumber,
            database: database.value.trim(),
            confirmed: true,
            password: code,
            deployerPassword,
          });
        } finally {
          code.fill(0);
          deployerPassword.fill(0);
        }
        const result = await pending;
        if (disposed) return;
        if (
          result === 'restored' ||
          result === 'already-restored' ||
          result === 'archive-changed' ||
          result === 'invalid-backup'
        )
          destination.hidden = true;
        if (result === 'archive-changed' || result === 'invalid-backup') details.replaceChildren();
        status.textContent = {
          restored: 'Workspace restored. Recover administrator access before enrolling devices.',
          'already-restored': 'This backup was already restored to the destination.',
          'invalid-backup': 'Could not reopen the backup. Inspect it again.',
          'invalid-password': 'The backup recovery password was not accepted.',
          'archive-changed': 'The backup changed. Inspect it again before restoring.',
          'logging-enabled':
            'Disable PostgreSQL parameter logging for the deployer login, then retry.',
          uncertain:
            'The restore result could not be confirmed. Retry with the same backup and destination.',
          rejected: 'Could not restore. Check the empty deployment, TLS and deployer credentials.',
        }[result];
        return;
      }
      let pending: ReturnType<typeof inspect>;
      try {
        pending = inspect({ password: code, saveScript: event.submitter === save });
      } finally {
        code.fill(0);
      }
      const result = await pending;
      if (disposed) return;
      if (result === null) {
        status.textContent = 'File selection cancelled.';
      } else if (!('summary' in result)) {
        status.textContent =
          result.status === 'invalid-password'
            ? 'The backup recovery password was not accepted.'
            : 'Could not authenticate the workspace backup.';
      } else {
        const summary = result.summary;
        if (apply) {
          login.textContent = `Deployer login wh_${summary.roleTag}_deployer`;
          destination.hidden = false;
        }
        for (const message of [
          `Workspace ID ${summary.workspaceId}`,
          `Role tag ${summary.roleTag}`,
          `Source schema ${summary.sourceSchemaVersion} · ${summary.profile === 'standard' ? 'Standard' : 'Default'}`,
          `${summary.accounts} archived accounts · ${summary.nodes} archived nodes`,
        ]) {
          const item = document.createElement('li');
          item.textContent = message;
          details.append(item);
        }
        status.textContent =
          result.status === 'saved'
            ? 'Deployment SQL saved. Run it on the dedicated destination before restoring.'
            : result.status === 'save-failed'
              ? 'Could not save the SQL. Choose a new file in a writable folder.'
              : 'Backup authenticated. You can save the deployment SQL.';
      }
    } catch {
      if (!disposed)
        status.textContent = applying
          ? 'The restore result could not be confirmed. Retry with the same backup and destination.'
          : 'Could not inspect the workspace backup.';
    } finally {
      if (!disposed)
        password.disabled =
          open.disabled =
          save.disabled =
          cancel.disabled =
          destination.disabled =
            false;
    }
  };
}
