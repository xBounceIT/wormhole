import type { AdminRecoveryInput } from '../electron/vault-admin-recovery.ts';

export function mountAdminRecovery(
  card: HTMLElement,
  submit: (input: AdminRecoveryInput) => Promise<boolean>,
  close: () => Promise<true>,
) {
  const title = document.createElement('h1');
  title.textContent = 'Recover shared workspace access';
  const instructions = document.createElement('p');
  instructions.textContent =
    'Use the offline recovery kit, its code and the current signed TLS bundle. A DBA must enable the workspace deployer login.';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const field = (
    name: string,
    labelText: string,
    maxLength: number,
    type = 'text',
    required = true,
  ) => {
    const label = document.createElement('label');
    label.textContent = labelText;
    const input = document.createElement('input');
    input.name = name;
    input.type = type;
    input.required = required;
    input.maxLength = maxLength;
    input.autocomplete = 'off';
    input.spellcheck = false;
    label.append(input);
    form.append(label);
    return input;
  };
  const workspace = field('workspaceId', 'Workspace ID', 36);
  const host = field('host', 'PostgreSQL host', 253);
  const port = field('port', 'Port', 5, 'number');
  port.min = '1';
  port.max = '65535';
  port.value = '5432';
  const database = field('database', 'Database', 63);
  const role = field('role', 'Workspace deployer login', 29);
  const deployer = field('deployerPassword', 'Deployer password', 1024, 'password');
  const code = field('recoveryCode', 'Organisation recovery code', 76, 'password');
  const login = field('loginName', 'New administrator login', 256);
  const password = field('accountPassword', 'New Wormhole password', 1024, 'password');
  const confirmation = field('confirmPassword', 'Confirm password', 1024, 'password');
  const ask = field(
    'ask',
    'Account Secret Key (64 hexadecimal characters, when required)',
    64,
    'password',
    false,
  );
  const device = field('deviceName', 'Device name', 256);
  const consent = field(
    'confirmed',
    'I understand that the recovery kit and deployer access together grant control of the workspace.',
    0,
    'checkbox',
  );
  const save = document.createElement('button');
  save.type = 'submit';
  save.className = 'startup-button';
  save.textContent = 'Choose recovery files and continue…';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'startup-button startup-button-secondary';
  cancel.textContent = 'Cancel';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  form.append(save, cancel, status);
  card.replaceChildren(title, instructions, form);
  const clear = () => {
    deployer.value = code.value = password.value = confirmation.value = ask.value = '';
  };
  let disposed = false;
  window.addEventListener(
    'pagehide',
    () => {
      disposed = true;
      clear();
    },
    { once: true },
  );
  cancel.onclick = () => {
    clear();
    void close().catch(() => {
      status.textContent = 'Could not close recovery.';
    });
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (disposed || save.disabled || !consent.checked) return;
    if (
      password.value !== confirmation.value ||
      (ask.value && !/^[0-9a-f]{64}$/i.test(ask.value))
    ) {
      clear();
      status.textContent = 'Check the password confirmation and Account Secret Key.';
      return;
    }
    const encoder = new TextEncoder();
    const askBytes = ask.value
      ? Uint8Array.from(ask.value.match(/../g)!, (pair) => parseInt(pair, 16))
      : undefined;
    const input: AdminRecoveryInput = {
      workspaceId: workspace.value.trim(),
      host: host.value.trim(),
      port: port.valueAsNumber,
      database: database.value.trim(),
      role: role.value.trim(),
      loginName: login.value.trim(),
      deviceName: device.value.trim(),
      confirmed: true,
      recoveryCode: encoder.encode(code.value.trim()),
      deployerPassword: encoder.encode(deployer.value),
      accountPassword: encoder.encode(password.value),
      ...(askBytes ? { ask: askBytes } : {}),
    };
    clear();
    save.disabled = cancel.disabled = true;
    status.textContent = 'Preparing workspace recovery…';
    let completion: Promise<boolean>;
    try {
      completion = submit(input);
    } catch {
      completion = Promise.reject(Error('Workspace recovery is unavailable.'));
    } finally {
      input.recoveryCode.fill(0);
      input.deployerPassword.fill(0);
      input.accountPassword.fill(0);
      input.ask?.fill(0);
    }
    void completion
      .then((finished) => {
        if (!disposed && !finished)
          status.textContent = 'File selection cancelled. Enter the factors to try again.';
      })
      .catch(() => {
        if (!disposed)
          status.textContent =
            'Could not recover access. Check the workspace, files and credentials, then try again with the same administrator login.';
      })
      .finally(() => {
        if (!disposed) save.disabled = cancel.disabled = false;
      });
  };
}
