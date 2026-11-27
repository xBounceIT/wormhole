import {
  validSharedHBANetworks,
  wipeSharedSetupRequest,
  type SharedAdminSetupRequest,
  type SharedAdminSetupStatus,
  type SharedSetupNetworkAction,
  type SharedSetupPlan,
  type SharedSetupPreflight,
  type SharedSetupReply,
  type SharedSetupRequest,
  type SharedSetupServerKit,
  type SharedSetupTLSCertificates,
} from '../electron/vault-shared-setup-contract.ts';
import { createRecoveryRecipient, type RecoveryRecipient } from './vault-recovery-recipient.ts';
import { mountAdminRecovery } from './vault-admin-recovery-screen.ts';
import type { AdminRecoveryInput } from '../electron/vault-admin-recovery.ts';
import {
  mountSharedAdministration,
  type SharedAdministrationApi,
} from './vault-shared-administration.ts';
import { mountSharedBackup, type SharedBackupApi } from './vault-shared-backup-screen.ts';
import {
  mountSharedAccountResetIssue,
  type SharedAccountResetIssueApi,
} from './vault-shared-account-reset-screen.ts';
import { mountSharedRestore } from './vault-shared-restore-screen.ts';
import {
  importReviewRequest,
  prepareImportReview,
  renderImportReview,
  type ImportReview,
} from './vault-shared-import-review.ts';

export type SharedSetupApi = {
  contentProtectionAvailable?: boolean;
  request(value: SharedSetupRequest): Promise<SharedSetupReply | null>;
  close(): Promise<true>;
};

const failureMessage: Record<NonNullable<SharedSetupReply['failure']>, string> = {
  dns: 'The host name could not be resolved.',
  tcp: 'The PostgreSQL port could not be reached.',
  tls: 'TLS verification failed. Check the server certificate, host name and CA.',
  scram: 'SCRAM authentication failed. Check the DBA login and server authentication settings.',
  'channel-binding':
    'The server did not offer SCRAM-SHA-256-PLUS. Check channel binding on the PostgreSQL endpoint or proxy.',
  database: 'The database is missing or the DBA login cannot access it.',
  'read-write': 'Connect to a writable PostgreSQL server.',
  rejected:
    'PostgreSQL rejected the deployment. Run the connection test again or export the script for the DBA.',
  mismatch:
    'Check the database, workspace identity, schema version, SQL functions and access grants against the deployment script.',
  configuration: 'The connection settings or DBA login are invalid.',
  csr: 'The certificate request could not be signed. Check its signature and the exact DNS names and IP addresses.',
  unavailable: 'The server could not complete the request.',
  'check-required': 'Check deployment to see whether PostgreSQL committed the migrations.',
  'export-failed': 'The script could not be saved. Choose a new file that does not already exist.',
  'invalid-networks':
    'Enter up to 32 IPv4 or IPv6 addresses or CIDR networks. Use the network address for each CIDR range.',
};

export function setupPreflightReady(report: SharedSetupPreflight): boolean {
  return (
    report.serverVersion >= 160000 &&
    report.canCreateRoles &&
    report.ownsDatabase &&
    report.ownsPublicSchema &&
    report.canGrantStatistics &&
    report.emptyDatabase
  );
}

function preflightMessages(report: SharedSetupPreflight): string[] {
  const version = Math.floor(report.serverVersion / 10000);
  const results = [`Verified TLS with SCRAM channel binding. PostgreSQL ${version}.`];
  if (version < 16) results.push('Upgrade PostgreSQL to version 16 or later.');
  if (!report.canCreateRoles) results.push('Use a DBA login permitted to create roles.');
  if (!report.ownsDatabase || !report.ownsPublicSchema)
    results.push('The DBA must own the target database and public schema.');
  if (!report.canGrantStatistics)
    results.push('Ask the DBA for permission to grant pg_read_all_stats.');
  if (!report.emptyDatabase) results.push('Choose an empty database.');
  results.push(...loggingMessages(report));
  return results;
}

function loggingMessages(
  report: Pick<SharedSetupPreflight, 'logsStatements' | 'logsParameters' | 'statementTracking'>,
): string[] {
  const results: string[] = [];
  if (report.logsStatements)
    results.push(
      'PostgreSQL logs statement text for this login. Ask the DBA to check log_statement.',
    );
  if (report.logsParameters)
    results.push(
      'PostgreSQL can log parameter values for this login. Ask the DBA to check log_parameter_max_length and log_parameter_max_length_on_error.',
    );
  if (report.statementTracking === 'all')
    results.push(
      'pg_stat_statements.track is set to all. Ask the DBA to review nested statement tracking.',
    );
  return results;
}

function button(title: string, action: () => void, prominent = false): HTMLButtonElement {
  const node = document.createElement('button');
  node.type = 'button';
  node.className = prominent ? 'startup-button' : 'startup-button startup-button-secondary';
  node.textContent = title;
  node.onclick = action;
  return node;
}

function input(
  name: string,
  label: string,
  type: string,
  container: HTMLElement,
): HTMLInputElement {
  const field = document.createElement('input');
  field.name = name;
  field.type = type;
  field.autocomplete = 'off';
  field.spellcheck = false;
  field.required = true;
  const caption = document.createElement('label');
  caption.append(label, field);
  container.append(caption);
  return field;
}

function textarea(name: string, label: string, maxLength: number): HTMLLabelElement {
  const field = document.createElement('textarea');
  field.name = name;
  field.required = true;
  field.maxLength = maxLength;
  field.spellcheck = false;
  const caption = document.createElement('label');
  caption.append(label, field);
  return caption;
}

function accountSecret(value: string): Uint8Array | undefined {
  return /^[a-f0-9]{64}$/i.test(value)
    ? Uint8Array.from({ length: 32 }, (_, n) => parseInt(value.slice(n * 2, n * 2 + 2), 16))
    : undefined;
}

function csrCommand(hosts: string[]): string | undefined {
  if (
    hosts.length > 64 ||
    hosts.some((host) => host.length > 253 || !/^[a-zA-Z0-9.:-]+$/.test(host))
  )
    return undefined;
  const san = hosts.map(
    (host) => `${host.includes(':') || /^\d+(?:\.\d+){3}$/.test(host) ? 'IP' : 'DNS'}:${host}`,
  );
  return `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout server.key -out server.csr -subj '/CN=Wormhole PostgreSQL' -addext 'subjectAltName=${san.join(',')}'`;
}

export function mountSharedSetup(card: HTMLElement, api: SharedSetupApi): void {
  const title = document.createElement('h1');
  title.textContent = 'Create a shared workspace';
  const content = document.createElement('div');
  const status = document.createElement('p');
  status.className = 'startup-status';
  status.setAttribute('role', 'status');
  const details = document.createElement('ul');
  details.className = 'shared-setup-results';
  const close = button('Close', () => {
    void api.close().catch(() => {
      status.textContent = 'The setup window is busy.';
    });
  });
  card.replaceChildren(title, content, status, details, close);
  for (const kind of ['copy', 'cut', 'dragstart']) {
    card.addEventListener(kind, (event) => {
      if (content.querySelector('code[data-recovery]')?.textContent) event.preventDefault();
    });
  }
  let busy = false;
  let plan: SharedSetupPlan | null = null;
  let certificates: SharedSetupTLSCertificates | undefined;
  let serverKit: SharedSetupServerKit | undefined;
  let tested = false;
  let roleName = '';
  let canJoin = false;
  let joinSwitchesOnRestart = false;
  let importReview: ImportReview | undefined;
  let adminPending = false;
  let adminMode = false;
  let administrator: SharedAdminSetupStatus | undefined;
  let deploymentVerified = false;
  let challenge: [number, number] | undefined;
  let recoveryVisible = false;
  let disposed = false;
  const showResults = (messages: string[]) => {
    details.replaceChildren(
      ...messages.map((message) => {
        const li = document.createElement('li');
        li.textContent = message;
        return li;
      }),
    );
  };

  function clearFactors(root: HTMLElement = content): void {
    for (const node of root.querySelectorAll<HTMLInputElement>('input[type=password]'))
      node.value = '';
    const code = root.querySelector('code[data-recovery]');
    if (code) code.textContent = '';
  }

  async function request(value: SharedSetupRequest, recipient?: RecoveryRecipient): Promise<void> {
    if (busy || disposed) {
      wipeSharedSetupRequest(value);
      recipient?.dispose();
      return;
    }
    busy = true;
    if (value.action === 'check' || value.action === 'plan' || value.action === 'run')
      deploymentVerified = false;
    close.disabled = true;
    clearFactors();
    const fieldset = content.querySelector('fieldset');
    if (fieldset) fieldset.disabled = true;
    showResults([]);
    status.textContent = value.action === 'run' ? 'Deploying the PostgreSQL schema…' : 'Working…';
    try {
      let response: Promise<SharedSetupReply | null>;
      try {
        response = api.request(value);
      } finally {
        wipeSharedSetupRequest(value);
      }
      const result = await response;
      if (disposed) return;
      if (!result) {
        status.textContent = '';
        return;
      }
      if (value.action === 'export-hba') {
        status.textContent =
          result.failure === 'export-failed'
            ? 'Choose a new .conf file to save the client access rules.'
            : result.failure
              ? failureMessage[result.failure]
              : 'Client access rules saved. Include this file before broader host rules in pg_hba.conf, then reload PostgreSQL.';
        return;
      }
      plan = result.plan;
      if (
        value.action === 'plan' ||
        value.action === 'prepare-tls' ||
        value.action === 'prepare-generated-tls' ||
        !plan
      )
        certificates = result.tls;
      if (result.serverKit || value.action === 'plan' || !plan) serverKit = result.serverKit;
      if (value.action === 'plan') {
        canJoin = result.joinAvailable === true;
        joinSwitchesOnRestart = result.joinSwitchesOnRestart === true;
        adminPending = result.adminPending === true;
        administrator = undefined;
        importReview = undefined;
        challenge = undefined;
        recoveryVisible = false;
        adminMode = canJoin && adminPending;
      }
      if (result.adminPending) adminPending = true;
      if (result.administrator) administrator = result.administrator;
      if (result.importPreview) importReview = prepareImportReview(result.importPreview);
      if (value.action === 'preflight')
        tested = !!result.preflight && setupPreflightReady(result.preflight);
      else if (value.action !== 'check') tested = false;
      status.textContent = result.failure ? failureMessage[result.failure] : '';
      if (value.action === 'prepare-tls') {
        if (result.failure) return;
        status.textContent =
          'Install the signed certificate on PostgreSQL, then test the connection.';
      }
      if (value.action === 'prepare-generated-tls')
        status.textContent = 'The server key is encrypted. Save the server files to continue.';
      if (value.action === 'save-server-kit')
        status.textContent =
          'Server files saved. Install them on PostgreSQL, then test the connection.';
      if (
        value.action === 'delete-server-key' &&
        !result.failure &&
        result.serverKit?.state === 'removed'
      )
        status.textContent = 'The local server key was removed.';
      if (result.preflight) showResults(preflightMessages(result.preflight));
      if (result.deployment) {
        deploymentVerified = result.deployment.provisioning && result.deployment.requiresTls;
        status.textContent = result.deployment.provisioning
          ? `Schema ${result.deployment.version} is installed. Workspace setup continues with the first administrator.`
          : `Schema ${result.deployment.version} is installed. PostgreSQL reports the workspace as ready.`;
        const messages: string[] = [];
        if (!result.deployment.requiresTls)
          messages.push('The server is not enforcing TLS for workspace sessions.');
        if (result.checks) {
          const observations = {
            refused:
              'PostgreSQL refused plaintext startup for the workspace deployer from this client.',
            offered:
              'PostgreSQL accepted plaintext startup or offered authentication for the workspace deployer from this client.',
            unconfirmed: 'The plaintext startup check was inconclusive.',
          };
          messages.push(
            observations[result.checks.plainStartup],
            plan?.hosting === 'managed'
              ? 'Ask the DBA to verify the provider’s TLS enforcement and allowed client networks.'
              : 'Ask the DBA to verify pg_hba.conf rule order for all workspace logins and allowed client networks.',
            ...loggingMessages(result.checks),
          );
        }
        showResults(messages);
      } else if (value.action === 'export' && !result.failure) {
        status.textContent =
          'SQL saved. Ask the DBA to run it in the selected database, then choose Check deployment.';
      }
      if (result.recovery) {
        if (!recipient) throw Error('Recovery recipient unavailable.');
        const code = await recipient.open(result.recovery);
        try {
          if (disposed) return;
          challenge = result.recovery.groups;
          recoveryVisible = true;
          render();
          const display = content.querySelector('code[data-recovery]');
          if (!display) throw Error('Recovery display unavailable.');
          display.textContent = new TextDecoder().decode(code);
          status.textContent = 'Recovery kit saved. Record this recovery key offline.';
        } finally {
          code.fill(0);
        }
        return;
      }
      if (result.administrator?.stage === 'recovery-confirmed') challenge = undefined;
      if (value.action === 'admin-confirm' && !result.failure)
        status.textContent = 'Offline recovery confirmed.';
      if (value.action === 'admin-publish' && !result.failure)
        status.textContent = 'Administrator invitation created. Join on this device to finish.';
      if (result.importPreview)
        status.textContent = result.importPreview.confirmation
          ? 'Review the destinations, then confirm the import.'
          : result.importPreview.items.length
            ? 'Review the destinations and account choices.'
            : '';
      render();
    } catch {
      if (!disposed) {
        tested = false;
        if (
          value.action === 'plan' ||
          value.action === 'run' ||
          value.action === 'export' ||
          value.action === 'prepare' ||
          value.action === 'prepare-tls' ||
          value.action === 'prepare-generated-tls' ||
          value.action === 'save-server-kit' ||
          value.action === 'delete-server-key' ||
          value.action === 'discard' ||
          value.action === 'admin-prepare' ||
          value.action === 'admin-confirm' ||
          value.action === 'admin-publish'
        ) {
          // A reply can be lost after the protected plan changed. Reload it
          // before enabling any mutating control in this document.
          content.replaceChildren(
            button('Reload deployment plan', () => void request({ action: 'plan' }), true),
          );
          status.textContent =
            'The request was interrupted. Reload the deployment plan before continuing.';
        } else {
          status.textContent = 'The setup request could not be completed.';
          render();
        }
      }
    } finally {
      recipient?.dispose();
      busy = false;
      if (!disposed) {
        close.disabled = false;
        if (fieldset) fieldset.disabled = false;
      }
    }
  }

  function render(): void {
    const form = document.createElement('form');
    form.className = 'startup-form';
    const fields = document.createElement('fieldset');
    form.append(fields);
    content.replaceChildren(form);

    if (!plan) {
      const hosting = document.createElement('select');
      hosting.name = 'hosting';
      hosting.add(new Option('Self-hosted PostgreSQL', 'self-hosted'));
      hosting.add(new Option('Managed PostgreSQL', 'managed'));
      const label = document.createElement('label');
      label.append('Where PostgreSQL runs', hosting);
      fields.append(label);
      const host = input('host', 'PostgreSQL host', 'text', fields);
      host.maxLength = 253;
      const port = input('port', 'Port', 'number', fields);
      port.min = '1';
      port.max = '65535';
      port.value = '5432';
      const database = input('database', 'Database', 'text', fields);
      database.maxLength = 63;
      const source = document.createElement('select');
      source.name = 'tlsSource';
      source.add(new Option('Wormhole workspace CA', 'workspace'));
      source.add(new Option('Generate for me (encrypted server key)', 'generate'));
      source.add(new Option('Existing server CA', 'external'));
      const sourceLabel = document.createElement('label');
      sourceLabel.append('TLS certificate authority', source);
      const caLabel = textarea('caPem', '', 256 * 1024);
      const caPem = caLabel.querySelector('textarea')!;
      const caCaption = document.createTextNode('Server CA certificate in PEM format');
      caLabel.prepend(caCaption);
      const tlsFields = document.createElement('fieldset');
      const aliases = input(
        'aliases',
        'Additional DNS names or IP addresses, separated by commas',
        'text',
        tlsFields,
      );
      aliases.required = false;
      aliases.maxLength = 16 * 1024;
      const approvedHosts = () => [
        host.value.trim(),
        ...aliases.value.split(/[,\s]+/u).filter(Boolean),
      ];
      const instructions = document.createElement('div');
      const command = document.createElement('pre');
      const commands = button('Show server commands', () => {
        const openssl = csrCommand(approvedHosts());
        if (!openssl) {
          status.textContent = 'Enter valid DNS names or IP addresses.';
          return;
        }
        status.textContent = '';
        command.textContent = `Linux\n(umask 077; test ! -e server.key && test ! -e server.csr && ${openssl})\n\nPowerShell 7\nif ((Test-Path -LiteralPath 'server.key') -or (Test-Path -LiteralPath 'server.csr')) { throw 'Choose an empty directory' }\n${openssl}\nif ($LASTEXITCODE -ne 0) { throw 'OpenSSL could not generate the request' }`;
        instructions.hidden = false;
      });
      const guide = document.createElement('p');
      guide.textContent =
        'Run the command with OpenSSL 3 on the database server in a directory restricted to the PostgreSQL service account. Paste only server.csr here.';
      instructions.append(guide, command);
      instructions.hidden = true;
      const csrLabel = textarea('csr', 'Server certificate request (PEM)', 32 * 1024);
      const csr = csrLabel.querySelector('textarea')!;
      tlsFields.append(commands, instructions, csrLabel);
      const passphraseFields = document.createElement('fieldset');
      const keyPassphrase = input(
        'keyPassphrase',
        'Server key passphrase (at least 16 characters)',
        'password',
        passphraseFields,
      );
      const confirmPassphrase = input(
        'confirmPassphrase',
        'Confirm server key passphrase',
        'password',
        passphraseFields,
      );
      keyPassphrase.maxLength = confirmPassphrase.maxLength = 1024;
      tlsFields.append(passphraseFields);
      const password = input(
        'accountPassword',
        'First administrator password',
        'password',
        tlsFields,
      );
      const confirm = input('confirm', 'Confirm administrator password', 'password', tlsFields);
      const ask = input(
        'ask',
        'Account Secret Key (optional, 64 hexadecimal characters)',
        'password',
        tlsFields,
      );
      password.maxLength = confirm.maxLength = 1024;
      ask.required = false;
      ask.maxLength = 64;
      const layout = () => {
        const managed = hosting.value === 'managed';
        const builtin = !managed && source.value !== 'external';
        const generating = builtin && source.value === 'generate';
        sourceLabel.hidden = managed;
        tlsFields.hidden = tlsFields.disabled = !builtin;
        commands.hidden = csrLabel.hidden = csr.disabled = generating;
        passphraseFields.hidden = passphraseFields.disabled = !generating;
        prepare.textContent = generating
          ? 'Generate server key'
          : builtin
            ? 'Sign certificate request'
            : 'Continue';
        clearFactors(tlsFields);
        caLabel.hidden = caPem.disabled = builtin;
        caCaption.textContent = managed
          ? 'Provider CA bundle in PEM format'
          : 'Server CA certificate in PEM format';
        instructions.hidden = true;
      };
      hosting.onchange = source.onchange = layout;
      host.oninput = aliases.oninput = () => {
        instructions.hidden = true;
      };
      const prepare = button('Continue', () => form.requestSubmit(), true);
      fields.append(sourceLabel, tlsFields, caLabel, prepare);
      layout();
      form.onsubmit = (event) => {
        event.preventDefault();
        const endpoint = {
          host: host.value.trim(),
          port: port.valueAsNumber,
          database: database.value.trim(),
        };
        if (hosting.value === 'managed' || source.value === 'external') {
          void request({
            action: 'prepare',
            ...endpoint,
            hosting: hosting.value === 'managed' ? 'managed' : 'self-hosted',
            caPem: caPem.value.trim(),
          });
          return;
        }
        const accountPassword = new TextEncoder().encode(password.value);
        const askBytes = accountSecret(ask.value);
        if (
          password.value !== confirm.value ||
          (ask.value && !askBytes) ||
          accountPassword.length > 1024
        ) {
          clearFactors();
          accountPassword.fill(0);
          askBytes?.fill(0);
          status.textContent = 'Check the administrator password and Account Secret Key.';
          return;
        }
        const factors = {
          ...endpoint,
          approvedHosts: approvedHosts(),
          accountPassword,
          ...(askBytes ? { ask: askBytes } : {}),
        };
        if (source.value === 'generate') {
          const value = keyPassphrase.value;
          const keyBytes = new TextEncoder().encode(value);
          if (
            value !== confirmPassphrase.value ||
            value === password.value ||
            Array.from(value).length < 16 ||
            keyBytes.length > 1024 ||
            /[\x00\r\n]/.test(value)
          ) {
            keyBytes.fill(0);
            accountPassword.fill(0);
            askBytes?.fill(0);
            clearFactors();
            status.textContent =
              'Enter and confirm a separate server key passphrase of at least 16 characters.';
            return;
          }
          void request({ action: 'prepare-generated-tls', ...factors, keyPassphrase: keyBytes });
          return;
        }
        const publicRequest = csr.value.trim();
        if (
          !publicRequest.startsWith('-----BEGIN CERTIFICATE REQUEST-----') ||
          !publicRequest.endsWith('-----END CERTIFICATE REQUEST-----') ||
          publicRequest.includes('PRIVATE KEY')
        ) {
          csr.value = '';
          clearFactors();
          accountPassword.fill(0);
          askBytes?.fill(0);
          status.textContent = 'Paste the PEM certificate request from the database server.';
          return;
        }
        void request({
          action: 'prepare-tls',
          ...factors,
          csr: publicRequest,
        });
      };
      return;
    }

    const current = plan;
    const target = document.createElement('p');
    const address = current.host.includes(':') ? `[${current.host}]` : current.host;
    target.textContent = `${current.hosting === 'managed' ? 'Managed PostgreSQL' : 'Self-hosted PostgreSQL'} · ${address}:${current.port} · ${current.database}`;
    fields.append(target);
    if (adminMode) {
      renderAdministrator(form, fields, current);
      return;
    }
    if (current.hosting === 'self-hosted') {
      const section = document.createElement('details');
      const summary = document.createElement('summary');
      summary.textContent = 'PostgreSQL client access rules';
      const label = textarea(
        'hbaNetworks',
        'Allowed client IP addresses or CIDR networks, separated by commas or spaces',
        2048,
      );
      const networks = label.querySelector('textarea')!;
      networks.required = false;
      const hint = document.createElement('p');
      hint.textContent =
        'These rules require TLS and SCRAM for the workspace logins. Configure the temporary DBA login separately.';
      section.append(
        summary,
        hint,
        label,
        button('Export pg_hba.conf rules', () => {
          const addresses = networks.value.trim().split(/[,\s]+/u);
          if (!validSharedHBANetworks(addresses)) {
            status.textContent = failureMessage['invalid-networks'];
            return;
          }
          void request({
            action: 'export-hba',
            workspaceId: current.workspaceId,
            networks: addresses,
          });
        }),
      );
      fields.append(section);
    }
    if (serverKit?.state === 'pending') {
      fields.append(
        button(
          'Save server files',
          () => void request({ action: 'save-server-kit', workspaceId: current.workspaceId }),
          true,
        ),
      );
      if (current.state === 'prepared')
        fields.append(
          button(
            'Change database',
            () => void request({ action: 'discard', workspaceId: current.workspaceId }),
          ),
        );
      form.onsubmit = (event) => event.preventDefault();
      return;
    }
    if (serverKit) {
      const folder = input('serverKitFolder', 'Server files folder', 'text', fields);
      folder.value = serverKit.folder;
      folder.readOnly = true;
      folder.required = false;
      if (serverKit.state !== 'removed') {
        const install = document.createElement('p');
        install.textContent =
          'Install the server files on PostgreSQL. Configure ssl_passphrase_command to retrieve the key passphrase from the server’s secret store.';
        fields.append(install);
      }
      if (serverKit.state === 'verified')
        fields.append(
          button(
            'Delete local server key',
            () => void request({ action: 'delete-server-key', workspaceId: current.workspaceId }),
          ),
        );
    } else if (certificates) {
      const content = document.createElement('details');
      content.open = current.state === 'prepared' && !tested;
      const heading = document.createElement('summary');
      heading.textContent = 'PostgreSQL certificates and installation';
      const installation = document.createElement('p');
      installation.textContent =
        'Save the server certificate as server.pem alongside server.key. Enable TLS and point PostgreSQL to these files before testing the connection.';
      const config = document.createElement('pre');
      config.textContent = "ssl = on\nssl_cert_file = 'server.pem'\nssl_key_file = 'server.key'";
      const leaf = textarea('serverCertificate', 'Server certificate (server.pem)', 64 * 1024);
      const root = textarea('workspaceCA', 'Workspace CA certificate', 64 * 1024);
      for (const [label, value] of [
        [leaf, certificates.serverPem],
        [root, certificates.caPem],
      ] as const) {
        const field = label.querySelector('textarea')!;
        field.required = false;
        field.readOnly = true;
        field.value = value;
      }
      content.append(heading, installation, config, leaf, root);
      fields.append(content);
    }
    const role = input('role', 'Temporary DBA login', 'text', fields);
    role.maxLength = 63;
    role.value = roleName;
    const password = input('password', 'DBA password', 'password', fields);
    password.maxLength = 1024;
    const connect = (action: SharedSetupNetworkAction) => {
      if (!form.reportValidity()) return;
      const bytes = new TextEncoder().encode(password.value);
      password.value = '';
      roleName = role.value.trim();
      void request({ action, workspaceId: current.workspaceId, role: roleName, password: bytes });
    };
    const actions = document.createElement('div');
    actions.className = 'shared-setup-actions';
    if (current.state === 'prepared') {
      actions.append(button('Test connection', () => connect('preflight'), !tested));
      const deploy = button('Deploy schema', () => connect('run'), tested);
      deploy.disabled = !tested;
      role.oninput = () => {
        tested = false;
        deploy.disabled = true;
      };
      actions.append(
        deploy,
        button(
          'Export SQL',
          () => void request({ action: 'export', workspaceId: current.workspaceId }),
        ),
      );
      actions.append(
        button(
          'Change database',
          () => void request({ action: 'discard', workspaceId: current.workspaceId }),
        ),
      );
    } else {
      actions.append(button('Check deployment', () => connect('check'), true));
      if (canJoin && (deploymentVerified || adminPending))
        actions.append(
          button(adminPending ? 'Resume administrator setup' : 'Create first administrator', () => {
            adminMode = true;
            clearFactors();
            status.textContent = '';
            render();
          }),
        );
      if (current.state === 'exported')
        actions.append(
          button(
            'Export SQL again',
            () => void request({ action: 'export', workspaceId: current.workspaceId }),
          ),
        );
    }
    fields.append(actions);
    form.onsubmit = (event) => {
      event.preventDefault();
      connect(current.state === 'prepared' ? 'preflight' : 'check');
    };
  }

  function renderAdministrator(
    form: HTMLFormElement,
    fields: HTMLFieldSetElement,
    current: SharedSetupPlan,
  ): void {
    const stage = administrator?.stage;
    const title = document.createElement('h2');
    title.textContent = administrator
      ? `First administrator · ${administrator.loginName}`
      : 'First administrator';
    fields.append(title);
    if (stage === 'recovery-exported' && recoveryVisible && challenge) {
      const code = document.createElement('code');
      code.dataset.recovery = '';
      code.className = 'vault-recovery-code';
      fields.append(code);
      if (api.contentProtectionAvailable === false) {
        const warning = document.createElement('p');
        warning.textContent = 'Screen capture protection is unavailable on this system.';
        fields.append(warning);
      }
      fields.append(
        button(
          'I saved the recovery key',
          () => {
            clearFactors(fields);
            recoveryVisible = false;
            status.textContent = 'Use the saved recovery key to enter the requested groups.';
            render();
          },
          true,
        ),
      );
      form.onsubmit = (event) => event.preventDefault();
      return;
    }
    const prepare = !stage && !adminPending;
    const publish = stage === 'recovery-confirmed';
    const role =
      prepare || publish ? input('role', 'Temporary DBA login', 'text', fields) : undefined;
    if (role) {
      role.maxLength = 63;
      role.value = roleName;
    }
    const dba = role ? input('password', 'DBA password', 'password', fields) : undefined;
    if (dba) dba.maxLength = 1024;
    const login = prepare
      ? input('loginName', 'Administrator login name', 'text', fields)
      : undefined;
    if (login) login.maxLength = 256;
    const profile = prepare ? document.createElement('select') : undefined;
    if (profile) {
      profile.name = 'profile';
      profile.add(new Option('Default', 'default'));
      profile.add(new Option('Standard', 'standard'));
      const label = document.createElement('label');
      label.append('Security profile', profile);
      fields.append(label);
    }
    const password = input(
      'accountPassword',
      prepare && certificates ? 'Administrator password from TLS setup' : 'Administrator password',
      'password',
      fields,
    );
    password.maxLength = 1024;
    const confirm = prepare
      ? input('confirm', 'Confirm administrator password', 'password', fields)
      : undefined;
    if (confirm) confirm.maxLength = 1024;
    const ask = input(
      'ask',
      'Account Secret Key (optional, 64 hexadecimal characters)',
      'password',
      fields,
    );
    ask.required = false;
    ask.maxLength = 64;
    const device =
      stage === 'published' ? input('deviceName', 'Device name', 'text', fields) : undefined;
    if (device) {
      device.value = 'This device';
      device.maxLength = 4096;
    }
    let first: HTMLInputElement | undefined;
    let second: HTMLInputElement | undefined;
    if (stage === 'recovery-exported' && challenge) {
      first = input('groupFirst', `Recovery key group ${challenge[0]}`, 'password', fields);
      second = input('groupSecond', `Recovery key group ${challenge[1]}`, 'password', fields);
      for (const entry of [first, second]) {
        entry.maxLength = 5;
        entry.required = false;
      }
    }

    async function submit(
      action: SharedAdminSetupRequest['action'],
      importConfirmation?: string,
    ): Promise<void> {
      if (busy || disposed || !form.reportValidity()) return;
      const rawAsk = ask.value;
      const accountPassword = new TextEncoder().encode(password.value);
      const askBytes = accountSecret(rawAsk);
      const factors = {
        workspaceId: current.workspaceId,
        accountPassword,
        ...(askBytes ? { ask: askBytes } : {}),
      };
      let value: SharedAdminSetupRequest | undefined;
      let recipient: RecoveryRecipient | undefined;
      try {
        if (
          (confirm && password.value !== confirm.value) ||
          (rawAsk && !askBytes) ||
          accountPassword.length > 1024
        ) {
          status.textContent = 'Check the administrator password and Account Secret Key.';
          return;
        }
        switch (action) {
          case 'admin-prepare':
            if (!login || !profile || !role || !dba) return;
            roleName = role.value.trim();
            value = {
              ...factors,
              action,
              role: roleName,
              password: new TextEncoder().encode(dba.value),
              loginName: login.value.trim().toLowerCase().normalize('NFC'),
              profile: profile.value === 'standard' ? 'standard' : 'default',
            };
            break;
          case 'admin-open':
          case 'admin-import-start':
            value = { ...factors, action };
            break;
          case 'admin-recovery':
            // Claim the screen before creating the asynchronous one-use key.
            fields.disabled = true;
            clearFactors();
            recipient = await createRecoveryRecipient();
            value = { ...factors, action, recipient: recipient.publicKey.slice() };
            break;
          case 'admin-confirm': {
            const groups = `${first?.value.trim().toUpperCase() ?? ''}${second?.value.trim().toUpperCase() ?? ''}`;
            if (
              !administrator ||
              first?.value.trim().length !== 5 ||
              second?.value.trim().length !== 5 ||
              !/^[A-Z2-7]{10}$/.test(groups)
            ) {
              status.textContent = 'Enter the two requested groups from the saved recovery key.';
              return;
            }
            value = {
              ...factors,
              action,
              enrollmentId: administrator.enrollmentId,
              groups: new TextEncoder().encode(groups),
            };
            break;
          }
          case 'admin-publish':
            if (!role || !dba) return;
            roleName = role.value.trim();
            value = {
              ...factors,
              action,
              role: roleName,
              password: new TextEncoder().encode(dba.value),
            };
            break;
          case 'admin-join':
            if (!device) return;
            value = {
              ...factors,
              action,
              deviceName: device.value.trim(),
              ...(importConfirmation ? { importConfirmation } : {}),
            };
            break;
        }
        if (value) await request(value, recipient);
      } catch {
        status.textContent = 'The protected recovery display could not be opened.';
      } finally {
        clearFactors(fields);
        accountPassword.fill(0);
        askBytes?.fill(0);
        wipeSharedSetupRequest(value);
        recipient?.dispose();
        if (!disposed) fields.disabled = false;
      }
    }
    const actions = document.createElement('div');
    actions.className = 'shared-setup-actions';
    const action: SharedAdminSetupRequest['action'] = !stage
      ? prepare
        ? 'admin-prepare'
        : 'admin-open'
      : stage === 'published'
        ? 'admin-join'
        : publish
          ? 'admin-publish'
          : challenge
            ? 'admin-confirm'
            : 'admin-recovery';
    const labels: Record<SharedAdminSetupRequest['action'], string> = {
      'admin-prepare': 'Prepare administrator',
      'admin-open': 'Unlock setup',
      'admin-import-start': 'Preview local import',
      'admin-recovery': 'Save recovery kit and show key',
      'admin-confirm': 'Confirm offline recovery',
      'admin-publish': 'Create administrator invitation',
      'admin-join': joinSwitchesOnRestart ? 'Join and switch on restart' : 'Join workspace',
    };
    const review = stage === 'published' && joinSwitchesOnRestart ? importReview : undefined;
    const approved = () => (review && !review.dirty ? review.preview.confirmation : undefined);
    const importAndJoin = () => {
      const token = approved();
      if (token) void submit('admin-join', token);
    };
    if (review) {
      const apply = button('Import and switch on restart', importAndJoin, true);
      const check = button(
        'Review selections',
        () => void request(importReviewRequest(current.workspaceId, review)),
      );
      const readiness = () => {
        apply.disabled = !approved();
        check.disabled = review.preview.items.length === 0 || !!approved();
      };
      renderImportReview(fields, review, readiness);
      readiness();
      actions.append(
        apply,
        check,
        button('Join without importing', () => void submit('admin-join')),
      );
    } else {
      actions.append(button(labels[action], () => void submit(action), true));
      if (action === 'admin-join' && joinSwitchesOnRestart)
        actions.append(
          button(labels['admin-import-start'], () => void submit('admin-import-start')),
        );
    }
    if (action === 'admin-confirm')
      actions.append(button(labels['admin-recovery'], () => void submit('admin-recovery')));
    actions.append(
      button('Deployment', () => {
        clearFactors();
        adminMode = false;
        render();
      }),
    );
    fields.append(actions);
    form.onsubmit = (event) => {
      event.preventDefault();
      if (review) importAndJoin();
      else void submit(action);
    };
  }

  window.addEventListener(
    'pagehide',
    () => {
      disposed = true;
      clearFactors();
    },
    { once: true },
  );
  void request({ action: 'plan' });
}

const card =
  typeof document === 'undefined'
    ? null
    : document.querySelector<HTMLElement>('.shared-setup-card');
if (card) {
  const api = (
    window as unknown as {
      vaultSharedSetup: SharedSetupApi &
        SharedBackupApi &
        SharedAdministrationApi &
        SharedAccountResetIssueApi & {
          mode?: () => Promise<
            | 'setup'
            | 'recovery'
            | 'backup'
            | 'restore'
            | 'account-reset'
            | 'administration'
            | 'my-devices'
          >;
          recover?: (input: AdminRecoveryInput) => Promise<boolean>;
          inspectBackup: Parameters<typeof mountSharedRestore>[1];
          applyBackup: Parameters<typeof mountSharedRestore>[3];
        };
    }
  ).vaultSharedSetup;
  if (api)
    void (api.mode?.() ?? Promise.resolve('setup'))
      .then(async (mode) => {
        if (mode === 'recovery' && api.recover) mountAdminRecovery(card, api.recover, api.close);
        if (mode === 'setup') mountSharedSetup(card, api);
        if (mode === 'backup') await mountSharedBackup(card, api);
        if (mode === 'account-reset') await mountSharedAccountResetIssue(card, api);
        if (mode === 'administration' || mode === 'my-devices')
          mountSharedAdministration(card, api, mode === 'my-devices');
        if (mode === 'restore')
          mountSharedRestore(card, api.inspectBackup, api.close, api.applyBackup);
      })
      .catch(() => {
        card.textContent = 'Shared workspace setup is unavailable.';
      });
}
