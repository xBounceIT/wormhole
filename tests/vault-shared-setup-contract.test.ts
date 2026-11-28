import assert from 'node:assert/strict';
import test from 'node:test';
import {
  consumeSharedSetupRequest,
  parseSharedCertificateRenewalRequest,
  parseSharedCertificateRenewalResult,
  parseSharedWorkspaceCARequest,
  parseSharedWorkspaceCAResult,
  parseSharedSetupReply,
  parseSharedWorkspaceSwitch,
} from '../electron/vault-shared-setup-contract.ts';

const workspaceId = '11111111-1111-4111-8111-111111111111';
const target = { hosting: 'managed', host: 'db.example.org', port: 5432, database: 'vault' };
const plan = { ...target, workspaceId, roleTag: 'abcd2345abcd2345', state: 'prepared' };
const deployment = { version: 44, provisioning: true, requiresTls: true };
const checks = {
  plainStartup: 'refused',
  maxConnections: 80,
  logsStatements: false,
  logsParameters: false,
  statementTracking: 'top',
};

test('only the native picker supplies the HBA export path and only self-hosted plans return a receipt', () => {
  const request = { action: 'export-hba', workspaceId, networks: ['127.0.0.1', '2001:db8::/64'] };
  assert.deepEqual(consumeSharedSetupRequest(request), request);
  for (const networks of [
    [],
    Array(33).fill('::1'),
    Array(2),
    ['all'],
    ['::1\nhost all all all trust'],
  ]) {
    assert.equal(consumeSharedSetupRequest({ ...request, networks }), undefined);
  }
  assert.equal(consumeSharedSetupRequest({ ...request, path: 'pg_hba.conf' }), undefined);
  assert.equal(parseSharedSetupReply({ plan }, 'export-hba'), undefined);
  const selfHosted = { ...plan, hosting: 'self-hosted' };
  for (const extra of [{}, { failure: 'invalid-networks' }, { failure: 'export-failed' }]) {
    const reply = { plan: selfHosted, ...extra };
    assert.deepEqual(parseSharedSetupReply(reply, 'export-hba', workspaceId), reply);
  }
  assert.equal(
    parseSharedSetupReply({ plan: selfHosted, failure: 'invalid-networks' }, 'check'),
    undefined,
  );
});

test('local import review carries only scoped item selections and resolver decisions', () => {
  const nodeId = '22222222-2222-4222-8222-222222222222';
  const credentialId = '33333333-3333-4333-8333-333333333333';
  const reviewId = '44444444-4444-4444-8444-444444444444';
  const confirmation = '55555555-5555-4555-8555-555555555555';
  const node = { kind: 'node', id: nodeId };
  const credential = { kind: 'credential', id: credentialId };
  const decision = { nodeId, protocolPath: 'ssh', choice: 'keep' };
  const inputs = {
    action: 'import-review',
    workspaceId,
    reviewId,
    shared: [node],
    decisions: [decision],
  };
  assert.deepEqual(consumeSharedSetupRequest(structuredClone(inputs)), inputs);
  for (const changes of [
    { reviewId: 'invalid' },
    { shared: [node, node] },
    { shared: [{ ...node, name: 'extra metadata' }] },
    { decisions: [decision, decision] },
    { decisions: [{ ...decision, protocolPath: 'unknown' }] },
    { decisions: [{ ...decision, choice: 'stale' }] },
  ])
    assert.equal(consumeSharedSetupRequest({ ...inputs, ...changes }), undefined);

  const accountPassword = Uint8Array.from([1, 2, 3]);
  const sent = {
    action: 'admin-join',
    workspaceId,
    accountPassword,
    deviceName: 'Device',
    importConfirmation: confirmation,
  };
  assert.equal(consumeSharedSetupRequest(sent)?.action, 'admin-join');
  assert.deepEqual(accountPassword, new Uint8Array(3));
  assert.equal(
    consumeSharedSetupRequest({
      ...sent,
      accountPassword: Uint8Array.from([9]),
      importConfirmation: '',
    }),
    undefined,
  );
  const report = {
    ...decision,
    oldCredentialId: credentialId,
    newCredentialId: '',
    credentialChanged: true,
    usernameChanged: false,
    domainChanged: false,
    sourceChanged: true,
  };
  const preview = {
    reviewId,
    resolverFingerprint: 'e'.repeat(64),
    items: [
      { ...node, name: 'Host', destination: 'shared' },
      { ...credential, name: 'Account', destination: 'personal' },
    ],
    resolverChanges: [report],
    conflicts: [{ item: node, dependency: credential }],
  };
  const ready = { ...plan, state: 'submitted' };
  const response = { plan: ready, importPreview: preview };
  const decoded = parseSharedSetupReply(response, 'import-review', workspaceId)?.importPreview;
  assert.equal(decoded?.reviewId, reviewId);
  assert.equal(decoded?.resolverChanges[0].credentialChanged, true);
  assert.equal(Object.hasOwn(decoded!.resolverChanges[0], 'oldCredentialId'), false);
  assert.equal(
    parseSharedSetupReply(
      { ...response, importPreview: { ...preview, confirmation } },
      'import-review',
      workspaceId,
    ),
    undefined,
  );
  for (const changes of [
    { resolverFingerprint: 'private' },
    { items: [...preview.items, preview.items[0]] },
    { conflicts: [{ item: credential, dependency: node }] },
    { resolverChanges: [{ ...report, nodeId: credentialId }] },
    { resolverChanges: [{ ...report, credentialChanged: false, sourceChanged: false }] },
    { resolverChanges: [{ ...report, password: 'private' }] },
  ])
    assert.equal(
      parseSharedSetupReply(
        { ...response, importPreview: { ...preview, ...changes } },
        'admin-import-start',
        workspaceId,
      ),
      undefined,
    );
  assert.equal(
    parseSharedSetupReply(
      { ...response, importPreview: { ...preview, conflicts: [], confirmation } },
      'admin-import-start',
      workspaceId,
    )?.importPreview?.confirmation,
    confirmation,
  );
  assert.equal(
    parseSharedSetupReply({ ...response, plan }, 'admin-import-start', workspaceId),
    undefined,
  );
});

test('workspace CA replies match the requested phase and carry only public certificate material', () => {
  const serverPem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
  const csr = '-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n';
  for (const value of [{ action: 'status' }, { action: 'retire' }, { action: 'rotate', csr }])
    assert.deepEqual(parseSharedWorkspaceCARequest(value), value);
  for (const value of [
    null,
    { action: 'status', csr },
    { action: 'rotate' },
    { action: 'retire', csr },
    { action: 'cancel' },
  ])
    assert.equal(parseSharedWorkspaceCARequest(value), undefined);
  const staged = { status: 'staged', serverPem };
  const retirement = { status: 'retired', reconnect: true };
  assert.deepEqual(parseSharedWorkspaceCAResult(staged, 'status'), staged);
  assert.deepEqual(parseSharedWorkspaceCAResult({ ...staged, reconnect: true }, 'rotate'), {
    ...staged,
    reconnect: true,
  });
  assert.deepEqual(parseSharedWorkspaceCAResult(retirement, 'retire'), retirement);
  for (const [status, action] of [
    ['ready', 'status'],
    ['invalid-csr', 'rotate'],
    ['installation-required', 'retire'],
    ['unavailable', 'status'],
  ] as const)
    assert.deepEqual(parseSharedWorkspaceCAResult({ status }, action), { status });
  for (const [value, action] of [
    [null, 'status'],
    [staged, 'rotate'],
    [{ ...staged, reconnect: true }, 'status'],
    [retirement, 'rotate'],
    [{ status: 'ready' }, 'retire'],
    [{ status: 'staged', serverPem: csr }, 'status'],
    [{ ...staged, keyCopy: 'unexpected' }, 'status'],
  ] as const)
    assert.equal(parseSharedWorkspaceCAResult(value, action), undefined);
});

test('server certificate renewal carries only bounded public PEM', () => {
  const csr =
    '-----BEGIN CERTIFICATE REQUEST-----\r\nAAAA\r\n-----END CERTIFICATE REQUEST-----\r\n';
  const serverPem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
  assert.deepEqual(parseSharedCertificateRenewalRequest({ csr }), { csr });
  for (const request of [
    null,
    [csr],
    { csr: serverPem },
    { csr, workspaceId },
    { csr: csr.replace('AAAA', 'A'.repeat(32 * 1024)) },
  ])
    assert.equal(parseSharedCertificateRenewalRequest(request), undefined);
  for (const status of ['invalid-csr', 'unavailable'])
    assert.deepEqual(parseSharedCertificateRenewalResult({ status }), { status });
  assert.deepEqual(parseSharedCertificateRenewalResult({ status: 'issued', serverPem }), {
    status: 'issued',
    serverPem,
  });
  for (const result of [
    null,
    { status: 'issued' },
    { status: 'issued', serverPem: serverPem + serverPem },
    { status: 'issued', serverPem, extra: 'unsupported' },
    { status: 'unavailable', serverPem },
    { status: 'unknown' },
  ])
    assert.equal(parseSharedCertificateRenewalResult(result), undefined);
});

test('generated server key requests wipe their factors and bind public receipts to the workspace', () => {
  const action = 'prepare-generated-tls';
  const input = () => ({
    action,
    host: target.host,
    port: target.port,
    database: target.database,
    approvedHosts: [target.host],
    accountPassword: new Uint8Array([1, 2]),
    keyPassphrase: new TextEncoder().encode('synthetic-independent-key-factor'),
  });
  const submitted = input();
  assert.deepEqual(consumeSharedSetupRequest(submitted), input());
  assert.ok(submitted.accountPassword.every((value) => value === 0));
  assert.ok(submitted.keyPassphrase.every((value) => value === 0));
  for (const changes of [
    { keyPassphrase: new Uint8Array(16).fill(0) },
    { keyPassphrase: new Uint8Array(15).fill(5) },
    { csr: 'mixed options' },
    { path: 'remote folder' },
  ]) {
    const invalid = { ...input(), ...changes };
    assert.equal(consumeSharedSetupRequest(invalid), undefined);
    assert.ok(invalid.accountPassword.every((value) => value === 0));
    assert.ok(invalid.keyPassphrase.every((value) => value === 0));
  }
  const selfHosted = { ...plan, hosting: 'self-hosted' };
  const pem = '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----';
  const tls = { caPem: pem, serverPem: pem };
  const folder = `C:\\Cache\\Wormhole-Server-Setup\\${workspaceId}`;
  const material = { plan: selfHosted, tls };
  const pending = { ...material, serverKit: { folder, state: 'pending' } };
  assert.deepEqual(parseSharedSetupReply(pending, 'prepare-generated-tls'), pending);
  assert.equal(parseSharedSetupReply(pending, 'prepare-tls'), undefined);
  assert.equal(
    parseSharedSetupReply(
      { ...pending, serverKit: { folder: `cache${workspaceId}`, state: 'pending' } },
      action,
    ),
    undefined,
  );
  for (const [verb, state] of [
    ['save-server-kit', 'saved'],
    ['delete-server-key', 'removed'],
  ] as const) {
    const receipt = { ...material, serverKit: { folder, state } };
    assert.deepEqual(parseSharedSetupReply(receipt, verb, workspaceId), receipt);
    assert.deepEqual(consumeSharedSetupRequest({ action: verb, workspaceId }), {
      action: verb,
      workspaceId,
    });
    assert.equal(consumeSharedSetupRequest({ action: verb, workspaceId, path: folder }), undefined);
    assert.equal(parseSharedSetupReply(pending, verb, workspaceId), undefined);
  }
  const checked = {
    plan: { ...selfHosted, state: 'submitted' },
    deployment,
    checks,
    serverKit: { folder, state: 'verified' },
  };
  assert.deepEqual(parseSharedSetupReply(checked, 'check', workspaceId), checked);
  assert.equal(parseSharedSetupReply(checked, 'run', workspaceId), undefined);
  assert.equal(
    parseSharedSetupReply(
      { ...checked, deployment: { ...deployment, requiresTls: false } },
      'check',
      workspaceId,
    ),
    undefined,
  );
  assert.equal(
    parseSharedSetupReply(
      { ...pending, serverKit: { ...pending.serverKit, encryptedKey: 'unexpected' } },
      action,
    ),
    undefined,
  );
});

test('self-hosted CSR setup owns its factors and accepts only public PEM receipts', () => {
  const csr = '-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----';
  const cert = '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n';
  const privatePEM = '-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----';
  const selfHosted = { ...plan, hosting: 'self-hosted' };
  const input = () => ({
    action: 'prepare-tls',
    host: target.host,
    port: target.port,
    database: target.database,
    approvedHosts: [target.host, '127.0.0.1'],
    csr,
    accountPassword: new Uint8Array([1, 2]),
    ask: new Uint8Array(32).fill(5),
  });
  const request = input();
  const consumed = consumeSharedSetupRequest(request);
  assert.deepEqual(consumed, input());
  assert.ok(
    request.accountPassword.every((byte) => byte === 0) && request.ask.every((byte) => byte === 0),
  );
  for (const changes of [
    { csr: privatePEM },
    { csr: csr + privatePEM + csr },
    { hosting: 'managed' },
    { approvedHosts: [] },
    { approvedHosts: ['bad host'] },
    { ask: new Uint8Array(31) },
  ]) {
    const invalid = { ...input(), ...changes };
    assert.equal(consumeSharedSetupRequest(invalid), undefined);
    assert.ok(invalid.accountPassword.every((byte) => byte === 0));
  }
  const tls = { caPem: cert, serverPem: cert };
  const reply = { plan: selfHosted, tls };
  assert.deepEqual(parseSharedSetupReply(reply, 'prepare-tls'), reply);
  assert.deepEqual(parseSharedSetupReply(reply, 'plan'), reply);
  const resumed = { plan: { ...selfHosted, state: 'submitted' }, tls, adminPending: true };
  assert.deepEqual(parseSharedSetupReply(resumed, 'plan'), resumed);
  const failure = { plan: null, failure: 'csr' };
  assert.deepEqual(parseSharedSetupReply(failure, 'prepare-tls'), failure);
  assert.equal(parseSharedSetupReply(failure, 'plan'), undefined);
  for (const invalid of [
    { plan, tls },
    { plan: selfHosted },
    { ...reply, tls: { ...tls, signingKey: privatePEM } },
    { ...reply, tls: { ...tls, caPem: privatePEM } },
    { ...reply, adminPending: true },
    resumed,
  ]) {
    assert.equal(parseSharedSetupReply(invalid, 'prepare-tls'), undefined);
  }
});

test('workspace switch receipt carries only a confirmed restart flag', () => {
  assert.deepEqual(parseSharedWorkspaceSwitch({ switchOnRestart: true }), {
    switchOnRestart: true,
  });
  for (const invalid of [
    null,
    {},
    { switchOnRestart: false },
    { switchOnRestart: 'true' },
    { switchOnRestart: true, vaultId: workspaceId },
    { admitted: true },
  ]) {
    assert.equal(parseSharedWorkspaceSwitch(invalid), undefined);
  }
});

test('accepts public setup input and keeps export destination in the native chooser', () => {
  const draft = { action: 'prepare', ...target, caPem: 'public certificate' };
  assert.deepEqual(consumeSharedSetupRequest(draft), draft);
  assert.deepEqual(consumeSharedSetupRequest({ action: 'plan' }), { action: 'plan' });
  for (const action of ['export', 'discard']) {
    assert.deepEqual(consumeSharedSetupRequest({ action, workspaceId }), { action, workspaceId });
    assert.equal(
      consumeSharedSetupRequest({ action, workspaceId, path: 'C:/file.sql' }),
      undefined,
    );
  }
  for (const invalid of [
    null,
    [],
    { ...draft, hosting: 'remote' },
    { ...draft, host: 'https://db.example.org' },
    { ...draft, host: '' },
    { ...draft, host: 'x'.repeat(254) },
    { ...draft, port: '5432' },
    { ...draft, port: 0 },
    { ...draft, port: 65536 },
    { ...draft, port: 5.5 },
    { ...draft, database: 'postgres?role=other' },
    { ...draft, caPem: new Uint8Array([1]) },
    { ...draft, caPem: '' },
    { ...draft, caPem: 'x'.repeat(256 * 1024 + 1) },
    { ...draft, caPem: '\u2028' },
  ]) {
    assert.equal(consumeSharedSetupRequest(invalid), undefined);
  }
});

test('transfers only accepted DBA bytes and wipes the received copy on rejection', () => {
  const base = { action: 'run', role: 'setup_role', workspaceId };
  for (const action of ['preflight', 'check', 'run'] as const) {
    const password = new Uint8Array([1, 2]);
    const input = { ...base, action, password };
    const accepted = consumeSharedSetupRequest(input);
    assert.deepEqual(accepted, { ...input, password: new Uint8Array([1, 2]) });
    assert.ok(password.every((byte) => byte === 0));
  }
  for (const input of [
    { ...base, action: 'untrusted', password: new Uint8Array([9]) },
    { ...base, workspaceId: 'wrong', password: new Uint8Array([9]) },
    { ...base, role: 'setup role', password: new Uint8Array([9]) },
    { ...base, extra: true, password: new Uint8Array([9]) },
    { ...base, password: new Uint8Array([0, 9]) },
    { ...base, password: new Uint8Array(new SharedArrayBuffer(2)).fill(9) },
    { ...base, password: new Uint8Array(1025).fill(9) },
    { ...base, password: new Uint8Array(0) },
  ]) {
    assert.equal(consumeSharedSetupRequest(input), undefined);
    assert.ok(input.password.every((byte) => byte === 0));
  }
  assert.equal(consumeSharedSetupRequest({ ...base, password: 'string' }), undefined);
});

test('ties receipts to the saved plan, action and deployment stage', () => {
  assert.deepEqual(parseSharedSetupReply({ plan: null }, 'plan'), { plan: null });
  assert.deepEqual(parseSharedSetupReply({ plan: null }, 'discard', workspaceId), { plan: null });
  assert.equal(parseSharedSetupReply({ plan: null }, 'run'), undefined);
  assert.deepEqual(parseSharedSetupReply({ plan }, 'prepare'), { plan });
  assert.deepEqual(parseSharedSetupReply({ plan }, 'plan'), { plan });
  assert.equal(parseSharedSetupReply({ plan }, 'discard'), undefined);
  assert.equal(parseSharedSetupReply({ plan }, 'check', 'different'), undefined);
  const submitted = { ...plan, state: 'submitted' };
  const exported = { ...plan, state: 'exported' };
  const exportReply = { plan: exported, failure: 'export-failed' };
  assert.deepEqual(parseSharedSetupReply({ plan: exported }, 'export'), { plan: exported });
  assert.deepEqual(parseSharedSetupReply(exportReply, 'export'), exportReply);
  assert.equal(parseSharedSetupReply(exportReply, 'check'), undefined);
  assert.equal(parseSharedSetupReply({ plan: exported, failure: 'mismatch' }, 'export'), undefined);
  assert.equal(parseSharedSetupReply({ plan: exported }, 'prepare'), undefined);
  assert.equal(parseSharedSetupReply({ plan }, 'export'), undefined);
  const runReply = { plan: submitted, deployment };
  assert.deepEqual(parseSharedSetupReply(runReply, 'run', workspaceId), runReply);
  assert.equal(parseSharedSetupReply({ ...runReply, plan }, 'run'), undefined);
  for (const invalid of [
    { version: 0 },
    { version: Number.MAX_SAFE_INTEGER + 1 },
    { version: '43' },
    { requiresTls: 1 },
    { requiresTls: false },
    { provisioning: false },
    { provisioning: 1 },
    { unrecognized: true },
  ]) {
    assert.equal(
      parseSharedSetupReply({ ...runReply, deployment: { ...deployment, ...invalid } }, 'run'),
      undefined,
    );
  }
  assert.equal(parseSharedSetupReply({ ...runReply, deployment: null }, 'check'), undefined);
  const checked = { plan: exported, checks, deployment: { ...deployment, provisioning: false } };
  assert.deepEqual(parseSharedSetupReply(checked, 'check'), checked);
  for (const invalid of [
    undefined,
    { ...checks, plainStartup: 'safe' },
    { ...checks, maxConnections: '80' },
    { ...checks, statementTracking: 'unknown' },
    { ...checks, logsParameters: 1 },
    { ...checks, password: 'unexpected' },
  ]) {
    assert.equal(parseSharedSetupReply({ ...checked, checks: invalid }, 'check'), undefined);
  }
  for (const invalid of [
    null,
    { plan: { ...plan, roleTag: 42 } },
    { plan: { ...plan, roleTag: 'ABCD2345ABCD2345' } },
    { plan: { ...plan, state: 'ready' } },
    { plan: { ...plan, caPem: 'unexpected' } },
  ]) {
    assert.equal(parseSharedSetupReply(invalid, 'plan'), undefined);
  }
});

test('checks preflight diagnostics and refuses extra receipt fields', () => {
  const preflight = {
    serverVersion: 160015,
    maxConnections: 100,
    tls: 'verified',
    canCreateRoles: true,
    ownsDatabase: true,
    ownsPublicSchema: true,
    canGrantStatistics: true,
    emptyDatabase: true,
    logsStatements: false,
    logsParameters: true,
    statementTracking: 'unavailable',
  };
  const receipt = { plan, preflight };
  assert.deepEqual(parseSharedSetupReply(receipt, 'preflight'), receipt);
  assert.equal(parseSharedSetupReply(receipt, 'run'), undefined);
  assert.equal(parseSharedSetupReply({ ...receipt, unexpected: true }, 'preflight'), undefined);
  assert.equal(parseSharedSetupReply({ plan, preflight: null }, 'preflight'), undefined);
  for (const invalid of [
    { serverVersion: '160015' },
    { serverVersion: 0 },
    { serverVersion: 1.5 },
    { maxConnections: 0 },
    { maxConnections: 1.5 },
    { maxConnections: 2 ** 31 },
    { maxConnections: '100' },
    { tls: 'off' },
    { logsParameters: 'false' },
    { statementTracking: 'unexpected' },
    { other: true },
  ]) {
    assert.equal(
      parseSharedSetupReply({ plan, preflight: { ...preflight, ...invalid } }, 'preflight'),
      undefined,
    );
  }
  for (const statementTracking of ['none', 'top', 'all']) {
    const accepted = { plan, preflight: { ...preflight, statementTracking } };
    assert.deepEqual(parseSharedSetupReply(accepted, 'preflight'), accepted);
  }
  assert.deepEqual(parseSharedSetupReply({ plan, failure: 'check-required' }, 'run'), {
    plan,
    failure: 'check-required',
  });
  assert.equal(parseSharedSetupReply({ plan, failure: 'secret-server-text' }, 'run'), undefined);
  const full = { plan, failure: 'connection-limit' };
  assert.deepEqual(parseSharedSetupReply(full, 'preflight'), full);
});

test('administrator setup consumes every factor and reserves native credentials and file selection', () => {
  const options = [
    {
      action: 'admin-prepare',
      role: 'dba',
      password: new Uint8Array([12]),
      loginName: 'first-admin',
      profile: 'standard',
    },
    { action: 'admin-open' },
    { action: 'admin-recovery', recipient: new Uint8Array(32).fill(9) },
    { action: 'admin-confirm', enrollmentId: workspaceId, groups: new Uint8Array(10).fill(73) },
    { action: 'admin-publish', role: 'dba', password: new Uint8Array([12]) },
    { action: 'admin-join', deviceName: 'First device' },
  ];
  for (const option of options) {
    const input = {
      ...option,
      workspaceId,
      accountPassword: new Uint8Array([7, 8]),
      ask: new Uint8Array(32).fill(3),
    };
    const expected = structuredClone(input);
    const accepted = consumeSharedSetupRequest(input);
    assert.deepEqual(accepted, expected);
    for (const entry of Object.values(input))
      if (entry instanceof Uint8Array) assert.ok(entry.every((byte) => byte === 0));
  }
  for (const input of [
    {
      action: 'admin-prepare',
      role: 'dba',
      password: Uint8Array.of(1),
      loginName: 'name',
      profile: 'hardened',
    },
    { action: 'admin-open', ask: Uint8Array.of(1) },
    { action: 'admin-open', accountPassword: new Uint8Array(new SharedArrayBuffer(1)).fill(5) },
    { action: 'admin-open', accountPassword: new Uint8Array() },
    { action: 'admin-recovery', recipient: new Uint8Array(32), path: 'C:/offline.whrecovery' },
    { action: 'admin-confirm', enrollmentId: 'elsewhere', groups: new Uint8Array(10) },
    { action: 'admin-join', deviceName: 'First device', appVersion: '9.9.9' },
    { action: 'admin-join', deviceName: '\u0000' },
    { action: 'admin-join', deviceName: '💡'.repeat(1025) },
    { action: 'admin-publish', role: 'dba', password: Uint8Array.of(0) },
  ]) {
    const request = { workspaceId, accountPassword: Uint8Array.of(5), ...input };
    assert.equal(consumeSharedSetupRequest(request), undefined);
    for (const entry of Object.values(request))
      if (entry instanceof Uint8Array) assert.ok(entry.every((byte) => byte === 0));
  }
});

test('administrator setup accepts only unsigned integer deployment estimates', () => {
  const prepare = (directConnectionDevices: unknown) => ({
    action: 'admin-prepare',
    role: 'dba',
    loginName: 'admin',
    profile: 'standard',
    workspaceId,
    accountPassword: Uint8Array.of(1),
    password: Uint8Array.of(2),
    directConnectionDevices,
  });
  for (const devices of [0, 1, 300, 301, 0xffffffff]) {
    const request = prepare(devices);
    const expected = structuredClone(request);
    assert.deepEqual(consumeSharedSetupRequest(request), expected);
  }
  for (const devices of [null, undefined, true, -1, 1.5, '300', 0x100000000]) {
    const request = prepare(devices);
    assert.equal(consumeSharedSetupRequest(request), undefined);
    assert.equal(request.password[0] | request.accountPassword[0], 0);
  }
  const { directConnectionDevices: _devices, ...legacy } = prepare(0);
  const inherited = Object.assign(Object.create({ directConnectionDevices: 300 }), legacy);
  const expected = structuredClone(legacy);
  assert.deepEqual(consumeSharedSetupRequest(inherited), expected);
});

test('administrator reply correlates the recovery recipient and only accepts the expected stage', () => {
  const submitted = { ...plan, state: 'submitted' };
  const initial = { plan: submitted, adminPending: true };
  assert.deepEqual(parseSharedSetupReply(initial, 'plan'), initial);
  assert.equal(parseSharedSetupReply({ ...initial, plan }, 'plan'), undefined);
  const administrator = {
    enrollmentId: '22222222-2222-4222-8222-222222222222',
    loginName: 'first-admin',
    stage: 'prepared',
  };
  const prepared = { ...initial, administrator };
  assert.deepEqual(parseSharedSetupReply(prepared, 'admin-prepare', workspaceId), prepared);
  assert.deepEqual(parseSharedSetupReply(prepared, 'admin-open', workspaceId), prepared);
  assert.equal(parseSharedSetupReply(prepared, 'admin-join'), undefined);
  assert.equal(parseSharedSetupReply(prepared, 'admin-confirm'), undefined);
  assert.equal(
    parseSharedSetupReply(
      { ...prepared, administrator: { ...administrator, stage: 'ready' } },
      'admin-open',
    ),
    undefined,
  );
  const recorded = { ...initial, administrator: { ...administrator, stage: 'recovery-exported' } };
  const recovery = {
    vaultId: workspaceId,
    enrollmentId: administrator.enrollmentId,
    groups: [3, 10],
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32).toString('base64'),
      ciphertext: Buffer.alloc(92).toString('base64'),
    },
  };
  const result = { ...recorded, recovery };
  assert.deepEqual(parseSharedSetupReply(result, 'admin-recovery'), result);
  assert.equal(
    parseSharedSetupReply(
      { ...result, recovery: { ...recovery, vaultId: administrator.enrollmentId } },
      'admin-recovery',
    ),
    undefined,
  );
  assert.equal(
    parseSharedSetupReply(
      { ...result, recovery: { ...recovery, enrollmentId: workspaceId } },
      'admin-recovery',
    ),
    undefined,
  );
  assert.equal(
    parseSharedSetupReply(
      { ...result, recovery: { ...recovery, groups: [3, 3] } },
      'admin-recovery',
    ),
    undefined,
  );
  assert.equal(parseSharedSetupReply(result, 'admin-open'), undefined);
  const confirmed = {
    ...initial,
    administrator: { ...administrator, stage: 'recovery-confirmed' },
  };
  assert.deepEqual(parseSharedSetupReply(confirmed, 'admin-confirm'), confirmed);
  const pending = { ...confirmed, failure: 'check-required' };
  assert.deepEqual(parseSharedSetupReply(pending, 'admin-publish'), pending);
  const rejection = { plan: submitted, failure: 'scram' };
  assert.deepEqual(parseSharedSetupReply(rejection, 'admin-prepare'), rejection);
  const published = { ...initial, administrator: { ...administrator, stage: 'published' } };
  assert.deepEqual(parseSharedSetupReply(published, 'admin-publish'), published);
});
