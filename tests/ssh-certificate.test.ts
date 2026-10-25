import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Session } from 'node:inspector/promises';
import { stripTypeScriptTypes } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { buildCredentialListProjection, sshCertificateExpiry } from '../src/credential-state.ts';
import { requiresSshCertificateReplacement } from '../src/runtime-credential-errors.ts';
import { hasValidCredentialSecretLength } from '../electron/credential-secret-length.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const uuid = '11111111-1111-4111-8111-111111111111';
const isUuid = (value: unknown) =>
  typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const plain = (value: unknown) => JSON.parse(JSON.stringify(value));

test('a completed credential creation selects only the connection editor that requested it', async () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = app.slice(
    app.indexOf('  async function createCredential('),
    app.indexOf('  async function updateCredential('),
  );
  for (const replaced of [false, true]) {
    const editor = { fromConnection: true };
    const currentEditor = { current: editor as object | null };
    const originalForm = {
      host: 'new-target',
      useSavedCredentials: false,
      credential: 'none',
      inlinePassword: 'new-input',
    };
    let form = originalForm;
    let complete: (value: unknown) => void = () => {};
    const pending = new Promise((resolve) => {
      complete = resolve;
    });
    const create = runInNewContext(stripTypeScriptTypes(`${source}\ncreateCredential;`), {
      window: { wormhole: { createCredential: () => pending } },
      sshKeyEditor: editor,
      sshKeyEditorRef: currentEditor,
      setCredentials: () => {},
      setCredentialOptions: () => {},
      setNewConnectionForm: (update: (current: typeof form) => typeof form) => {
        form = update(form);
      },
      refreshWorkspaceCredentials: async () => {},
    });
    const saved = create({ provider: 'Local' });
    if (replaced) currentEditor.current = { fromConnection: true };
    complete({ id: uuid, name: 'Saved SSH key' });
    await saved;
    if (replaced) assert.equal(form, originalForm, 'an old save changed the new connection draft');
    else assert.equal(form.credential, uuid);
  }
});

test('an obsolete temporary credential editor cannot close its replacement', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const callback = app.match(/onEditorClose=\{([\s\S]*?)\}/)?.[1];
  assert.ok(callback);
  const original = { fromConnection: true };
  const replacement = { fromConnection: true };
  for (const current of [original, replacement]) {
    let active: object | null = current;
    const close = runInNewContext(stripTypeScriptTypes(`(${callback})`), {
      sshKeyEditor: original,
      setSshKeyEditor: (value: object | null | ((current: object | null) => object | null)) => {
        active = typeof value === 'function' ? value(active) : value;
      },
    });
    close();
    assert.equal(active, current === original ? null : replacement);
  }
});

test('certificate expiry, credential search and runtime recovery use public metadata', () => {
  const now = Date.parse('2026-10-25T12:00:00Z');
  assert.deepEqual(sshCertificateExpiry(undefined, now), { label: 'No expiry', expired: false });
  assert.equal(sshCertificateExpiry('bad', now).label, 'Unknown expiry');
  assert.deepEqual(sshCertificateExpiry('2026-10-25T12:00:00Z', now), {
    label: 'Expired',
    expired: true,
  });
  assert.equal(sshCertificateExpiry('2026-10-25T18:30:00Z', now).label, 'Expires in 7 h');
  assert.equal(sshCertificateExpiry('2026-10-27T12:00:00Z', now).label, 'Expires in 2 d');
  const credential = {
    id: uuid,
    name: 'SSH',
    username: 'operator',
    kind: 'sshKey' as const,
    provider: 'Local',
    hasCertificate: true,
    certificateFileName: 'renewal-cert.pub',
    certificate: { keyId: 'vault-production' },
  };
  for (const query of ['renewal-cert.pub', 'vault-production', 'ssh key + certificate']) {
    assert.deepEqual(buildCredentialListProjection([credential], 'Local', query).credentials, [
      credential,
    ]);
  }
  assert.equal(
    requiresSshCertificateReplacement('SSH certificate expired on 2026-10-24 14:00 UTC'),
    true,
  );
  assert.equal(requiresSshCertificateReplacement('SSH host key mismatch'), false);
  assert.equal(requiresSshCertificateReplacement(undefined), false);
});

test('SSH certificate failures carry only a validated credential ID to the renderer', () => {
  const source = main.slice(
    main.indexOf('function parseSshBackendEvent('),
    main.indexOf('function isMcpRequestId('),
  );
  const parse = runInNewContext(stripTypeScriptTypes(`${source}\nparseSshBackendEvent;`), {
    isUuid,
    isRecord: (value: unknown) => value !== null && typeof value === 'object',
    isSshSessionId: (value: unknown) => typeof value === 'string' && value.length > 0,
    isSshFingerprint: () => false,
    isSshHostKeyMismatch: () => false,
  });
  for (const credentialId of [uuid, 'invalid', undefined, 123]) {
    const event = parse(
      JSON.stringify({
        type: 'error',
        session_id: 'ssh',
        credential_id: credentialId,
        error: 'SSH certificate expired',
      }),
    );
    assert.equal(event.credentialId, credentialId === uuid ? uuid : undefined);
    assert.equal(event.error, 'SSH certificate expired');
  }
});

test('native SSH certificate parsers, pickers and selection lifetimes stay behind IPC', async (context) => {
  const inspector = new Session();
  const measure =
    !process.execArgv.includes('--experimental-test-coverage') && !process.env.NODE_V8_COVERAGE;
  if (measure) {
    inspector.connect();
    context.after(() => inspector.disconnect());
    await inspector.post('Profiler.enable');
    await inspector.post('Profiler.startPreciseCoverage', { detailed: true, callCount: true });
  }
  const parsers = main.slice(
    main.indexOf('function sshPrivateKeyDisplayName('),
    main.indexOf('function parseWorkspaceNodeWriteRequest('),
  );
  const updater = main.slice(
    main.indexOf('function parseCredentialUpdateRequest('),
    main.indexOf('function parseCredentialDeleteRequest('),
  );
  const parse = runInNewContext(
    stripTypeScriptTypes(
      `${parsers}\n${updater}\n({ parseCredentialCreateRequest, parseCredentialUpdateRequest, sshPrivateKeyDisplayName })`,
    ),
    {
      path,
      isUuid,
      isRecord: (value: unknown) =>
        value !== null && typeof value === 'object' && !Array.isArray(value),
      credentialMaxNameLength: 256,
      credentialMaxUsernameLength: 512,
      credentialMaxDomainLength: 512,
      credentialMaxPasswordLength: 4096,
      credentialMaxBitwardenItemIdLength: 512,
      credentialMaxBitwardenItemNameLength: 1024,
      hasValidCredentialSecretLength,
    },
    { filename: 'wormhole-ssh-certificate-parsers.js' },
  );
  const draft = {
    name: 'SSH key',
    protocol: 'ssh',
    kind: 'sshKey',
    username: 'operator',
    domain: '',
    password: '',
    passphrase: '',
    clearPassphrase: false,
    privateKeySelectionId: uuid,
    certificateSelectionId: randomUUID(),
    provider: 'Local',
  };
  assert.equal(
    parse.parseCredentialCreateRequest(draft).certificateSelectionId,
    draft.certificateSelectionId,
  );
  assert.equal(
    parse.parseCredentialUpdateRequest({ ...draft, id: uuid, privateKeySelectionId: undefined })
      .certificateSelectionId,
    draft.certificateSelectionId,
  );
  assert.equal(
    parse.parseCredentialUpdateRequest({
      ...draft,
      id: uuid,
      certificateSelectionId: undefined,
      clearCertificate: true,
    }).clearCertificate,
    true,
  );
  const passwordDraft = {
    ...draft,
    kind: 'password',
    password: 'password',
    privateKeySelectionId: undefined,
    certificateSelectionId: undefined,
  };
  parse.parseCredentialCreateRequest(passwordDraft);
  parse.parseCredentialUpdateRequest({
    ...passwordDraft,
    id: uuid,
    provider: 'Bitwarden',
    bitwardenItemId: 'item',
  });
  for (const mutation of [
    { certificateSelectionId: 'bad' },
    { certificateSelectionId: 3 },
    { certificateSelectionId: {} },
    { privateKeySelectionId: 3 },
    { clearCertificate: 'true' },
    { clearCertificate: null },
    { clearCertificate: true },
    { provider: 'Bitwarden' },
    { protocol: 'rdp' },
    { kind: 'password', password: 'pass' },
    { name: null },
    { kind: 'bad' },
    { passphrase: 3 },
    { clearPassphrase: 'true' },
    { privateKeySelectionId: undefined },
  ])
    assert.throws(
      () => parse.parseCredentialCreateRequest({ ...draft, ...mutation }),
      /invalid|Bitwarden/,
    );
  assert.throws(() => parse.parseCredentialCreateRequest(null), /invalid/);
  assert.throws(
    () =>
      parse.parseCredentialCreateRequest({
        ...passwordDraft,
        provider: 'Bitwarden',
        bitwardenItemId: 'item',
      }),
    /cannot be created/,
  );
  assert.throws(() => parse.parseCredentialUpdateRequest({ ...draft, id: 'bad' }), /invalid/);
  assert.throws(
    () => parse.parseCredentialUpdateRequest({ ...draft, id: uuid, clearCertificate: true }),
    /invalid/,
  );
  assert.throws(
    () =>
      parse.parseCredentialUpdateRequest({ ...passwordDraft, id: uuid, clearCertificate: true }),
    /invalid/,
  );
  assert.equal(parse.sshPrivateKeyDisplayName('/keys/id_ed25519'), 'id_ed25519');
  assert.equal(parse.sshPrivateKeyDisplayName('/keys/bad\u0000name'), 'SSH private key');
  assert.equal(parse.sshPrivateKeyDisplayName('/keys/' + 'a'.repeat(257)), 'SSH private key');

  type Selection = { id: string; path: string; fileName: string; authorizationEpoch: number };
  type Handler = (event: { sender: object }, value?: unknown) => Promise<any>;
  const handlers = new Map<string, Handler>();
  const keys = new WeakMap<object, Selection>();
  const certificates = new WeakMap<object, Selection>();
  const owner = {},
    otherOwner = {};
  let authenticated = true;
  let epoch = 1;
  let files = ['/keys/id_ed25519'];
  let canceled = false;
  let pickerInvalidatesAuth = false;
  let info: { isFile(): boolean; size: number } | null = { isFile: () => true, size: 1000 };
  let backendFails = false;
  const writes: any[] = [];
  const options: any[] = [];
  const handlerSource = main.slice(
    main.indexOf("  ipcMain.handle('credential:select-ssh-private-key'"),
    main.indexOf("  ipcMain.handle('workspace:delete-credential'"),
  );
  runInNewContext(
    stripTypeScriptTypes(handlerSource),
    {
      ipcMain: { handle: (channel: string, handler: Handler) => handlers.set(channel, handler) },
      ...parse,
      isUuid,
      randomUUID,
      isRecord: (value: unknown) => value !== null && typeof value === 'object',
      serializeAuthOperation: (action: () => Promise<unknown>) => action(),
      requireWorkspaceAuth: async () => {
        if (!authenticated) throw new Error('locked');
      },
      authSession: {
        get authorizationEpoch() {
          return epoch;
        },
      },
      requireAuthorizationEpoch: (value: number) => {
        if (value !== epoch) throw new Error('expired authorization');
      },
      BrowserWindow: { fromWebContents: () => ({}) },
      showCoordinatedOpenDialog: async (_owner: unknown, option: unknown) => {
        options.push(option);
        if (pickerInvalidatesAuth) epoch++;
        return { canceled, filePaths: files };
      },
      statFile: async () => {
        if (!info) throw new Error('missing');
        return info;
      },
      sshPrivateKeySelections: keys,
      sshCertificateSelections: certificates,
      runBackend: async (action: string, request: any) => {
        if (backendFails) throw new Error('save failed');
        writes.push([action, plain(request)]);
        return { id: uuid, name: request.name };
      },
    },
    { filename: 'wormhole-ssh-certificate-handlers.js' },
  );
  const invoke = async (channel: string, request?: unknown, sender = owner) =>
    handlers.get(channel)!({ sender }, request);
  const keyPicker = 'credential:select-ssh-private-key';
  const certPicker = 'credential:select-ssh-certificate';
  const create = 'workspace:create-credential';
  const update = 'workspace:update-credential';
  const discard = 'credential:discard-ssh-certificate';
  for (const channel of [keyPicker, certPicker]) {
    canceled = true;
    assert.equal(await invoke(channel), null);
    canceled = false;
    files = [];
    assert.equal(await invoke(channel), null);
    files = ['/keys/id_ed25519'];
    pickerInvalidatesAuth = true;
    await assert.rejects(invoke(channel), /expired authorization/);
    pickerInvalidatesAuth = false;
    authenticated = false;
    await assert.rejects(invoke(channel), /locked/);
    authenticated = true;
  }
  for (const entry of [
    null,
    { isFile: () => false, size: 100 },
    { isFile: () => true, size: 0 },
    { isFile: () => true, size: 16385 },
  ]) {
    info = entry;
    assert.equal((await invoke(keyPicker)).suggestedCertificate, undefined);
    await assert.rejects(invoke(certPicker), /regular OpenSSH/);
  }
  info = { isFile: () => true, size: 1000 };
  const selected = await invoke(keyPicker);
  assert.equal(selected.fileName, 'id_ed25519');
  assert.equal(selected.suggestedCertificate.fileName, 'id_ed25519-cert.pub');
  assert.deepEqual(Object.keys(selected.suggestedCertificate).sort(), ['fileName', 'selectionId']);
  assert.equal(options[0].filters[0].name, 'All files');
  const request = {
    ...draft,
    privateKeySelectionId: selected.selectionId,
    certificateSelectionId: selected.suggestedCertificate.selectionId,
  };
  await assert.rejects(invoke(create, request, otherOwner), /Select the SSH private key again/);
  await assert.rejects(
    invoke(create, { ...request, certificateSelectionId: randomUUID() }),
    /Select the SSH certificate again/,
  );
  backendFails = true;
  await assert.rejects(invoke(create, request), /save failed/);
  backendFails = false;
  await invoke(create, request);
  assert.equal(keys.get(owner), undefined);
  assert.equal(certificates.get(owner), undefined);
  assert.equal(writes[0][1].privateKeyPath, '/keys/id_ed25519');
  assert.equal(writes[0][1].certificatePath, '/keys/id_ed25519-cert.pub');
  assert.equal(writes[0][1].certificateSelectionId, undefined);
  await assert.rejects(invoke(create, request), /Select the SSH private key again/);
  let certificate = await invoke(certPicker);
  await assert.rejects(invoke(discard, {}), /invalid/);
  assert.equal((await invoke(discard, { selectionId: randomUUID() })).discarded, false);
  assert.equal((await invoke(discard, { selectionId: certificate.selectionId })).discarded, true);
  certificate = await invoke(certPicker);
  const certUpdate = {
    ...draft,
    id: uuid,
    privateKeySelectionId: undefined,
    certificateSelectionId: certificate.selectionId,
  };
  await assert.rejects(
    invoke(update, { ...certUpdate, privateKeySelectionId: randomUUID() }),
    /Select the SSH private key again/,
  );
  await assert.rejects(
    invoke(update, { ...certUpdate, certificateSelectionId: randomUUID() }),
    /Select the SSH certificate again/,
  );
  epoch++;
  await assert.rejects(invoke(update, certUpdate), /expired authorization/);
  certificate = await invoke(certPicker);
  await invoke(update, { ...certUpdate, certificateSelectionId: certificate.selectionId });
  assert.equal(writes.at(-1)[1].privateKeyPath, undefined);
  assert.equal(writes.at(-1)[1].certificatePath, '/keys/id_ed25519');
  await invoke(update, {
    ...draft,
    id: uuid,
    privateKeySelectionId: undefined,
    certificateSelectionId: undefined,
    clearCertificate: true,
  });
  assert.equal(writes.at(-1)[1].clearCertificate, true);
  const replacement = await invoke(keyPicker);
  await invoke(update, {
    ...draft,
    id: uuid,
    privateKeySelectionId: replacement.selectionId,
    certificateSelectionId: replacement.suggestedCertificate.selectionId,
  });
  assert.equal(keys.get(owner), undefined);
  assert.equal(certificates.get(owner), undefined);
  await assert.rejects(invoke('credential:discard-ssh-private-key', {}), /invalid/);
  assert.equal(
    (await invoke('credential:discard-ssh-private-key', { selectionId: uuid })).discarded,
    false,
  );
  const discardedKey = await invoke(keyPicker);
  assert.equal(
    (await invoke('credential:discard-ssh-private-key', { selectionId: discardedKey.selectionId }))
      .discarded,
    true,
  );
  const stale = await invoke(keyPicker);
  epoch++;
  await assert.rejects(
    invoke(create, {
      ...draft,
      privateKeySelectionId: stale.selectionId,
      certificateSelectionId: undefined,
    }),
    /expired authorization/,
  );

  // Execute the real cleanup callbacks with the same maps used by the handlers.
  const cleanupStart = main.indexOf('  const credentialSelectionOwner = window.webContents;');
  const cleanupEnd = main.indexOf('  });', cleanupStart) + '  });'.length;
  let destroyed: () => void = () => assert.fail('missing destroyed callback');
  const contents = {
    once: (_event: string, callback: () => void) => {
      destroyed = callback;
    },
  };
  keys.set(contents, { id: uuid, path: '/key', fileName: 'key', authorizationEpoch: epoch });
  certificates.set(contents, {
    id: uuid,
    path: '/cert',
    fileName: 'cert',
    authorizationEpoch: epoch,
  });
  runInNewContext(stripTypeScriptTypes(main.slice(cleanupStart, cleanupEnd)), {
    window: { webContents: contents },
    sshPrivateKeySelections: keys,
    sshCertificateSelections: certificates,
  });
  destroyed();
  assert.equal(keys.get(contents), undefined);
  assert.equal(certificates.get(contents), undefined);
  const lock = main.slice(
    main.indexOf("ipcMain.handle('auth:lock'"),
    main.indexOf("ipcMain.handle('auth:lock'") + 2200,
  );
  assert.match(lock, /sshCertificateSelections.delete\(event.sender\)/);
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(preload, /credential:select-ssh-certificate/);
  assert.doesNotMatch(preload, /certificatePath|privateKeyPath/);

  if (measure) {
    const coverage = await inspector.post('Profiler.takePreciseCoverage');
    for (const filename of [
      'wormhole-ssh-certificate-parsers.js',
      'wormhole-ssh-certificate-handlers.js',
    ]) {
      const blocks = coverage.result
        .filter((script) => script.url === filename)
        .flatMap((script) => script.functions.flatMap((fn) => fn.ranges));
      const percent = (100 * blocks.filter((block) => block.count > 0).length) / blocks.length;
      context.diagnostic(`${filename}: V8 block coverage ${percent.toFixed(2)}%`);
      assert.ok(percent >= coverageThreshold, `${filename} coverage below ${coverageThreshold}%`);
    }
    await inspector.post('Profiler.stopPreciseCoverage');
  }
});
