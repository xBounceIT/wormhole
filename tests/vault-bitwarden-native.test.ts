import { resolve } from 'node:path';
import {
  parseBitwardenCleanupRequest,
  parseBitwardenCleanupResult,
  parseBitwardenZipInstallRequest,
  parseBitwardenZipInstallResult,
  parseBitwardenFolderInstallRequest,
  parseBitwardenFolderInstallResult,
  parseBitwardenInstallationRevision,
  parseBitwardenInstallationRequest,
  parseBitwardenInstallationPlan,
} from '../electron/vault-bitwarden-installation.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import {
  beginNativeBrowserTransfer,
  parseBrowserTransferRequest,
  parseBrowserTransferBegun,
  parseBrowserTransferAccepted,
  parseBrowserTransferCommitted,
  parseBrowserTransferCancelled,
  parseBrowserProfileClosed,
  type BrowserTransferClient,
} from '../electron/vault-bitwarden-native.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import type {
  BrowserTransferContext,
  BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';

const tick = () => new Promise<void>((r) => setImmediate(r));
function fixture() {
  const q = {
    workspaceId: randomUUID(),
    profileId: randomUUID(),
    requestId: randomUUID(),
    epoch: 2,
    action: 'hydrate' as const,
    sourceRevision: '0',
    restorePublicKey: Buffer.alloc(32, 1).toString('base64'),
  };
  const c: BrowserTransferContext = {
    ...q,
    fileId: randomUUID(),
    transferId: randomUUID(),
    policySequence: '3',
    capturePublicKey: Buffer.alloc(32, 2).toString('base64'),
  };
  const manifest = { bytes: 14, revision: '0', restore: false };
  const packet: BrowserTransferPacket = {
    context: c,
    direction: 'capture',
    manifest,
    index: 0,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 3).toString('base64'),
      ciphertext: Buffer.alloc(30, 4).toString('base64'),
    },
  };
  return { q, c, manifest, packet };
}
function fakeClient(c: BrowserTransferContext, manifest: ReturnType<typeof fixture>['manifest']) {
  const calls: string[] = [];
  const client: BrowserTransferClient = {
    beginBitwardenTransfer: async () => {
      calls.push('begin');
      return c;
    },
    pushBitwardenTransfer: async () => {
      calls.push('push');
      return { accepted: true, index: 0 };
    },
    commitBitwardenTransfer: async () => {
      calls.push('commit');
      return manifest;
    },
    takeBitwardenTransfer: async () => {
      calls.push('take');
      return { ...fixture().packet, context: c, direction: 'restore' };
    },
    cancelBitwardenTransfer: async () => {
      calls.push('cancel');
      return { cancelled: true };
    },
    closeBitwardenProfile: async (profileId) => {
      calls.push('profile:' + profileId);
      return { closed: true };
    },
  };
  return { client, calls };
}

test('native Bitwarden metadata contracts reject extras, coercion and mismatched ownership', () => {
  const { q, c, manifest } = fixture();
  assert.deepEqual(parseBrowserTransferRequest(q), q);
  assert.deepEqual(parseBrowserTransferBegun(c, q), c);
  for (const value of [
    null,
    [],
    {},
    { ...q, epoch: 0 },
    { ...q, epoch: 1.1 },
    { ...q, epoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...q, epoch: '2' },
    { ...q, action: 'restore' },
    { ...q, workspaceId: 'bad' },
    { ...q, sourceRevision: '01' },
    { ...q, sourceRevision: '9223372036854775808' },
    { ...q, restorePublicKey: 'AA==' },
    { ...q, extra: true },
  ])
    assert.equal(parseBrowserTransferRequest(value), undefined);
  assert.equal(parseBrowserTransferBegun(null, q), undefined);
  assert.equal(parseBrowserTransferBegun({ ...c, profileId: randomUUID() }, q), undefined);
  assert.deepEqual(parseBrowserTransferAccepted({ accepted: true, index: 0 }, 0), {
    accepted: true,
    index: 0,
  });
  for (const v of [
    null,
    {},
    { accepted: false, index: 0 },
    { accepted: true, index: 1 },
    { accepted: true, index: 0, extra: 1 },
  ])
    assert.equal(parseBrowserTransferAccepted(v, 0), undefined);
  assert.deepEqual(parseBrowserTransferCommitted({ manifest }, c), manifest);
  for (const v of [
    null,
    {},
    { manifest: null },
    { manifest: { ...manifest, revision: 'bad' } },
    { manifest, extra: 1 },
  ])
    assert.equal(parseBrowserTransferCommitted(v, c), undefined);
  for (const [parse, key] of [
    [parseBrowserTransferCancelled, 'cancelled'],
    [parseBrowserProfileClosed, 'closed'],
  ] as const) {
    assert.deepEqual(parse({ [key]: true }), { [key]: true });
    for (const v of [null, {}, { [key]: false }, { [key]: true, extra: 1 }])
      assert.equal(parse(v), undefined);
  }
});

test('browser capability keeps an immutable context and cancels failed or foreign operations', async () => {
  const { q, c, manifest, packet } = fixture(),
    { client, calls } = fakeClient(c, manifest);
  const handle = await beginNativeBrowserTransfer(client, q, () => true);
  handle.context.profileId = randomUUID();
  assert.deepEqual(handle.context, c);
  await handle.push(packet);
  assert.deepEqual(await handle.commit(), manifest);
  assert.equal((await handle.take(0)).direction, 'restore');
  await handle.cancel();
  await assert.rejects(handle.commit(), /locked/);
  assert.deepEqual(calls.slice(0, 5), ['begin', 'push', 'commit', 'take', 'cancel']);
  const other = await beginNativeBrowserTransfer(client, q, () => true),
    n = calls.length;
  await assert.rejects(
    other.push({ ...packet, context: { ...c, profileId: randomUUID() } }),
    /Invalid/,
  );
  assert.deepEqual(calls.slice(n), ['cancel']);
  const failed = await beginNativeBrowserTransfer(client, q, () => true);
  client.commitBitwardenTransfer = async () => {
    throw Error('native failure');
  };
  await assert.rejects(failed.commit(), /native failure/);
  assert.equal(calls.at(-1), 'cancel');
});

test('browser capability fences late begin and late replies and reports uncertain cleanup', async () => {
  const { q, c, manifest, packet } = fixture(),
    { client, calls } = fakeClient(c, manifest);
  let current = false,
    release!: () => void;
  await assert.rejects(
    beginNativeBrowserTransfer(client, q, () => current),
    /locked/,
  );
  assert.equal(calls.length, 0);
  current = true;
  client.beginBitwardenTransfer = async () => {
    await new Promise<void>((r) => (release = r));
    return c;
  };
  const starting = beginNativeBrowserTransfer(client, q, () => current);
  await tick();
  current = false;
  release();
  await assert.rejects(starting, /locked/);
  assert.deepEqual(calls, ['cancel']);
  client.beginBitwardenTransfer = async () => c;
  current = true;
  const handle = await beginNativeBrowserTransfer(client, q, () => current);
  client.pushBitwardenTransfer = async () => {
    await new Promise<void>((r) => (release = r));
    return { accepted: true, index: 0 };
  };
  const push = handle.push(packet);
  await tick();
  await assert.rejects(handle.commit(), /busy/);
  current = false;
  release();
  await assert.rejects(push, /locked/);
  current = true;
  const uncertain = await beginNativeBrowserTransfer(client, q, () => current);
  client.cancelBitwardenTransfer = async () => {
    throw Error('key release failed');
  };
  current = false;
  await assert.rejects(
    uncertain.commit(),
    (e: any) =>
      e instanceof AggregateError && e.errors.length === 2 && /not confirmed/.test(e.message),
  );
  await assert.rejects(uncertain.cancel(), /key release failed/);
});

test('host captures the original backend and browser authority without renderer IPC registration', async () => {
  const { q, c, manifest } = fixture(),
    { client, calls } = fakeClient(c, manifest);
  let allowed = true,
    release!: () => void;
  const full: any = {
    ...client,
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
  };
  const host = new VaultBackendHost(
    () => full,
    () => true,
  );
  const unlock = () =>
    host.unlock({
      vaultId: q.workspaceId,
      slotId: q.profileId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
  await assert.rejects(host.beginBitwardenTransfer(q), /Invalid/);
  await unlock();
  await assert.rejects(host.beginBitwardenTransfer(null), /Invalid/);
  await assert.rejects(host.beginBitwardenTransfer({ ...q, workspaceId: randomUUID() }), /Invalid/);
  const handle = await host.beginBitwardenTransfer(q, () => allowed);
  assert.deepEqual(handle.context, c);
  assert.deepEqual(await handle.closeProfile(), { closed: true });
  const next = await host.beginBitwardenTransfer(q, () => allowed);
  allowed = false;
  await assert.rejects(next.commit(), /locked/);
  allowed = true;
  full.beginBitwardenTransfer = async () => {
    await new Promise<void>((r) => (release = r));
    return c;
  };
  const pending = host.beginBitwardenTransfer(q);
  await tick();
  await host.stop();
  release();
  await assert.rejects(pending, /locked/);
  assert.equal(calls.at(-1), 'cancel');
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
  assert.equal(
    channels.some((x) => x.includes('bitwarden-transfer') || x.includes('bitwarden-profile')),
    false,
  );
});

test('profile cleanup remains bound to its original backend after replacement and retries failed release', async () => {
  const { q, c, manifest } = fixture(),
    first = fakeClient(c, manifest),
    replacement = fakeClient(c, manifest);
  let active = first.client,
    fail = true;
  first.client.closeBitwardenProfile = async (profileId) => {
    first.calls.push('profile:' + profileId);
    if (fail) {
      fail = false;
      throw Error('profile release failed');
    }
    return { closed: true };
  };
  const handle = await beginNativeBrowserTransfer(first.client, q, () => active === first.client);
  active = replacement.client;
  await assert.rejects(handle.closeProfile(), /profile release failed/);
  assert.deepEqual(await handle.closeProfile(), { closed: true });
  assert.deepEqual(first.calls, ['begin', 'profile:' + c.profileId, 'profile:' + c.profileId]);
  assert.deepEqual(replacement.calls, []);
});

class Child extends EventEmitter {
  pid = process.pid;
  exitCode: number | null = null;
  signalCode = null;
  killed = false;
  stdout = new PassThrough();
  stderr = new PassThrough();
  requests: any[] = [];
  respond: (request: any) => unknown;
  stdin = new Writable({
    write: (chunk, _encoding, done) => {
      const q = JSON.parse(chunk.toString());
      this.requests.push(q);
      if (q.operation !== 'lock')
        queueMicrotask(() =>
          this.stdout.write(
            JSON.stringify({ version: 1, id: q.id, result: this.respond(q) }) + '\n',
          ),
        );
      done();
    },
  });
  constructor(respond: (request: any) => unknown) {
    super();
    this.respond = respond;
    this.stdin.on('finish', () => this.exit());
    setImmediate(() => this.emit('spawn'));
  }
  exit() {
    if (this.exitCode !== null) return;
    this.exitCode = 0;
    this.emit('exit', 0, null);
    this.emit('close', 0, null);
  }
  kill() {
    this.killed = true;
    this.exit();
    return true;
  }
}
test('native client serializes typed opaque operations, validates acknowledgements and bounds output chunks', async () => {
  const { q, c, manifest, packet } = fixture();
  const child = new Child((r) => {
    switch (r.operation) {
      case 'bitwarden-transfer-begin':
        return c;
      case 'bitwarden-transfer-push':
        return { accepted: true, index: r.payload.index };
      case 'bitwarden-transfer-commit':
        return { manifest };
      case 'bitwarden-transfer-take':
        return { ...packet, direction: 'restore' };
      case 'bitwarden-transfer-cancel':
        return { cancelled: true };
      case 'bitwarden-profile-close':
        return { closed: true };
      default:
        return { alive: true };
    }
  });
  const client = new VaultBackendClient(
    { executable: 'synthetic', databasePath: 'synthetic' },
    () => child as any,
  );
  try {
    for (const value of [null, {}]) {
      await assert.rejects(client.beginBitwardenTransfer(value), /Invalid/);
      await assert.rejects(client.pushBitwardenTransfer(value), /Invalid/);
      await assert.rejects(client.commitBitwardenTransfer(value), /Invalid/);
      await assert.rejects(client.takeBitwardenTransfer(value, 0), /Invalid/);
      await assert.rejects(client.cancelBitwardenTransfer(value), /Invalid/);
    }
    for (const i of [-1, 1.1, 5, NaN])
      await assert.rejects(client.takeBitwardenTransfer(c, i), /Invalid/);
    await assert.rejects(client.closeBitwardenProfile('bad'), /Invalid/);
    assert.deepEqual(await client.beginBitwardenTransfer(q), c);
    assert.equal(child.requests[0].payload.epoch, '2');
    assert.deepEqual(await client.pushBitwardenTransfer(packet), { accepted: true, index: 0 });
    assert.deepEqual(await client.commitBitwardenTransfer(c), manifest);
    assert.deepEqual(await client.takeBitwardenTransfer(c, 0), { ...packet, direction: 'restore' });
    assert.deepEqual(await client.cancelBitwardenTransfer(c), { cancelled: true });
    assert.deepEqual(await client.closeBitwardenProfile(q.profileId), { closed: true });
    child.respond = () => ({ ...packet, direction: 'restore', index: 1 });
    await assert.rejects(client.takeBitwardenTransfer(c, 0), /unavailable/);
  } finally {
    await client.lock();
  }
});

function installationFixture() {
  const request = { workspaceId: randomUUID(), minimumRevision: '1' };
  const plan = {
    workspaceId: request.workspaceId,
    revision: '2',
    installation: {
      id: randomUUID(),
      extensionId: 'a'.repeat(32),
      version: '2026.10.1',
      popup: 'popup/index.html',
      background: '_generated_background_page.html',
    },
  };
  return { request, plan };
}
test('installation plan validates exact public metadata, canonical versions and relative package files', () => {
  const { request, plan } = installationFixture();
  assert.deepEqual(parseBitwardenInstallationRequest(request), request);
  assert.deepEqual(parseBitwardenInstallationPlan(plan, request), plan);
  assert.notEqual(parseBitwardenInstallationPlan(plan, request)!.installation, plan.installation);
  assert.deepEqual(parseBitwardenInstallationPlan({ ...plan, installation: null }, request), {
    ...plan,
    installation: null,
  });
  for (const q of [
    null,
    {},
    { ...request, path: 'outside' },
    { ...request, workspaceId: 'bad' },
    { ...request, minimumRevision: '01' },
    { ...request, minimumRevision: '9223372036854775808' },
  ])
    assert.equal(parseBitwardenInstallationRequest(q), undefined);
  for (const p of [
    null,
    {},
    { ...plan, path: 'outside' },
    { ...plan, workspaceId: randomUUID() },
    { ...plan, revision: '0' },
    { ...plan, revision: '01' },
    { ...plan, installation: { ...plan.installation, key: 'private' } },
    { ...plan, installation: { ...plan.installation, id: 'bad' } },
    { ...plan, installation: { ...plan.installation, extensionId: 'q'.repeat(32) } },
  ])
    assert.equal(parseBitwardenInstallationPlan(p, request), undefined);
  assert.equal(parseBitwardenInstallationPlan(plan, {} as any), undefined);
  for (const version of ['', '0', '01', '1.2.3.4.5', '65536', '1.-1'])
    assert.equal(
      parseBitwardenInstallationPlan(
        { ...plan, installation: { ...plan.installation, version } },
        request,
      ),
      undefined,
    );
  for (const path of [
    '',
    '/',
    'a//b',
    'a/../b',
    './a',
    'https://host/x',
    'a\\b',
    'a%2fb',
    'a?x',
    'a#x',
    'a\nb',
    'a\rb',
    'a\tb',
    'x'.repeat(1025),
    '\ud800',
  ]) {
    for (const field of ['popup', 'background'])
      assert.equal(
        parseBitwardenInstallationPlan(
          { ...plan, installation: { ...plan.installation, [field]: path } },
          request,
        ),
        undefined,
      );
  }
  const max = {
    ...plan,
    revision: '9223372036854775807',
    installation: {
      ...plan.installation,
      version: '65535.65535.65535.65535',
      popup: '日本語.html',
    },
  };
  assert.ok(parseBitwardenInstallationPlan(max, request));
  const zero = { ...request, minimumRevision: '0' };
  assert.equal(parseBitwardenInstallationPlan({ ...plan, revision: '0' }, zero), undefined);
  assert.ok(parseBitwardenInstallationPlan({ ...plan, revision: '0', installation: null }, zero));
});

test('installation client snapshots its request and rejects substituted native plans', async () => {
  const { request, plan } = installationFixture();
  const child = new Child(() => plan);
  const client = new VaultBackendClient(
    { executable: 'synthetic', databasePath: 'synthetic' },
    () => child as any,
  );
  try {
    await assert.rejects(client.bitwardenInstallationPlan(null), /Invalid/);
    const q = { ...request };
    const pending = client.bitwardenInstallationPlan(q);
    q.workspaceId = randomUUID();
    q.minimumRevision = '99';
    assert.deepEqual(await pending, plan);
    assert.deepEqual(child.requests[0].payload, request);
    assert.equal(child.requests[0].operation, 'bitwarden-installation-plan');
    child.respond = () => ({ ...plan, workspaceId: randomUUID() });
    await assert.rejects(client.bitwardenInstallationPlan(request), /unavailable/);
  } finally {
    await client.lock();
  }
});

test('installation host captures workspace and backend authority across asynchronous plan reads', async () => {
  const { request, plan } = installationFixture();
  let allowed = true,
    finish!: (v: unknown) => void;
  const full: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
    bitwardenInstallationPlan: async () => plan,
  };
  let activeClient = full;
  const host = new VaultBackendHost(
    () => activeClient,
    () => true,
  );
  const unlock = () =>
    host.unlock({
      vaultId: request.workspaceId,
      slotId: randomUUID(),
      kind: 'password',
      factor: new Uint8Array([1]),
    });
  await assert.rejects(
    host.bitwardenInstallationPlan(request, () => allowed),
    /unavailable/,
  );
  await unlock();
  await assert.rejects(
    host.bitwardenInstallationPlan(null, () => allowed),
    /unavailable/,
  );
  await assert.rejects(
    host.bitwardenInstallationPlan({ ...request, workspaceId: randomUUID() }, () => allowed),
    /unavailable/,
  );
  assert.deepEqual(await host.bitwardenInstallationPlan(request, () => allowed), plan);
  allowed = false;
  await assert.rejects(
    host.bitwardenInstallationPlan(request, () => allowed),
    /unavailable/,
  );
  allowed = true;
  full.bitwardenInstallationPlan = async () => ({
    ...plan,
    installation: { ...plan.installation, path: 'private' },
  });
  await assert.rejects(
    host.bitwardenInstallationPlan(request, () => allowed),
    /unavailable/,
  );
  full.bitwardenInstallationPlan = () => new Promise((r) => (finish = r));
  const denied = host.bitwardenInstallationPlan(request, () => allowed);
  allowed = false;
  finish(plan);
  await assert.rejects(denied, /unavailable/);
  allowed = true;
  const stale = host.bitwardenInstallationPlan(request, () => allowed);
  await host.stop();
  activeClient = { ...full };
  await unlock();
  finish(plan);
  await assert.rejects(stale, /unavailable/);
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
  assert.ok(channels.every((name) => !name.includes('bitwarden')));
  await host.stop();
});

function folderInstallFixture() {
  const q = {
    workspaceId: randomUUID(),
    sourceDirectory: resolve('extension'),
    expectedRevision: '0',
  };
  return { q, result: { workspaceId: q.workspaceId, revision: '1' } };
}
test('folder installation contract rejects ambiguous paths, revision overflow and substituted receipts', () => {
  const { q, result } = folderInstallFixture();
  assert.deepEqual(parseBitwardenFolderInstallRequest(q), q);
  assert.notEqual(parseBitwardenFolderInstallRequest(q), q);
  assert.deepEqual(parseBitwardenFolderInstallResult(result, q), result);
  for (const v of [
    null,
    {},
    { ...q, extra: true },
    { ...q, workspaceId: 'bad' },
    { ...q, expectedRevision: '01' },
    { ...q, expectedRevision: '9223372036854775807' },
    ...[
      '',
      'relative',
      'a/../b',
      resolve('a') + '\0',
      resolve('a') + '\ud800',
      resolve('a') + 'a'.repeat(4097),
      resolve('a') + '日'.repeat(1400),
    ].map((sourceDirectory) => ({ ...q, sourceDirectory })),
  ])
    assert.equal(parseBitwardenFolderInstallRequest(v), undefined);
  for (const v of [
    null,
    {},
    { ...result, extra: true },
    { ...result, workspaceId: randomUUID() },
    { ...result, revision: '0' },
    { ...result, revision: '2' },
    { ...result, revision: '01' },
  ])
    assert.equal(parseBitwardenFolderInstallResult(v, q), undefined);
  assert.equal(parseBitwardenFolderInstallResult(result, {} as any), undefined);
  assert.ok(
    parseBitwardenFolderInstallResult(
      { ...result, revision: '9223372036854775807' },
      { ...q, expectedRevision: '9223372036854775806' },
    ),
  );
});
for (const archive of [false, true]) {
  const method = archive ? 'installBitwardenZip' : 'installBitwardenFolder';
  const chooseMethod = archive ? 'chooseBitwardenZip' : 'chooseBitwardenFolder';
  const operation = archive ? 'bitwarden-install-zip' : 'bitwarden-install-folder';
  test(`${archive ? 'ZIP' : 'folder'} installation client snapshots action and wipes fresh authentication on success and rejection`, async () => {
    for (const fresh of [false, true]) {
      const { q: folder, result } = folderInstallFixture();
      const q = archive
        ? {
            workspaceId: folder.workspaceId,
            sourceFile: folder.sourceDirectory,
            expectedRevision: folder.expectedRevision,
          }
        : folder;
      const child = new Child(() => result);
      const client = new VaultBackendClient(
        { executable: 'synthetic', databasePath: 'synthetic' },
        () => child as any,
      );
      const authentication = () => ({
        vaultId: q.workspaceId,
        slotId: randomUUID(),
        kind: 'password' as const,
        factor: new Uint8Array([5]),
      });
      try {
        const invalid = authentication();
        await assert.rejects(client[method](null, invalid), /Invalid/);
        assert.deepEqual([...invalid.factor], [0]);
        const input = { ...q },
          auth = authentication();
        const pending = client[method](input, fresh ? auth : undefined);
        input[archive ? 'sourceFile' : 'sourceDirectory'] = resolve('substituted');
        assert.deepEqual(await pending, result);
        const frame = child.requests.find(
          (r) => r.operation === (fresh ? 'fresh-action' : operation),
        )!;
        if (fresh) {
          assert.equal(frame.payload.operation, operation);
          assert.deepEqual(JSON.parse(Buffer.from(frame.payload.action, 'base64').toString()), q);
          assert.deepEqual([...auth.factor], [0]);
        } else assert.deepEqual(frame.payload, q);
        child.respond = () => ({ ...result, revision: '2' });
        await assert.rejects(client[method](q), /unavailable/);
      } finally {
        await client.lock();
      }
    }
  });
  test(`${archive ? 'ZIP' : 'folder'} installation host requires current authority and Standard fresh authentication`, async () => {
    const { q: folder, result } = folderInstallFixture();
    const q = archive
      ? {
          workspaceId: folder.workspaceId,
          sourceFile: folder.sourceDirectory,
          expectedRevision: folder.expectedRevision,
        }
      : folder;
    const slotId = randomUUID();
    let allowed = true,
      effective = 'default',
      calls = 0;
    const full: any = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective }),
      lock: async () => {},
      describe: async () => ({ vaultId: q.workspaceId, slots: [{ id: slotId, kind: 'password' }] }),
      [method]: async () => {
        calls++;
        return result;
      },
    };
    const host = new VaultBackendHost(
      () => full,
      () => true,
    );
    const auth = () => ({
      vaultId: q.workspaceId,
      slotId,
      kind: 'password' as const,
      factor: new Uint8Array([5]),
    });
    const accepted = () => allowed;
    await assert.rejects(host[method](q, accepted), /unavailable/);
    await host.unlock(auth());
    await assert.rejects(host[method](null, accepted), /unavailable/);
    await assert.rejects(
      host[method]({ ...q, workspaceId: randomUUID() }, accepted),
      /unavailable/,
    );
    assert.deepEqual(await host[method](q, accepted), result);
    effective = 'standard';
    await assert.rejects(host[method](q, accepted), /Fresh authentication/);
    assert.equal(calls, 1);
    const factor = auth();
    assert.deepEqual(
      await host[method](q, accepted, async (op, descriptor, submit) => {
        assert.equal(op, operation);
        assert.equal(descriptor.vaultId, q.workspaceId);
        return submit(factor);
      }),
      result,
    );
    assert.deepEqual([...factor.factor], [0]);
    effective = 'default';
    allowed = false;
    await assert.rejects(host[method](q, accepted), /unavailable/);
    allowed = true;
    full[method] = async () => ({ ...result, path: 'private' });
    await assert.rejects(host[method](q, accepted), /unavailable/);
    let finish!: (v: unknown) => void;
    full[method] = () =>
      new Promise((r) => {
        finish = r;
      });
    const pending = host[method](q, accepted);
    await tick();
    allowed = false;
    finish(result);
    await assert.rejects(pending, /unavailable/);
    allowed = true;
    const locked = host[method](q, accepted);
    await tick();
    await host.stop();
    finish(result);
    await assert.rejects(locked, /unavailable/);
  });

  test(`native ${archive ? 'ZIP' : 'folder'} picker keeps original owner and revision and serializes choices`, async () => {
    const { request, plan } = installationFixture();
    let damaged = true;
    let selected: string | null = resolve('selected'),
      revision = '3',
      calls = 0,
      allowed = true;
    let pick: () => Promise<string | null> = async () => selected;
    const full: any = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {},
      bitwardenInstallationRevision: async () => ({ workspaceId: request.workspaceId, revision }),
      bitwardenInstallationPlan: async () => {
        if (damaged) throw Error('old package is unavailable');
        return { ...plan, revision };
      },
      [method]: async (q: any) => {
        calls++;
        damaged = false;
        assert.equal(q[archive ? 'sourceFile' : 'sourceDirectory'], resolve('selected'));
        assert.equal(q.expectedRevision, revision);
        revision = String(BigInt(revision) + 1n);
        return { workspaceId: request.workspaceId, revision };
      },
    };
    let activeClient = full;
    const host = new VaultBackendHost(
      () => activeClient,
      () => true,
    );
    const unlock = () =>
      host.unlock({
        vaultId: request.workspaceId,
        slotId: randomUUID(),
        kind: 'password',
        factor: new Uint8Array([1]),
      });
    const choose = () =>
      host[chooseMethod](
        () => pick(),
        () => allowed,
      );
    await assert.rejects(choose(), /unavailable/);
    await unlock();
    const readRevision = full.bitwardenInstallationRevision;
    let picked = false;
    pick = async () => {
      picked = true;
      return selected;
    };
    full.bitwardenInstallationRevision = async () => ({ workspaceId: randomUUID(), revision });
    await assert.rejects(choose(), /unavailable/);
    assert.equal(picked, false);
    let finishRevision!: (value: unknown) => void;
    full.bitwardenInstallationRevision = () =>
      new Promise((r) => {
        finishRevision = r;
      });
    const expiredPreflight = choose();
    await tick();
    allowed = false;
    finishRevision({ workspaceId: request.workspaceId, revision });
    await assert.rejects(expiredPreflight, /unavailable/);
    assert.equal(picked, false);
    allowed = true;
    full.bitwardenInstallationRevision = readRevision;
    assert.equal((await choose())!.revision, '4');
    selected = null;
    assert.equal(await choose(), null);
    assert.equal(calls, 1);
    selected = 'relative';
    await assert.rejects(choose(), /unavailable/);
    selected = resolve('selected');
    let finish!: (path: string | null) => void;
    pick = () =>
      new Promise((r) => {
        finish = r;
      });
    const busy = choose();
    await tick();
    await assert.rejects(choose(), /unavailable/);
    await assert.rejects(
      host[archive ? 'chooseBitwardenFolder' : 'chooseBitwardenZip'](
        () => pick(),
        () => allowed,
      ),
      /unavailable/,
    );
    allowed = false;
    finish(selected);
    await assert.rejects(busy, /unavailable/);
    allowed = true;
    const stale = choose();
    await tick();
    await host.stop();
    activeClient = { ...full };
    await unlock();
    finish(selected);
    await assert.rejects(stale, /unavailable/);
    assert.equal(calls, 1);
    pick = async () => {
      throw Error('picker failed');
    };
    await assert.rejects(choose(), /picker failed/);
    pick = async () => selected;
    assert.equal((await choose())!.revision, '5');
    await host.stop();
  });
}

test('ZIP contract accepts only sourceFile and binds the exact next native revision', () => {
  const { q: folder, result } = folderInstallFixture();
  const q = {
    workspaceId: folder.workspaceId,
    sourceFile: folder.sourceDirectory,
    expectedRevision: folder.expectedRevision,
  };
  assert.deepEqual(parseBitwardenZipInstallRequest(q), q);
  assert.deepEqual(parseBitwardenZipInstallResult(result, q), result);
  for (const bad of [
    null,
    {},
    folder,
    { ...q, sourceFile: 'relative' },
    { ...q, sourceDirectory: folder.sourceDirectory },
  ])
    assert.equal(parseBitwardenZipInstallRequest(bad), undefined);
  assert.equal(parseBitwardenZipInstallResult(result, {} as any), undefined);
  assert.equal(parseBitwardenZipInstallResult({ ...result, revision: '2' }, q), undefined);
});

test('revision preflight binds native workspace and minimum without claiming package integrity', async () => {
  const request = { workspaceId: randomUUID(), minimumRevision: '1' };
  const result = { workspaceId: request.workspaceId, revision: '2' };
  assert.deepEqual(parseBitwardenInstallationRevision(result, request), result);
  for (const bad of [
    null,
    {},
    { ...result, workspaceId: randomUUID() },
    { ...result, revision: '0' },
    { ...result, revision: '01' },
    { ...result, installation: null },
  ])
    assert.equal(parseBitwardenInstallationRevision(bad, request), undefined);
  assert.equal(parseBitwardenInstallationRevision(result, {} as any), undefined);
  const child = new Child(() => result);
  const client = new VaultBackendClient(
    { executable: 'synthetic', databasePath: 'synthetic' },
    () => child as any,
  );
  try {
    await assert.rejects(client.bitwardenInstallationRevision(null), /Invalid/);
    const input = { ...request };
    const pending = client.bitwardenInstallationRevision(input);
    input.workspaceId = randomUUID();
    assert.deepEqual(await pending, result);
    assert.equal(child.requests[0].operation, 'bitwarden-installation-revision');
    assert.deepEqual(child.requests[0].payload, request);
    child.respond = () => ({ ...result, path: 'private' });
    await assert.rejects(client.bitwardenInstallationRevision(request), /unavailable/);
  } finally {
    await client.lock();
  }
});

test('cleanup accepts only revision-bound metadata and consumes fresh factors', async () => {
  const q = { workspaceId: randomUUID(), expectedRevision: '2' };
  const result = { workspaceId: q.workspaceId, revision: '3' };
  assert.deepEqual(parseBitwardenCleanupRequest(q), q);
  assert.deepEqual(parseBitwardenCleanupResult(result, q), result);
  for (const bad of [
    null,
    {},
    { ...q, path: 'outside' },
    { ...q, workspaceId: 'bad' },
    { ...q, expectedRevision: '01' },
    { ...q, expectedRevision: '9223372036854775807' },
  ])
    assert.equal(parseBitwardenCleanupRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...result, revision: '2' },
    { ...result, revision: '4' },
    { ...result, workspaceId: randomUUID() },
    { ...result, path: 'outside' },
  ])
    assert.equal(parseBitwardenCleanupResult(bad, q), undefined);
  assert.equal(parseBitwardenCleanupResult(result, {} as any), undefined);
  const child = new Child(() => result);
  const client = new VaultBackendClient(
    { executable: 'synthetic', databasePath: 'synthetic' },
    () => child as any,
  );
  try {
    const invalidFactor = {
      vaultId: q.workspaceId,
      kind: 'recovery' as const,
      slotId: randomUUID(),
      factor: new Uint8Array(32).fill(7),
    };
    await assert.rejects(client.cleanupBitwardenInstallations(null, invalidFactor), /Invalid/);
    assert.ok(invalidFactor.factor.every((b) => b === 0));
    assert.equal(child.requests.length, 0);
    const input = { ...q };
    const pending = client.cleanupBitwardenInstallations(input);
    input.workspaceId = randomUUID();
    assert.deepEqual(await pending, result);
    assert.equal(child.requests[0].operation, 'bitwarden-cleanup');
    assert.deepEqual(child.requests[0].payload, q);
    const factor = {
      vaultId: q.workspaceId,
      kind: 'recovery' as const,
      slotId: randomUUID(),
      factor: new Uint8Array(32).fill(7),
    };
    assert.deepEqual(await client.cleanupBitwardenInstallations(q, factor), result);
    assert.ok(factor.factor.every((b) => b === 0));
    assert.equal(child.requests[1].operation, 'fresh-action');
    child.respond = () => ({ ...result, revision: '4' });
    await assert.rejects(client.cleanupBitwardenInstallations(q), /unavailable/);
  } finally {
    await client.lock();
  }
});

test('cleanup host binds original authority, serializes package actions and requires fresh Standard confirmation', async () => {
  const workspaceId = randomUUID(),
    slotId = randomUUID();
  let allowed = true,
    effective = 'default',
    calls = 0;
  const result = { workspaceId, revision: '3' };
  const full: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective }),
    lock: async () => {},
    describe: async () => ({ vaultId: workspaceId, slots: [{ id: slotId, kind: 'password' }] }),
    bitwardenInstallationRevision: async () => ({ workspaceId, revision: '2' }),
    cleanupBitwardenInstallations: async (q: any) => {
      assert.deepEqual(q, { workspaceId, expectedRevision: '2' });
      calls++;
      return result;
    },
  };
  const host = new VaultBackendHost(
    () => full,
    () => true,
  );
  const auth = () => ({
    vaultId: workspaceId,
    slotId,
    kind: 'password' as const,
    factor: new Uint8Array([5]),
  });
  const clean = () => host.cleanupBitwardenInstallations(() => allowed);
  await assert.rejects(clean(), /unavailable/);
  await host.unlock(auth());
  try {
    assert.deepEqual(await clean(), result);
    effective = 'standard';
    await assert.rejects(clean(), /Fresh authentication/);
    assert.equal(calls, 1);
    const factor = auth();
    assert.deepEqual(
      await host.cleanupBitwardenInstallations(
        () => allowed,
        async (op, descriptor, submit) => {
          assert.equal(op, 'bitwarden-cleanup');
          assert.equal(descriptor.vaultId, workspaceId);
          return submit(factor);
        },
      ),
      result,
    );
    assert.ok(factor.factor.every((b) => b === 0));
    effective = 'default';
    allowed = false;
    await assert.rejects(clean(), /unavailable/);
    allowed = true;
    full.bitwardenInstallationRevision = async () => ({ workspaceId: randomUUID(), revision: '2' });
    await assert.rejects(clean(), /unavailable/);
    full.bitwardenInstallationRevision = async () => ({
      workspaceId,
      revision: '9223372036854775807',
    });
    await assert.rejects(clean(), /unavailable/);
    let finish!: (v: any) => void;
    full.bitwardenInstallationRevision = () => new Promise((r) => (finish = r));
    const pending = clean();
    await tick();
    await assert.rejects(clean(), /unavailable/);
    await assert.rejects(
      host.chooseBitwardenFolder(
        async () => null,
        () => true,
      ),
      /unavailable/,
    );
    allowed = false;
    finish({ workspaceId, revision: '2' });
    await assert.rejects(pending, /unavailable/);
    allowed = true;
    full.bitwardenInstallationRevision = async () => ({ workspaceId, revision: '2' });
    full.cleanupBitwardenInstallations = async () => ({ ...result, revision: '4' });
    await assert.rejects(clean(), /unavailable/);
    full.cleanupBitwardenInstallations = () => new Promise((r) => (finish = r));
    const stale = clean();
    await tick();
    await host.stop();
    finish(result);
    await assert.rejects(stale, /unavailable/);
  } finally {
    await host.stop();
  }
});
