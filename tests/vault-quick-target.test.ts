import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import {
  parseVaultQuickSshHostReceipt,
  parseVaultQuickTarget,
  parseVaultQuickTargetRequest,
  parseVaultQuickTargetRef,
  parseVaultQuickTargetReleased,
  vaultQuickTargetPayload,
} from '../electron/vault-quick-target.ts';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';

function target(protocol = 'rdp'): any {
  return {
    protocol,
    host: 'quick.example',
    port: 0,
    credentialId: '',
    tunnelId: '',
    sshAutoSudo: false,
    httpPath: '',
    ignoreCertificateErrors: false,
    rdp: null,
  };
}
function request(): any {
  return { workspaceId: randomUUID(), sessionId: randomUUID(), epoch: 1, target: target() };
}
function settings(): any {
  return {
    domain: '',
    screenSize: 'fitToWindow',
    fullScreen: false,
    colorDepth: 32,
    useAllMonitors: false,
    audioMode: 0,
    audioCaptureMode: 0,
    keyboardHookMode: 2,
    redirectClipboard: true,
    redirectPrinters: false,
    redirectSmartCards: false,
    redirectPorts: false,
    redirectDevices: false,
    redirectDrives: '',
    connectionSpeed: 7,
    desktopBackground: true,
    fontSmoothing: true,
    desktopComposition: true,
    windowDrag: true,
    menuAnimation: true,
    visualStyles: true,
    bitmapCaching: true,
    autoReconnect: true,
    serverAuthentication: 2,
    gatewayUsageMethod: 0,
    gatewayHostname: '',
    gatewayCredentialId: '',
    gatewayBypassLocal: true,
    gatewayUseSameCreds: false,
    useExternalClient: false,
  };
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

test('quick target contracts accept exact public protocol metadata and own their copies', () => {
  for (const protocol of ['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https']) {
    const value = target(protocol);
    assert.deepEqual(parseVaultQuickTarget(value), value);
  }
  const value = target();
  value.rdp = settings();
  const parsed = parseVaultQuickTarget(value)!;
  assert.deepEqual(parsed, value);
  parsed.rdp!.screenSize = '640x480';
  assert.equal(value.rdp.screenSize, 'fitToWindow');
  const good = target();
  for (const value of [
    null,
    {},
    [],
    { ...good, password: 'private' },
    { ...good, username: 'private' },
    { ...good, protocol: 'serial' },
    { ...good, host: '' },
    { ...good, host: 'bad host' },
    { ...good, host: 'user@host' },
    { ...good, host: 'x/path' },
    { ...good, host: String.fromCharCode(0) },
    { ...good, host: 'x'.repeat(1025) },
    { ...good, host: 'x'.repeat(254) },
    { ...good, port: -1 },
    { ...good, port: 65536 },
    { ...good, port: 1.5 },
    { ...good, credentialId: 'bad' },
    { ...good, tunnelId: 'bad' },
    { ...good, sshAutoSudo: 1 },
    { ...good, sshAutoSudo: true },
    { ...good, httpPath: '/' },
    { ...good, ignoreCertificateErrors: true },
    { ...good, rdp: {} },
    { ...good, rdp: { ...settings(), domain: 'ordinary' } },
    { ...good, rdp: { ...settings(), gatewayCredentialId: 'BAD' } },
    { ...good, rdp: { ...settings(), password: 'private' } },
    { ...target('http'), credentialId: randomUUID() },
    { ...target('vnc'), rdp: settings() },
  ])
    assert.equal(parseVaultQuickTarget(value), undefined, JSON.stringify(value));
  for (const key of Object.keys(good)) {
    const value = { ...good };
    delete value[key];
    assert.equal(parseVaultQuickTarget(value), undefined, key);
  }
  const q = request();
  assert.deepEqual(parseVaultQuickTargetRequest(q), q);
  assert.equal(vaultQuickTargetPayload(q).epoch, '1');
  assert.equal('workspaceId' in vaultQuickTargetPayload(q), false);
  for (const value of [
    null,
    {},
    { ...q, workspaceId: 'bad' },
    { ...q, sessionId: 'bad' },
    { ...q, epoch: 0 },
    { ...q, epoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...q, extra: true },
    { ...q, target: {} },
  ])
    assert.equal(parseVaultQuickTargetRequest(value), undefined);
  const ref = {
    workspaceId: q.workspaceId,
    id: randomUUID(),
    sessionId: q.sessionId,
    epoch: q.epoch,
  };
  assert.deepEqual(parseVaultQuickTargetRef(ref, q), ref);
  for (const value of [
    null,
    {},
    { ...ref, id: 'bad' },
    { ...ref, workspaceId: randomUUID() },
    { ...ref, sessionId: randomUUID() },
    { ...ref, epoch: 2 },
    { ...ref, extra: true },
  ])
    assert.equal(parseVaultQuickTargetRef(value, q), undefined);
  for (const value of [null, {}, { released: false }, { released: true, extra: true }])
    assert.equal(parseVaultQuickTargetReleased(value), undefined);
  assert.equal(parseVaultQuickTargetReleased({ released: true }), true);
});

async function hostFixture() {
  const q = request(),
    slot = randomUUID(),
    calls: any[] = [];
  let backend: any,
    allowed = true,
    delayed = false,
    resolve!: () => void,
    malformed = false,
    releaseFails = false,
    lockFails = false;
  let nextOwner = 0;
  const makeClient = () => {
    const owner = ++nextOwner;
    return {
      describe: async () => ({ vaultId: q.workspaceId, slots: [{ id: slot, kind: 'recovery' }] }),
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {
        calls.push(['lock', owner]);
        if (lockFails) throw Error('unconfirmed');
      },
      registerQuickTarget: async (value: any) => {
        calls.push(['register', owner, value]);
        if (delayed) await new Promise<void>((r) => (resolve = r));
        return malformed
          ? {}
          : {
              workspaceId: q.workspaceId,
              id: randomUUID(),
              sessionId: q.sessionId,
              epoch: q.epoch,
            };
      },
      releaseQuickTarget: async (value: any) => {
        calls.push(['release', value, owner]);
        if (releaseFails) throw Error('failed');
        return true;
      },
    };
  };
  backend = makeClient();
  const host = new VaultBackendHost(
    () => backend,
    () => true,
  );
  const unlock = async () => {
    await host.describe();
    await host.unlock({
      vaultId: q.workspaceId,
      slotId: slot,
      kind: 'recovery',
      factor: new Uint8Array(32),
    });
  };
  return {
    q,
    host,
    calls,
    unlock,
    accepted: () => allowed,
    setAllowed: (v: boolean) => (allowed = v),
    setDelayed: (v: boolean) => (delayed = v),
    resolve: () => resolve(),
    setMalformed: (v: boolean) => (malformed = v),
    setReleaseFails: (v: boolean) => (releaseFails = v),
    setLockFails: (v: boolean) => (lockFails = v),
    replace: () => (backend = makeClient()),
  };
}

test('quick target host owns one idempotent immutable lease and invalidates late owners', async () => {
  const f = await hostFixture();
  await assert.rejects(f.host.beginQuickTarget(null), /Invalid/);
  await assert.rejects(f.host.beginQuickTarget(f.q), /locked/);
  await f.unlock();
  await assert.rejects(f.host.beginQuickTarget({ ...f.q, workspaceId: randomUUID() }), /locked/);
  f.setAllowed(false);
  await assert.rejects(f.host.beginQuickTarget(f.q, f.accepted), /locked/);
  f.setAllowed(true);
  const lease = await f.host.beginQuickTarget(f.q, f.accepted);
  assert.equal(Object.isFrozen(lease.reference), true);
  await Promise.all([lease.release(), lease.release()]);
  await lease.release();
  assert.equal(f.calls.filter((c) => c[0] === 'release').length, 1);
  f.setDelayed(true);
  const late = f.host.beginQuickTarget(f.q, f.accepted);
  await tick();
  f.setAllowed(false);
  f.resolve();
  await assert.rejects(late, /locked/);
  assert.equal(f.calls.filter((c) => c[0] === 'release').length, 2);
  await f.host.stop();
});

test('quick target host requires a real release or confirmed original-owner exit', async () => {
  const f = await hostFixture();
  await f.unlock();
  const lease = await f.host.beginQuickTarget(f.q);
  f.setReleaseFails(true);
  f.setLockFails(true);
  await assert.rejects(lease.release(), /unconfirmed/);
  f.setLockFails(false);
  await lease.release();
  assert.ok(f.calls.filter((c) => c[0] === 'lock').length >= 2);
  const g = await hostFixture();
  await g.unlock();
  g.setMalformed(true);
  await assert.rejects(g.host.beginQuickTarget(g.q), /Invalid/);
  assert.ok(g.calls.some((c) => c[0] === 'lock'));
  await g.host.stop();
});

test('quick client rejects secret-bearing or malformed requests before native startup', async () => {
  let spawned = 0;
  const client = new VaultBackendClient(
    { executable: 'never-start', databasePath: 'never-open' },
    () => {
      spawned++;
      throw Error('unexpected process');
    },
  );
  for (const value of [null, {}, { ...request(), target: { ...target(), password: 'private' } }])
    await assert.rejects(client.registerQuickTarget(value), /Invalid/);
  for (const value of [null, {}, { ...request(), id: 'bad' }])
    await assert.rejects(client.releaseQuickTarget(value), /Invalid/);
  const factor = new Uint8Array(32).fill(3);
  await assert.rejects(
    client.trustQuickSshHost(null, {
      vaultId: randomUUID(),
      slotId: randomUUID(),
      kind: 'recovery',
      factor,
    }),
    /Invalid/,
  );
  assert.ok(factor.every((value) => value === 0));
  assert.equal(spawned, 0);
  await client.lock();
});

test('quick SSH host confirmation binds its returned pin and requires fresh Standard authentication', async () => {
  const { publicKey: _, ...base } = sshRequest();
  const q = { ...base, credentialOverride: '', route: null };
  const expected = {
    binding: sshBundle({ ...q, publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }).binding,
    fileId: randomUUID(),
    revision: 'a'.repeat(64),
    fingerprint: '',
  };
  const received = 'SHA256:' + Buffer.alloc(32, 1).toString('base64').slice(0, -1);
  const goodReceipt = { ...expected, revision: 'b'.repeat(64), fingerprint: received };
  for (const receipt of [
    { ...goodReceipt, fileId: randomUUID() },
    { ...goodReceipt, binding: { ...expected.binding, host: 'redirect.example' } },
    { ...goodReceipt, revision: expected.revision },
    null,
  ])
    assert.equal(parseVaultQuickSshHostReceipt(receipt, { ...q, expected, received }), undefined);
  assert.equal(parseVaultQuickSshHostReceipt(goodReceipt, null), undefined);
  const value = { ...q, expected, received },
    slot = randomUUID();
  let profile = 'standard',
    wrong = false,
    calls = 0;
  const client: any = {
    describe: async () => ({ vaultId: q.workspaceId, slots: [{ id: slot, kind: 'recovery' }] }),
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: profile }),
    trustQuickSshHost: async (_value: any, auth: any) => {
      calls++;
      if (profile === 'standard') assert.ok(auth);
      return { ...expected, revision: 'b'.repeat(64), fingerprint: wrong ? '' : received };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await assert.rejects(host.trustQuickSshHost(null), /Invalid/);
  await assert.rejects(host.trustQuickSshHost(value), /locked/);
  await host.describe();
  await host.unlock({
    vaultId: q.workspaceId,
    slotId: slot,
    kind: 'recovery',
    factor: new Uint8Array(32),
  });
  await assert.rejects(host.trustQuickSshHost(value), /Fresh/);
  assert.equal(calls, 0);
  const factor = new Uint8Array(32).fill(4);
  const confirm: any = async (operation: any, _descriptor: any, run: any) => {
    assert.equal(operation, 'ssh-quick-host-trust');
    return run({ vaultId: q.workspaceId, slotId: slot, kind: 'recovery', factor });
  };
  assert.equal((await host.trustQuickSshHost(value, confirm)).fingerprint, received);
  assert.ok(factor.every((n) => n === 0));
  profile = 'default';
  wrong = true;
  await assert.rejects(host.trustQuickSshHost(value), /Invalid/);
  await assert.rejects(
    host.trustQuickSshHost({ ...value, credentialOverride: randomUUID() }),
    /Invalid/,
  );
  await host.stop();
});

test('late quick-target admission and cleanup stay with the original native owner after replacement', async () => {
  for (const malformed of [false, true]) {
    const f = await hostFixture();
    await f.unlock();
    f.setDelayed(true);
    const pending = f.host.beginQuickTarget(f.q, f.accepted);
    await tick();
    const original = f.calls.find((c) => c[0] === 'register')![1];
    await f.host.stop();
    f.replace();
    await f.unlock();
    f.setMalformed(malformed);
    f.resolve();
    await assert.rejects(pending, malformed ? /Invalid/ : /locked/);
    if (malformed)
      assert.ok(f.calls.filter((c) => c[0] === 'lock').every((c) => c[1] === original));
    else assert.equal(f.calls.find((c) => c[0] === 'release')![2], original);
    assert.equal(
      f.host.unlockedWorkspaceId,
      f.q.workspaceId,
      'cleanup must not retire the replacement owner',
    );
    f.setDelayed(false);
    f.setMalformed(false);
    const current = await f.host.beginQuickTarget(f.q);
    await current.release();
    await f.host.stop();
  }
});
