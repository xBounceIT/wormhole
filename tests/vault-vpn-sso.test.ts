import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import test from 'node:test';
import {
  parseVPNSSOContext,
  parseVPNSSOBegin,
  parseVPNSSOCheckpoint,
  parseVPNSSOManifest,
  parseVPNSSOOffer,
  parseVPNSSOPacket,
  vpnSSOArchiveBytes,
  vpnSSOChunkBytes,
  vpnSSOChunkCount,
  beginNativeVPNSSO,
  type VPNSSOClient,
} from '../electron/vault-vpn-sso.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { vpnSSOFixture } from './fixtures/vault-vpn-sso.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';

test('fallback SSO binds an original request to a separate exact SSL source without retagging it', async () => {
  const f = vpnSSOFixture();
  const primary = { ...f.q.binding, kind: 9 };
  const active = { ...f.q.binding, requestId: randomUUID(), tunnelConfigId: randomUUID() };
  const q = { ...f.q, binding: active, fallback: { primary, fallback: active } };
  assert.deepEqual(parseVPNSSOBegin(q), q);
  assert.deepEqual(parseVPNSSOOffer(f.offer, q), f.offer);
  const large = structuredClone(q);
  large.binding.host =
    large.fallback.primary.host =
    large.fallback.fallback.host =
      'h'.repeat(1024);
  large.startURL = 'https://ssl.test:443/remote/saml/start?realm=' + 'r'.repeat(4000);
  assert.deepEqual(parseVPNSSOBegin(large), large);
  const mutable = structuredClone(q),
    parsed = parseVPNSSOBegin(mutable)!;
  mutable.fallback.primary.host = 'changed';
  mutable.fallback.fallback.rowVersion = '9';
  assert.deepEqual(parsed, q);
  for (const value of [
    null,
    undefined,
    {},
    { ...q.fallback, extra: 1 },
    { ...q.fallback, primary: { ...primary, kind: 2 } },
    { ...q.fallback, fallback: { ...active, rowVersion: '99' } },
    { ...q.fallback, fallback: { ...active, requestId: primary.requestId } },
  ])
    assert.equal(parseVPNSSOBegin({ ...q, fallback: value }), undefined);
  assert.equal(parseVPNSSOBegin({ ...q, request: null }), undefined);
  assert.equal(parseVPNSSOBegin({ ...q, binding: primary }), undefined);
  const { fallback: _, ...ordinary } = q;
  assert.equal(parseVPNSSOBegin(ordinary), undefined);
  assert.equal(
    parseVPNSSOBegin({ ...q, request: { ...q.request, requestId: active.requestId } }),
    undefined,
  );
  let sent: any;
  const handle = await beginNativeVPNSSO(
    {
      beginVPNSSO: async (value: unknown) => {
        sent = value;
        return f.offer;
      },
      cancelVPNSSO: async () => ({ cancelled: true }),
    } as VPNSSOClient,
    q,
    () => true,
  );
  assert.deepEqual(sent, q);
  assert.equal(sent.request.requestId, primary.requestId);
  assert.equal(sent.binding.requestId, active.requestId);
  await handle.cancel();
});

test('shared SSO offers pin native personal custody independently of the source workspace', async () => {
  const f = vpnSSOFixture(),
    personal = randomUUID();
  const custody = { workspaceId: personal, fileId: f.q.binding.fileId };
  const q = { ...f.q, custody },
    offer = { ...f.offer, context: { ...f.c, workspaceId: personal } };
  assert.deepEqual(parseVPNSSOBegin(q), q);
  assert.deepEqual(parseVPNSSOOffer(offer, q), offer);
  assert.equal(parseVPNSSOOffer(f.offer, q), undefined);
  assert.equal(parseVPNSSOOffer(offer, f.q), undefined);
  assert.equal(parseVPNSSOContext({ ...f.c, custody }), undefined);
  for (const bad of [
    undefined,
    null,
    {},
    [],
    { ...custody, extra: true },
    { ...custody, workspaceId: 'bad' },
    { ...custody, fileId: randomUUID() },
  ])
    assert.equal(parseVPNSSOBegin({ ...f.q, custody: bad }), undefined);
  let sent: any;
  const security = {
    sequence: '3',
    workspace: 'default',
    user: 'default',
    os: 'default',
    effective: 'default',
    source: 'workspace',
  };
  const client: any = {
    startup: async () => ({
      slots: {
        formatVersion: 1,
        vaultId: personal,
        encrypted: true,
        slots: [{ id: f.q.profileId, kind: 'password', preset: 'kdf-v1' }],
      },
      cosmetics: { theme: 'system' },
      newWorkspace: false,
      shared: { lastLoginName: 'alice', serverDisplayName: 'Team' },
    }),
    sharedUnlock: async () => ({ admitted: true, lockedMemory: true, orgEscrow: true }),
    sharedRuntime: async () => ({
      vaultId: personal,
      workspaceId: f.q.request.workspaceId,
      security,
      tls: 'off',
    }),
    security: async () => security,
    beginVPNSSO: async (value: unknown) => {
      sent = value;
      return offer;
    },
    cancelVPNSSO: async () => ({ cancelled: true }),
    lock: async () => {},
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await host.sharedUnlock(
    {
      vaultId: personal,
      slotId: f.q.profileId,
      password: new Uint8Array([1]),
      ask: new Uint8Array(32).fill(2),
    },
    '1.0.0',
    () => true,
  );
  try {
    const authority = host.vpnSSOAuthority(() => true);
    assert.deepEqual(await authority.security(), security);
    const handle = await authority.begin({
      ...f.q,
      custody: { ...custody, workspaceId: randomUUID() },
    });
    assert.deepEqual(sent.custody, custody);
    assert.equal(sent.request.workspaceId, f.q.request.workspaceId);
    await handle.cancel();
    await host.stop();
    assert.throws(() => authority.begin(f.q));
  } finally {
    await host.stop();
  }
});

test('VPN SSO contexts reject malformed identity, source checkpoints and extra fields', () => {
  const { c } = vpnSSOFixture();
  assert.deepEqual(parseVPNSSOContext(c), c);
  for (const bad of [
    null,
    [],
    {},
    { ...c, extra: 1 },
    { ...c, epoch: '7' },
    { ...c, epoch: 0 },
    { ...c, epoch: 1.5 },
    { ...c, epoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...c, workspaceId: 'bad' },
    { ...c, policySequence: '0' },
    { ...c, policySequence: '01' },
    { ...c, sourceRevision: '9223372036854775808' },
    { ...c, sourceDeleted: 0 },
    { ...c, sourceDigest: 'AA==' },
    { ...c, sourceDeleted: true },
    { ...c, sourceRevision: '1' },
    { ...c, sourceDigest: c.bindingDigest },
    { ...c, bindingDigest: c.sourceDigest },
    { ...c, capturePublicKey: '' },
    { ...c, restorePublicKey: 'AA==' },
  ])
    assert.equal(parseVPNSSOContext(bad), undefined);
  assert.ok(
    parseVPNSSOContext({
      ...c,
      sourceRevision: '9223372036854775807',
      sourceDeleted: true,
      sourceDigest: c.bindingDigest,
    }),
  );
});

test('VPN SSO manifests and packets pin complete context, direction, length, digest and chunk order', () => {
  const { c, packet, offer } = vpnSSOFixture();
  assert.deepEqual(parseVPNSSOPacket(packet, c, 'capture'), packet);
  assert.deepEqual(parseVPNSSOManifest(offer.manifest, c, 'restore'), offer.manifest);
  for (const m of [
    null,
    {},
    { ...packet.manifest, extra: true },
    { ...packet.manifest, bytes: -1 },
    { ...packet.manifest, bytes: 1.2 },
    { ...packet.manifest, bytes: vpnSSOArchiveBytes + 1 },
    { ...packet.manifest, digest: c.sourceDigest },
    { ...packet.manifest, digest: 'bad' },
    { ...packet.manifest, bytes: 0 },
  ])
    assert.equal(parseVPNSSOManifest(m, c, 'capture'), undefined);
  assert.equal(parseVPNSSOManifest(packet.manifest, null, 'capture'), undefined);
  assert.equal(parseVPNSSOManifest(packet.manifest, c, 'restore'), undefined);
  assert.equal(parseVPNSSOManifest({ bytes: 0, digest: c.bindingDigest }, c, 'restore'), undefined);
  const stored = { ...c, sourceRevision: '3', sourceDigest: c.bindingDigest };
  assert.ok(parseVPNSSOManifest(packet.manifest, stored, 'restore'));
  assert.equal(parseVPNSSOManifest(offer.manifest, stored, 'restore'), undefined);
  assert.equal(parseVPNSSOManifest(packet.manifest, c, 'wrong' as 'capture'), undefined);
  const tombstone = { ...stored, sourceDeleted: true };
  assert.ok(parseVPNSSOManifest(offer.manifest, tombstone, 'restore'));
  for (const bad of [
    null,
    {},
    { ...packet, extra: true },
    { ...packet, context: null },
    { ...packet, direction: 'restore' },
    { ...packet, index: -1 },
    { ...packet, index: 1 },
    { ...packet, index: 0.5 },
    { ...packet, context: { ...c, challengeId: randomUUID() } },
    { ...packet, manifest: {} },
    { ...packet, bundle: null },
    { ...packet, bundle: { ...packet.bundle, extra: true } },
    { ...packet, bundle: { ...packet.bundle, formatVersion: 2 } },
    { ...packet, bundle: { ...packet.bundle, suiteId: 1 } },
    { ...packet, bundle: { ...packet.bundle, enc: '' } },
    { ...packet, bundle: { ...packet.bundle, ciphertext: Buffer.alloc(34).toString('base64') } },
  ])
    assert.equal(parseVPNSSOPacket(bad, c, 'capture'), undefined);
  assert.equal(parseVPNSSOPacket(packet, null, 'capture'), undefined);
  const final = {
    ...packet,
    manifest: { ...packet.manifest, bytes: vpnSSOChunkBytes + 19 },
    index: 1,
  };
  assert.ok(parseVPNSSOPacket(final, c, 'capture'));
  assert.equal(vpnSSOChunkCount(offer.manifest), 0);
  assert.equal(vpnSSOChunkCount({ ...packet.manifest, bytes: vpnSSOArchiveBytes }), 16);
  for (const bytes of [-1, 1.5, NaN, vpnSSOArchiveBytes + 1])
    assert.throws(() => vpnSSOChunkCount({ bytes, digest: '' }));
});

test('VPN SSO admission and receipt DTOs match the original native route and detached floor', () => {
  const { q, offer, c } = vpnSSOFixture();
  assert.deepEqual(parseVPNSSOBegin(q), q);
  for (const bad of [
    null,
    {},
    { ...q, extra: true },
    { ...q, profileId: 'bad' },
    { ...q, challengeId: 'bad' },
    { ...q, startURL: 0 },
    { ...q, startURL: 'bad' },
    { ...q, startURL: 'http://vpn.test/' },
    { ...q, startURL: 'https://u:p@vpn.test/' },
    { ...q, startURL: 'https://vpn.test/#x' },
    { ...q, startURL: 'https://vpn.test/\nx' },
    { ...q, startURL: 'https://vpn.test/' + 'x'.repeat(4096) },
    { ...q, ignoreCertificateErrors: 0 },
    { ...q, restorePublicKey: 'bad' },
    { ...q, request: {} },
    { ...q, binding: {} },
    { ...q, binding: { ...q.binding, kind: 1 } },
  ])
    assert.equal(parseVPNSSOBegin(bad), undefined);
  const parsed = parseVPNSSOOffer(offer, q)!;
  parsed.context.challengeId = randomUUID();
  parsed.floor.checkpoint.digest[0] = 255;
  assert.deepEqual(parseVPNSSOOffer(offer, q), offer);
  for (const bad of [
    null,
    {},
    { ...offer, extra: true },
    { ...offer, context: null },
    ...['workspaceId', 'fileId', 'profileId', 'requestId', 'sessionId', 'challengeId'].map(
      (key) => ({ ...offer, context: { ...c, [key]: randomUUID() } }),
    ),
    { ...offer, context: { ...c, epoch: 8 } },
    { ...offer, context: { ...c, restorePublicKey: c.capturePublicKey } },
    { ...offer, floor: null },
    { ...offer, floor: { ...offer.floor, extra: 1 } },
    { ...offer, floor: { ...offer.floor, rowVersion: '1' } },
    { ...offer, floor: { ...offer.floor, checkpoint: null } },
    { ...offer, manifest: null },
  ])
    assert.equal(parseVPNSSOOffer(bad, q), undefined);
  const checkpoint = { revision: '1', deleted: false, digest: Array(32).fill(1) };
  assert.deepEqual(parseVPNSSOCheckpoint(checkpoint), checkpoint);
  assert.deepEqual(parseVPNSSOCheckpoint(offer.floor.checkpoint), offer.floor.checkpoint);
  for (const bad of [
    null,
    {},
    { ...checkpoint, extra: 1 },
    { ...checkpoint, revision: '01' },
    { ...checkpoint, deleted: 0 },
    { ...checkpoint, digest: 'x' },
    { ...checkpoint, digest: Array(32) },
    { ...checkpoint, digest: Array(31).fill(1) },
    { ...checkpoint, digest: Array(32).fill(256) },
    { ...checkpoint, digest: Array(32).fill(0) },
    { ...checkpoint, revision: '0' },
    { ...offer.floor.checkpoint, deleted: true },
  ])
    assert.equal(parseVPNSSOCheckpoint(bad), undefined);
});

class NativeSSOChild extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  exitCode: number | null = null;
  signalCode = null;
  pid = process.pid;
  readonly requests: any[] = [];
  respond: (request: any) => unknown = () => ({ cancelled: true });
  readonly stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      const request = JSON.parse(chunk.toString());
      this.requests.push(request);
      const result =
        request.operation === 'heartbeat'
          ? { alive: true }
          : request.operation === 'lock'
            ? { locked: true }
            : this.respond(request);
      queueMicrotask(() =>
        this.stdout.write(JSON.stringify({ version: 1, id: request.id, result }) + '\n'),
      );
      callback();
    },
    final: (callback) => {
      callback();
      this.kill();
    },
  });
  kill() {
    this.exitCode = 0;
    this.emit('exit', 0, null);
    this.stdout.end();
    this.stderr.end();
    this.emit('close', 0, null);
    return true;
  }
}
function clientFixture() {
  const child = new NativeSSOChild();
  const client = new VaultBackendClient(
    { executable: 'fixture', databasePath: 'fixture', heartbeatMs: 120000 },
    () => {
      queueMicrotask(() => child.emit('spawn'));
      return child as unknown as ChildProcessWithoutNullStreams;
    },
  );
  return { child, client };
}

test('native SSO client sends original overrides over stdio and validates all six responses', async () => {
  const { q, offer, c, packet } = vpnSSOFixture(),
    { child, client } = clientFixture();
  const stored = { ...c, sourceRevision: '3', sourceDigest: c.bindingDigest },
    restore = { ...packet, direction: 'restore' as const, context: stored };
  child.respond = ({ operation }) =>
    ({
      'vpn-sso-begin': offer,
      'vpn-sso-take': restore,
      'vpn-sso-restore-ack': { restored: true },
      'vpn-sso-push': { accepted: true, index: 0 },
      'vpn-sso-commit': { revision: '1', deleted: false, digest: Array(32).fill(9) },
      'vpn-sso-cancel': { cancelled: true },
    })[operation as string];
  try {
    const pending = client.beginVPNSSO(q);
    q.request.credentialOverride = randomUUID();
    assert.deepEqual(await pending, offer);
    const payload = child.requests[0].payload;
    assert.equal(payload.request.epoch, '7');
    assert.equal('workspaceId' in payload.request, false);
    assert.notEqual(payload.request.credentialOverride, q.request.credentialOverride);
    assert.deepEqual(await client.takeVPNSSO(stored, packet.manifest, 0), restore);
    assert.deepEqual(await client.acknowledgeVPNSSO(c, offer.manifest), { restored: true });
    assert.deepEqual(await client.pushVPNSSO(packet), { accepted: true, index: 0 });
    assert.equal((await client.commitVPNSSO(c)).revision, '1');
    assert.deepEqual(await client.cancelVPNSSO(c), { cancelled: true });
    const count = child.requests.length;
    for (const call of [
      () => client.beginVPNSSO(null),
      () => client.takeVPNSSO(null, null, 0),
      () => client.takeVPNSSO(c, offer.manifest, 0),
      () => client.takeVPNSSO(stored, packet.manifest, -1),
      () => client.acknowledgeVPNSSO(c, {}),
      () => client.pushVPNSSO(null),
      () => client.commitVPNSSO(null),
      () => client.cancelVPNSSO(null),
    ])
      await assert.rejects(call());
    assert.equal(child.requests.length, count);
  } finally {
    await client.stop();
  }
});

test('native SSO client rejects substituted packets and receipts by retiring that process', async () => {
  const { offer, c, packet } = vpnSSOFixture(),
    stored = { ...c, sourceRevision: '1', sourceDigest: c.bindingDigest };
  for (const [call, response] of [
    [
      (client: VaultBackendClient) => client.takeVPNSSO(stored, packet.manifest, 0),
      {
        ...packet,
        direction: 'restore',
        context: stored,
        manifest: { ...packet.manifest, digest: c.capturePublicKey },
      },
    ],
    [
      (client: VaultBackendClient) => client.acknowledgeVPNSSO(c, offer.manifest),
      { restored: false },
    ],
    [(client: VaultBackendClient) => client.pushVPNSSO(packet), { accepted: true, index: 1 }],
    [
      (client: VaultBackendClient) => client.commitVPNSSO(c),
      { revision: '2', deleted: false, digest: Array(32).fill(9) },
    ],
    [(client: VaultBackendClient) => client.cancelVPNSSO(c), { cancelled: true, private: 1 }],
  ] as const) {
    const { child, client } = clientFixture();
    child.respond = () => response;
    try {
      await assert.rejects(call(client));
      await assert.rejects(client.cancelVPNSSO(c));
    } finally {
      await client.stop();
    }
  }
});

test('native SSO ciphertext chunks use their bounded larger response allowance', async () => {
  const { c, packet } = vpnSSOFixture(),
    { child, client } = clientFixture();
  const context = { ...c, sourceRevision: '1', sourceDigest: c.bindingDigest },
    manifest = { ...packet.manifest, bytes: vpnSSOChunkBytes },
    large = {
      ...packet,
      context,
      manifest,
      direction: 'restore',
      bundle: {
        ...packet.bundle,
        ciphertext: Buffer.alloc(vpnSSOChunkBytes + 16, 4).toString('base64'),
      },
    };
  child.respond = () => large;
  try {
    assert.equal((await client.takeVPNSSO(context, manifest, 0)).manifest.bytes, vpnSSOChunkBytes);
  } finally {
    await client.stop();
  }
});

function capabilityFixture(stored = false) {
  const f = vpnSSOFixture(),
    calls: string[] = [];
  if (stored) {
    f.c.sourceRevision = '2';
    f.c.sourceDigest = f.c.bindingDigest;
    f.offer.manifest = f.packet.manifest;
    f.offer.floor = {
      rowVersion: '2',
      checkpoint: { revision: '2', deleted: false, digest: Array(32).fill(3) },
    };
  }
  const client: VPNSSOClient = {
    beginVPNSSO: async () => {
      calls.push('begin');
      return f.offer;
    },
    takeVPNSSO: async () => {
      calls.push('take');
      return { ...f.packet, direction: 'restore' };
    },
    acknowledgeVPNSSO: async () => {
      calls.push('ack');
      return { restored: true };
    },
    pushVPNSSO: async () => {
      calls.push('push');
      return { accepted: true, index: 0 };
    },
    commitVPNSSO: async () => {
      calls.push('commit');
      return { revision: stored ? '3' : '1', deleted: false, digest: Array(32).fill(8) };
    },
    cancelVPNSSO: async () => {
      calls.push('cancel');
      return { cancelled: true };
    },
  };
  return { ...f, calls, client };
}

test('native SSO capability detaches the original context and permits one completed capture', async () => {
  const f = capabilityFixture(true),
    handle = await beginNativeVPNSSO(f.client, f.q, () => true);
  handle.offer.context.challengeId = randomUUID();
  handle.offer.floor.checkpoint.digest[0] = 255;
  f.offer.context.profileId = randomUUID();
  const packet = { ...f.packet, context: handle.offer.context };
  f.client.takeVPNSSO = async () => ({ ...packet, direction: 'restore' });
  assert.equal((await handle.take(0)).index, 0);
  await handle.acknowledge();
  await handle.push(packet);
  assert.equal((await handle.commit()).revision, '3');
  await assert.rejects(handle.commit(), /closed/);
  await handle.cancel();
});

test('native SSO capability rejects foreign packets, bad receipts and unconfirmed cancellation', async () => {
  for (const failure of ['index', 'packet', 'take', 'ack', 'push', 'commit', 'cancel']) {
    const f = capabilityFixture(true),
      handle = await beginNativeVPNSSO(f.client, f.q, () => true);
    if (failure === 'take')
      f.client.takeVPNSSO = async () => ({ ...f.packet, direction: 'restore', index: 1 });
    if (failure === 'ack') f.client.acknowledgeVPNSSO = async () => ({ restored: false }) as any;
    if (failure === 'push') f.client.pushVPNSSO = async () => ({ accepted: true, index: 1 });
    if (failure === 'commit')
      f.client.commitVPNSSO = async () => ({
        revision: '4',
        deleted: false,
        digest: Array(32).fill(1),
      });
    if (failure === 'cancel') f.client.cancelVPNSSO = async () => ({ cancelled: false }) as any;
    const call =
      failure === 'index'
        ? () => handle.take(-1)
        : failure === 'take'
          ? () => handle.take(0)
          : failure === 'ack' || failure === 'cancel'
            ? () => handle.acknowledge()
            : failure === 'commit'
              ? () => handle.commit()
              : () =>
                  handle.push(
                    failure === 'packet'
                      ? { ...f.packet, context: { ...f.c, profileId: randomUUID() } }
                      : f.packet,
                  );
    if (failure === 'cancel') {
      f.client.acknowledgeVPNSSO = async () => {
        throw Error('fixture failure');
      };
      await assert.rejects(call(), AggregateError);
      await assert.rejects(handle.cancel(), /unconfirmed/);
      f.client.cancelVPNSSO = async () => ({ cancelled: true });
      await handle.cancel();
    } else {
      await assert.rejects(call());
      assert.equal(f.calls.at(-1), 'cancel');
    }
  }
  const f = capabilityFixture();
  await assert.rejects(
    beginNativeVPNSSO(f.client, null, () => true),
    /Invalid/,
  );
  await assert.rejects(
    beginNativeVPNSSO(f.client, f.q, () => false),
    /unavailable/,
  );
  assert.equal(f.calls.length, 0);
  f.client.beginVPNSSO = async () => ({
    ...f.offer,
    context: { ...f.c, challengeId: randomUUID() },
  });
  await assert.rejects(
    beginNativeVPNSSO(f.client, f.q, () => true),
    /Invalid/,
  );
});

test('native SSO capability fences late begins, concurrent captures and revoked original owners', async () => {
  const f = capabilityFixture();
  let allowed = true,
    finish!: () => void;
  f.client.beginVPNSSO = async () => {
    await new Promise<void>((r) => {
      finish = r;
    });
    return f.offer;
  };
  const pending = beginNativeVPNSSO(f.client, f.q, () => allowed);
  allowed = false;
  finish();
  await assert.rejects(pending, /unavailable/);
  assert.deepEqual(f.calls, ['cancel']);
  allowed = true;
  f.client.beginVPNSSO = async () => f.offer;
  const handle = await beginNativeVPNSSO(f.client, f.q, () => allowed);
  f.client.pushVPNSSO = async () => {
    await new Promise<void>((r) => {
      finish = r;
    });
    return { accepted: true, index: 0 };
  };
  const capture = handle.push(f.packet);
  await assert.rejects(handle.commit(), /busy/);
  await handle.cancel();
  finish();
  await assert.rejects(capture, /closed/);
  const revoked = await beginNativeVPNSSO(f.client, f.q, () => allowed);
  const late = revoked.push(f.packet);
  allowed = false;
  finish();
  await assert.rejects(late, /unavailable/);
  assert.equal(f.calls.at(-1), 'cancel');
});
test('a late SSO begin reserves its original cleanup handle before a denied final gate or failed cancellation', async () => {
  const f = capabilityFixture();
  let accepted = true,
    finish!: () => void,
    reserved: any;
  f.client.beginVPNSSO = async () => {
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
    return f.offer;
  };
  f.client.cancelVPNSSO = async () => {
    throw Error('fixture cleanup failure');
  };
  const pending = beginNativeVPNSSO(
    f.client,
    f.q,
    () => accepted,
    (handle) => {
      reserved = handle;
    },
  );
  accepted = false;
  finish();
  await assert.rejects(pending, AggregateError);
  assert.ok(reserved);
  f.client.cancelVPNSSO = async () => ({ cancelled: true });
  await reserved.cancel();
  accepted = true;
  f.client.beginVPNSSO = async () => f.offer;
  await assert.rejects(
    beginNativeVPNSSO(
      f.client,
      f.q,
      () => accepted,
      () => {
        throw Error('fixture reservation rejected');
      },
    ),
  );
});
test('failed SSO cancellation requires confirmed original-process exit and retries an unconfirmed exit', async () => {
  const f = capabilityFixture();
  let finish!: () => void,
    exits = 0,
    settled = false;
  f.client.cancelVPNSSO = async () => {
    throw Error('fixture root exited');
  };
  const handle = await beginNativeVPNSSO(
    f.client,
    f.q,
    () => true,
    undefined,
    async () => {
      exits++;
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
    },
  );
  const pending = handle.cancel().then(() => {
    settled = true;
  });
  await new Promise(setImmediate);
  assert.equal(settled, false);
  finish();
  await pending;
  await handle.cancel();
  assert.equal(exits, 1);
  let fails = true;
  const retry = await beginNativeVPNSSO(
    f.client,
    f.q,
    () => true,
    undefined,
    async () => {
      if (fails) throw Error('fixture unconfirmed native exit');
    },
  );
  await assert.rejects(retry.cancel());
  fails = false;
  await retry.cancel();
});

test('host SSO capability captures the original native process and stays absent from renderer IPC', async () => {
  const f = capabilityFixture();
  const full: any = {
    ...f.client,
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => undefined,
  };
  const host = new VaultBackendHost(
    () => full,
    () => true,
  );
  await assert.rejects(host.beginVPNSSO(f.q, () => true));
  await host.unlock({
    vaultId: f.q.request.workspaceId,
    slotId: randomUUID(),
    kind: 'password',
    factor: new Uint8Array([1]),
  });
  const handle = await host.beginVPNSSO(f.q, () => true);
  try {
    await assert.rejects(
      host.beginVPNSSO(
        { ...f.q, request: { ...f.q.request, workspaceId: randomUUID() } },
        () => true,
      ),
    );
    const names: string[] = [];
    registerVaultIpc({ handle: (name: string) => names.push(name) } as any, host, () => true);
    assert.equal(
      names.some((name) => /sso|transfer/.test(name)),
      false,
    );
    await host.stop();
    await assert.rejects(handle.acknowledge(), /unavailable/);
    assert.equal(f.calls.at(-1), 'cancel');
    await handle.cancel();
  } finally {
    await host.stop();
  }
});
