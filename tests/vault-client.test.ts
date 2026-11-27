import { webRequest, webPlan } from './fixtures/vault-web.ts';
import { vncManualPayload, vncPlanPayload } from '../electron/vault-vnc-manual.ts';
import { vncRequest, vncBundle, routedVncRequest, routedVncBundle } from './fixtures/vault-vnc.ts';
import { rdpRequest, rdpBundle, routedRdpRequest, routedRdpBundle } from './fixtures/vault-rdp.ts';
import {
  migrationReport,
  migrationDecision,
  migrationSelection,
  migrationNode,
} from './fixtures/vault-migration.ts';
import { connectionInput, connectionNodeId } from './fixtures/vault-connection.ts';
import { preferences } from './fixtures/vault-preferences.ts';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { Socket } from 'node:net';
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { launchVaultTouchIDBroker } from '../electron/vault-touchid-broker.ts';
import {
  maxBitwardenFrame,
  parseVaultSSHBitwardenPreparation,
  resolveVaultSSHBitwarden,
} from '../electron/vault-ssh-bitwarden.ts';
import { fallbackPlan, fallbackRequest, fallbackBundle } from './fixtures/vault-tunnel-fallback.ts';
import {
  VaultBackendClient,
  vaultMetadataFrameLimit,
  vaultCatalogFrameLimit,
} from '../electron/vault-client.ts';

const status = {
  formatVersion: 1,
  stage: 'foundation',
  protectionAvailable: false,
  sharedWorkspaceAvailable: false,
  unlocked: false,
  lockedMemory: false,
};
type Request = { version: number; id: number; operation: string };
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

test('personal Standard is sent only as a fresh action with the observed policy sequence', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  await assert.rejects(client.tightenLocalProfile('4', undefined as never), /authentication/);
  assert.equal(child.requests.length, 0);
  const factor = new Uint8Array([1, 2, 3]);
  const pending = client.tightenLocalProfile('4', {
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
    kind: 'password',
    factor,
  });
  await tick();
  const request = child.requests.at(-1)!;
  assert.equal(request.operation, 'fresh-action');
  const payload = (request as any).payload;
  assert.equal(payload.operation, 'tighten-local-profile');
  assert.deepEqual(JSON.parse(Buffer.from(payload.action, 'base64').toString()), { sequence: '4' });
  assert.equal(
    JSON.parse(Buffer.from(payload.authentication, 'base64').toString()).password,
    'AQID',
  );
  assert.deepEqual([...factor], [0, 0, 0]);
  child.reply(request, true);
  assert.equal(await pending, true);
  await client.lock();
});

test('Windows Hello sends only native metadata or a freshly authorized slot edit', async (context) => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const { child, client } = fixture();
  child.automatic = false;
  const selection = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
  };
  const input = () => ({
    ...selection,
    kind: 'password' as const,
    factor: new Uint8Array([1, 2, 3]),
  });
  for (const handle of ['0', '01', '18446744073709551616', '-1', '4.2'])
    await assert.rejects(client.unlockPresence('hello', selection, handle), /Invalid/);
  await assert.rejects(
    client.unlockPresence('hello', { ...selection, signature: 'private' }, '57'),
    /Invalid/,
  );
  const invalidFactor = input();
  await assert.rejects(client.enrollPresence('hello', '0', invalidFactor), /Invalid/);
  assert.deepEqual([...invalidFactor.factor], [0, 0, 0]);
  const invalidRemoval = input();
  await assert.rejects(client.removePresence('hello', 'invalid', invalidRemoval), /Invalid/);
  assert.deepEqual([...invalidRemoval.factor], [0, 0, 0]);
  assert.equal(child.requests.length, 0);

  const availability = client.presenceAvailability('hello');
  await tick();
  const available = child.requests.at(-1)!;
  assert.equal(available.operation, 'hello-availability');
  assert.equal('payload' in available, false);
  child.reply(available, { status: 'ready' });
  assert.equal(await availability, 'ready');

  for (const result of [
    { status: 'remote-desktop' },
    { status: 'canceled' },
    { unlocked: true, lockedMemory: true },
  ]) {
    const pending = client.unlockPresence('hello', selection, '18446744073709551615');
    await tick();
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, 'hello-unlock');
    assert.deepEqual((request as any).payload, {
      ...selection,
      ownerWindow: '18446744073709551615',
    });
    child.reply(request, result);
    assert.deepEqual(await pending, result);
  }

  for (const [operation, action, result] of [
    ['hello-enroll', { ownerWindow: '57' }, { status: 'not-repeatable' }],
    ['hello-enroll', { ownerWindow: '57' }, { enrolled: true }],
    ['hello-remove', { slotId: selection.slotId }, { removed: true, keyDeleted: false }],
  ] as const) {
    const factor = input();
    const pending =
      operation === 'hello-enroll'
        ? client.enrollPresence('hello', '57', factor)
        : client.removePresence('hello', selection.slotId, factor);
    await tick();
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, 'fresh-action');
    const payload = (request as any).payload;
    assert.equal(payload.operation, operation);
    assert.deepEqual(JSON.parse(Buffer.from(payload.action, 'base64').toString()), action);
    assert.deepEqual(JSON.parse(Buffer.from(payload.authentication, 'base64').toString()), {
      ...selection,
      password: 'AQID',
    });
    assert.deepEqual([...factor.factor], [0, 0, 0]);
    if (operation === 'hello-enroll') {
      context.mock.timers.tick(180_000);
      assert.equal(child.killed, false);
    }
    child.reply(request, result);
    assert.deepEqual(await pending, result);
  }
  const unexpected = client.unlockPresence('hello', selection, '57');
  await tick();
  child.reply(child.requests.at(-1)!, { status: 'unavailable', signature: 'private fixture' });
  await assert.rejects(unexpected, (error: Error) => !error.message.includes('private fixture'));
  await client.lock();
});

test('Touch ID crosses stdin with scoped metadata and a fresh software factor for each edit', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  const selection = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
  };
  const input = () => ({
    ...selection,
    kind: 'password' as const,
    factor: new Uint8Array([1, 2, 3]),
  });
  await assert.rejects(client.unlockPresence('touch-id', selection, '314'), /Invalid/);
  const rejected = input();
  await assert.rejects(client.enrollPresence('touch-id', '314', rejected), /Invalid/);
  assert.deepEqual([...rejected.factor], [0, 0, 0]);
  assert.equal(child.requests.length, 0);
  const availability = client.presenceAvailability('touch-id');
  await tick();
  const probe = child.requests.at(-1)!;
  assert.equal(probe.operation, 'touch-id-availability');
  assert.equal('payload' in probe, false);
  child.reply(probe, { status: 'ready' });
  assert.equal(await availability, 'ready');
  const opening = client.unlockPresence('touch-id', selection);
  await tick();
  const request = child.requests.at(-1)!;
  assert.equal(request.operation, 'touch-id-unlock');
  assert.deepEqual((request as any).payload, selection);
  child.reply(request, { status: 'canceled' });
  assert.deepEqual(await opening, { status: 'canceled' });
  for (const [operation, action, result] of [
    ['touch-id-enroll', {}, { enrolled: true }],
    ['touch-id-remove', { slotId: selection.slotId }, { removed: true, keyDeleted: true }],
  ] as const) {
    const factor = input();
    const change =
      operation === 'touch-id-enroll'
        ? client.enrollPresence('touch-id', undefined, factor)
        : client.removePresence('touch-id', selection.slotId, factor);
    await tick();
    const edit = child.requests.at(-1)!;
    assert.equal(edit.operation, 'fresh-action');
    const payload = (edit as any).payload;
    assert.equal(payload.operation, operation);
    assert.deepEqual(JSON.parse(Buffer.from(payload.action, 'base64').toString()), action);
    assert.deepEqual(JSON.parse(Buffer.from(payload.authentication, 'base64').toString()), {
      ...selection,
      password: 'AQID',
    });
    assert.deepEqual([...factor.factor], [0, 0, 0]);
    child.reply(edit, result);
    assert.deepEqual(await change, result);
  }
  await client.lock();
});

test('personal key recovery sends fresh factors only with the approved scoped native request', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  const request = { accountId: '11111111-1111-4111-8111-111111111111', suspension: '8' };
  const review = 'ab'.repeat(32);
  const confirm = { ...request, review };
  const auth = () => ({
    vaultId: request.accountId,
    slotId: '22222222-2222-4222-8222-222222222222',
    password: new Uint8Array([1, 2, 3]),
    ask: new Uint8Array(32).fill(4),
  });
  const premature = auth();
  try {
    await assert.rejects(client.sharedPersonalRootRecovery(request, premature), /reviewed/i);
    assert.deepEqual(premature.password, new Uint8Array(3));
    assert.deepEqual(premature.ask, new Uint8Array(32));
    await assert.rejects(client.sharedPersonalRootRecovery(confirm), /reviewed/i);
    assert.equal(child.requests.length, 0);
    const read = client.sharedPersonalRootRecovery(request);
    await tick();
    const draft = child.requests[0] as Request & { payload: unknown };
    assert.equal(draft.operation, 'shared-personal-root-recovery');
    assert.deepEqual(draft.payload, request);
    const reviewed = {
      status: 'review',
      review,
      enrollment: '33333333-3333-4333-8333-333333333333',
    };
    child.reply(draft, reviewed);
    assert.deepEqual(await read, reviewed);
    const factors = auth();
    const pending = client.sharedPersonalRootRecovery(confirm, factors);
    await tick();
    const submitted = child.requests[1] as Request & {
      payload: { authentication: string; review: string; accountId: string; suspension: string };
    };
    assert.equal(submitted.operation, 'shared-personal-root-recovery');
    const { authentication, ...scope } = submitted.payload;
    assert.deepEqual(scope, confirm);
    assert.deepEqual(JSON.parse(Buffer.from(authentication, 'base64').toString()), {
      vaultId: factors.vaultId,
      slotId: factors.slotId,
      password: 'AQID',
      ask: Buffer.alloc(32, 4).toString('base64'),
    });
    child.reply(submitted, { status: 'changed' });
    assert.deepEqual(await pending, { status: 'changed' });
    assert.deepEqual(factors.password, new Uint8Array(3));
    assert.deepEqual(factors.ask, new Uint8Array(32));
  } finally {
    child.automatic = true;
    await client.lock();
  }
});

test('workspace backup uses the recovery channel and consumes authenticated export factors', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  const path = resolve('workspace-recovery.json');
  const publicKey = new Uint8Array(32).fill(21);
  const auth = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
    password: new Uint8Array([1, 2, 3]),
  };
  try {
    const malformed = { ...auth, password: auth.password.slice() };
    await assert.rejects(client.exportSharedRecoveryBackup(path, publicKey.subarray(1), malformed));
    assert.deepEqual(malformed.password, new Uint8Array(3));
    await assert.rejects(client.exportSharedRecoveryBackup('relative.json', publicKey));
    assert.equal(child.requests.length, 0);
    const pending = client.exportSharedRecoveryBackup(path, publicKey, auth);
    await tick();
    const request = child.requests[0] as Request & {
      payload: { path: string; recipient: string; authentication: string };
    };
    assert.equal(request.operation, 'shared-recovery-export');
    assert.equal(request.payload.path, path);
    assert.deepEqual(Buffer.from(request.payload.recipient, 'base64'), Buffer.from(publicKey));
    assert.deepEqual(JSON.parse(Buffer.from(request.payload.authentication, 'base64').toString()), {
      vaultId: auth.vaultId,
      slotId: auth.slotId,
      password: 'AQID',
    });
    child.reply(request, { status: 'invalid-authentication' });
    assert.deepEqual(await pending, { status: 'invalid-authentication' });
    assert.deepEqual(auth.password, new Uint8Array(3));
    assert.ok(child.writtenFrames[0].every((byte) => byte === 0));
  } finally {
    await client.lock();
  }
});

class Child extends EventEmitter {
  pid: number | undefined = process.pid;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly requests: Request[] = [];
  readonly kills: string[] = [];
  killed = false;
  exitOnEnd = true;
  exitOnKill = true;
  automatic = true;
  heartbeatOnly = false;
  writeFailure = false;
  holdUnlockWrites = false;
  heldUnlockWrite: { frame: Buffer; callback: (error?: Error | null) => void } | undefined;
  readonly writtenFrames: Buffer[] = [];
  ended = false;
  readonly stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      if (Buffer.isBuffer(chunk)) this.writtenFrames.push(chunk);
      if (this.writeFailure) {
        callback(new Error('private write diagnostic'));
        return;
      }
      for (const line of chunk.toString().trim().split('\n')) {
        const request = JSON.parse(line) as Request;
        this.requests.push(request);
        this.emit('request', request);
        if (request.operation === 'lock') continue;
        if (this.automatic || (this.heartbeatOnly && request.operation === 'heartbeat'))
          this.reply(request);
        if (
          this.holdUnlockWrites &&
          ['unlock', 'shared-unlock', 'shared-recover-password'].includes(request.operation)
        ) {
          this.heldUnlockWrite = { frame: chunk, callback };
          return;
        }
      }
      callback();
    },
  });
  constructor() {
    super();
    this.stdin.on('finish', () => {
      if (this.exitOnEnd) queueMicrotask(() => this.exit());
    });
  }
  reply(
    request: Request,
    result: unknown = request.operation === 'preferences'
      ? preferences()
      : request.operation === 'status'
        ? status
        : request.operation === 'startup'
          ? { slots: null, cosmetics: { theme: 'system' }, newWorkspace: false }
          : request.operation === 'heartbeat'
            ? { alive: true }
            : request.operation === 'catalog'
              ? { nodes: [], credentials: [], tunnels: [] }
              : request.operation === 'workspace'
                ? {
                    tree: [],
                    credentials: [],
                    credentialOptions: { ssh: [], rdp: [], vnc: [] },
                    tunnels: [],
                  }
                : request.operation === 'shared-unlock' ||
                    request.operation === 'shared-continue-enrollment'
                  ? { admitted: true, lockedMemory: false, orgEscrow: true }
                  : request.operation === 'shared-recover-password'
                    ? { recovered: true }
                    : request.operation === 'unlock'
                      ? { unlocked: true, lockedMemory: true }
                      : { slots: null },
  ): void {
    this.stdout.write(JSON.stringify({ version: 1, id: request.id, result }) + '\n');
  }
  exit(): void {
    if (this.ended) return;
    this.ended = true;
    this.exitCode = 0;
    this.emit('exit', 0, null);
    this.stdout.end();
    this.stderr.end();
    this.emit('close', 0, null);
  }
  kill(signal: string): boolean {
    this.killed = true;
    this.kills.push(signal);
    if (this.exitOnKill) this.exit();
    return true;
  }
  process(): ChildProcessWithoutNullStreams {
    return this as unknown as ChildProcessWithoutNullStreams;
  }
}

test('native unavailability may reenter host retirement without recursion or replacement', async () => {
  for (const mode of ['explicit', 'protocol']) {
    const child = new Child();
    let notifications = 0,
      spawned = 0;
    let cleanup: Promise<void> | undefined;
    const host = new VaultBackendHost(
      () =>
        new VaultBackendClient(
          {
            executable: 'fixture',
            databasePath: 'workspace',
            onUnavailable: () => {
              notifications++;
              cleanup = host.stop();
            },
          },
          () => {
            spawned++;
            queueMicrotask(() => child.emit('spawn'));
            return child.process();
          },
        ),
      () => true,
    );
    await host.status();
    if (mode === 'protocol') child.stdout.write('invalid-frame\n');
    await host.stop();
    await cleanup;
    assert.equal(notifications, 1);
    assert.equal(spawned, 1);
    assert.equal(child.requests.filter((request) => request.operation === 'lock').length, 1);
    assert.equal(host.hasOwner, false);
  }
});

function fixture(
  options: ConstructorParameters<typeof VaultBackendClient>[0] = {
    executable: 'vault',
    databasePath: 'workspace.db',
  },
) {
  const child = new Child();
  const launches: { executable: string; args: string[] }[] = [];
  const client = new VaultBackendClient(options, (executable, args) => {
    launches.push({ executable, args });
    queueMicrotask(() => child.emit('spawn'));
    return child.process();
  });
  return { child, client, launches };
}

test('SSH Bitwarden helper uses only the exact native recipient and sealed relay frames', async () => {
  const direct = sshRequest();
  const routed = {
    ...direct,
    sftpOnly: true as const,
    endpoint: '127.0.0.1:12345',
    route: {
      ...sshBundle(direct).binding,
      tunnelConfigId: direct.nodeId,
      fileId: direct.workspaceId,
      kind: 6,
      rowVersion: '1',
      configurationVersion: '1',
    },
  };
  const revision = 'abcde0'.repeat(10) + '1234';
  const publicKey = Buffer.alloc(32, 9).toString('base64');
  const {
    fileId: _fileId,
    kind: _kind,
    rowVersion: _rowVersion,
    configurationVersion: _configurationVersion,
    ...base
  } = routed.route;
  for (const mode of [
    'direct',
    'routed',
    'local',
    'recipient',
    'result',
    'extra',
    'partial',
    'oversize',
    'exit',
    'no-release',
    'cancel',
  ]) {
    const request = mode === 'routed' ? routed : direct;
    const final =
      mode === 'routed'
        ? { ...sshBundle(routed), binding: routed.route, endpoint: routed.endpoint }
        : sshBundle(direct);
    const ticket = {
      binding: mode === 'routed' ? base : sshBundle(direct).binding,
      ticket: final.bundle,
    };
    const abort = new AbortController();
    let spawned = 0;
    let writes = 0;
    let releases = 0;
    const result = resolveVaultSSHBitwarden({
      executable: 'native',
      databasePath: 'workspace.db',
      request,
      signal: abort.signal,
      prepare: async (recipient) => {
        if (!recipient)
          return mode === 'local' ? { required: false } : { required: true, revision };
        assert.deepEqual(recipient, { publicKey, revision });
        releases++;
        if (mode === 'cancel') abort.abort();
        if (mode === 'no-release') return { required: true, revision };
        const prepared = parseVaultSSHBitwardenPreparation(
          { required: true, revision, release: ticket },
          request,
          recipient,
        );
        assert.ok(prepared);
        return prepared;
      },
      start: (exe, args) => {
        spawned++;
        assert.equal(exe, 'native');
        assert.deepEqual(args, [
          '--operation',
          'serve',
          '--sealed-ssh-bitwarden',
          '--database',
          'workspace.db',
        ]);
        const child = new EventEmitter() as ChildProcessWithoutNullStreams;
        const stdout = new PassThrough();
        const stderr = new PassThrough();
        child.stdout = stdout as any;
        child.stderr = stderr as any;
        const finish = () => {
          if (child.exitCode !== null) return;
          child.exitCode = mode === 'exit' ? 1 : 0;
          stdout.end();
          stderr.end();
          queueMicrotask(() => child.emit('close', child.exitCode));
        };
        child.stdin = new Writable({
          write(buffer, _encoding, done) {
            writes++;
            assert.deepEqual(JSON.parse(String(buffer)), ticket);
            const response = mode === 'result' ? { ...final, password: 'synthetic' } : final;
            stdout.write(JSON.stringify(response) + '\n');
            if (mode === 'extra') stdout.write('{}\n');
            done();
            finish();
          },
          destroy(err, done) {
            finish();
            done(err);
          },
        }) as any;
        child.exitCode = child.signalCode = null;
        child.kill = () => {
          finish();
          return true;
        };
        queueMicrotask(() => {
          if (mode === 'partial' || mode === 'oversize') {
            stdout.write(mode === 'partial' ? '{' : Buffer.alloc(maxBitwardenFrame, 88));
            finish();
          } else {
            const line =
              JSON.stringify({ publicKey: mode === 'recipient' ? direct.publicKey : publicKey }) +
              '\n';
            stdout.write(line.slice(0, 4));
            stdout.write(line.slice(4));
          }
        });
        return child;
      },
    });
    if (mode === 'local') {
      assert.equal(await result, undefined);
      assert.equal(spawned, 0);
    } else if (mode === 'direct' || mode === 'routed') {
      assert.deepEqual(await result, final);
      assert.equal(writes, 1);
    } else {
      await assert.rejects(result, /unavailable/);
      if (['recipient', 'partial', 'oversize', 'cancel', 'no-release'].includes(mode))
        assert.equal(writes, 0);
    }
    assert.equal(releases, ['local', 'recipient', 'partial', 'oversize'].includes(mode) ? 0 : 1);
  }
});

test('SSH Bitwarden rejects stale or redirected grants and redacts startup failures', async () => {
  const request = sshRequest();
  const { binding, bundle: ticket } = sshBundle(request);
  const revision = 'a'.repeat(64);
  const recipient = { publicKey: Buffer.alloc(32, 9).toString('base64'), revision };
  const probe = { required: true, revision };
  const release = { ...probe, release: { binding, ticket } };
  assert.deepEqual(parseVaultSSHBitwardenPreparation(probe, request), probe);
  assert.deepEqual(parseVaultSSHBitwardenPreparation(release, request, recipient), release);
  for (const candidate of [
    null,
    { required: 'yes', revision },
    { ...probe, revision: 'stale' },
    { ...probe, unexpected: true },
    { required: false },
    { ...release, revision: 'b'.repeat(64) },
    { ...release, release: { ...release.release, extra: true } },
    {
      ...release,
      release: {
        ...release.release,
        binding: { ...binding, host: 'other', nodeId: request.sessionId },
      },
    },
    {
      ...release,
      release: { ...release.release, ticket: { ...ticket, ciphertext: 'not-base64' } },
    },
  ])
    assert.equal(parseVaultSSHBitwardenPreparation(candidate, request, recipient), undefined);
  const routed = {
    ...request,
    endpoint: '127.0.0.1:3000',
    route: {
      ...binding,
      tunnelConfigId: request.nodeId,
      kind: 6,
      fileId: request.workspaceId,
      rowVersion: '1',
      configurationVersion: '1',
    },
  };
  assert.equal(parseVaultSSHBitwardenPreparation(release, routed, recipient), undefined);

  const abort = new AbortController();
  await assert.rejects(
    resolveVaultSSHBitwarden({
      request,
      executable: resolve('missing-bitwarden-resolver-fixture', 'native.exe'),
      databasePath: 'workspace.db',
      prepare: async () => probe,
      signal: abort.signal,
    }),
    { message: 'Bitwarden credential is unavailable.' },
  );
  abort.abort();
  await assert.rejects(
    resolveVaultSSHBitwarden({
      request,
      executable: 'native',
      databasePath: 'workspace.db',
      prepare: async () => {
        assert.fail('aborted request asked the vault for a grant');
      },
      signal: abort.signal,
    }),
    { name: 'AbortError' },
  );
});

test('SSH Bitwarden vault RPC binds the grant to the current local owner', async () => {
  const q = sshRequest();
  const { client, child } = fixture();
  child.automatic = false;
  const owner = {
    client,
    unlockedWorkspaceId: q.workspaceId,
    isSharedWorkspace: true,
  };
  const prepare = VaultBackendHost.prototype.prepareSSHBitwarden.bind(owner as any);
  const revision = 'a'.repeat(64);
  const recipient = { publicKey: Buffer.alloc(32, 8).toString('base64'), revision };
  try {
    await assert.rejects(
      prepare(q, undefined, () => true),
      /locked/,
    );
    owner.isSharedWorkspace = false;
    await assert.rejects(
      prepare(q, undefined, () => false),
      /locked/,
    );
    await assert.rejects(client.prepareSSHBitwarden({ ...q, nodeId: 'invalid' }), /Invalid/);
    assert.equal(child.requests.length, 0);
    const probe = prepare(q, undefined, () => true);
    await tick();
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, 'ssh-bitwarden-prepare');
    assert.equal(Object.hasOwn((request as any).payload, 'resolverPublicKey'), false);
    child.reply(request, { required: true, revision });
    assert.deepEqual(await probe, { required: true, revision });

    const release = prepare(q, recipient, () => true);
    await tick();
    const issue = child.requests.at(-1)!;
    assert.equal((issue as any).payload.resolverPublicKey, recipient.publicKey);
    assert.equal((issue as any).payload.revision, revision);
    const { binding, bundle: ticket } = sshBundle(q);
    owner.unlockedWorkspaceId = '';
    child.reply(issue, { required: true, revision, release: { binding, ticket } });
    await assert.rejects(release, /locked/);
  } finally {
    await client.lock();
  }
});

test('Bitwarden CLI renewal transports sealed sessions against one local owner', async () => {
  const q = sshRequest();
  for (const mode of ['commit', 'invalid-ack', 'released', 'wrong-workspace', 'retired'] as const) {
    const { client, child } = fixture();
    child.automatic = false;
    let valid = true;
    const owner = {
      client: mode === 'released' ? undefined : client,
      unlockedWorkspaceId: q.workspaceId,
      isSharedWorkspace: true,
    };
    const begin = VaultBackendHost.prototype.beginBitwardenCLIUnlock.bind(owner as any);
    const binding = {
      workspaceId: mode === 'wrong-workspace' ? q.nodeId : q.workspaceId,
      requestId: q.requestId,
      expiresAt: Date.now() + 60_000,
      configuration: 'a'.repeat(64),
      vaultKey: q.publicKey,
    };
    const session = sshBundle(q).bundle;
    try {
      await assert.rejects(
        begin(() => true),
        /locked/,
      );
      await assert.rejects(client.commitBitwardenCLIUnlock('invalid', session), /Invalid/);
      await assert.rejects(client.commitBitwardenCLIUnlock(q.requestId, {}), /Invalid/);
      await assert.rejects(client.cancelBitwardenCLIUnlock('invalid'), /Invalid/);
      owner.isSharedWorkspace = false;
      owner.client = client;
      await assert.rejects(
        begin(() => false),
        /locked/,
      );
      assert.equal(child.requests.length, 0);
      const starting = begin(() => valid);
      const rejected =
        mode === 'released' || mode === 'wrong-workspace'
          ? assert.rejects(starting, /locked/)
          : undefined;
      await tick();
      assert.equal(child.requests.at(-1)?.operation, 'bitwarden-cli-unlock-begin');
      assert.equal('payload' in child.requests.at(-1)!, false);
      if (mode === 'released') valid = false;
      child.reply(child.requests.at(-1)!, binding);
      if (rejected) {
        await tick();
        const cancel = child.requests.at(-1)!;
        assert.equal(cancel.operation, 'bitwarden-cli-unlock-cancel');
        assert.deepEqual((cancel as any).payload, { requestId: q.requestId });
        child.reply(cancel, { cancelled: true });
        await rejected;
        continue;
      }
      const grant = await starting;
      assert.deepEqual(grant.binding, binding);
      const writing = grant.commit(session);
      const stale = mode !== 'commit' ? assert.rejects(writing) : undefined;
      await tick();
      const request = child.requests.at(-1)!;
      assert.equal(request.operation, 'bitwarden-cli-unlock-commit');
      assert.deepEqual((request as any).payload, { requestId: q.requestId, session });
      if (mode === 'retired') owner.client = undefined;
      child.reply(
        request,
        mode === 'invalid-ack' ? { unlocked: true, key: 'foreign' } : { unlocked: true },
      );
      await (stale ?? writing);
      if (mode === 'retired') {
        await assert.rejects(grant.commit(session), /locked/);
        await grant.cancel();
        assert.strictEqual(child.requests.at(-1), request);
      }
    } finally {
      await client.lock();
    }
  }
});

test('VNC Bitwarden client scopes the ticket request to the current local owner and route', async () => {
  const { client, child } = fixture();
  child.automatic = false;
  const q = routedVncRequest();
  const owner = { client, unlockedWorkspaceId: q.workspaceId, isSharedWorkspace: true };
  const open = VaultBackendHost.prototype.prepareVNCBitwarden.bind(owner as any);
  const recipient = { publicKey: Buffer.alloc(32, 8).toString('base64'), revision: 'a'.repeat(64) };
  let accepted = true;
  try {
    await assert.rejects(
      open(q, undefined, () => true),
      /locked/,
    );
    owner.isSharedWorkspace = false;
    await assert.rejects(
      open(q, undefined, () => false),
      /locked/,
    );
    await assert.rejects(client.prepareVNCBitwarden({ ...q, endpoint: 'invalid' }), /Invalid/);
    await assert.rejects(
      client.prepareVNCBitwarden(q, { ...recipient, revision: 'invalid' }),
      /Invalid/,
    );
    assert.equal(child.requests.length, 0);
    const probe = open(q, undefined, () => true);
    await tick();
    assert.equal(child.requests.at(-1)?.operation, 'vnc-bitwarden-prepare');
    child.reply(child.requests.at(-1)!, { required: true, revision: recipient.revision });
    assert.equal((await probe).required, true);
    const release = open(q, recipient, () => accepted);
    const rejected = assert.rejects(release, /locked/);
    await tick();
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, 'vnc-bitwarden-prepare');
    assert.deepEqual((request as any).payload.route, q.route);
    assert.equal((request as any).payload.endpoint, q.endpoint);
    assert.equal((request as any).payload.resolverPublicKey, recipient.publicKey);
    const { fileId: _f, kind: _k, rowVersion: _r, configurationVersion: _c, ...binding } = q.route;
    accepted = false;
    child.reply(request, {
      required: true,
      revision: recipient.revision,
      release: { binding, ticket: vncBundle(q).bundle },
    });
    await rejected;
  } finally {
    await client.lock();
  }
});

test('RDP Bitwarden client accepts the full paired frame and rejects a retired owner', async () => {
  const { client, child } = fixture();
  child.automatic = false;
  const q = routedRdpRequest();
  const owner = { client, unlockedWorkspaceId: q.workspaceId, isSharedWorkspace: true };
  const prepare = VaultBackendHost.prototype.prepareRDPBitwarden.bind(owner as any);
  const revision = 'd'.repeat(64);
  const recipient = { publicKey: Buffer.alloc(32, 9).toString('base64'), revision };
  const { fileId: _f, kind: _k, rowVersion: _r, configurationVersion: _c, ...binding } = q.route;
  const envelope = rdpBundle(q).bundle;
  const pair = {
    required: true,
    revision,
    release: {
      binding,
      ticket: { ...envelope, ciphertext: Buffer.alloc(96 * 1024 + 16, 5).toString('base64') },
    },
    rdpBase: { ...envelope, ciphertext: Buffer.alloc(64 * 1024 + 16, 4).toString('base64') },
  };
  try {
    await assert.rejects(
      prepare(q, undefined, () => true),
      /locked/,
    );
    owner.isSharedWorkspace = false;
    await assert.rejects(
      prepare(q, undefined, () => false),
      /locked/,
    );
    await assert.rejects(client.prepareRDPBitwarden({ ...q, endpoint: 'invalid' }), /Invalid/);
    await assert.rejects(
      client.prepareRDPBitwarden(q, { ...recipient, publicKey: 'invalid' }),
      /Invalid/,
    );
    const pending = prepare(q, recipient, () => true);
    await tick();
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, 'rdp-bitwarden-prepare');
    assert.deepEqual((request as any).payload.route, q.route);
    assert.equal((request as any).payload.endpoint, q.endpoint);
    assert.equal((request as any).payload.resolverPublicKey, recipient.publicKey);
    child.reply(request, pair);
    assert.deepEqual(await pending, {
      required: true,
      revision,
      release: {
        ticket: pair.release,
        base: { binding: q.route, endpoint: q.endpoint, bundle: pair.rdpBase },
      },
    });
    const stale = assert.rejects(
      prepare(q, undefined, () => true),
      /locked/,
    );
    await tick();
    owner.unlockedWorkspaceId = '';
    child.reply(child.requests.at(-1)!, { required: true, revision });
    await stale;
  } finally {
    await client.lock();
  }
});

test('manual RDP gateway release binds both the document and direct destination', async () => {
  const q = rdpRequest();
  const template = rdpBundle(q);
  const input = {
    context: { binding: template.binding, publicKey: q.publicKey },
    credentialOverride: '',
    manual: template.bundle,
  };
  const revision = '7'.repeat(64);
  const recipient = { publicKey: Buffer.alloc(32, 2).toString('base64'), revision };
  const routed = routedRdpRequest();
  for (const mode of ['released', 'redirected', 'retired']) {
    const { client, child } = fixture();
    child.automatic = false;
    const owner = { client, unlockedWorkspaceId: q.workspaceId, isSharedWorkspace: true };
    const prepare = VaultBackendHost.prototype.prepareManualRDPBitwarden.bind(owner as any);
    try {
      await assert.rejects(
        prepare(input, undefined, () => true),
        /unavailable/,
      );
      owner.isSharedWorkspace = false;
      await assert.rejects(
        prepare(input, undefined, () => false),
        /unavailable/,
      );
      await assert.rejects(
        client.prepareManualRDPBitwarden({
          ...input,
          context: {
            binding: routed.route,
            publicKey: routed.publicKey,
            endpoint: routed.endpoint,
          },
        }),
        /Invalid/,
      );
      await assert.rejects(
        client.prepareManualRDPBitwarden(input, {
          publicKey: recipient.publicKey,
          revision: 'invalid',
        }),
        /Invalid/,
      );
      const discovery = prepare(input, undefined, () => true);
      await tick();
      const probe = child.requests.at(-1)!;
      assert.equal(probe.operation, 'rdp-manual-bitwarden-prepare');
      assert.deepEqual((probe as any).payload.manual, input.manual);
      assert.equal((probe as any).payload.revision, undefined);
      child.reply(probe, { required: true, revision });
      assert.deepEqual(await discovery, { required: true, revision });
      const pending = prepare(input, recipient, () => true);
      const failed =
        mode === 'released'
          ? undefined
          : assert.rejects(pending, mode === 'retired' ? /locked/ : /Vault is unavailable/);
      await tick();
      const grant = child.requests.at(-1)!;
      assert.deepEqual((grant as any).payload.binding, input.context.binding);
      assert.equal((grant as any).payload.resolverPublicKey, recipient.publicKey);
      if (mode === 'retired') owner.unlockedWorkspaceId = '';
      const binding = {
        ...template.binding,
        port: mode === 'redirected' ? 3390 : template.binding.port,
      };
      const base = { ...template.bundle, ciphertext: Buffer.alloc(76, 7).toString('base64') };
      child.reply(grant, {
        required: true,
        revision,
        release: { binding, ticket: template.bundle },
        rdpBase: base,
      });
      if (failed) await failed;
      else
        assert.deepEqual(await pending, {
          required: true,
          revision,
          release: {
            ticket: { binding, ticket: template.bundle },
            base: { binding, bundle: base },
          },
        });
    } finally {
      await client.lock();
    }
  }
});

test('Touch ID broker hands an anonymous descriptor to the vault and main closes its copy', async () => {
  for (const mode of ['ready', 'closed', 'missing'] as const) {
    const native = new Child();
    const channel = new Socket();
    let opened = 0;
    const client = new VaultBackendClient(
      {
        executable: 'signed-backend',
        databasePath: 'workspace.db',
        openTouchIDBroker: (executable) => {
          assert.equal(executable, 'signed-backend');
          opened++;
          if (mode === 'closed') channel.destroy();
          return mode === 'missing' ? undefined : channel;
        },
      },
      (_executable, args, inherited) => {
        assert.equal(args.includes('--touch-id-channel'), mode === 'ready');
        assert.equal(inherited, mode === 'ready' ? channel : undefined);
        assert.equal(channel.listenerCount('data'), 0);
        queueMicrotask(() => native.emit('spawn'));
        return native.process();
      },
    );
    try {
      assert.deepEqual(await client.status(), status);
      assert.equal(opened, 1);
      assert.equal(channel.destroyed, mode !== 'missing');
    } finally {
      channel.destroy();
      await client.lock();
    }
  }
});

test('Touch ID broker accepts only a live socket and handles spawn errors', () => {
  const channel = new Socket();
  const handle = new EventEmitter();
  let unreferenced = false;
  Object.assign(handle, {
    pid: 100,
    stdio: [null, null, null, channel],
    unref: () => {
      unreferenced = true;
    },
  });
  const installed = launchVaultTouchIDBroker('signed-native', (executable, args, options) => {
    assert.equal(executable, 'signed-native');
    assert.deepEqual(args, ['--operation', 'vault-touch-id-broker']);
    assert.deepEqual(options.stdio, ['ignore', 'ignore', 'ignore', 'pipe']);
    return handle as any;
  });
  assert.equal(installed, channel);
  assert.equal(channel.isPaused(), true);
  assert.equal(unreferenced, true);
  handle.emit('error', Error('synthetic'));
  assert.equal(channel.destroyed, true);

  const broken = new Socket();
  Object.assign(handle, { stdio: [null, null, null, broken] });
  assert.equal(
    launchVaultTouchIDBroker('signed-native', () => handle as any),
    broken,
  );
  broken.emit('error', Error('synthetic pipe failure'));
  assert.equal(broken.destroyed, true);

  const next = new Socket();
  Object.assign(handle, { pid: undefined, stdio: [null, null, null, next] });
  assert.equal(
    launchVaultTouchIDBroker('signed-native', () => handle as any),
    undefined,
  );
  assert.equal(next.destroyed, true);
  Object.assign(handle, { pid: 100, stdio: [null, null, null, null] });
  assert.equal(
    launchVaultTouchIDBroker('signed-native', () => handle as any),
    undefined,
  );
  assert.equal(
    launchVaultTouchIDBroker('signed-native', () => {
      throw Error('unavailable');
    }),
    undefined,
  );
});

test(
  'Unix libuv transfers a broker socket end directly between two native processes',
  { skip: process.platform === 'win32', timeout: 3000 },
  async (t) => {
    const brokerCode = `
      const { Socket } = require('node:net');
      const endpoint = new Socket({ fd: 3, readable: true, writable: true });
      let request = '';
      endpoint.on('data', (chunk) => {
        request += chunk.toString();
        if (request.length < 5) return;
        if (request !== 'probe') process.exit(2);
        endpoint.end('fixture');
      });
    `;
    const channel = launchVaultTouchIDBroker(process.execPath, (exe, _args, options) =>
      spawn(exe, ['-e', brokerCode], options),
    );
    assert.ok(channel);
    t.after(() => channel.destroy());
    const ownerCode = `
      const { Socket } = require('node:net');
      const endpoint = new Socket({ fd: 3, readable: true, writable: true });
      endpoint.on('data', (chunk) => process.stdout.write(chunk));
      endpoint.once('end', () => endpoint.destroy());
      endpoint.write('probe');
    `;
    const owner = spawn(process.execPath, ['-e', ownerCode], {
      stdio: ['ignore', 'pipe', 'ignore', channel],
    });
    t.after(() => owner.kill());
    channel.destroy();
    let result = '';
    owner.stdout!.on('data', (chunk: Buffer) => (result += chunk.toString()));
    const [status] = await once(owner, 'close');
    assert.equal(status, 0);
    assert.equal(result, 'fixture');
  },
);

test('confirmed recovery kit refresh keeps both factors in the wiped native request', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const { child, client } = fixture();
  child.automatic = false;
  const source = resolve('old.whrecovery');
  const destination = resolve('updated.whrecovery');
  const input = () => ({
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
    appVersion: '2.4.3',
    password: new Uint8Array([1, 2, 3]),
    ask: new Uint8Array(32).fill(5),
  });
  try {
    const rejected = input();
    await assert.rejects(client.refreshSharedRecoveryKit(source, 'relative.whrecovery', rejected));
    assert.ok(rejected.password.every((n) => n === 0) && rejected.ask.every((n) => n === 0));
    assert.equal(child.requests.length, 0);
    const check = client.refreshSharedRecoveryKit(source, destination);
    await tick();
    assert.deepEqual(child.requests[0], {
      version: 1,
      id: 1,
      operation: 'shared-recovery-kit-refresh',
      payload: { source, destination },
    });
    child.reply(child.requests[0], 'authentication-required');
    assert.equal(await check, 'authentication-required');
    const auth = input();
    const updated = client.refreshSharedRecoveryKit(source, destination, auth);
    await tick();
    const request = child.requests[1] as Request & {
      payload: { source: string; destination: string; authentication: string };
    };
    const { authentication, ...paths } = request.payload;
    assert.deepEqual(paths, { source, destination });
    const { appVersion: _version, password, ask, ...identity } = input();
    assert.deepEqual(JSON.parse(Buffer.from(authentication, 'base64').toString()), {
      ...identity,
      password: Buffer.from(password).toString('base64'),
      ask: Buffer.from(ask).toString('base64'),
    });
    child.reply(request, 'updated');
    assert.equal(await updated, 'updated');
    assert.ok(auth.password.every((n) => n === 0) && auth.ask.every((n) => n === 0));
    assert.ok(child.writtenFrames[1].every((n) => n === 0));
    const report = await profiler.post('Profiler.takePreciseCoverage');
    const script = report.result.find((entry) => entry.url.endsWith('/vault-client.ts'))!;
    const method = script.functions.find((fn) => fn.functionName === 'refreshSharedRecoveryKit')!;
    const extent = method.ranges[0];
    const ranges = script.functions
      .filter(
        (fn) =>
          fn.ranges[0].startOffset >= extent.startOffset &&
          fn.ranges[0].endOffset <= extent.endOffset,
      )
      .flatMap((fn) => fn.ranges);
    const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
    t.diagnostic(`Recovery kit client: ${percent.toFixed(2)}% V8 blocks`);
    assert.ok(percent >= coverageThreshold);
  } finally {
    await client.lock();
  }
});

test('main-only shared runtime uses a fixed empty request and rejects private response members', async () => {
  const runtime = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    workspaceId: '33333333-3333-4333-8333-333333333333',
    tls: 'verified',
    security: {
      sequence: '1',
      workspace: 'standard',
      user: 'default',
      os: 'default',
      effective: 'standard',
      source: 'workspace',
    },
  };
  for (const invalid of [false, true]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      const pending = client.sharedRuntime();
      await tick();
      assert.deepEqual(child.requests[0], { version: 1, id: 1, operation: 'shared-runtime' });
      child.reply(child.requests[0], invalid ? { ...runtime, rootKey: 'private' } : runtime);
      if (invalid) await assert.rejects(pending, /invalid|unavailable/i);
      else assert.deepEqual(await pending, runtime);
    } finally {
      await client.lock();
    }
  }
});

test('shared catalog client validates requests and responses without local catalog fallback', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const [changes, invalid] of [
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      const invoke = (value: unknown) =>
        changes ? client.sharedChanges(value) : client.sharedCatalog(value);
      await assert.rejects(invoke({}), /Invalid shared/);
      assert.equal(child.requests.length, 0);
      const pending = invoke(
        changes
          ? { epoch: '0', changeSeq: '0' }
          : { after: '', epoch: '0', changeSeq: '0', limit: 1 },
      );
      await tick();
      const request = child.requests.find(
        (r) => r.operation === (changes ? 'shared-changes' : 'shared-catalog'),
      );
      assert.ok(request);
      const result = changes
        ? { epoch: '1', changeSeq: '0', reset: true, nodes: [] }
        : { epoch: '1', changeSeq: '0', nodes: [], next: null };
      child.reply(request, invalid ? { ...result, privateKey: 'forbidden' } : result);
      if (invalid) await assert.rejects(pending);
      else assert.deepEqual(await pending, result);
      assert.equal(
        child.requests.some((r) => r.operation === 'catalog'),
        false,
      );
    } finally {
      await client.lock();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-client.ts'))
    .flatMap((s) => s.functions)
    .filter((f) => ['sharedCatalog', 'sharedChanges'].includes(f.functionName))
    .flatMap((f) => f.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`shared catalog client: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('serial Use checks are native-only and reject malformed or stale permission results', async () => {
  const workspaceId = '91111111-1111-4111-8111-111111111111';
  const node = '92222222-2222-4222-8222-222222222222';
  for (const mode of ['allowed', 'malformed', 'stale']) {
    const { child, client } = fixture();
    child.automatic = false;
    const owner = { client, unlockedWorkspaceId: workspaceId, isSharedWorkspace: true };
    const check = VaultBackendHost.prototype.checkSharedSerialUse.bind(owner as any);
    try {
      await assert.rejects(check('other', [node]), /unavailable/);
      await assert.rejects(check(workspaceId, []), /Invalid shared/);
      await assert.rejects(check(workspaceId, [node, node]), /Invalid shared/);
      const pending = check(workspaceId, [node]);
      const rejected =
        mode === 'allowed'
          ? undefined
          : assert.rejects(pending, mode === 'stale' ? /locked/ : /unavailable/);
      await tick();
      const request = child.requests.find((q) => q.operation === 'serial-use-check');
      assert.ok(request);
      assert.deepEqual((request as any).payload, { nodeIds: [node] });
      if (mode === 'stale') owner.unlockedWorkspaceId = '';
      child.reply(request, { current: mode === 'malformed' ? [true, false] : [true] });
      if (rejected) await rejected;
      else assert.deepEqual(await pending, [true]);
    } finally {
      await client.lock();
    }
  }
});

test('native catalog events carry no data and do not resolve pending requests', async () => {
  for (const invalid of [false, true]) {
    let hints = 0;
    const { child, client } = fixture({
      executable: 'vault',
      databasePath: 'workspace.db',
      onSharedCatalogChanged: () => {
        hints++;
      },
    });
    try {
      await client.status();
      child.automatic = false;
      const pending = client.catalog();
      await tick();
      child.stdout.write(
        JSON.stringify({
          version: 1,
          id: 0,
          event: 'shared-catalog-changed',
          ...(invalid ? { result: 'forbidden' } : {}),
        }) + '\n',
      );
      if (invalid) {
        await assert.rejects(pending);
        assert.equal(hints, 0);
      } else {
        assert.equal(hints, 1);
        const request = child.requests.find((r) => r.operation === 'catalog');
        assert.ok(request);
        child.reply(request, { nodes: [], credentials: [], tunnels: [] });
        assert.deepEqual(await pending, { nodes: [], credentials: [], tunnels: [] });
      }
    } finally {
      await client.lock();
    }
  }
});

test('shared client operations consume both factors and erase stdin frames without local unlock', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of ['admit', 'password', 'continuation']) {
    const recovery = mode === 'password',
      continuation = mode === 'continuation';
    const { child, client, launches } = fixture();
    try {
      const local = unlockInput();
      const input = {
        vaultId: local.vaultId,
        slotId: local.slotId,
        password: local.factor,
        ...(recovery ? { ask: new Uint8Array(32).fill(5) } : {}),
        ...(continuation ? { code: new Uint8Array(16).fill(6), acknowledgeTLSOff: true } : {}),
      };
      const pending = recovery
        ? client.sharedRecoverPassword(input, '1.0.0')
        : continuation
          ? client.sharedContinueEnrollment(input, '1.0.0')
          : client.sharedUnlock(input, '1.0.0');
      assert.ok(input.password.every((n) => n === 0));
      if (input.ask) assert.ok(input.ask.every((n) => n === 0));
      if (input.code) assert.ok(input.code.every((n) => n === 0));
      assert.deepEqual(
        await pending,
        recovery ? { recovered: true } : { admitted: true, lockedMemory: false, orgEscrow: true },
      );
      await tick();
      assert.equal(
        child.requests[0].operation,
        recovery
          ? 'shared-recover-password'
          : continuation
            ? 'shared-continue-enrollment'
            : 'shared-unlock',
      );
      assert.ok(child.writtenFrames[0].every((n) => n === 0));
      assert.deepEqual(launches[0].args, ['--operation', 'vault', '--database', 'workspace.db']);
      await client.lock();
      const retired = {
        vaultId: local.vaultId,
        slotId: local.slotId,
        password: new Uint8Array([1]),
        ask: new Uint8Array(32).fill(4),
      };
      await assert.rejects(client.sharedUnlock(retired, '1.0.0'), /unavailable/);
      assert.ok(retired.password.every((n) => n === 0));
      assert.ok(retired.ask.every((n) => n === 0));
      await assert.rejects(client.sharedUnlock(retired, 'bad'), /Invalid shared/);
    } finally {
      await client.lock();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const functions = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-client.ts'))
    .flatMap((s) => s.functions)
    .filter((f) =>
      [
        'sharedUnlock',
        'sharedRecoverPassword',
        'sharedContinueEnrollment',
        'sharedAuthentication',
      ].includes(f.functionName),
    );
  assert.equal(functions.length, 4);
  const ranges = functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`shared client methods: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('shared client rejects malformed input and wipes backpressured frames at lock', async () => {
  const { child, client, launches } = fixture();
  try {
    const local = unlockInput();
    const invalid = {
      vaultId: local.vaultId,
      slotId: local.slotId,
      password: local.factor,
      ask: new Uint8Array(32).fill(5),
    };
    await assert.rejects(client.sharedUnlock(invalid, 'bad'), /Invalid shared/);
    assert.equal(launches.length, 0);
    assert.ok(invalid.ask.every((n) => n === 0));
    assert.ok(invalid.password.every((n) => n === 0));
    child.holdUnlockWrites = true;
    await client.sharedUnlock(
      { vaultId: local.vaultId, slotId: local.slotId, password: new Uint8Array([1, 2, 3]) },
      '1.0.0',
    );
    const held = child.heldUnlockWrite!;
    assert.ok(held.frame.some((n) => n !== 0));
    const stopping = client.lock();
    assert.ok(held.frame.every((n) => n === 0));
    held.callback();
    await stopping;
  } finally {
    await client.lock();
  }
});

test('connection save consumes and wipes secret frames across success, rejection and lock', async () => {
  for (const scenario of [
    'create',
    'edit',
    'wrong-id',
    'wrong-version',
    'invalid',
    'lock',
    'write-error',
  ]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.saveConnection(null), /Invalid/);
      const input = connectionInput();
      if (scenario === 'edit' || scenario === 'wrong-id') {
        input.metadata.id = connectionNodeId;
        input.rowVersion = '7';
      }
      if (scenario === 'write-error') child.writeFailure = true;
      const pending = client.saveConnection(input),
        valid = scenario === 'create' || scenario === 'edit';
      const checked = valid ? pending : assert.rejects(pending, /unavailable|locked/);
      assert.ok(input.password.every((v) => v === 0) && input.notes.every((v) => v === 0));
      input.metadata.name = 'Later caller change';
      await tick();
      if (scenario === 'lock') await client.lock();
      else if (scenario !== 'write-error') {
        const request = child.requests.find((r) => r.operation === 'connection-save')!;
        const payload = (request as any).payload;
        assert.equal(payload.metadata.name, 'Connection');
        assert.equal(Buffer.from(payload.password, 'base64').toString(), 'password-fixture');
        assert.equal(Buffer.from(payload.notes, 'base64').toString(), 'notes-fixture');
        child.reply(
          request,
          scenario === 'invalid'
            ? {}
            : {
                nodeId:
                  scenario === 'wrong-id'
                    ? '22222222-2222-4222-8222-222222222222'
                    : connectionNodeId,
                rowVersion: scenario === 'edit' ? '8' : scenario === 'wrong-version' ? '2' : '1',
                updated: true,
              },
        );
      }
      await checked;
      assert.ok(
        child.writtenFrames[0]?.every((v) => v === 0),
        scenario,
      );
    } finally {
      await client.lock();
    }
  }
});

test('folder save snapshots metadata and rejects mismatched mutation acknowledgements', async () => {
  const id = '11111111-1111-4111-8111-111111111111';
  for (const scenario of ['create', 'edit', 'wrong-id', 'wrong-version', 'invalid']) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.saveFolder(null), /Invalid/);
      const input = {
        id: scenario === 'create' ? '' : id,
        rowVersion: scenario === 'create' ? '0' : '7',
        parentId: '',
        name: 'Original',
        sshAutoSudo: null,
        tunnelEnabled: false,
        tunnelConfigId: '',
        credentialMode: 0,
        credentialId: '',
      };
      const pending = client.saveFolder(input);
      const valid = scenario === 'create' || scenario === 'edit';
      const checked = valid ? pending : assert.rejects(pending, /unavailable/);
      input.name = 'Queued caller edit';
      input.rowVersion = '99';
      await tick();
      const sent = child.requests.find((r) => r.operation === 'folder-save')!;
      assert.equal((sent as any).payload.name, 'Original');
      assert.equal((sent as any).payload.rowVersion, scenario === 'create' ? '0' : '7');
      child.reply(
        sent,
        scenario === 'invalid'
          ? {}
          : {
              nodeId: scenario === 'wrong-id' ? '22222222-2222-4222-8222-222222222222' : id,
              rowVersion: scenario === 'create' ? '1' : scenario === 'wrong-version' ? '9' : '8',
              updated: true,
            },
      );
      await checked;
    } finally {
      await client.lock();
    }
  }
});

test('node deletion snapshots versioned metadata and validates native acknowledgements', async () => {
  for (const validReply of [true, false]) {
    const { child, client } = fixture();
    child.automatic = false;
    await assert.rejects(client.deleteNodes({ nodes: [] }), /Invalid/);
    const input = { nodes: [{ id: '11111111-1111-4111-8111-111111111111', rowVersion: '7' }] };
    const pending = client.deleteNodes(input);
    const checked = validReply ? pending : assert.rejects(pending, /unavailable/);
    input.nodes[0].rowVersion = '99';
    await tick();
    const sent = child.requests.find((r) => r.operation === 'node-delete-trees')!;
    assert.equal((sent as any).payload.nodes[0].rowVersion, '7');
    child.reply(
      sent,
      validReply ? { deleted: true, deletedCount: '1' } : { deleted: true, deletedCount: '0' },
    );
    if (validReply) assert.deepEqual(await checked, { deleted: true, deletedCount: '1' });
    else await checked;
    await client.lock();
  }
});

test('native SSH requests snapshot recipient authority and allow bounded ciphertext responses', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  try {
    const q = sshRequest(),
      original = { ...q };
    await assert.rejects(client.sshBundle({ ...q, epoch: 0 }), /Invalid/);
    const pending = client.sshBundle(q);
    q.nodeId = sshRequest().nodeId;
    q.publicKey = 'changed';
    await tick();
    const sent = child.requests.at(-1)!;
    assert.equal(sent.operation, 'ssh-bundle');
    assert.deepEqual((sent as any).payload, {
      nodeId: original.nodeId,
      credentialOverride: '',
      sessionId: original.sessionId,
      requestId: original.requestId,
      epoch: '1',
      publicKey: original.publicKey,
    });
    const result = sshBundle(original);
    result.bundle.ciphertext = Buffer.alloc(128 * 1024).toString('base64');
    child.reply(sent, result);
    assert.deepEqual(await pending, result);
    const bad = client.sshBundle(original);
    await tick();
    result.binding.sessionId = sshRequest().sessionId;
    child.reply(child.requests.at(-1)!, result);
    await assert.rejects(bad, /protocol|unavailable/i);
  } finally {
    await client.lock();
  }
});

test('vault client owns a single lifetime and sends metadata-only requests', async () => {
  const { child, client, launches } = fixture();
  try {
    assert.deepEqual(await client.status(), status);
    assert.equal(await client.describe(), null);
    assert.deepEqual(await client.startup(), {
      slots: null,
      cosmetics: { theme: 'system' },
      newWorkspace: false,
    });
    assert.deepEqual(await client.catalog(), { nodes: [], credentials: [], tunnels: [] });
    assert.deepEqual(await client.workspace(), {
      tree: [],
      credentials: [],
      credentialOptions: { ssh: [], rdp: [], vnc: [] },
      tunnels: [],
    });
    assert.deepEqual(launches, [
      { executable: 'vault', args: ['--operation', 'vault', '--database', 'workspace.db'] },
    ]);
    assert.deepEqual(
      child.requests.map((request) => request.operation),
      ['status', 'describe', 'startup', 'catalog', 'workspace'],
    );
    assert.deepEqual(
      child.requests.map((request) => request.id),
      [1, 2, 3, 4, 5],
    );
    const stopping = client.lock();
    assert.equal(client.lock(), stopping);
    await stopping;
    assert.ok(child.ended);
    await assert.rejects(client.status(), /unavailable/);
    assert.equal(launches.length, 1);
    await client.lock();
  } finally {
    await client.lock();
  }
});

test('startup metadata retains the small frame limit and rejects policy fields', async () => {
  for (const mode of ['oversized', 'policy'] as const) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      const rejection = assert.rejects(client.startup(), /unavailable/);
      await tick();
      if (mode === 'oversized') child.stdout.write(Buffer.alloc(vaultMetadataFrameLimit + 1, 65));
      else
        child.reply(child.requests[0], {
          slots: null,
          cosmetics: { theme: 'system', profile: 'Default' },
        });
      await rejection;
      await client.lock();
      assert.ok(child.ended);
    } finally {
      await client.lock();
    }
  }
});

test('vault request queue is bounded and serialized while heartbeats can overtake work', async () => {
  const { child, client } = fixture({
    executable: 'vault',
    databasePath: 'db',
    heartbeatMs: 20,
    requestTimeoutMs: 1000,
  });
  child.automatic = false;
  child.heartbeatOnly = true;
  const requests = Array.from({ length: 16 }, () => client.status());
  const completion = Promise.all(requests);
  try {
    await assert.rejects(client.describe(), /queue is full/);
    await tick();
    assert.equal(child.requests.filter((request) => request.operation === 'status').length, 1);
    await new Promise<void>((resolve) => {
      if (child.requests.some((request) => request.operation === 'heartbeat')) resolve();
      else
        child.on('request', (request: Request) => {
          if (request.operation === 'heartbeat') resolve();
        });
    });
    for (let i = 0; i < 16; i++) {
      await tick();
      const current = child.requests.filter((request) => request.operation === 'status');
      assert.equal(current.length, i + 1);
      child.reply(current[i]);
    }
    assert.equal((await completion).length, 16);
    assert.ok(child.requests.some((request) => request.operation === 'heartbeat'));
  } finally {
    await client.lock();
    await completion.catch(() => undefined);
  }
});

test('vault reads fragmented CRLF frames and discards private diagnostics', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  try {
    const pending = client.status();
    await tick();
    child.stderr.write('password=private-diagnostic\n');
    const response = Buffer.from(JSON.stringify({ version: 1, id: 1, result: status }) + '\r\n');
    for (const byte of response) child.stdout.write(Buffer.from([byte]));
    assert.deepEqual(await pending, status);
  } finally {
    await client.lock();
  }
});

test('malformed, unbounded, duplicate and secret-bearing responses retire the process', async (t) => {
  const cases: [string, Buffer][] = [
    ['oversized', Buffer.alloc(vaultMetadataFrameLimit + 1, 65)],
    ['invalid UTF-8', Buffer.from([0xff, 10])],
    ['invalid JSON', Buffer.from('{\n')],
    ['unknown ID', Buffer.from(JSON.stringify({ version: 1, id: 2, result: status }) + '\n')],
    [
      'secret in status',
      Buffer.from(
        JSON.stringify({ version: 1, id: 1, result: { ...status, password: 'do-not-expose' } }) +
          '\n',
      ),
    ],
    ['private error', Buffer.from('{"version":1,"id":1,"error":"password=do-not-expose"}\n')],
    [
      'invalid response code',
      Buffer.from('{"version":1,"id":1,"error":"vault_invalid_response"}\n'),
    ],
    [
      'duplicate response',
      Buffer.from((JSON.stringify({ version: 1, id: 1, result: status }) + '\n').repeat(2)),
    ],
  ];
  for (const [name, frame] of cases)
    await t.test(name, async () => {
      const { child, client, launches } = fixture();
      child.automatic = false;
      try {
        const pending = client.status();
        const rejected = assert.rejects(
          pending,
          (error: Error) =>
            !error.message.includes('do-not-expose') && /unavailable/.test(error.message),
        );
        await tick();
        child.stdout.write(frame);
        await rejected;
        await client.lock();
        assert.ok(child.ended);
        assert.equal(launches.length, 1);
      } finally {
        await client.lock();
      }
    });
});

test('operation failures are redacted but do not corrupt the request sequence', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  try {
    for (const error of ['vault_operation_failed', 'vault_cancelled', 'vault_busy']) {
      const pending = client.describe();
      const rejection = assert.rejects(pending, /Vault (operation failed|request cancelled)/);
      await tick();
      const request = child.requests.at(-1)!;
      child.stdout.write(JSON.stringify({ version: 1, id: request.id, error }) + '\n');
      await rejection;
    }
    child.automatic = true;
    assert.deepEqual(await client.status(), status);
  } finally {
    await client.lock();
  }
});

test('lock before startup never spawns and rejects work already queued', async () => {
  const { client, launches } = fixture();
  const pending = client.status();
  const rejection = assert.rejects(pending, /unavailable/);
  await client.lock();
  await rejection;
  assert.equal(launches.length, 0);
});

test('request timeout forces termination when the graceful lock is ignored', async () => {
  const { child, client } = fixture({
    executable: 'vault',
    databasePath: 'db',
    requestTimeoutMs: 20,
    stopGraceMs: 10,
    stopConfirmationMs: 30,
  });
  child.automatic = false;
  child.exitOnEnd = false;
  await assert.rejects(client.status(), /respond in time/);
  await client.lock();
  assert.deepEqual(child.kills, ['SIGKILL']);
  assert.ok(child.ended);
});

test('a kill request alone does not count as confirmed process termination', async () => {
  const { child, client, launches } = fixture({
    executable: 'vault',
    databasePath: 'db',
    stopGraceMs: 10,
    stopConfirmationMs: 10,
  });
  child.exitOnEnd = false;
  child.exitOnKill = false;
  await client.status();
  await assert.rejects(client.lock(), /could not be confirmed/);
  assert.equal(child.killed, true);
  assert.equal(child.ended, false);
  await assert.rejects(client.status(), /unavailable/);
  assert.equal(launches.length, 1);
  child.exit();
  await client.lock();
});

test('spawn and pipe failures never expose native diagnostics or restart', async (t) => {
  const thrown = new VaultBackendClient({ executable: 'private-path', databasePath: 'db' }, () => {
    throw Error('password=hidden');
  });
  await assert.rejects(
    thrown.status(),
    (error: Error) => error.message === 'Vault is unavailable.',
  );
  await thrown.lock();
  const absent = new VaultBackendClient({
    executable: 'wormhole-vault-that-does-not-exist',
    databasePath: 'db',
  });
  await assert.rejects(
    absent.status(),
    (error: Error) => error.message === 'Vault is unavailable.',
  );
  await absent.lock();
  for (const mode of ['write', 'stdout', 'stderr', 'exit', 'end'] as const)
    await t.test(mode, async () => {
      const { child, client } = fixture();
      child.automatic = false;
      if (mode === 'write') child.writeFailure = true;
      const pending = client.status();
      const rejection = assert.rejects(pending, /unavailable/);
      await tick();
      if (mode === 'stdout') child.stdout.emit('error', Error('private diagnostic'));
      if (mode === 'stderr') child.stderr.emit('error', Error('private diagnostic'));
      if (mode === 'exit') child.exit();
      if (mode === 'end') child.stdout.end();
      await rejection;
      await client.lock();
    });
});

test('startup timeout and lock during startup cannot create a replacement owner', async () => {
  for (const cancel of [false, true]) {
    const child = new Child();
    child.exitOnEnd = false;
    const client = new VaultBackendClient(
      {
        executable: 'vault',
        databasePath: 'db',
        requestTimeoutMs: 15,
        stopGraceMs: 10,
        stopConfirmationMs: 20,
      },
      () => child.process(),
    );
    const pending = client.status();
    const rejection = assert.rejects(pending, /locked|respond in time/);
    await tick();
    if (cancel) void client.lock();
    await rejection;
    await client.lock();
    assert.ok(child.ended);
  }
});

test('invalid options fail before a process can be launched', () => {
  for (const options of [
    { executable: '', databasePath: 'db' },
    { executable: 'vault', databasePath: '' },
    { executable: 'vault', databasePath: 'db', heartbeatMs: 0 },
    { executable: 'vault', databasePath: 'db', requestTimeoutMs: Infinity },
  ])
    assert.throws(() => new VaultBackendClient(options), /Invalid vault process options/);
});

test('late spawn and failed termination cannot escape the confirmed-exit boundary', async () => {
  const child = new Child();
  child.exitOnEnd = false;
  child.kill = () => {
    throw Error('private native diagnostic');
  };
  const client = new VaultBackendClient(
    { executable: 'vault', databasePath: 'db', stopGraceMs: 10, stopConfirmationMs: 10 },
    () => child.process(),
  );
  const pending = assert.rejects(client.status(), /locked/);
  await tick();
  const stopping = assert.rejects(client.lock(), /could not be confirmed/);
  assert.doesNotThrow(() => child.emit('spawn'));
  await pending;
  await stopping;
  child.exit();
  await client.lock();
});

test('vault client works with real anonymous process pipes and waits for exit', async () => {
  const fixturePath = fileURLToPath(new URL('./fixtures/vault-process.mjs', import.meta.url));
  let child: ChildProcessWithoutNullStreams | undefined;
  const client = new VaultBackendClient(
    { executable: process.execPath, databasePath: 'workspace.db' },
    (executable, args) => {
      child = spawn(executable, [fixturePath, ...args], { stdio: 'pipe', windowsHide: true });
      return child;
    },
  );
  try {
    assert.deepEqual(await client.status(), status);
    assert.equal(await client.describe(), null);
    await client.lock();
    assert.notEqual(child?.exitCode, null);
  } finally {
    await client.lock();
  }
});

test('catalog accepts fragmented metadata beyond the status budget and locks pending reads', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  try {
    const pending = client.catalog();
    await tick();
    const catalog = {
      nodes: [],
      tunnels: [],
      credentials: Array.from({ length: 400 }, (_, i) => ({
        id: (i + 1).toString(16).padStart(8, '0') + '-1111-4111-8111-111111111111',
        name: 'Account <&> 日本語',
        protocol: 'ssh',
        kind: 'password',
        username: 'alice',
        domain: '',
        provider: 'local',
        rowVersion: '1',
      })),
    };
    const frame = Buffer.from(
      JSON.stringify({ version: 1, id: child.requests[0].id, result: catalog }) + '\n',
    );
    assert.ok(frame.length > vaultMetadataFrameLimit);
    for (let offset = 0; offset < frame.length; offset += 137)
      child.stdout.write(frame.subarray(offset, offset + 137));
    assert.deepEqual(await pending, catalog);
    const locked = assert.rejects(client.catalog(), /locked/);
    await tick();
    await client.lock();
    await locked;
    await assert.rejects(client.catalog(), /unavailable/);
  } finally {
    await client.lock();
  }
});

test('catalog frame bounds do not relax heartbeat bounds or permit private fields', async () => {
  for (const mode of ['oversized', 'private', 'heartbeat'] as const) {
    const { child, client } = fixture({
      executable: 'vault',
      databasePath: 'db',
      heartbeatMs: 20,
      requestTimeoutMs: 1000,
    });
    child.automatic = false;
    try {
      const rejection = assert.rejects(client.catalog(), /unavailable/);
      await tick();
      if (mode === 'oversized') child.stdout.write(Buffer.alloc(vaultCatalogFrameLimit + 1, 65));
      if (mode === 'private')
        child.reply(child.requests[0], {
          nodes: [],
          credentials: [],
          tunnels: [],
          password: 'private',
        });
      if (mode === 'heartbeat') {
        const request = await new Promise<Request>((resolve) =>
          child.on('request', (request) => {
            if (request.operation === 'heartbeat') resolve(request);
          }),
        );
        child.reply(request, { alive: true, extra: 'x'.repeat(vaultMetadataFrameLimit) });
      }
      await rejection;
      await client.lock();
      assert.ok(child.ended);
    } finally {
      await client.lock();
    }
  }
});

const unlockInput = () => ({
  vaultId: '11111111-1111-4111-8111-111111111111',
  slotId: '22222222-2222-4222-8222-222222222222',
  kind: 'password',
  factor: new Uint8Array([1, 2, 3]),
});

test('workspace uses its bounded large frame, tolerates read latency and refuses secret-bearing responses', async () => {
  for (const mode of ['valid', 'private', 'oversized'] as const) {
    const { child, client } = fixture({
      executable: 'vault',
      databasePath: 'db',
      requestTimeoutMs: 10,
    });
    child.automatic = false;
    try {
      const pending = client.workspace();
      const rejected = mode === 'valid' ? undefined : assert.rejects(pending, /unavailable/);
      await tick();
      if (mode === 'oversized') child.stdout.write(Buffer.alloc(vaultCatalogFrameLimit + 1, 65));
      else {
        const result = {
          tree: Array.from({ length: 1000 }, (_, i) => ({
            id: (i + 1).toString(16).padStart(8, '0') + '-1111-4111-8111-111111111111',
            name: 'Connection 日本語',
            kind: 'connection',
            persisted: true,
          })),
          credentials: [],
          credentialOptions: { ssh: [], rdp: [], vnc: [] },
          tunnels: [],
          ...(mode === 'private' ? { password: 'never-expose' } : {}),
        };
        // Workspace resolution may take longer than a small status request.
        await new Promise((resolve) => setTimeout(resolve, 30));
        const frame = Buffer.from(
          JSON.stringify({ version: 1, id: child.requests[0].id, result }) + '\n',
        );
        assert.ok(frame.length > vaultMetadataFrameLimit);
        for (let offset = 0; offset < frame.length; offset += 137)
          child.stdout.write(frame.subarray(offset, offset + 137));
        if (mode === 'valid') {
          assert.deepEqual(await pending, result);
          const stopped = assert.rejects(client.workspace(), /locked/);
          await tick();
          await client.lock();
          await stopped;
        }
      }
      if (rejected) await rejected;
    } finally {
      await client.lock();
    }
  }
});

test('client unlock consumes factor, writes only stdin and erases forwarded frames', async () => {
  const { child, client, launches } = fixture();
  try {
    const input = unlockInput();
    const pending = client.unlock(input);
    assert.ok(input.factor.every((byte) => byte === 0));
    assert.deepEqual(await pending, { unlocked: true, lockedMemory: true });
    await tick();
    assert.equal(child.requests[0].operation, 'unlock');
    assert.ok(child.writtenFrames[0].every((byte) => byte === 0));
    assert.deepEqual(launches[0].args, ['--operation', 'vault', '--database', 'workspace.db']);
    await client.lock();
    const retired = unlockInput();
    await assert.rejects(client.unlock(retired), /unavailable/);
    assert.ok(retired.factor.every((byte) => byte === 0));
  } finally {
    await client.lock();
  }
});

test('unlock failure, queue rejection and startup failure erase submitted factors', async () => {
  const { child, client } = fixture();
  child.automatic = false;
  try {
    const rejected = assert.rejects(client.unlock({ ...unlockInput(), kind: 'hello' }), /Invalid/);
    await rejected;
    const badPassword = assert.rejects(client.unlock(unlockInput()), /operation failed/);
    await tick();
    child.stdout.write(
      JSON.stringify({ version: 1, id: child.requests[0].id, error: 'vault_operation_failed' }) +
        '\n',
    );
    await badPassword;
    assert.ok(child.writtenFrames[0].every((byte) => byte === 0));
    const queued = Array.from({ length: 16 }, () =>
      assert.rejects(client.status(), /locked|unavailable/),
    );
    const overflow = unlockInput();
    await assert.rejects(client.unlock(overflow), /queue is full/);
    assert.ok(overflow.factor.every((byte) => byte === 0));
    await client.lock();
    await Promise.all(queued);
  } finally {
    await client.lock();
  }
  const failed = new VaultBackendClient({ executable: 'vault', databasePath: 'db' }, () => {
    throw Error('private native text');
  });
  const input = unlockInput();
  await assert.rejects(failed.unlock(input), { message: 'Vault is unavailable.' });
  assert.ok(input.factor.every((byte) => byte === 0));
  await failed.lock();
});

test('lock erases an unlock frame retained by a backpressured pipe', async () => {
  const { child, client } = fixture();
  child.holdUnlockWrites = true;
  try {
    await client.unlock(unlockInput());
    const held = child.heldUnlockWrite!;
    assert.ok(held.frame.some((byte) => byte !== 0));
    const stopping = client.lock();
    assert.ok(held.frame.every((byte) => byte === 0));
    held.callback();
    await stopping;
  } finally {
    await client.lock();
  }
});

test('unlock write errors and thrown writes erase the frame before retiring', async () => {
  for (const mode of ['callback', 'throw'] as const) {
    const { child, client } = fixture();
    let frame: Buffer | undefined;
    if (mode === 'callback') child.writeFailure = true;
    else {
      const write = child.stdin.write.bind(child.stdin);
      child.stdin.write = ((value: Buffer | string) => {
        if (Buffer.isBuffer(value)) {
          frame = value;
          throw Error('private pipe text');
        }
        return write(value);
      }) as typeof child.stdin.write;
    }
    try {
      await assert.rejects(client.unlock(unlockInput()), { message: 'Vault is unavailable.' });
      frame ??= child.writtenFrames[0];
      assert.ok(frame?.every((byte) => byte === 0));
    } finally {
      await client.lock();
    }
  }
});

test('unlock allows KDF work beyond the short metadata timeout', async () => {
  const { child, client } = fixture({
    executable: 'vault',
    databasePath: 'db',
    requestTimeoutMs: 20,
  });
  child.automatic = false;
  try {
    const pending = client.unlock(unlockInput());
    await tick();
    await new Promise((resolve) => setTimeout(resolve, 40));
    child.reply(child.requests[0]);
    assert.deepEqual(await pending, { unlocked: true, lockedMemory: true });
  } finally {
    await client.lock();
  }
});

test('lock before queued unlock starts retires its factor without launching a child', async () => {
  const { client, launches } = fixture();
  const input = unlockInput();
  const rejected = assert.rejects(client.unlock(input), /locked|unavailable/);
  await client.lock();
  await rejected;
  assert.ok(input.factor.every((byte) => byte === 0));
  assert.equal(launches.length, 0);
});

test('client exposes native preferences as a bounded typed read', async () => {
  const child = new Child();
  const client = new VaultBackendClient({ executable: 'fixture', databasePath: 'fixture' }, () => {
    queueMicrotask(() => child.emit('spawn'));
    return child.process();
  });
  try {
    assert.deepEqual(await client.preferences(), preferences());
  } finally {
    await client.lock();
  }
});

test('notes client snapshots recipients, bounds ciphertext and rejects wrong response binding', async () => {
  const context = {
    workspaceId: '11111111-1111-4111-8111-111111111111',
    nodeId: '22222222-2222-4222-8222-222222222222',
    requestId: '33333333-3333-4333-8333-333333333333',
    rowVersion: '1',
  };
  for (const bad of [false, true]) {
    const child = new Child();
    child.automatic = false;
    const client = new VaultBackendClient(
      { executable: 'fixture', databasePath: 'workspace' },
      () => {
        queueMicrotask(() => child.emit('spawn'));
        return child.process();
      },
    );
    try {
      await assert.rejects(client.displayNotes(null), /Invalid/);
      const request = { ...context, publicKey: Buffer.alloc(32, 1).toString('base64') };
      const pending = client.displayNotes(request);
      const checked = bad ? assert.rejects(pending, /unavailable/) : pending;
      request.nodeId = 'changed';
      await tick();
      const sent = child.requests[0];
      assert.equal(sent.operation, 'notes-display');
      assert.equal((sent as any).payload.nodeId, context.nodeId);
      assert.equal(Object.hasOwn((sent as any).payload, 'workspaceId'), false);
      child.reply(sent, {
        ...context,
        nodeId: bad ? context.requestId : context.nodeId,
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: request.publicKey,
          ciphertext: Buffer.alloc(65552).toString('base64'),
        },
      });
      const received = await checked;
      if (!bad)
        assert.deepEqual(Object.keys(received as object).sort(), [
          'bundle',
          'nodeId',
          'requestId',
          'rowVersion',
          'workspaceId',
        ]);
    } finally {
      await client.lock();
    }
  }
});

test('migration client snapshots report and decision authority and checks exact responses', async () => {
  for (const operation of ['report', 'decide'])
    for (const wrong of ['', 'node', 'revision', 'shape']) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const method =
          operation === 'report'
            ? client.migrationReport.bind(client)
            : client.decideMigration.bind(client);
        await assert.rejects(method(null), /Invalid/);
        const input = operation === 'report' ? { ...migrationSelection } : migrationDecision();
        const pending = method(input),
          checked = wrong ? assert.rejects(pending, /unavailable/) : pending;
        input.rowVersion = '99';
        if ('choices' in input) input.choices[0].choice = 'keep';
        await tick();
        const sent = child.requests.find((r) => r.operation === 'migration-' + operation)!;
        assert.equal((sent as any).payload.rowVersion, '2');
        if (operation === 'decide') assert.equal((sent as any).payload.choices[0].choice, 'new');
        const result: any =
          operation === 'report'
            ? migrationReport()
            : { nodeId: migrationNode, rowVersion: '3', updated: true };
        if (wrong === 'node') result.nodeId = '22222222-2222-4222-8222-222222222222';
        if (wrong === 'revision') result.rowVersion = '4';
        if (wrong === 'shape') result.username = 'private';
        child.reply(sent, result);
        await checked;
      } finally {
        await client.lock();
      }
    }
});

test('credential client snapshots secrets and rejects mismatched save and delete acknowledgements', async () => {
  const id = '11111111-1111-4111-8111-111111111111',
    other = '22222222-2222-4222-8222-222222222222';
  for (const remove of [false, true])
    for (const scenario of ['ok', 'wrong-id', 'wrong-version', 'invalid']) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const factor = {
          vaultId: id,
          slotId: other,
          kind: 'password' as const,
          factor: new Uint8Array([5]),
        };
        await assert.rejects(
          remove ? client.deleteCredential(null, factor) : client.editCredential(null, factor),
          /Invalid/,
        );
        assert.deepEqual([...factor.factor], [0]);
        const input = {
          metadata: {
            id,
            name: 'Original',
            protocol: 'ssh',
            kind: 'password',
            username: 'alice',
            domain: '',
            provider: 'Local',
            bitwardenItemId: '',
            bitwardenItemName: '',
            privateKeyPath: '',
            certificatePath: '',
            clearPassphrase: false,
            clearCertificate: false,
          },
          rowVersion: '7',
          password: new Uint8Array([65, 66]),
          passphrase: new Uint8Array(),
        };
        const selected = { id, rowVersion: '7' };
        const pending = remove ? client.deleteCredential(selected) : client.editCredential(input);
        const checked = scenario === 'ok' ? pending : assert.rejects(pending, /unavailable/);
        selected.rowVersion = '99';
        input.metadata.name = 'Changed';
        input.rowVersion = '99';
        await tick();
        const sent = child.requests.find(
          (r) => r.operation === (remove ? 'credential-delete' : 'credential-edit'),
        )!;
        assert.ok(sent);
        assert.equal((sent as any).payload.rowVersion, '7');
        if (!remove) {
          assert.equal((sent as any).payload.metadata.name, 'Original');
          assert.equal((sent as any).payload.password, 'QUI=');
          assert.ok(input.password.every((x) => x === 0));
        }
        child.reply(
          sent,
          scenario === 'invalid'
            ? {}
            : {
                id: scenario === 'wrong-id' ? other : id,
                rowVersion: scenario === 'wrong-version' ? '9' : '8',
                ...(remove ? { deleted: true } : { updated: true }),
              },
        );
        await checked;
        if (!remove) assert.ok(child.writtenFrames[0].every((x) => x === 0));
      } finally {
        await client.lock();
      }
    }
});

test('tunnel editor client snapshots recipient, accepts maximum sealed projection and rejects response substitution', async () => {
  const context = {
    workspaceId: '11111111-1111-4111-8111-111111111111',
    tunnelId: '22222222-2222-4222-8222-222222222222',
    requestId: '33333333-3333-4333-8333-333333333333',
    rowVersion: '1',
  };
  for (const wrong of ['', 'workspaceId', 'tunnelId', 'requestId', 'rowVersion', 'oversize']) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.displayTunnelEditor(null), /Invalid/);
      const request = { ...context, publicKey: Buffer.alloc(32, 1).toString('base64') };
      const pending = client.displayTunnelEditor(request);
      const checked = wrong ? assert.rejects(pending, /unavailable/) : pending;
      request.tunnelId = 'Changed';
      await tick();
      const sent = child.requests[0];
      assert.equal(sent.operation, 'tunnel-editor-display');
      assert.equal((sent as any).payload.tunnelId, context.tunnelId);
      assert.equal(Object.hasOwn((sent as any).payload, 'workspaceId'), false);
      child.reply(sent, {
        ...context,
        ...(wrong && wrong !== 'oversize' ? { [wrong]: 'bad' } : {}),
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: request.publicKey,
          ciphertext: Buffer.alloc(wrong === 'oversize' ? 800000 : 524304).toString('base64'),
        },
      });
      await checked;
    } finally {
      await client.lock();
    }
  }
});

test('tunnel mutations bind exact revisions and wipe patches and fresh authentication frames', async () => {
  const id = '11111111-1111-4111-8111-111111111111',
    other = '22222222-2222-4222-8222-222222222222';
  for (const remove of [false, true])
    for (const fresh of [false, true])
      for (const scenario of ['ok', 'new', 'wrong-id', 'wrong-version', 'invalid', 'bad-factor']) {
        if (remove && scenario === 'new') continue;
        const { child, client } = fixture();
        child.automatic = false;
        try {
          const factor = () => ({
            vaultId: id,
            slotId: other,
            kind: 'password' as const,
            factor: new Uint8Array([5]),
          });
          const bad = factor();
          await assert.rejects(
            remove ? client.deleteTunnel(null, bad) : client.editTunnel(null, bad),
            /Invalid/,
          );
          assert.deepEqual([...bad.factor], [0]);
          const input = {
            metadata: { id: scenario === 'new' ? '' : id, name: 'Original', kind: 1 },
            rowVersion: scenario === 'new' ? '0' : '7',
            forgetHostKey: false,
            patch: new TextEncoder().encode('{"Password":"secret"}'),
          };
          const selected = { id, rowVersion: '7' };
          const auth =
            scenario === 'bad-factor'
              ? ({ ...factor(), kind: 'bad' } as any)
              : fresh
                ? factor()
                : undefined;
          const pending = remove
            ? client.deleteTunnel(selected, auth)
            : client.editTunnel(input, auth);
          if (scenario === 'bad-factor') {
            await assert.rejects(pending, /Invalid/);
            assert.ok(auth.factor.every((b: number) => b === 0));
            if (!remove) assert.ok(input.patch.every((b) => b === 0));
            continue;
          }
          const checked = ['ok', 'new'].includes(scenario)
            ? pending
            : assert.rejects(pending, /unavailable/);
          selected.rowVersion = '99';
          input.metadata.name = 'Changed';
          input.rowVersion = '99';
          await tick();
          const operation = remove ? 'tunnel-delete' : 'tunnel-edit';
          const sent: any = child.requests.find(
            (r) => r.operation === (fresh ? 'fresh-action' : operation),
          );
          assert.ok(sent);
          let payload = sent.payload;
          if (fresh) {
            assert.equal(payload.operation, operation);
            const authentication = JSON.parse(
              Buffer.from(payload.authentication, 'base64').toString(),
            );
            assert.equal(authentication.password, 'BQ==');
            payload = JSON.parse(Buffer.from(payload.action, 'base64').toString());
            assert.ok(auth.factor.every((b: number) => b === 0));
          }
          assert.equal(payload.rowVersion, scenario === 'new' ? '0' : '7');
          if (!remove) {
            assert.equal(payload.metadata.name, 'Original');
            assert.equal(Buffer.from(payload.patch, 'base64').toString(), '{"Password":"secret"}');
            assert.ok(input.patch.every((b) => b === 0));
          }
          child.reply(
            sent,
            scenario === 'invalid'
              ? {}
              : {
                  id: scenario === 'wrong-id' ? other : id,
                  rowVersion: scenario === 'wrong-version' ? '9' : scenario === 'new' ? '1' : '8',
                  ...(remove ? { deleted: true } : { updated: true }),
                },
          );
          await checked;
          if (!remove || fresh) assert.ok(child.writtenFrames[0].every((b) => b === 0));
        } finally {
          await client.lock();
        }
      }
});

test('profile import transport snapshots picker context, bounds ciphertext and validates discard acknowledgement', async () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const context = { workspaceId: id, editorId: id, importId: id, kind: 1 };
  for (const wrong of ['', 'workspaceId', 'editorId', 'importId', 'kind', 'oversize']) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.stageTunnelImport(null), /Invalid/);
      const request = {
        ...context,
        tunnelId: '',
        rowVersion: '0',
        path: '/picked/profile',
        format: 'openvpn',
        publicKey: Buffer.alloc(32, 1).toString('base64'),
      };
      const pending = client.stageTunnelImport(request),
        checked = wrong ? assert.rejects(pending, /unavailable/) : pending;
      request.path = 'substituted';
      request.importId = 'substituted';
      await tick();
      const sent: any = child.requests[0];
      assert.equal(sent.operation, 'tunnel-import-stage');
      assert.equal(sent.payload.path, '/picked/profile');
      assert.equal(sent.payload.importId, id);
      assert.equal(sent.payload.workspaceId, undefined);
      child.reply(sent, {
        ...context,
        ...(wrong && wrong !== 'oversize' ? { [wrong]: 'wrong' } : {}),
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: request.publicKey,
          ciphertext: Buffer.alloc(wrong === 'oversize' ? 800000 : 524304).toString('base64'),
        },
      });
      const result = await checked;
      if (!wrong)
        assert.deepEqual(Object.keys(result).sort(), [
          'bundle',
          'editorId',
          'importId',
          'kind',
          'workspaceId',
        ]);
    } finally {
      await client.lock();
    }
  }
  for (const valid of [true, false]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.discardTunnelImport(null), /Invalid/);
      const pending = client.discardTunnelImport({ workspaceId: id, editorId: id, importId: '' });
      const checked = valid ? pending : assert.rejects(pending, /unavailable/);
      await tick();
      const sent: any = child.requests[0];
      assert.equal(sent.operation, 'tunnel-import-discard');
      assert.deepEqual(sent.payload, { editorId: id, importId: '' });
      child.reply(sent, { discarded: valid });
      await checked;
    } finally {
      await client.lock();
    }
  }
});

test('route transport preserves maximum sealed frames and rejects context replacement', async () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const request = {
    workspaceId: id,
    nodeId: id,
    credentialOverride: '',
    sessionId: id,
    requestId: id,
    epoch: 1,
    publicKey: Buffer.alloc(32, 1).toString('base64'),
  };
  for (const wrong of [
    '',
    'workspaceId',
    'nodeId',
    'sessionId',
    'requestId',
    'epoch',
    'configurationVersion',
    'oversize',
  ]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.tunnelBundle(null), /Invalid/);
      const input = { ...request },
        pending = client.tunnelBundle(input),
        checked = wrong ? assert.rejects(pending, /unavailable/) : pending;
      input.publicKey = 'changed';
      input.nodeId = 'changed';
      await tick();
      const sent: any = child.requests[0];
      assert.equal(sent.operation, 'tunnel-bundle');
      assert.equal(sent.payload.nodeId, id);
      assert.equal(sent.payload.publicKey, request.publicKey);
      assert.equal(sent.payload.epoch, '1');
      assert.equal(sent.payload.workspaceId, undefined);
      const binding = {
        workspaceId: id,
        nodeId: id,
        sessionId: id,
        requestId: id,
        epoch: 1,
        fileId: id,
        tunnelConfigId: id,
        protocol: 'https',
        host: 'host.example',
        port: 443,
        useExternalClient: false,
        kind: 1,
        rowVersion: '1',
        configurationVersion: '1',
        ...(wrong && wrong !== 'oversize' ? { [wrong]: 'bad' } : {}),
      };
      child.reply(sent, {
        binding,
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: request.publicKey,
          ciphertext: Buffer.alloc(
            wrong === 'oversize' ? 4 * 1024 * 1024 + 17 : 4 * 1024 * 1024 + 16,
          ).toString('base64'),
        },
      });
      await checked;
    } finally {
      await client.lock();
    }
  }
});

test('route plan transport snapshots context, omits recipients and checks native response', async () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const q = {
    workspaceId: id,
    nodeId: id,
    sessionId: id,
    requestId: id,
    credentialOverride: '',
    epoch: 1,
  };
  for (const wrong of [false, true]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      await assert.rejects(client.tunnelPlan(null), /Invalid/);
      const input = { ...q },
        pending = client.tunnelPlan(input),
        checked = wrong ? assert.rejects(pending, /unavailable/) : pending;
      input.nodeId = 'changed';
      await tick();
      const sent: any = child.requests[0];
      assert.equal(sent.operation, 'tunnel-plan');
      assert.deepEqual(sent.payload, {
        nodeId: id,
        credentialOverride: '',
        sessionId: id,
        requestId: id,
        epoch: '1',
      });
      child.reply(sent, {
        ...q,
        credentialOverride: undefined,
        fileId: id,
        protocol: 'ssh',
        host: 'host.example',
        port: 22,
        tunnelConfigId: id,
        useExternalClient: false,
        kind: 1,
        rowVersion: '1',
        configurationVersion: '1',
        ...(wrong ? { epoch: 2 } : {}),
      });
      await checked;
    } finally {
      await client.lock();
    }
  }
});

test('fallback transport snapshots both sources, checks native context and admits maximum sealed frames', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const method of ['tunnelFallbackPlan', 'tunnelFallbackBundle'] as const) {
    for (const mode of ['valid', 'primary', 'fallback', 'extra', 'oversize']) {
      if (method === 'tunnelFallbackPlan' && mode === 'oversize') continue;
      const { child, client, launches } = fixture();
      child.automatic = false;
      try {
        await assert.rejects(client[method](null), /Invalid/);
        const input = structuredClone(
          method === 'tunnelFallbackPlan' ? fallbackPlan : fallbackRequest,
        );
        const pending = client[method](input);
        const checked = mode === 'valid' ? pending : assert.rejects(pending, /unavailable/);
        input.nodeId = 'changed';
        if ('primary' in input) input.primary.rowVersion = '1';
        else input.binding.fallback.configurationVersion = '1';
        await tick();
        const sent: any = child.requests[0];
        const original = method === 'tunnelFallbackPlan' ? fallbackPlan : fallbackRequest;
        const { workspaceId: _, epoch, ...payload } = original;
        assert.equal(
          sent.operation,
          method === 'tunnelFallbackPlan' ? 'tunnel-fallback-plan' : 'tunnel-fallback-bundle',
        );
        assert.deepEqual(sent.payload, { ...payload, epoch: String(epoch) });
        const result: any = structuredClone(
          method === 'tunnelFallbackPlan' ? fallbackRequest.binding : fallbackBundle,
        );
        const pair = method === 'tunnelFallbackPlan' ? result : result.binding;
        if (mode === 'primary') pair.primary.host = 'replacement.example';
        if (mode === 'fallback') {
          if (method === 'tunnelFallbackPlan') pair.fallback.host = 'replacement.example';
          else pair.fallback.rowVersion = '9'; // valid source metadata, but not the requested pair
        }
        if (mode === 'extra') result.privateKey = 'must-refuse';
        if (method === 'tunnelFallbackBundle')
          result.bundle.ciphertext = Buffer.alloc(
            4 * 1024 * 1024 + (mode === 'oversize' ? 17 : 16),
          ).toString('base64');
        child.reply(sent, result);
        const response = await checked;
        if (mode === 'valid') assert.deepEqual(response, result);
        else await assert.rejects(client[method](original), /unavailable/);
        assert.equal(launches.length, 1);
      } finally {
        await client.lock();
      }
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-client.ts'))
    .flatMap((s) => s.functions)
    .filter((f) => ['tunnelFallbackPlan', 'tunnelFallbackBundle'].includes(f.functionName))
    .flatMap((f) => f.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`fallback client: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('connection route and routed SSH transport validate and snapshot native context', async () => {
  const q = sshRequest();
  const { publicKey: _, ...plan } = q;
  const binding = {
    ...sshBundle(q).binding,
    fileId: q.workspaceId,
    tunnelConfigId: q.nodeId,
    kind: 6,
    rowVersion: '1',
    configurationVersion: '1',
  };
  const routed = { ...q, route: binding, endpoint: '127.0.0.1:12345' };
  for (const method of ['connectionRoute', 'routedSshBundle'] as const) {
    for (const mode of ['valid', 'invalid', 'direct'] as const) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        await assert.rejects(client[method](null), /Invalid/);
        const input = structuredClone(method === 'connectionRoute' ? plan : routed);
        const pending = client[method](input);
        const rejects = mode === 'invalid' || (mode === 'direct' && method === 'routedSshBundle');
        const checked = rejects ? assert.rejects(pending, /unavailable/) : pending;
        input.nodeId = 'changed';
        if ('route' in input) input.route.host = 'changed';
        await tick();
        const sent: any = child.requests[0];
        assert.equal(
          sent.operation,
          method === 'connectionRoute' ? 'connection-route' : 'ssh-route-bundle',
        );
        assert.equal(sent.payload.nodeId, q.nodeId);
        assert.equal(sent.payload.epoch, '1');
        assert.equal(sent.payload.workspaceId, undefined);
        if (method === 'routedSshBundle') {
          assert.deepEqual(sent.payload.route, binding);
          assert.equal(sent.payload.endpoint, routed.endpoint);
          assert.equal(sent.payload.publicKey, q.publicKey);
        } else assert.equal(sent.payload.publicKey, undefined);
        const value =
          method === 'connectionRoute'
            ? binding
            : { binding, bundle: sshBundle(q).bundle, endpoint: routed.endpoint };
        child.reply(sent, mode === 'invalid' ? {} : mode === 'direct' ? null : value);
        const result = await checked;
        if (!rejects) assert.deepEqual(result, mode === 'direct' ? null : value);
      } finally {
        await client.lock();
      }
    }
  }
});

test('SSH host plan and trust transport bind native context and snapshot confirmations', async () => {
  const q = sshRequest(),
    { publicKey: _, ...context } = q;
  const request = { ...context, route: null };
  const plan = {
    binding: sshBundle(q).binding,
    fileId: q.workspaceId,
    revision: 'a'.repeat(64),
    fingerprint: '',
  };
  const trust = {
    ...request,
    expected: plan,
    received: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  };
  for (const method of ['sshHostPlan', 'trustSshHost'] as const)
    for (const bad of [false, true]) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        await assert.rejects(client[method](null), /Invalid/);
        const mutable = structuredClone(method === 'sshHostPlan' ? request : trust);
        const pending = client[method](mutable),
          checked = bad ? assert.rejects(pending, /unavailable/) : pending;
        mutable.nodeId = 'changed';
        if ('expected' in mutable) mutable.expected.binding.host = 'changed';
        await tick();
        const sent: any = child.requests[0];
        assert.equal(sent.operation, method === 'sshHostPlan' ? 'ssh-host-plan' : 'ssh-host-trust');
        assert.equal(sent.payload.nodeId, q.nodeId);
        assert.equal(sent.payload.epoch, '1');
        assert.equal(sent.payload.workspaceId, undefined);
        assert.equal(sent.payload.route, null);
        if (method === 'trustSshHost') assert.deepEqual(sent.payload.expected, plan);
        const result =
          method === 'sshHostPlan' ? plan : { nodeId: q.nodeId, rowVersion: '2', updated: true };
        child.reply(sent, bad ? {} : result);
        await checked;
      } finally {
        await client.lock();
      }
    }
  const { client } = fixture();
  const factor = new Uint8Array([1]);
  await assert.rejects(
    client.trustSshHost(null, {
      vaultId: q.workspaceId,
      slotId: q.nodeId,
      kind: 'password',
      factor,
    }),
    /Invalid/,
  );
  assert.ok(factor.every((x) => x === 0));
  await client.lock();
});
test('file-only native requests snapshot and verify the subsystem selection', async () => {
  for (const routed of [false, true]) {
    const { child, client } = fixture();
    child.automatic = false;
    try {
      const q = { ...sshRequest(), sftpOnly: true as const };
      const binding = {
        ...sshBundle(q).binding,
        fileId: q.workspaceId,
        tunnelConfigId: q.nodeId,
        kind: 6,
        rowVersion: '1',
        configurationVersion: '1',
      };
      const input = { ...q, ...(routed ? { route: binding, endpoint: '127.0.0.1:4321' } : {}) };
      const method = routed ? 'routedSshBundle' : 'sshBundle';
      const pending = client[method](input);
      delete (input as { sftpOnly?: true }).sftpOnly;
      await tick();
      const sent: any = child.requests.at(-1)!;
      assert.equal(sent.payload.sftpOnly, true);
      const result = routed
        ? { ...sshBundle(q), binding, endpoint: '127.0.0.1:4321' }
        : sshBundle(q);
      child.reply(sent, result);
      assert.deepEqual(await pending, result);
      const second = client[method]({ ...input, sftpOnly: true });
      const rejected = assert.rejects(second, /protocol|unavailable/i);
      await tick();
      const stripped = { ...result };
      delete stripped.sftpOnly;
      child.reply(child.requests.at(-1)!, stripped);
      await rejected;
    } finally {
      await client.lock();
    }
  }
});

test('node move snapshots the target and sources and accepts an unchanged acknowledgement', async () => {
  for (const valid of [true, false]) {
    const { child, client } = fixture();
    child.automatic = false;
    await assert.rejects(client.moveNodes({}), /Invalid/);
    const input = {
      nodes: [{ id: '11111111-1111-4111-8111-111111111111', rowVersion: '7' }],
      target: { id: '22222222-2222-4222-8222-222222222222', rowVersion: '4' },
      placement: 'after',
    };
    const pending = client.moveNodes(input),
      checked = valid ? pending : assert.rejects(pending, /unavailable/);
    input.nodes[0].rowVersion = '99';
    input.target.rowVersion = '99';
    input.placement = 'inside';
    await tick();
    const sent = child.requests.find((r) => r.operation === 'node-move')!;
    assert.equal((sent as any).payload.nodes[0].rowVersion, '7');
    assert.equal((sent as any).payload.target.rowVersion, '4');
    assert.equal((sent as any).payload.placement, 'after');
    child.reply(sent, { moved: true, updatedCount: valid ? '0' : '01' });
    await checked;
    await client.lock();
  }
});

test('duplicate snapshots source revision and rejects a reused identity or malformed acknowledgement', async () => {
  for (const mode of ['ok', 'same-id', 'bad-version', 'bad-shape']) {
    const { child, client } = fixture();
    child.automatic = false;
    await assert.rejects(client.duplicateConnection({}), /Invalid/);
    const input = { id: '11111111-1111-4111-8111-111111111111', rowVersion: '7' };
    const pending = client.duplicateConnection(input),
      checked = mode === 'ok' ? pending : assert.rejects(pending, /unavailable/);
    input.rowVersion = '99';
    await tick();
    const sent = child.requests.find((r) => r.operation === 'node-duplicate')!;
    assert.equal((sent as any).payload.rowVersion, '7');
    child.reply(
      sent,
      mode === 'bad-shape'
        ? {}
        : {
            nodeId: mode === 'same-id' ? input.id : '22222222-2222-4222-8222-222222222222',
            name: 'Copy',
            rowVersion: mode === 'bad-version' ? '2' : '1',
          },
    );
    await checked;
    await client.lock();
  }
});

test('native VNC bundle methods snapshot context and validate both direct and routed replies', async () => {
  for (const routed of [false, true])
    for (const valid of [false, true]) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const q = routed ? routedVncRequest() : vncRequest(),
          snapshot = structuredClone(q);
        const method = routed ? 'routedVncBundle' : 'vncBundle';
        await assert.rejects(client[method]({ ...q, epoch: 0 }), /Invalid/);
        const pending = client[method](q);
        const checked = valid ? pending : assert.rejects(pending, /protocol|unavailable/i);
        q.nodeId = vncRequest().nodeId;
        q.publicKey = 'changed';
        if (routed) (q as any).route.host = 'changed';
        await tick();
        const sent = child.requests.at(-1)!;
        assert.equal(sent.operation, routed ? 'vnc-route-bundle' : 'vnc-bundle');
        const { workspaceId: _, epoch, ...base } = snapshot;
        assert.deepEqual((sent as any).payload, { ...base, epoch: String(epoch) });
        const reply = routed ? routedVncBundle(snapshot as any) : vncBundle(snapshot);
        if (!valid) reply.binding.sessionId = vncRequest().sessionId;
        child.reply(sent, reply);
        if (valid) assert.deepEqual(await checked, reply);
        else await checked;
      } finally {
        await client.lock();
      }
    }
});

test('native temporary VNC methods send only validated snapshots and reject swapped native replies', async () => {
  for (const operation of ['plan', 'direct', 'route'])
    for (const valid of [false, true]) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const q = routedVncRequest(),
          binding = operation === 'route' ? q.route : vncBundle(q).binding;
        const { publicKey, route: _, endpoint: __, ...plan } = q;
        const manual = vncBundle(q).bundle,
          context = {
            binding,
            publicKey,
            ...(operation === 'route' ? { endpoint: q.endpoint } : {}),
          };
        const input = operation === 'plan' ? plan : { context, credentialOverride: '', manual };
        const snapshot = structuredClone(input);
        const method = operation === 'plan' ? 'vncPlan' : 'vncManualBundle';
        await assert.rejects(client[method](null), /Invalid/);
        const pending = client[method](input),
          checked = valid ? pending : assert.rejects(pending, /protocol|unavailable/i);
        if ('context' in input) input.context.binding.host = 'changed';
        else input.nodeId = 'changed';
        await tick();
        const sent = child.requests.at(-1)!;
        assert.equal(
          sent.operation,
          operation === 'plan'
            ? 'vnc-plan'
            : operation === 'route'
              ? 'vnc-manual-route-bundle'
              : 'vnc-manual-bundle',
        );
        assert.deepEqual(
          (sent as any).payload,
          operation === 'plan'
            ? vncPlanPayload(snapshot as any)
            : vncManualPayload(snapshot as any),
        );
        const originalBinding =
          operation === 'plan' ? vncBundle(q).binding : (snapshot as any).context.binding;
        const reply: any =
          operation === 'plan'
            ? { binding: originalBinding }
            : {
                binding: originalBinding,
                bundle: { ...manual, ciphertext: Buffer.alloc(75).toString('base64') },
                ...(operation === 'route' ? { endpoint: q.endpoint } : {}),
              };
        if (!valid) reply.binding.sessionId = vncRequest().sessionId;
        child.reply(sent, reply);
        if (valid) assert.deepEqual(await checked, operation === 'plan' ? reply.binding : reply);
        else await checked;
      } finally {
        await client.lock();
      }
    }
});

test(
  'Windows PID absence cannot acknowledge vault shutdown without an independent native proof',
  { skip: process.platform !== 'win32' },
  async () => {
    const native = spawn(process.execPath, ['-e', 'process.exit(0)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    await new Promise<void>((resolve, reject) => {
      native.once('close', () => resolve());
      native.once('error', reject);
    });
    assert.ok(native.pid);
    for (const phase of ['initial', 'grace', 'kill', 'confirmation']) {
      const { child, client } = fixture({
        executable: 'vault',
        databasePath: 'workspace.db',
        stopGraceMs: 10,
        stopConfirmationMs: 30,
      });
      await client.status();
      child.exitOnEnd = false;
      child.exitOnKill = false;
      if (phase === 'initial') child.pid = native.pid;
      if (phase === 'kill')
        child.kill = () => {
          child.pid = native.pid;
          return false;
        };
      const stopping = client.lock();
      if (phase === 'grace') queueMicrotask(() => (child.pid = native.pid));
      if (phase === 'confirmation') setTimeout(() => (child.pid = native.pid), 20);
      await assert.rejects(stopping, /termination could not be confirmed/);
      // The missing helper and signal-zero PID absence cannot acknowledge lock.
      await assert.rejects(client.status(), /unavailable/i);
      child.exit();
      await client.lock();
    }
  },
);

test('web planning sends native metadata only, snapshots identity and rejects substituted results', async () => {
  for (const valid of [false, true])
    for (const routed of [false, true]) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const q = webRequest(),
          snapshot = structuredClone(q);
        await assert.rejects(client.webPlan({ ...q, credentialOverride: q.nodeId }), /Invalid/);
        const pending = client.webPlan(q),
          checked = valid ? pending : assert.rejects(pending, /protocol|unavailable/i);
        q.nodeId = 'changed';
        await tick();
        const sent = child.requests.at(-1)!;
        assert.equal(sent.operation, 'web-plan');
        assert.deepEqual((sent as any).payload, {
          nodeId: snapshot.nodeId,
          credentialOverride: '',
          sessionId: snapshot.sessionId,
          requestId: snapshot.requestId,
          epoch: '1',
        });
        const reply = webPlan(snapshot, routed);
        if (!valid) reply.binding.sessionId = webRequest().sessionId;
        child.reply(sent, reply);
        if (valid) assert.deepEqual(await checked, reply);
        else await checked;
      } finally {
        await client.lock();
      }
    }
});

test('native shared connection context is exact, bound and read only', async (t) => {
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const nodeId = '11111111-1111-4111-8111-111111111111';
  for (const mode of ['ok', 'wrong-node', 'secret', 'protocol', 'invalid']) {
    const { client, child, launches } = fixture();
    child.automatic = false;
    child.on('request', (request: any) => {
      if (request.operation === 'lock') return;
      assert.equal(request.operation, 'shared-connection-context');
      assert.deepEqual(request.payload, { nodeId });
      child.reply(
        request,
        mode === 'wrong-node'
          ? { nodeId: '22222222-2222-4222-8222-222222222222', protocol: 0 }
          : mode === 'secret'
            ? { nodeId, protocol: 0, password: 'private' }
            : { nodeId, protocol: mode === 'protocol' ? 2 : 7 },
      );
    });
    try {
      const result = client.sharedConnectionContext(
        mode === 'invalid' ? { nodeId: 'bad' } : { nodeId },
      );
      if (mode === 'ok') assert.deepEqual(await result, { nodeId, protocol: 7 });
      else await assert.rejects(result);
      assert.equal(launches.length, mode === 'invalid' ? 0 : 1);
      assert.equal(
        child.requests.some(
          (r) => r.operation.includes('bundle') || r.operation.includes('unlock'),
        ),
        false,
      );
    } finally {
      await client.lock();
    }
  }
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((script) => script.url.endsWith('/electron/vault-client.ts'))
    .flatMap((script) => script.functions)
    .filter((fn) => fn.functionName === 'sharedConnectionContext')
    .flatMap((fn) => fn.ranges);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
  t.diagnostic('shared connection client: ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});

test('native RDP bundle methods snapshot context and validate both direct and routed replies', async () => {
  for (const routed of [false, true])
    for (const valid of [false, true]) {
      const { child, client } = fixture();
      child.automatic = false;
      try {
        const q = routed ? routedRdpRequest() : rdpRequest(),
          snapshot = structuredClone(q);
        const method = routed ? 'routedRdpBundle' : 'rdpBundle';
        await assert.rejects(client[method]({ ...q, epoch: 0 }), /Invalid/);
        const pending = client[method](q);
        const checked = valid ? pending : assert.rejects(pending, /protocol|unavailable/i);
        q.nodeId = rdpRequest().nodeId;
        q.publicKey = 'changed';
        if (routed) (q as any).route.host = 'changed';
        await tick();
        const sent = child.requests.at(-1)!;
        assert.equal(sent.operation, routed ? 'rdp-route-bundle' : 'rdp-bundle');
        const { workspaceId: _, epoch, ...base } = snapshot;
        assert.deepEqual((sent as any).payload, { ...base, epoch: String(epoch) });
        const reply = routed ? routedRdpBundle(snapshot as any) : rdpBundle(snapshot);
        if (!valid) reply.binding.sessionId = rdpRequest().sessionId;
        child.reply(sent, reply);
        if (valid) assert.deepEqual(await checked, reply);
        else await checked;
      } finally {
        await client.lock();
      }
    }
});

test('migration client requires native isolation, keeps long work alive and encodes factors only in stdin', async (t) => {
  const profiler =
    process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE
      ? undefined
      : new Session();
  if (profiler) {
    profiler.connect();
    t.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }

  const input = () => ({
    vaultId: '11111111-1111-4111-8111-111111111111',
    slotId: '22222222-2222-4222-8222-222222222222',
    kind: 'password',
    factor: new Uint8Array([1, 2, 3]),
  });
  for (const operation of ['migration-resume', 'rotation-resume'] as const) {
    const method = operation === 'migration-resume' ? 'resumeMigration' : 'resumeRootRotation';
    const ordinary = fixture();
    const rejected = input();
    await assert.rejects(ordinary.client[method](rejected), /restart required/);
    assert.ok(rejected.factor.every((x) => x === 0));
    assert.equal(ordinary.launches.length, 0);
    await assert.rejects(ordinary.client[method]({}), /Invalid/);
    await ordinary.client.lock();
    if (operation === 'migration-resume') t.mock.timers.enable({ apis: ['setTimeout'] });
    const { child, client, launches } = fixture({
      executable: 'native',
      databasePath: 'fixed-source',
      userDataPath: 'original-profile',
      migrationSessionData: 'isolated-profile',
      heartbeatMs: 120_000,
    });
    child.automatic = false;
    const factor = input();
    const pending = client[method](factor);
    await tick();
    assert.ok(factor.factor.every((x) => x === 0));
    const request = child.requests.at(-1)!;
    assert.equal(request.operation, operation);
    assert.deepEqual((request as any).payload, {
      vaultId: input().vaultId,
      slotId: input().slotId,
      password: 'AQID',
    });
    assert.deepEqual(launches[0].args, [
      '--operation',
      'vault-migration',
      '--database',
      'fixed-source',
      '--electron-user-data',
      'original-profile',
      '--migration-session-data',
      'isolated-profile',
    ]);
    t.mock.timers.tick(6000);
    assert.equal(child.killed, false);
    child.reply(request, { unlocked: true, lockedMemory: true });
    assert.deepEqual(await pending, { unlocked: true, lockedMemory: true });
    await client.lock();
  }
  if (!profiler) return;
  const coverage = await profiler.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .filter((s) => s.url.endsWith('/electron/vault-client.ts'))
    .flatMap((s) => s.functions)
    .filter((f) =>
      ['resumeMigration', 'resumeRootRotation', 'resumeMaintenance'].includes(f.functionName),
    )
    .flatMap((f) => f.ranges);
  assert.ok(ranges.length);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('migration client ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});
