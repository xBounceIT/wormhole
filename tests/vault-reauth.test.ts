import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { connectionInput, connectionNodeId } from './fixtures/vault-connection.ts';
import { migrationDecision } from './fixtures/vault-migration.ts';

const id = '11111111-1111-4111-8111-111111111111',
  slot = '22222222-2222-4222-8222-222222222222';
const factor = () => ({
  vaultId: id,
  slotId: slot,
  kind: 'password' as const,
  factor: new TextEncoder().encode('fresh-password'),
});
const descriptor = {
  formatVersion: 1,
  vaultId: id,
  encrypted: false,
  slots: [{ id: slot, kind: 'password', preset: 'kdf-v1' }],
};
const folder = () => ({
  id: '',
  rowVersion: '0',
  parentId: '',
  name: 'Fresh folder',
  sshAutoSudo: null,
  tunnelEnabled: null,
  tunnelConfigId: '',
  credentialMode: 0,
  credentialId: '',
});
const security = (profile = 'standard') => ({
  sequence: '1',
  workspace: profile,
  user: 'default',
  os: 'default',
  effective: profile,
  source: 'workspace',
});
const tick = () => new Promise(setImmediate);

class Child extends EventEmitter {
  stdout = new PassThrough();
  stderr = new PassThrough();
  frames: Buffer[] = [];
  requests: any[] = [];
  stdin = new Writable({
    write: (chunk, _encoding, done) => {
      this.frames.push(chunk);
      const request = JSON.parse(chunk.toString());
      this.requests.push(request);
      if (request.operation === 'lock') {
        done();
        return;
      }
      let result: any;
      if (request.operation === 'heartbeat') result = { alive: true };
      else {
        assert.equal(request.operation, 'fresh-action');
        const action = JSON.parse(Buffer.from(request.payload.action, 'base64').toString());
        result =
          request.payload.operation === 'credential-copy'
            ? { expiresInSeconds: 20 }
            : request.payload.operation === 'credential-display'
              ? {
                  nodeId: action.nodeId,
                  requestId: action.requestId,
                  rowVersion: action.rowVersion,
                  workspaceId: id,
                  bundle: {
                    formatVersion: 1,
                    suiteId: 2,
                    enc: Buffer.alloc(32, 1).toString('base64'),
                    ciphertext: Buffer.alloc(32).toString('base64'),
                  },
                }
              : request.payload.operation === 'node-duplicate'
                ? { nodeId: slot, name: 'Copy', rowVersion: '1' }
                : request.payload.operation === 'node-move'
                  ? { moved: true, updatedCount: '1' }
                  : request.payload.operation === 'node-delete-trees'
                    ? { deleted: true }
                    : {
                        nodeId:
                          action.nodeId ?? (action.metadata?.id || action.id || connectionNodeId),
                        rowVersion: String(BigInt(action.rowVersion) + 1n),
                        updated: true,
                      };
      }
      this.stdout.write(JSON.stringify({ version: 1, id: request.id, result }) + '\n');
      done();
    },
  });
  constructor() {
    super();
    this.stdin.on('finish', () => this.emit('exit', 0, null));
  }
  kill() {
    this.emit('exit', 0, null);
    return true;
  }
}

test('client binds each fresh factor to one exact typed action and clears mutable frames', async () => {
  const child = new Child();
  const client = new VaultBackendClient(
    { executable: 'native', databasePath: 'vault.db', heartbeatMs: 100000 },
    () => {
      queueMicrotask(() => child.emit('spawn'));
      return child as any;
    },
  );
  try {
    for (const kind of ['password', 'recovery', 'recovery-code'] as const) {
      const input = connectionInput(),
        auth = {
          ...factor(),
          kind,
          factor: new Uint8Array(kind === 'password' ? 5 : kind === 'recovery' ? 32 : 76).fill(65),
        };
      const result = await client.saveConnection(input, auth);
      assert.equal(result.nodeId, connectionNodeId);
      assert.ok(auth.factor.every((x) => x === 0));
      assert.ok(input.password.every((x) => x === 0));
      const frame = child.requests.at(-1),
        action = JSON.parse(Buffer.from(frame.payload.action, 'base64').toString()),
        authentication = JSON.parse(Buffer.from(frame.payload.authentication, 'base64').toString());
      assert.equal(frame.payload.operation, 'connection-save');
      assert.equal(authentication.vaultId, id);
      assert.equal(authentication.slotId, slot);
      assert.equal(Buffer.from(action.password, 'base64').toString(), 'password-fixture');
      assert.equal(Buffer.from(action.notes, 'base64').toString(), 'notes-fixture');
      assert.equal(Object.keys(authentication).length, 3);
    }
    const movement = {
      nodes: [{ id, rowVersion: '7' }],
      target: { id: slot, rowVersion: '3' },
      placement: 'inside',
    };
    const movementFactor = factor();
    await client.moveNodes(movement, movementFactor);
    const moveFrame = child.requests.at(-1);
    assert.equal(moveFrame.operation, 'fresh-action');
    assert.equal(moveFrame.payload.operation, 'node-move');
    assert.deepEqual(
      JSON.parse(Buffer.from(moveFrame.payload.action, 'base64').toString()),
      movement,
    );
    assert.ok(movementFactor.factor.every((byte) => byte === 0));
    const duplicateAuth = factor(),
      duplicateInput = { id, rowVersion: '7' };
    await client.duplicateConnection(duplicateInput, duplicateAuth);
    const duplicateFrame = child.requests.at(-1);
    assert.equal(duplicateFrame.operation, 'fresh-action');
    assert.equal(duplicateFrame.payload.operation, 'node-duplicate');
    assert.deepEqual(
      JSON.parse(Buffer.from(duplicateFrame.payload.action, 'base64').toString()),
      duplicateInput,
    );
    assert.ok(duplicateAuth.factor.every((byte) => byte === 0));
    const revealAuth = factor(),
      revealInput = {
        workspaceId: id,
        nodeId: slot,
        requestId: id,
        rowVersion: '1',
        publicKey: Buffer.alloc(32, 1).toString('base64'),
      };
    await client.displayCredentials(revealInput, revealAuth);
    assert.equal(child.requests.at(-1).payload.operation, 'credential-display');
    assert.ok(revealAuth.factor.every((x) => x === 0));
    const clipboardAuth = factor();
    const clipboardInput = { workspaceId: id, nodeId: slot, rowVersion: '1', field: 'secret' };
    assert.deepEqual(await client.copyCredential(clipboardInput, clipboardAuth), {
      expiresInSeconds: 20,
    });
    const copyFrame = child.requests.at(-1);
    assert.equal(copyFrame.payload.operation, 'credential-copy');
    assert.deepEqual(JSON.parse(Buffer.from(copyFrame.payload.action, 'base64').toString()), {
      nodeId: slot,
      rowVersion: '1',
      field: 'secret',
    });
    assert.ok(clipboardAuth.factor.every((x) => x === 0));
    await client.saveFolder(folder(), factor());
    await client.decideMigration(migrationDecision(), factor());
    await tick();
    assert.ok(child.frames.every((frame) => frame.every((x) => x === 0)));
    for (const method of [
      'saveConnection',
      'saveFolder',
      'deleteNodes',
      'moveNodes',
      'duplicateConnection',
      'displayCredentials',
      'copyCredential',
      'decideMigration',
    ] as const) {
      const authentication = factor();
      await assert.rejects(client[method](null, authentication));
      assert.ok(authentication.factor.every((byte) => byte === 0));
    }
    const bad = { ...factor(), slotId: 'bad' },
      request = connectionInput();
    await assert.rejects(client.saveConnection(request, bad));
    assert.ok(bad.factor.every((x) => x === 0));
    assert.ok(request.password.every((x) => x === 0));
  } finally {
    await client.lock();
  }
});

test('host uses fresh native security, preserves pending edit on a wrong factor and binds owner lifetime', async () => {
  let profile = 'standard',
    calls = 0,
    closed = false;
  const attempts: any[] = [];
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => security(profile),
    describe: async () => descriptor,
    lock: async () => {
      closed = true;
    },
    saveConnection: async (input: any, auth: any) => {
      calls++;
      attempts.push({ input, auth, password: [...input.password] });
      input.password.fill(0);
      input.notes.fill(0);
      if (calls === 1) throw Error('rejected factor');
      return { nodeId: connectionNodeId, rowVersion: '1', updated: true };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => !closed,
  );
  await host.unlock(factor());
  await assert.rejects(host.saveConnection(connectionInput()), /Fresh authentication/);
  assert.equal(calls, 0);
  const request = connectionInput();
  const result = await host.saveConnection(request, async (operation, slots, submit) => {
    assert.equal(operation, 'connection-save');
    assert.equal(slots.vaultId, id);
    const wrong = factor();
    await assert.rejects(submit(wrong));
    assert.ok(wrong.factor.every((x) => x === 0));
    return submit(factor());
  });
  assert.equal(result.nodeId, connectionNodeId);
  assert.deepEqual(attempts[0].password, attempts[1].password);
  assert.ok(request.password.every((x) => x === 0));
  for (const attempt of attempts) {
    assert.ok(attempt.input.password.every((x: number) => x === 0));
    assert.ok(attempt.auth.factor.every((x: number) => x === 0));
  }
  profile = 'hardened';
  await assert.rejects(
    host.saveFolder(folder(), async () => {
      throw Error('must not prompt');
    }),
    /Fresh authentication/,
  );
  profile = 'standard';
  await assert.rejects(
    host.saveConnection(connectionInput(), async (_operation, _slots, submit) => {
      await host.stop();
      return submit(factor());
    }),
    /locked/,
  );
  assert.equal(calls, 2);
});

test('host rejects identity drift and requester loss before sending a mutation', async () => {
  let allowed = true,
    actual: any = descriptor,
    calls = 0;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => security(),
    describe: async () => actual,
    lock: async () => {},
    saveFolder: async () => {
      calls++;
      return { nodeId: id, rowVersion: '1', updated: true };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await host.unlock(factor());
  actual = null;
  await assert.rejects(
    host.saveFolder(folder(), async () => {
      throw Error('unexpected prompt');
    }),
    /locked/,
  );
  actual = descriptor;
  await assert.rejects(
    host.saveFolder(folder(), async (_op, _slots, submit) =>
      submit({ ...factor(), vaultId: slot }),
    ),
    /locked/,
  );
  await assert.rejects(
    host.saveFolder(
      folder(),
      async (_op, _slots, submit) => {
        allowed = false;
        return submit(factor());
      },
      () => allowed,
    ),
    /locked/,
  );
  assert.equal(calls, 0);
  await host.stop();
});
