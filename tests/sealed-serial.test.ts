import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { PassThrough } from 'node:stream';
import { setImmediate as flush } from 'node:timers/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { SealedSerialBackend } from '../electron/sealed-serial.ts';
import { isSerialInput, isSerialOpenRequest, isSerialSessionId } from '../electron/serial.ts';
import { ipcRegistration } from './fixtures/main-source.ts';
import {
  parseVaultSerialRequest,
  normalizeQuickSerial,
  parseVaultSerialBundle,
  type VaultSerialBundle,
  type VaultSerialRequest,
} from '../electron/vault-serial-contract.ts';

const publicKey = Buffer.alloc(32, 1).toString('base64');

class Child extends EventEmitter {
  stdin = new PassThrough();
  stdout = new PassThrough();
  stderr = new PassThrough();
  exitCode: number | null = null;
  signalCode = null;
  written: Buffer[] = [];
  constructor() {
    super();
    this.stdin.on('data', (data) => this.written.push(data));
    this.stdin.on('finish', () => this.kill());
  }
  line(value: unknown): void {
    this.stdout.write(JSON.stringify(value) + '\n');
  }
  kill(): boolean {
    this.exitCode = 0;
    this.emit('close');
    return true;
  }
  get packets(): unknown[] {
    return Buffer.concat(this.written)
      .toString()
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  }
}

class Owner extends EventEmitter {
  sent: unknown[] = [];
  isDestroyed = () => false;
  send(channel: string, value: unknown): void {
    this.sent.push({ channel, value });
  }
}

function bundle(
  request: VaultSerialRequest,
  host = request.quick?.portName ?? 'COM42',
): VaultSerialBundle {
  const { workspaceId, sessionId, nodeId, requestId, epoch } = request;
  return {
    binding: {
      workspaceId,
      sessionId,
      nodeId,
      requestId,
      epoch,
      host,
      protocol: 'serial',
      port: 0,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: publicKey,
      ciphertext: Buffer.alloc(25, 7).toString('base64'),
    },
  };
}

function setup(
  authorize: (q: VaultSerialRequest, current: () => boolean) => Promise<VaultSerialBundle>,
  sharedUse?: ConstructorParameters<typeof SealedSerialBackend>[0]['sharedUse'],
) {
  const workspaceId = randomUUID();
  const owner = new Owner();
  const child = new Child();
  const backend = new SealedSerialBackend({
    executable: () => 'backend',
    workspaceId: () => workspaceId,
    authorize,
    sharedUse,
    spawnChild: ((exe: string, flags: string[]) => {
      assert.equal(exe, 'backend');
      assert.deepEqual(flags, ['--operation', 'serial-sealed']);
      return child;
    }) as any,
  });
  return { backend, child, owner, workspaceId };
}

test('shared serial rechecks live Use grants after notifications received during a check', async () => {
  const nodeId = randomUUID();
  const sessionId = randomUUID();
  let first!: (allowed: boolean[]) => void;
  const pending = new Promise<boolean[]>((resolve) => {
    first = resolve;
  });
  let reads = 0;
  const { backend, child, owner, workspaceId } = setup(async (q) => bundle(q), {
    active: () => true,
    check: async (workspace, nodes) => {
      assert.equal(workspace, workspaceId);
      assert.deepEqual(nodes, [nodeId]);
      return ++reads === 1 ? pending : [false];
    },
  });
  await assert.rejects(
    backend.open(
      owner as any,
      { sessionId, portName: 'COM1', columns: 80, rows: 24 },
      1,
      () => true,
    ),
    /saved shared/,
  );
  const opening = backend.open(
    owner as any,
    { sessionId, nodeId, columns: 80, rows: 24 },
    1,
    () => true,
  );
  child.line({ type: 'recipient', publicKey });
  await flush();
  child.line({
    type: 'connected',
    session_id: sessionId,
    port_name: 'COM42',
    baud_rate: 9600,
    data_bits: 8,
    stop_bits: 1,
    parity: 0,
    flow_control: 0,
  });
  await opening;
  const check = backend.verifySharedUse();
  await flush();
  assert.equal(backend.verifySharedUse(), check);
  first([true]);
  await check;
  await backend.closeAll();
  assert.equal(reads, 2);
  assert.equal(backend.handles(sessionId), false);
  assert.equal(child.exitCode, 0);
  assert.deepEqual(owner.sent.at(-1), {
    channel: 'serial:event',
    value: { type: 'closed', sessionId },
  });
  assert.throws(
    () => backend.command(owner as any, sessionId, { type: 'input', data: 'YQ==' }),
    /owner/,
  );
});

test('shared serial closes when periodic permission verification is unavailable', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let reads = 0;
  const { backend, child, owner } = setup(async (q) => bundle(q), {
    active: () => true,
    check: async () => {
      reads++;
      throw Error('private transport error');
    },
  });
  const sessionId = randomUUID();
  const opening = backend.open(
    owner as any,
    { sessionId, nodeId: randomUUID(), columns: 80, rows: 24 },
    1,
    () => true,
  );
  child.line({ type: 'recipient', publicKey });
  await flush();
  child.line({
    type: 'connected',
    session_id: sessionId,
    port_name: 'COM42',
    baud_rate: 9600,
    data_bits: 8,
    stop_bits: 1,
    parity: 0,
    flow_control: 0,
  });
  await opening;
  t.mock.timers.tick(29_999);
  await flush();
  assert.equal(reads, 0);
  t.mock.timers.tick(1);
  await flush();
  await backend.closeAll();
  assert.equal(reads, 1);
  assert.equal(backend.handles(sessionId), false);
  assert.deepEqual(owner.sent.at(-1), {
    channel: 'serial:event',
    value: { type: 'closed', sessionId },
  });
  t.mock.timers.tick(30_000);
  await flush();
  assert.equal(reads, 1);
});

test('saved serial requests use the native vault target and are owned by one renderer', async () => {
  const requests: VaultSerialRequest[] = [];
  const { backend, child, owner, workspaceId } = setup(async (q, current) => {
    assert.equal(current(), true);
    requests.push(q);
    return bundle(q);
  });
  const sessionId = randomUUID();
  const nodeId = randomUUID();
  const opening = backend.open(
    owner as any,
    { sessionId, nodeId, portName: 'ignored', columns: 82, rows: 26 },
    2,
    () => true,
  );
  await assert.rejects(
    backend.open(owner as any, { sessionId, nodeId, columns: 1, rows: 1 }, 2, () => true),
    /unavailable/,
  );
  assert.equal(child.packets.length, 0);
  child.stdout.write('{"type":"rec');
  child.stdout.write(`ipient","publicKey":"${publicKey}"}\n`);
  await flush();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].workspaceId, workspaceId);
  assert.equal(requests[0].nodeId, nodeId);
  assert.equal(requests[0].publicKey, publicKey);
  assert.equal(requests[0].quick, undefined);
  assert.deepEqual(child.packets, [{ ...bundle(requests[0]), columns: 82, rows: 26 }]);
  backend.command(owner as any, sessionId, { type: 'resize', columns: 120, rows: 30 });
  assert.equal(child.packets.length, 1, 'controls wait for the native connected event');
  const other = new Owner();
  assert.throws(
    () => backend.command(other as any, sessionId, { type: 'input', data: 'YQ==' }),
    /owner/,
  );
  await assert.rejects(backend.close(other as any, sessionId), /owner/);
  child.line({
    type: 'connected',
    session_id: sessionId,
    port_name: 'COM42',
    baud_rate: 9600,
    data_bits: 8,
    stop_bits: 1,
    parity: 0,
    flow_control: 0,
  });
  assert.equal((await opening).portName, 'COM42');
  assert.equal(owner.sent.length, 1);
  assert.equal(other.sent.length, 0);
  backend.command(owner as any, sessionId, { type: 'input', data: 'YQ==' });
  backend.command(owner as any, sessionId, { type: 'resize', columns: 120, rows: 30 });
  backend.requestSnapshots();
  assert.deepEqual(child.packets.slice(1), [
    { type: 'input', data: 'YQ==', session_id: sessionId },
    { type: 'resize', columns: 120, rows: 30, session_id: sessionId },
    { type: 'snapshot', session_id: sessionId },
  ]);
  await backend.closeAll();
  assert.equal(backend.handles(sessionId), false);
  assert.equal(child.exitCode, 0);
  assert.equal(owner.listenerCount('destroyed'), 0);
});

test('serial release validation binds owner, route, epoch and selected Quick port', () => {
  const normalized = normalizeQuickSerial('COM26', {
    baudRate: 115200,
    dataBits: 7,
    stopBits: 2,
    parity: 1,
    flowControl: 3,
  });
  assert.equal(normalized?.settings.dataBits, 7);
  assert.equal(normalizeQuickSerial(' COM1'), undefined);
  assert.equal(normalizeQuickSerial('COM1\x1b'), undefined);
  const coords = {
    workspaceId: randomUUID(),
    nodeId: randomUUID(),
    requestId: randomUUID(),
    sessionId: randomUUID(),
    epoch: 1,
    publicKey,
  };
  assert.equal(parseVaultSerialRequest({ ...coords, epoch: 0 }), undefined);
  assert.equal(parseVaultSerialRequest({ ...coords, publicKey: 'garbage' }), undefined);
  assert.equal(
    parseVaultSerialRequest({
      ...coords,
      quick: { ...normalized, settings: { ...normalized?.settings, flowControl: 4 } },
    }),
    undefined,
  );
  assert.ok(parseVaultSerialRequest(coords));
  const release = bundle(coords);
  for (const binding of [
    { ...release.binding, nodeId: randomUUID() },
    { ...release.binding, epoch: 2 },
    { ...release.binding, port: 23 },
    { ...release.binding, tunnelConfigId: randomUUID() },
    { ...release.binding, useExternalClient: true },
  ]) {
    assert.equal(parseVaultSerialBundle({ ...release, binding }, coords), undefined);
  }
  assert.equal(
    parseVaultSerialBundle(
      { ...release, bundle: { ...release.bundle, ciphertext: publicKey } },
      coords,
    ),
    undefined,
  );
});

test('an admitted serial device emits one terminal close when its worker exits', async () => {
  const { backend, child, owner } = setup(async (q) => bundle(q));
  const sessionId = randomUUID();
  const opening = backend.open(
    owner as any,
    { sessionId, nodeId: randomUUID(), columns: 80, rows: 24 },
    1,
    () => true,
  );
  child.line({ type: 'recipient', publicKey });
  await flush();
  child.line({
    type: 'connected',
    session_id: sessionId,
    port_name: 'COM42',
    baud_rate: 9600,
    data_bits: 8,
    stop_bits: 1,
    parity: 0,
    flow_control: 0,
  });
  await opening;
  child.kill();
  await flush();
  assert.deepEqual(owner.sent.at(-1), {
    channel: 'serial:event',
    value: { type: 'closed', sessionId },
  });
  assert.equal(owner.sent.length, 2);
  assert.equal(backend.handles(sessionId), false);
  await backend.close(owner as any, sessionId);
});

test('Quick serial defaults are authenticated and pending releases cannot survive navigation', async () => {
  for (const mode of ['wrong port', 'navigation', 'foreign event', 'wrong connected port']) {
    let request!: VaultSerialRequest;
    let release!: (value: VaultSerialBundle) => void;
    let accepted!: () => boolean;
    const { backend, child, owner } = setup((q, current) => {
      request = q;
      accepted = current;
      return new Promise((resolve) => {
        release = resolve;
      });
    });
    const sessionId = randomUUID();
    const failure = assert.rejects(
      backend.open(
        owner as any,
        { sessionId, portName: 'COM9', columns: 80, rows: 24 },
        1,
        () => true,
      ),
      /stopped/,
    );
    child.line({ type: 'recipient', publicKey });
    assert.deepEqual(request.quick, {
      portName: 'COM9',
      settings: { baudRate: 9600, dataBits: 8, stopBits: 1, parity: 0, flowControl: 0 },
    });
    assert.ok(parseVaultSerialRequest(request));
    assert.equal(
      parseVaultSerialRequest({ ...request, quick: { ...request.quick, token: 'fixture' } }),
      undefined,
    );
    if (mode === 'navigation') owner.emit('did-start-loading');
    assert.equal(accepted(), mode !== 'navigation');
    release(bundle(request, mode === 'wrong port' ? 'COM8' : 'COM9'));
    await flush();
    if (mode === 'foreign event') child.line({ type: 'closed', session_id: randomUUID() });
    if (mode === 'wrong connected port')
      child.line({
        type: 'connected',
        session_id: sessionId,
        port_name: 'COM8',
        baud_rate: 9600,
        data_bits: 8,
        stop_bits: 1,
        parity: 0,
        flow_control: 0,
      });
    await failure;
    await backend.closeAll();
    assert.equal(
      child.packets.length,
      mode === 'foreign event' || mode === 'wrong connected port' ? 1 : 0,
    );
    assert.equal(owner.sent.length, 0);
    assert.equal(backend.handles(sessionId), false);
  }
});

test('the actual main IPC routes vault serial controls without opening a legacy service', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const channels = ['serial:open', 'serial:input', 'serial:resize', 'serial:close'];
  const handlers = new Map<string, (...args: any[]) => Promise<unknown>>();
  const calls: string[] = [];
  let vault = true;
  let known = false;
  let auth = true;
  const owner = {};
  const register = Object.fromEntries(
    ['open', 'command', 'close'].map((name) => [
      name,
      (...args: unknown[]) => {
        assert.equal(args[0], owner);
        if (name === 'open') {
          assert.equal(args[2], 11);
          assert.equal((args[3] as () => boolean)(), true);
        }
        calls.push(name);
        return name;
      },
    ]),
  );
  runInNewContext(
    stripTypeScriptTypes(channels.map((channel) => ipcRegistration(source, channel)).join('\n')),
    {
      ipcMain: {
        handle: (name: string, callback: (...args: any[]) => Promise<unknown>) =>
          handlers.set(name, callback),
      },
      isSerialInput,
      isSerialOpenRequest,
      isSerialSessionId,
      vaultBackend: {
        get isVaultWorkspace() {
          return vault;
        },
      },
      sealedSerial: { ...register, handles: () => known },
      isTrustedVaultSender: (e: { sender: object }) => e.sender === owner,
      requireNativeResourcesRunning: () => {},
      runAuthorizedOperation: async (run: (epoch: number) => unknown) => run(10),
      isAuthorizationEpochCurrent: (epoch: number) => auth && epoch === 10,
      serializeAuthOperation: async (run: () => unknown) => run(),
      requireWorkspaceAuth: async () => {
        if (!auth) throw Error('locked');
      },
      getSerialBackend: () => ({
        open: () => 'legacy',
        sendInput: () => calls.push('legacy input'),
        resize: () => calls.push('legacy resize'),
        close: () => calls.push('legacy close'),
      }),
      isQuitting: false,
    },
  );
  const id = randomUUID();
  const input = [
    [{ sessionId: id, nodeId: randomUUID(), columns: 80, rows: 24 }],
    [id, 'YQ=='],
    [id, 80, 24],
    [id],
  ];
  for (const [index, channel] of channels.entries()) {
    const handler = handlers.get(channel)!;
    await assert.rejects(handler({ sender: {} }, ...input[index]), /owner/);
    await handler({ sender: owner }, ...input[index]);
  }
  assert.deepEqual(calls, ['open', 'command', 'command', 'close']);
  auth = false;
  await assert.rejects(handlers.get('serial:input')!({ sender: owner }, id, 'YQ=='), /locked/);
  vault = false;
  known = true;
  await handlers.get('serial:close')!({ sender: owner }, id);
  known = false;
  auth = true;
  assert.equal(await handlers.get('serial:open')!({ sender: owner }, ...input[0]), 'legacy');
});
