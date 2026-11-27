import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { SealedVncBackend, parseSealedVncEvent } from '../electron/sealed-vnc.ts';
import { vncBundle, vncRequest, routedVncBundle, routedVncRequest } from './fixtures/vault-vnc.ts';
import type { VaultVncRequest } from '../electron/vault-vnc.ts';
import {
  parseVaultVNCBitwardenPlan,
  resolveVaultVNCBitwarden,
} from '../electron/vault-vnc-bitwarden.ts';
const tick = () => new Promise<void>((r) => setImmediate(r));
const png = () => {
  const p = Buffer.alloc(33);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(p);
  p.writeUInt32BE(13, 8);
  p.write('IHDR', 12);
  p.writeUInt32BE(1, 16);
  p.writeUInt32BE(1, 20);
  return 'data:image/png;base64,' + p.toString('base64');
};
class Child extends EventEmitter {
  exitCode: number | null = null;
  signalCode: string | null = null;
  stdout = new PassThrough();
  stderr = new PassThrough();
  requests: any[] = [];
  exitOnEnd = true;
  kills = 0;
  stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      this.requests.push(JSON.parse(chunk.toString()));
      callback();
    },
  });
  constructor() {
    super();
    this.stdin.on('finish', () => {
      if (this.exitOnEnd) queueMicrotask(() => this.exit());
    });
  }
  exit() {
    if (this.exitCode !== null) return;
    this.exitCode = 0;
    this.emit('close');
  }
  kill() {
    this.kills++;
    this.exit();
    return true;
  }
  line(v: unknown) {
    this.stdout.write(JSON.stringify(v) + '\n');
  }
}
function fixture(
  t: TestContext,
  route?: ConstructorParameters<typeof SealedVncBackend>[0]['route'],
  timeoutMs = 1000,
  manual?: ConstructorParameters<typeof SealedVncBackend>[0]['manual'],
  bitwarden?: ConstructorParameters<typeof SealedVncBackend>[0]['bitwarden'],
) {
  const children: Child[] = [],
    requests: VaultVncRequest[] = [],
    events: any[] = [];
  let allowed = true,
    workspace: string | undefined = randomUUID(),
    bundle = (q: VaultVncRequest) => Promise.resolve(vncBundle(q)),
    onEvent = (_event: any) => {},
    spawnError = false;
  const broker = new SealedVncBackend(
    {
      executable: () => '/native/backend',
      workspaceId: () => workspace,
      authorized: (epoch) => allowed && epoch === 1,
      bundle: (q) => {
        requests.push(q);
        return bundle(q);
      },
      onEvent: (e) => {
        events.push(e);
        onEvent(e);
      },
      route,
      timeoutMs,
      manual,
      bitwarden,
    },
    (exe, args) => {
      assert.equal(exe, '/native/backend');
      assert.deepEqual(args, ['--operation', manual ? 'vnc-manual-sealed' : 'vnc-sealed']);
      if (spawnError) throw Error('private diagnostic');
      const child = new Child();
      children.push(child);
      return child as unknown as ChildProcessWithoutNullStreams;
    },
  );
  t.after(async () => {
    children.forEach((c) => c.exit());
    await broker.closeAll().catch(() => {});
  });
  const open = (owner = () => true, id = randomUUID(), manualPassword?: true) => {
    const request = {
        nodeId: randomUUID(),
        sessionId: id,
        ...(manualPassword ? { manualPassword } : {}),
      },
      result = broker.open(request, 1, owner);
    void result.catch(() => {});
    return { request, result };
  };
  const recipient = (child = children.at(-1)!) =>
    child.line({ type: 'recipient', publicKey: Buffer.alloc(32, 7).toString('base64') });
  const opening = async () => {
    const x = open();
    await tick();
    recipient();
    await tick();
    return { ...x, child: children.at(-1)! };
  };
  const connect = async () => {
    const x = await opening();
    x.child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connecting' });
    x.child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
    await x.result;
    return x;
  };
  return {
    broker,
    children,
    events,
    requests,
    open,
    opening,
    connect,
    recipient,
    setAllowed: (v: boolean) => (allowed = v),
    setWorkspace: (v: string | undefined) => (workspace = v),
    setBundle: (v: typeof bundle) => (bundle = v),
    setOnEvent: (v: typeof onEvent) => (onEvent = v),
    setSpawnError: () => (spawnError = true),
  };
}

test('VNC accepts only a scoped Bitwarden ticket and final bundle', async () => {
  const revision = 'a'.repeat(64);
  const publicKey = Buffer.alloc(32, 11).toString('base64');
  const recipient = { publicKey, revision };
  assert.equal(parseVaultVNCBitwardenPlan(null, vncRequest()), undefined);
  for (const request of [vncRequest(), routedVncRequest()]) {
    const direct = vncBundle(request);
    const routed = 'route' in request ? routedVncBundle(request) : undefined;
    const result = routed ?? direct;
    const binding = { ...direct.binding, tunnelConfigId: routed?.binding.tunnelConfigId ?? '' };
    const release = { binding, ticket: direct.bundle };
    const probe = { required: true as const, revision };
    const selected = { ...probe, release };
    assert.deepEqual(parseVaultVNCBitwardenPlan(probe, request), probe);
    assert.deepEqual(parseVaultVNCBitwardenPlan({ required: false }, request), { required: false });
    assert.equal(parseVaultVNCBitwardenPlan({ required: false }, request, recipient), undefined);
    assert.equal(parseVaultVNCBitwardenPlan({ required: false, extra: 1 }, request), undefined);
    assert.equal(parseVaultVNCBitwardenPlan({ ...probe, revision: 'x' }, request), undefined);
    assert.equal(parseVaultVNCBitwardenPlan(selected, request), undefined);
    assert.equal(
      parseVaultVNCBitwardenPlan(selected, request, { ...recipient, revision: '0'.repeat(64) }),
      undefined,
    );
    for (const bad of [
      null,
      { ...release, password: 'unexpected' },
      { ...release, binding: null },
      { ...release, ticket: null },
      { ...release, ticket: { ...direct.bundle, suiteId: 1 } },
      { ...release, ticket: { ...direct.bundle, formatVersion: 2 } },
      { ...release, ticket: { ...direct.bundle, enc: '' } },
      { ...release, ticket: { ...direct.bundle, ciphertext: 'bad' } },
      { ...release, ticket: { ...direct.bundle, extra: true } },
      { ...release, binding: { ...binding, nodeId: randomUUID() } },
      { ...release, binding: { ...binding, unknown: true } },
    ])
      assert.equal(
        parseVaultVNCBitwardenPlan({ ...probe, release: bad }, request, recipient),
        undefined,
      );
    const accepted = parseVaultVNCBitwardenPlan(selected, request, recipient);
    assert.deepEqual(accepted, selected);
    for (const mode of ['ok', 'local', 'unbound', 'missing-release', 'cancel']) {
      const abort = new AbortController();
      const opening = resolveVaultVNCBitwarden({
        executable: 'native',
        databasePath: 'workspace.db',
        request,
        signal: abort.signal,
        prepare: async (target) => {
          if (!target) {
            if (mode === 'cancel') abort.abort();
            return mode === 'local' ? { required: false } : probe;
          }
          assert.deepEqual(target, recipient);
          return mode === 'missing-release' ? probe : selected;
        },
        exchange: async (options) => {
          assert.equal(options.mode, 'vnc');
          assert.equal(options.otherRecipient, request.publicKey);
          assert.equal(options.parse(result), undefined);
          assert.deepEqual(await options.prepare(publicKey, options.signal), release);
          const final =
            mode === 'unbound'
              ? { ...result, binding: { ...result.binding, host: 'unexpected.example' } }
              : result;
          const checked = options.parse(final);
          if (!checked) throw Error('Unbound result');
          return checked;
        },
      });
      switch (mode) {
        case 'ok':
          assert.deepEqual(await opening, result);
          break;
        case 'local':
          assert.equal(await opening, undefined);
          break;
        default:
          await assert.rejects(opening);
      }
    }
  }
});

test('VNC close cancels and waits for a pending Bitwarden resolution', async (t) => {
  let finish!: () => void;
  let aborted = false;
  const f = fixture(t, undefined, 1000, undefined, async (_request, signal, accepted) => {
    assert.equal(accepted(), true);
    signal.addEventListener(
      'abort',
      () => {
        aborted = true;
      },
      { once: true },
    );
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
    assert.equal(accepted(), false);
    throw Error('Private CLI diagnostic');
  });
  const { child, request, result } = await f.opening();
  assert.equal(f.requests.length, 0);
  let stopped = false;
  const closed = f.broker.close(request.sessionId).then(() => {
    stopped = true;
  });
  assert.equal(aborted, true);
  await tick();
  assert.equal(stopped, false);
  finish();
  await closed;
  await assert.rejects(result, /VNC connection stopped/);
  assert.equal(child.requests.length, 0);
  assert.equal(f.requests.length, 0);
});

test('VNC uses the Bitwarden bundle and falls back only for an ordinary credential', async (t) => {
  let cached = true;
  const f = fixture(t, undefined, 1000, undefined, async (request) =>
    cached ? vncBundle(request) : undefined,
  );
  const protectedSession = await f.opening();
  assert.equal(protectedSession.child.requests.length, 1);
  assert.equal(f.requests.length, 0);
  const rejected = assert.rejects(protectedSession.result);
  await f.broker.close(protectedSession.request.sessionId);
  await rejected;
  cached = false;
  const ordinarySession = await f.connect();
  assert.equal(f.requests.length, 1);
  await f.broker.close(ordinarySession.request.sessionId);
});

test('VNC relay connects one recipient and forwards only validated frames and controls', async (t) => {
  const f = fixture(t),
    x = await f.connect(),
    id = x.request.sessionId;
  assert.equal(f.requests.length, 1);
  assert.equal(f.broker.has(id), true);
  assert.equal(x.child.requests.length, 1);
  assert.deepEqual(x.child.requests[0], vncBundle(f.requests[0]));
  x.child.line({ type: 'vnc.frame', sessionId: id, width: 1, height: 1, image: png() });
  assert.equal(f.events.at(-1).type, 'vnc.frame');
  for (const value of [
    { type: 'pointer', sessionId: id, x: 65535, y: 0, buttons: 255 },
    { type: 'key', sessionId: id, keysym: 0xffffffff, down: false },
  ]) {
    f.broker.send(id, value);
    assert.deepEqual(x.child.requests.at(-1), value);
  }
  for (const value of [
    null,
    { type: 'open', sessionId: id },
    { type: 'key', sessionId: randomUUID(), keysym: 1, down: true },
    { type: 'key', sessionId: id, keysym: 0, down: true },
    { type: 'key', sessionId: id, keysym: 1, down: 1 },
    { type: 'key', sessionId: id, keysym: 1, down: true, password: 'secret' },
    { type: 'pointer', sessionId: id, x: -1, y: 0, buttons: 0 },
    { type: 'pointer', sessionId: id, x: 0, y: 0, buttons: 256 },
  ])
    assert.throws(() => f.broker.send(id, value), /Invalid|unavailable/);
  const close = f.broker.close(id);
  assert.equal(f.broker.close(id), close);
  await close;
  assert.equal(f.broker.has(id), false);
  await f.broker.close(id);
  assert.equal(f.events.at(-1).status, 'disconnected');
});

test('VNC event validation rejects private metadata, wrong identity, malformed PNG and invalid sizes', () => {
  const id = randomUUID(),
    frame = { type: 'vnc.frame', sessionId: id, width: 1, height: 1, image: png() };
  assert.deepEqual(parseSealedVncEvent(frame, id), frame);
  for (const status of ['connecting', 'connected', 'failed', 'disconnected']) {
    const event = { type: 'vnc.status', sessionId: id, status };
    assert.deepEqual(parseSealedVncEvent(event, id), event);
  }
  const failed = {
    type: 'vnc.status',
    sessionId: id,
    status: 'failed',
    message: 'VNC connection failed',
    passwordRequired: true,
  };
  assert.deepEqual(parseSealedVncEvent(failed, id), failed);
  for (const value of [
    null,
    {},
    { ...frame, sessionId: randomUUID() },
    { ...frame, password: 'secret' },
    { ...frame, width: 0 },
    { ...frame, height: 16385 },
    { ...frame, width: 16384, height: 16384 },
    { ...frame, image: 'data:text/html;base64,YQ==' },
    { ...frame, image: 'data:image/png;base64,YQ==' },
    { ...frame, image: png().slice(0, -1) },
    { type: 'vnc.status', sessionId: id, status: 'weird' },
    { ...failed, message: 'private diagnostic' },
    { ...failed, passwordRequired: 'true' },
    { type: 'vnc.status', sessionId: id, status: 'connected', passwordRequired: true },
  ])
    assert.equal(parseSealedVncEvent(value, id), undefined);
  for (const offset of [0, 8, 12, 16, 20]) {
    const bytes = Buffer.from(png().slice(22), 'base64');
    bytes[offset] ^= 255;
    assert.equal(
      parseSealedVncEvent(
        { ...frame, image: 'data:image/png;base64,' + bytes.toString('base64') },
        id,
      ),
      undefined,
    );
  }
});

test('VNC openings reject invalid authority, duplicate IDs, capacity and unavailable owners', async (t) => {
  const f = fixture(t),
    valid = { nodeId: randomUUID(), sessionId: randomUUID() };
  for (const q of [
    { ...valid, nodeId: 'bad' },
    { ...valid, credentialId: 'bad' },
    { ...valid, password: 'secret' },
    null,
  ])
    await assert.rejects(f.broker.open(q as any, 1), /unavailable/);
  for (const epoch of [0, 2, 2 ** 53])
    await assert.rejects(f.broker.open(valid, epoch), /unavailable/);
  await assert.rejects(
    f.broker.open(valid, 1, () => false),
    /unavailable/,
  );
  f.setWorkspace(undefined);
  await assert.rejects(f.broker.open(valid, 1), /unavailable/);
  f.setWorkspace(randomUUID());
  f.open(() => true, valid.sessionId);
  await assert.rejects(f.broker.open(valid, 1), /unavailable/);
  for (let i = 1; i < 32; i++) f.open();
  await assert.rejects(
    f.broker.open({ nodeId: randomUUID(), sessionId: randomUUID() }, 1),
    /unavailable/,
  );
  await f.broker.closeAll();
  assert.equal(f.broker.has(valid.sessionId), false);
});

test('VNC relay cancels stale ownership and late bundles, with no secret-bearing event', async (t) => {
  for (const mode of [
    'owner',
    'workspace',
    'lock',
    'bundle-failure',
    'bundle-invalid',
    'spawn',
  ] as const) {
    const f = fixture(t);
    let owner = true,
      finish!: (v: any) => void;
    f.setBundle(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    if (mode === 'spawn') f.setSpawnError();
    const x = f.open(() => owner);
    await tick();
    if (mode === 'spawn') {
      await assert.rejects(x.result, /stopped/);
      continue;
    }
    f.recipient();
    await tick();
    const child = f.children[0];
    if (mode === 'owner') owner = false;
    if (mode === 'workspace') f.setWorkspace(randomUUID());
    if (mode === 'lock') f.setAllowed(false);
    if (mode === 'bundle-failure') await f.broker.close(x.request.sessionId);
    finish(mode === 'bundle-invalid' ? {} : vncBundle(f.requests[0]));
    await assert.rejects(x.result, /stopped/);
    await tick();
    assert.equal(child.requests.length, 0);
    assert.equal(f.broker.has(x.request.sessionId), false);
  }
});

test('VNC relay rejects replay, early frames, foreign sessions, encoding and oversized output', async (t) => {
  for (const mode of [
    'replay',
    'early',
    'foreign',
    'bad-json',
    'utf8',
    'oversized',
    'bundle-event',
    'error',
    'end',
    'callback',
  ] as const) {
    const f = fixture(t),
      x = await f.opening(),
      id = x.request.sessionId;
    if (mode === 'replay') f.recipient(x.child);
    if (mode === 'early')
      x.child.line({ type: 'vnc.frame', sessionId: id, width: 1, height: 1, image: png() });
    if (mode === 'foreign')
      x.child.line({ type: 'vnc.status', sessionId: randomUUID(), status: 'connected' });
    if (mode === 'bad-json') x.child.stdout.write('{bad}\n');
    if (mode === 'utf8') x.child.stdout.write(Buffer.from([255, 10]));
    if (mode === 'oversized') x.child.stdout.write(Buffer.alloc(32 * 1024 * 1024 + 1, 32));
    if (mode === 'bundle-event') {
      x.child.line({ type: 'vnc.status', sessionId: id, status: 'connected' });
      await x.result;
      x.child.line({ type: 'vnc.status', sessionId: id, status: 'connected' });
    }
    if (mode === 'error') x.child.emit('error', Error('private diagnostic'));
    if (mode === 'end') x.child.stdout.end();
    if (mode === 'callback') {
      f.setOnEvent(() => {
        throw Error('presentation closed');
      });
      x.child.line({ type: 'vnc.status', sessionId: id, status: 'connected' });
    }
    if (mode !== 'bundle-event') await assert.rejects(x.result, /stopped/);
    await tick();
    assert.equal(f.broker.has(id), false);
  }
});

test('VNC relay preserves native authentication failures and retires on remote disconnect', async (t) => {
  for (const status of ['failed', 'disconnected'] as const) {
    const f = fixture(t),
      x = await f.opening();
    x.child.line({
      type: 'vnc.status',
      sessionId: x.request.sessionId,
      status,
      ...(status === 'failed'
        ? { message: 'VNC connection failed', passwordRequired: true }
        : { message: 'VNC connection closed' }),
    });
    await assert.rejects(x.result, /stopped/);
    await tick();
    assert.equal(f.events.length, 1);
    assert.equal(f.events[0].status, status);
  }
});

test('VNC child timeout and stdin failure terminate one session', async (t) => {
  const f = fixture(t, undefined, 10),
    x = f.open();
  await assert.rejects(x.result, /stopped/);
  await tick();
  assert.equal(f.broker.has(x.request.sessionId), false);
  for (const timeoutMs of [0, NaN, 360001])
    assert.throws(
      () =>
        new SealedVncBackend({
          executable: () => '',
          workspaceId: () => '',
          authorized: () => false,
          bundle: async () => {
            throw Error();
          },
          onEvent: () => {},
          timeoutMs,
        }),
      /timeout/,
    );
  const active = fixture(t),
    c = await active.connect();
  c.child.stdin.destroy();
  assert.throws(
    () =>
      active.broker.send(c.request.sessionId, {
        type: 'key',
        sessionId: c.request.sessionId,
        down: true,
        keysym: 1,
      }),
    /unavailable/,
  );
  await tick();
});

test('VNC routes bind the exact lease and release on child close or route failure', async (t) => {
  for (const mode of ['ok', 'substitution', 'lease-invalid', 'inactive', 'closed'] as const) {
    const q = routedVncRequest();
    let released = 0,
      active = true,
      close!: () => void;
    const closed = new Promise<void>((r) => (close = r));
    let planned: any;
    const route = {
      resolve: async ({ credentialOverride, ...context }: any) => {
        assert.equal(credentialOverride, '');
        return (planned = { ...q.route, ...context });
      },
      broker: {
        acquire: async (input: any, epoch: number, owner: () => boolean) => {
          assert.equal(epoch, 1);
          assert.equal(owner(), true);
          return {
            binding: {
              ...planned,
              nodeId: input.nodeId,
              sessionId: input.sessionId,
              ...(mode === 'lease-invalid' ? { protocol: 'ssh' as const } : {}),
            },
            endpoint: q.endpoint,
            get active() {
              return mode === 'inactive' ? false : active && owner();
            },
            closed,
            release: async () => {
              released++;
              active = false;
              close();
            },
          };
        },
        close: async () => {},
      },
      bundle: async (request: any) => {
        const result = routedVncBundle(request);
        if (mode === 'substitution') result.endpoint = '127.0.0.1:2346';
        return result;
      },
    };
    const f = fixture(t, route),
      x = f.open();
    await tick();
    if (mode === 'lease-invalid' || mode === 'inactive') {
      await assert.rejects(x.result, /stopped/);
      assert.equal(released, 1);
      continue;
    }
    f.recipient();
    await tick();
    if (mode === 'substitution') {
      await assert.rejects(x.result, /stopped/);
      await tick();
      assert.equal(released, 1);
      continue;
    }
    const child = f.children[0];
    child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
    await x.result;
    assert.equal(child.requests[0].endpoint, q.endpoint);
    assert.equal(child.requests[0].binding.tunnelConfigId, q.route.tunnelConfigId);
    if (mode === 'closed') {
      active = false;
      close();
      await tick();
    } else await f.broker.close(x.request.sessionId);
    assert.equal(released, 1);
    assert.equal(f.broker.has(x.request.sessionId), false);
  }
});

test('VNC shutdown reserves identity, blocks new opens and tolerates synchronous event reentry', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  let reentered: Promise<void> | undefined;
  f.setOnEvent((e) => {
    if (e.status === 'disconnected') reentered = f.broker.close(e.sessionId);
  });
  const closing = f.broker.closeAll();
  assert.equal(f.broker.closeAll(), closing);
  assert.throws(
    () =>
      f.broker.send(x.request.sessionId, {
        type: 'key',
        sessionId: x.request.sessionId,
        keysym: 1,
        down: true,
      }),
    /unavailable/,
  );
  await assert.rejects(
    f.broker.open({ nodeId: randomUUID(), sessionId: randomUUID() }, 1),
    /unavailable/,
  );
  await closing;
  await reentered;
  assert.equal(f.broker.has(x.request.sessionId), false);
  const next = f.open();
  await f.broker.close(next.request.sessionId);
  await assert.rejects(next.result, /stopped/);
});

test('VNC recipient fragmentation, bundle phase and bounded stdin are enforced', async (t) => {
  for (const mode of [
    'fragment',
    'early',
    'greeting-limit',
    'chunks',
    'write-limit',
    'write-error',
  ] as const) {
    const f = fixture(t),
      x = f.open();
    await tick();
    const child = f.children[0];
    if (mode === 'greeting-limit') {
      child.stdout.write('x'.repeat(1025));
      await assert.rejects(x.result, /stopped/);
      continue;
    }
    if (mode === 'early') {
      f.setBundle(() => new Promise(() => {}));
      f.recipient(child);
      await tick();
      child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
      await assert.rejects(x.result, /stopped/);
      continue;
    }
    const greeting =
      JSON.stringify({ type: 'recipient', publicKey: Buffer.alloc(32, 7).toString('base64') }) +
      '\r\n';
    child.stdout.write(greeting.slice(0, 5));
    child.stdout.write(greeting.slice(5));
    await tick();
    child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
    await x.result;
    if (mode === 'chunks') {
      for (let i = 0; i < 4097; i++) child.stdout.write(' ');
      await tick();
      assert.equal(f.broker.has(x.request.sessionId), false);
      continue;
    }
    if (mode === 'write-limit')
      Object.defineProperty(child.stdin, 'writableLength', { value: 4096 });
    if (mode === 'write-error')
      child.stdin.write = (() => {
        throw Error('private diagnostic');
      }) as any;
    if (mode.startsWith('write')) {
      assert.throws(
        () =>
          f.broker.send(x.request.sessionId, {
            type: 'key',
            sessionId: x.request.sessionId,
            keysym: 1,
            down: true,
          }),
        /unavailable/,
      );
      await tick();
      assert.equal(f.broker.has(x.request.sessionId), false);
    }
  }
});

test('VNC cancelled route acquisition releases a late lease and never starts its recipient', async (t) => {
  const q = routedVncRequest();
  let planned: any,
    finish!: (value: any) => void,
    released = 0,
    cancelled = 0;
  const route = {
    resolve: async ({ credentialOverride, ...context }: any) => {
      assert.equal(credentialOverride, '');
      return (planned = { ...q.route, ...context });
    },
    broker: {
      acquire: async () => new Promise<any>((resolve) => (finish = resolve)),
      close: async () => {
        cancelled++;
      },
    },
    bundle: async (value: any) => routedVncBundle(value),
  };
  const f = fixture(t, route),
    x = f.open();
  await tick();
  await f.broker.close(x.request.sessionId);
  await assert.rejects(x.result, /stopped/);
  assert.equal(cancelled, 1);
  finish({
    binding: planned,
    endpoint: q.endpoint,
    active: true,
    closed: new Promise(() => {}),
    release: async () => {
      released++;
    },
  });
  await tick();
  assert.equal(released, 1);
  assert.equal(f.children.length, 0);
});

test('VNC route failures retain unconfirmed identities and cannot silently permit a replacement', async (t) => {
  const q = routedVncRequest();
  let planned: any,
    releaseFails = true,
    releases = 0;
  const route = {
    resolve: async ({ credentialOverride, ...context }: any) => {
      assert.equal(credentialOverride, '');
      return (planned = { ...q.route, ...context });
    },
    broker: {
      acquire: async () => ({
        binding: planned,
        endpoint: q.endpoint,
        active: true,
        closed: new Promise<void>(() => {}),
        release: async () => {
          releases++;
          if (releaseFails) throw Error('private route shutdown failure');
        },
      }),
      close: async () => {},
    },
    bundle: async (value: any) => routedVncBundle(value),
  };
  const f = fixture(t, route),
    x = f.open();
  await tick();
  f.recipient();
  await tick();
  const child = f.children[0];
  child.line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
  await x.result;
  await assert.rejects(f.broker.close(x.request.sessionId), /could not be confirmed/);
  assert.equal(f.broker.has(x.request.sessionId), true);
  await assert.rejects(f.broker.open(x.request, 1), /unavailable/);
  await assert.rejects(f.broker.closeAll(), /could not be confirmed/);
  await assert.rejects(
    f.broker.open({ nodeId: randomUUID(), sessionId: randomUUID() }, 1),
    /unavailable/,
  );
  releaseFails = false;
  const retry = f.broker.closeAll();
  assert.equal(f.broker.closeAll(), retry);
  await retry;
  assert.equal(releases, 3);
  assert.equal(f.broker.has(x.request.sessionId), false);
  const replacement = await f.connect();
  await f.broker.close(replacement.request.sessionId);
});

test('VNC forced shutdown handles a child that cannot finish after EOF', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  x.child.exitOnEnd = false;
  await f.broker.close(x.request.sessionId);
  assert.equal(x.child.kills, 1);
  assert.equal(f.broker.has(x.request.sessionId), false);
});

test('temporary VNC relay binds prompt to native context and never asks for a saved password', async (t) => {
  for (const routed of [false, true]) {
    let direct = 0,
      prompts = 0,
      sealed = 0,
      released = 0,
      planned: any;
    const routeTemplate = routedVncRequest();
    const route = routed
      ? {
          resolve: async ({ credentialOverride, ...context }: any) => {
            assert.equal(credentialOverride, '');
            return (planned = { ...routeTemplate.route, ...context });
          },
          broker: {
            acquire: async () => ({
              binding: planned,
              endpoint: routeTemplate.endpoint,
              active: true,
              closed: new Promise<void>(() => {}),
              release: async () => {
                released++;
              },
            }),
            close: async () => {},
          },
          bundle: async () => {
            throw Error('saved routed password must not be read');
          },
        }
      : undefined;
    const f = fixture(t, route, 1000, {
      plan: async (q) => {
        direct++;
        return vncBundle({ ...q, publicKey: '' }).binding;
      },
      prompt: async (context, active, signal) => {
        prompts++;
        assert.equal(active(), true);
        assert.equal(signal.aborted, false);
        assert.equal(context.endpoint, routed ? routeTemplate.endpoint : undefined);
        return vncBundle({
          ...context.binding,
          credentialOverride: '',
          publicKey: context.publicKey,
        }).bundle;
      },
      bundle: async (q) => {
        sealed++;
        return {
          binding: q.context.binding,
          bundle: { ...q.manual, ciphertext: Buffer.alloc(16459).toString('base64') },
          ...(q.context.endpoint ? { endpoint: q.context.endpoint } : {}),
        } as any;
      },
    });
    f.setBundle(async () => {
      throw Error('saved password must not be read');
    });
    const x = f.open(() => true, randomUUID(), true);
    await tick();
    f.recipient();
    await tick();
    assert.equal(direct, routed ? 0 : 1);
    assert.equal(prompts, 1);
    assert.equal(sealed, 1);
    assert.equal(f.requests.length, 0);
    assert.equal(f.children[0].requests.length, 1);
    f.children[0].line({ type: 'vnc.status', sessionId: x.request.sessionId, status: 'connected' });
    await x.result;
    await f.broker.close(x.request.sessionId);
    assert.equal(released, routed ? 1 : 0);
  }
});
test('temporary VNC relay cancels pending password entry and discards late crypto or authorization', async (t) => {
  for (const mode of [
    'prompt',
    'bad-plan',
    'bad-envelope',
    'bad-bundle',
    'late-bundle',
    'lock',
    'owner',
    'timeout',
    'route-loss',
  ]) {
    let release!: (value: any) => void,
      signal: AbortSignal | undefined,
      active: (() => boolean) | undefined,
      calls = 0,
      planned: any,
      closed!: () => void;
    const route =
      mode === 'route-loss'
        ? {
            resolve: async ({ credentialOverride, ...context }: any) => {
              assert.equal(credentialOverride, '');
              return (planned = { ...routedVncRequest().route, ...context });
            },
            broker: {
              acquire: async () => ({
                binding: planned,
                endpoint: '127.0.0.1:2345',
                active: true,
                closed: new Promise<void>((r) => (closed = r)),
                release: async () => {},
              }),
              close: async () => {},
            },
            bundle: async () => {
              throw Error('no saved flow');
            },
          }
        : undefined;
    let owner = true;
    const f = fixture(t, route, mode === 'timeout' ? 20 : 1000, {
      plan: async (q) =>
        mode === 'bad-plan'
          ? { ...vncBundle({ ...q, publicKey: '' }).binding, nodeId: randomUUID() }
          : vncBundle({ ...q, publicKey: '' }).binding,
      prompt: async (context, current, abort) => {
        signal = abort;
        active = current;
        if (mode === 'bad-envelope') return {} as any;
        if (mode === 'bad-bundle' || mode === 'late-bundle')
          return vncBundle({
            ...context.binding,
            credentialOverride: '',
            publicKey: context.publicKey,
          }).bundle;
        return new Promise((r) => (release = r));
      },
      bundle: async () => {
        calls++;
        if (mode === 'late-bundle') return new Promise((r) => (release = r));
        return {} as any;
      },
    });
    const x = f.open(() => owner, randomUUID(), true);
    await tick();
    f.recipient();
    await tick();
    if (mode === 'lock') f.setAllowed(false);
    if (mode === 'owner') owner = false;
    if (mode === 'route-loss') closed();
    else if (!['bad-plan', 'bad-envelope', 'bad-bundle', 'timeout'].includes(mode))
      await f.broker.close(x.request.sessionId);
    if (['lock', 'owner'].includes(mode)) assert.equal(active?.(), false);
    await assert.rejects(x.result, /stopped/);
    await tick();
    if (signal) assert.equal(signal.aborted, true);
    if (release) {
      release({});
      await tick();
    }
    assert.equal(f.children[0].requests.length, 0);
    assert.equal(calls, ['bad-bundle', 'late-bundle'].includes(mode) ? 1 : 0);
    assert.equal(f.broker.has(x.request.sessionId), false);
  }
  const f = fixture(t);
  await assert.rejects(
    f.broker.open({ sessionId: randomUUID(), nodeId: randomUUID(), manualPassword: true }, 1),
    /unavailable/,
  );
});
