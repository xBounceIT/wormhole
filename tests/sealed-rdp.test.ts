import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { SealedRdpBackend } from '../electron/sealed-rdp.ts';
import { rdpBundle, rdpRequest, routedRdpBundle, routedRdpRequest } from './fixtures/vault-rdp.ts';
import type { VaultRdpRequest } from '../electron/vault-rdp.ts';
import {
  parseVaultRDPBitwardenPlan,
  parseVaultRDPBitwardenBundle,
  resolveVaultRDPBitwarden,
} from '../electron/vault-rdp-bitwarden.ts';
const tick = () => new Promise<void>((r) => setImmediate(r));
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
  route?: ConstructorParameters<typeof SealedRdpBackend>[0]['route'],
  timeoutMs = 1000,
  manual?: ConstructorParameters<typeof SealedRdpBackend>[0]['manual'],
  bitwarden?: ConstructorParameters<typeof SealedRdpBackend>[0]['bitwarden'],
) {
  const children: Child[] = [],
    requests: VaultRdpRequest[] = [],
    events: any[] = [];
  let allowed = true,
    workspace: string | undefined = randomUUID(),
    spawnError = false,
    bundle = (q: VaultRdpRequest) => Promise.resolve(rdpBundle(q)),
    onEvent = (_event: any) => {};
  const backend = new SealedRdpBackend(
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
      manual,
      bitwarden,
      timeoutMs,
    },
    (exe, args) => {
      assert.equal(exe, '/native/backend');
      assert.deepEqual(args, ['--operation', manual ? 'rdp-manual-sealed' : 'rdp-sealed']);
      if (spawnError) throw Error('private diagnostic');
      const child = new Child();
      children.push(child);
      return child as unknown as ChildProcessWithoutNullStreams;
    },
  );
  t.after(async () => {
    children.forEach((c) => c.exit());
    await backend.closeAll().catch(() => {});
  });
  const open = (owner = () => true, id = randomUUID(), manualCredentials?: true) => {
    const request = {
        sessionId: id,
        nodeId: randomUUID(),
        ownerWindow: '123',
        ...(manualCredentials ? { manualCredentials } : {}),
        bounds: { x: 0, y: -1, width: 800, height: 600 },
      },
      result = backend.open(request, 1, owner);
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
  const event = (child: Child, type: string, extra = {}) => {
    const id = child.requests[0].binding.sessionId;
    child.line({
      type,
      sessionId: id,
      lifecycleId: id,
      external: false,
      backend: 'activex',
      ...extra,
    });
  };
  const connect = async () => {
    const x = await opening();
    event(x.child, 'ready', { requestId: x.child.requests[0].binding.requestId });
    await x.result;
    return x;
  };
  return {
    backend,
    children,
    requests,
    events,
    open,
    opening,
    connect,
    recipient,
    event,
    setAllowed: (v: boolean) => (allowed = v),
    setWorkspace: (v: string | undefined) => (workspace = v),
    setBundle: (v: typeof bundle) => (bundle = v),
    setEvent: (v: typeof onEvent) => (onEvent = v),
    setSpawnError: () => (spawnError = true),
  };
}

test('RDP Bitwarden releases require a target base, a separate ticket, and one sealed accounts reply', async () => {
  const revision = 'c'.repeat(64);
  const publicKey = Buffer.alloc(32, 8).toString('base64');
  const recipient = { revision, publicKey };
  const probe = { required: true as const, revision };
  const template = (q: VaultRdpRequest) => ({
    ...rdpBundle(q).bundle,
    ciphertext: Buffer.alloc(76, 1).toString('base64'),
  });
  assert.equal(parseVaultRDPBitwardenPlan(null, rdpRequest()), undefined);
  for (const q of [rdpRequest(), routedRdpRequest()]) {
    const direct = rdpBundle(q);
    const route = 'route' in q ? routedRdpBundle(q) : undefined;
    const rdpBase = template(q);
    const base = { ...(route ?? direct), bundle: rdpBase };
    const binding = { ...direct.binding, tunnelConfigId: route?.binding.tunnelConfigId ?? '' };
    const release = { binding, ticket: direct.bundle };
    const final = { ...base, bitwarden: direct.bundle };
    const prepared = { ...probe, release, rdpBase };
    assert.deepEqual(parseVaultRDPBitwardenPlan(probe, q), probe);
    assert.deepEqual(parseVaultRDPBitwardenPlan({ required: false }, q), { required: false });
    assert.equal(parseVaultRDPBitwardenPlan({ required: false }, q, recipient), undefined);
    assert.equal(parseVaultRDPBitwardenPlan(prepared, q), undefined);
    assert.equal(
      parseVaultRDPBitwardenPlan(prepared, q, { ...recipient, revision: 'b'.repeat(64) }),
      undefined,
    );
    assert.equal(
      parseVaultRDPBitwardenPlan({ ...prepared, required: 'true' }, q, recipient),
      undefined,
    );
    const validated = parseVaultRDPBitwardenPlan(prepared, q, recipient);
    assert.deepEqual(validated, { ...probe, release: { ticket: release, base } });
    for (const bad of [
      { ...prepared, release: null },
      { ...prepared, release: { ...release, unknown: true } },
      { ...prepared, release: { ...release, binding: null } },
      { ...prepared, release: { ...release, binding: { ...binding, nodeId: randomUUID() } } },
      { ...prepared, release: { ...release, binding: { ...binding, password: '' } } },
      { ...prepared, release: { ...release, ticket: { ...direct.bundle, unknown: true } } },
      { ...prepared, release: { ...release, ticket: { ...direct.bundle, formatVersion: 0 } } },
      { ...prepared, release: { ...release, ticket: { ...direct.bundle, suiteId: 7 } } },
      { ...prepared, release: { ...release, ticket: { ...direct.bundle, enc: 'wrong' } } },
      { ...prepared, rdpBase: { ...rdpBase, ciphertext: '' } },
      { ...prepared, rdpBase: direct.bundle },
    ])
      assert.equal(parseVaultRDPBitwardenPlan(bad, q, recipient), undefined);
    assert.deepEqual(parseVaultRDPBitwardenBundle(final, q), final);
    for (const bad of [
      null,
      base,
      { ...final, password: 'unexpected' },
      {
        ...final,
        bitwarden: { ...direct.bundle, ciphertext: Buffer.alloc(32).toString('base64') },
      },
      {
        ...final,
        bitwarden: { ...direct.bundle, ciphertext: Buffer.alloc(37 * 1024).toString('base64') },
      },
    ])
      assert.equal(parseVaultRDPBitwardenBundle(bad, q), undefined);
    for (const mode of ['ready', 'ordinary', 'cancel', 'missing-release', 'foreign-reply']) {
      const abort = new AbortController();
      const result = resolveVaultRDPBitwarden({
        executable: 'backend',
        databasePath: 'workspace.db',
        request: q,
        signal: abort.signal,
        prepare: async (received) => {
          if (!received) {
            if (mode === 'cancel') abort.abort();
            return mode === 'ordinary' ? { required: false } : probe;
          }
          assert.deepEqual(received, recipient);
          return mode === 'missing-release' ? probe : validated!;
        },
        exchange: async (request) => {
          assert.equal(request.mode, 'rdp');
          assert.equal(request.otherRecipient, q.publicKey);
          assert.equal(request.parse(direct.bundle), undefined);
          assert.deepEqual(await request.prepare(publicKey, request.signal), release);
          const output = request.parse(
            mode === 'foreign-reply' ? { ...direct.bundle, password: '' } : direct.bundle,
          );
          if (!output) throw Error('Invalid accounts reply.');
          return output;
        },
      });
      if (mode === 'ready') assert.deepEqual(await result, final);
      else if (mode === 'ordinary') assert.equal(await result, undefined);
      else await assert.rejects(result);
    }
  }
});

test('RDP forwards both protected frames and retains cancellation until the CLI has exited', async (t) => {
  let pending = false,
    aborted = false,
    finish!: () => void;
  const f = fixture(t, undefined, 1000, undefined, async (request, signal, accepted) => {
    if (pending) {
      assert.equal(accepted(), true);
      signal.addEventListener('abort', () => {
        aborted = true;
      });
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
      assert.equal(accepted(), false);
      throw Error('private reason');
    }
    const clear = rdpBundle(request);
    return {
      ...clear,
      bundle: { ...clear.bundle, ciphertext: Buffer.alloc(76, 5).toString('base64') },
      bitwarden: { ...clear.bundle, enc: Buffer.alloc(32, 11).toString('base64') },
    };
  });
  const connected = await f.connect();
  assert.equal(f.requests.length, 0);
  assert.ok(connected.child.requests[0].bitwarden);
  assert.notEqual(
    connected.child.requests[0].bitwarden.enc,
    connected.child.requests[0].bundle.enc,
  );
  await f.backend.close(connected.request.sessionId);
  pending = true;
  const opening = await f.opening();
  let stopped = false;
  const closed = f.backend.close(opening.request.sessionId).then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(aborted, true);
  assert.equal(stopped, false);
  finish();
  await closed;
  await assert.rejects(opening.result, /RDP connection stopped/);
  assert.equal(opening.child.requests.length, 0);
  assert.equal(f.requests.length, 0);
});

test('sealed RDP snapshots the surface and relays only a sealed native opening and public events', async (t) => {
  const f = fixture(t),
    x = f.open();
  x.request.bounds.width = 1;
  await tick();
  f.recipient();
  await tick();
  const child = f.children[0],
    frame = child.requests[0];
  assert.equal(frame.ownerWindow, '123');
  assert.equal(frame.requireContentProtection, undefined);
  assert.equal(frame.bounds.width, 800);
  assert.equal(frame.binding.nodeId, x.request.nodeId);
  assert.equal(frame.binding.protocol, 'rdp');
  assert.equal(frame.binding.epoch, 1);
  assert.equal(frame.bundle.ciphertext, rdpBundle(f.requests[0]).bundle.ciphertext);
  assert.equal(f.events.length, 0);
  f.event(child, 'ready', { requestId: frame.binding.requestId });
  await x.result;
  f.event(child, 'connected');
  assert.deepEqual(
    f.events.map((e) => e.type),
    ['ready', 'connected'],
  );
  assert.equal(JSON.stringify(f.events).includes('publicKey'), false);
  await f.backend.close(x.request.sessionId);
  assert.equal(f.backend.has(x.request.sessionId), false);
  assert.equal(f.events.at(-1).type, 'exited');
  await f.backend.close(randomUUID());
});

test('sealed RDP correlates acknowledgements, preserves certificate choices and drains pending controls', async (t) => {
  const f = fixture(t),
    x = await f.connect(),
    id = x.request.sessionId;
  const controls = [
    { op: 'resize', bounds: x.request.bounds },
    { op: 'show', bounds: x.request.bounds },
    { op: 'hide' },
    { op: 'focus' },
    { op: 'certificate', certificateAccepted: false },
    { op: 'input', input: { kind: 'release' } },
  ];
  for (const control of controls) {
    const response = f.backend.command(id, control as any),
      wire = x.child.requests.at(-1);
    assert.deepEqual(wire, { ...control, sessionId: id, requestId: wire.requestId });
    f.event(x.child, 'ack', { requestId: wire.requestId });
    assert.equal((await response).requestId, wire.requestId);
  }
  const failed = f.backend.command(id, { op: 'focus' });
  f.event(x.child, 'error', { requestId: x.child.requests.at(-1).requestId, message: 'private' });
  await assert.rejects(failed, /operation failed/);
  assert.equal(f.backend.has(id), true);
  const pending = f.backend.command(id, { op: 'hide' });
  void pending.catch(() => {});
  await f.backend.close(id);
  await assert.rejects(pending, /stopped/);
  await assert.rejects(f.backend.command(id, { op: 'focus' }), /unavailable/);
});

test('sealed RDP rejects malformed admission and bounds concurrent native sessions', async (t) => {
  const f = fixture(t),
    sample = f.open();
  for (const patch of [
    { sessionId: '' },
    { nodeId: '' },
    { password: 'secret' },
    { ownerWindow: '0' },
    { bounds: {} },
  ])
    await assert.rejects(f.backend.open({ ...sample.request, ...patch } as any, 1), /unavailable/);
  await assert.rejects(f.backend.open(sample.request, 0), /unavailable/);
  await assert.rejects(f.backend.open(sample.request, NaN), /unavailable/);
  await assert.rejects(f.backend.open(sample.request, 1), /unavailable/);
  f.setAllowed(false);
  await assert.rejects(f.open().result);
  f.setAllowed(true);
  f.setWorkspace(undefined);
  await assert.rejects(f.open().result);
  f.setWorkspace(randomUUID());
  await assert.rejects(f.open(() => false).result);
  await f.backend.closeAll();
  const admitted = Array.from({ length: 32 }, () => f.open());
  await assert.rejects(f.open().result, /unavailable/);
  await f.backend.closeAll();
  await Promise.all(admitted.map((x) => assert.rejects(x.result)));
  for (const timeoutMs of [0, -1, NaN, 360001])
    assert.throws(
      () =>
        new SealedRdpBackend({
          executable: () => '',
          workspaceId: () => '',
          authorized: () => true,
          bundle: async () => ({}) as any,
          onEvent: () => {},
          timeoutMs,
        }),
      /timeout/,
    );
});

test('sealed RDP cancellation fences delayed ciphertext and recipient replay', async (t) => {
  const f = fixture(t);
  let finish!: (value: any) => void;
  f.setBundle(() => new Promise((r) => (finish = r)));
  const x = f.open();
  await tick();
  f.recipient();
  await tick();
  await f.backend.close(x.request.sessionId);
  finish(rdpBundle(f.requests[0]));
  await tick();
  assert.equal(f.children[0].requests.length, 0);
  await assert.rejects(x.result);
  const g = fixture(t),
    y = g.open();
  await tick();
  g.recipient();
  g.recipient();
  await tick();
  await assert.rejects(y.result);
  assert.equal(g.children[0].requests.length, 0);
});

test('sealed RDP fails closed on native corruption, stdout loss, stale owners and callbacks', async (t) => {
  for (const scenario of [
    'recipient',
    'extra',
    'unknownAck',
    'crossSession',
    'utf8',
    'oversize',
    'end',
    'exit',
    'error',
    'stdin',
    'stderr',
    'stale',
    'workspace',
    'callback',
    'early',
  ]) {
    await t.test(scenario, async (t) => {
      const f = fixture(t);
      if (scenario === 'recipient' || scenario === 'early') {
        const x = f.open();
        await tick();
        f.children[0].line(
          scenario === 'recipient' ? { type: 'recipient', publicKey: 'bad' } : { type: 'ready' },
        );
        await assert.rejects(x.result);
        return;
      }
      const x = await f.connect();
      switch (scenario) {
        case 'extra':
          f.event(x.child, 'connected', { password: 'injected' });
          break;
        case 'unknownAck':
          f.event(x.child, 'ack', { requestId: randomUUID() });
          break;
        case 'crossSession':
          f.event(x.child, 'connected', { sessionId: randomUUID() });
          break;
        case 'utf8':
          x.child.stdout.write(Buffer.from([0xff, 10]));
          break;
        case 'oversize':
          x.child.stdout.write(Buffer.alloc(256 * 1024 + 1));
          break;
        case 'end':
          x.child.stdout.end();
          break;
        case 'exit':
          x.child.exit();
          break;
        case 'error':
          x.child.emit('error', Error('private'));
          break;
        case 'stdin':
          x.child.stdin.emit('error', Error('private'));
          break;
        case 'stderr':
          x.child.stderr.emit('error', Error('private'));
          break;
        case 'stale':
          f.setAllowed(false);
          f.event(x.child, 'connected');
          break;
        case 'workspace':
          f.setWorkspace(randomUUID());
          f.event(x.child, 'connected');
          break;
        case 'callback':
          f.setEvent(() => {
            throw Error('owner gone');
          });
          f.event(x.child, 'connected');
          break;
      }
      await tick();
      await f.backend.closeAll();
      assert.equal(f.backend.has(x.request.sessionId), false);
      assert.equal(JSON.stringify(f.events).includes('injected'), false);
    });
  }
});

test('sealed RDP handles fragmented output, terminal events, malformed bundles and startup timeouts', async (t) => {
  const f = fixture(t),
    x = f.open();
  await tick();
  const encoded =
    JSON.stringify({ type: 'recipient', publicKey: Buffer.alloc(32, 7).toString('base64') }) +
    '\r\n';
  for (const byte of Buffer.from(encoded)) f.children[0].stdout.write(Buffer.from([byte]));
  await tick();
  f.event(f.children[0], 'started', { requestId: f.children[0].requests[0].binding.requestId });
  await x.result;
  f.event(f.children[0], 'fatalError', { message: 'private' });
  await tick();
  assert.equal(f.events.at(-1).type, 'fatalError');
  assert.equal(f.events.at(-1).message, 'RDP connection failed');
  const g = fixture(t);
  g.setBundle(async (q) => ({ ...rdpBundle(q), password: 'secret' }));
  const bad = g.open();
  await tick();
  g.recipient();
  await assert.rejects(bad.result);
  const h = fixture(t);
  h.setSpawnError();
  await assert.rejects(h.open().result);
  const timeout = fixture(t, undefined, 10);
  await assert.rejects(timeout.open().result);
});

function routeFixture() {
  const template = routedRdpRequest();
  let active = true,
    releases = 0,
    closes = 0,
    failRelease = false;
  let lost!: () => void;
  const closed = new Promise<void>((r) => (lost = r));
  const binding = (q: any) => {
    const { credentialOverride: _, ...context } = q;
    return { ...template.route, ...context, requestId: template.route.requestId };
  };
  let selected: any;
  const route = {
    resolve: async (q: any) => {
      selected = binding(q);
      return { ...selected, requestId: q.requestId };
    },
    broker: {
      acquire: async () => ({
        binding: selected,
        endpoint: template.endpoint,
        get active() {
          return active;
        },
        closed,
        release: async () => {
          releases++;
          if (failRelease) throw Error('release failed');
          active = false;
        },
      }),
      close: async () => {
        closes++;
      },
    },
    bundle: async (q: any) => routedRdpBundle(q),
  };
  return {
    route,
    lose: () => {
      active = false;
      lost();
    },
    releases: () => releases,
    closes: () => closes,
    failRelease: (v: boolean) => (failRelease = v),
  };
}

test('sealed RDP rejects a changed protocol or inactive lease before launching a client', async (t) => {
  for (const mode of ['wrong-plan', 'wrong-lease', 'inactive', 'direct']) {
    const r = routeFixture(),
      original = r.route.broker.acquire;
    if (mode === 'wrong-plan') {
      const resolve = r.route.resolve;
      r.route.resolve = async (q) => ({ ...(await resolve(q)), protocol: 'ssh' });
    }
    if (mode === 'wrong-lease' || mode === 'inactive') {
      r.route.broker.acquire = async () => {
        const lease = await original();
        return {
          ...lease,
          binding: { ...lease.binding, ...(mode === 'wrong-lease' ? { protocol: 'ssh' } : {}) },
          active: mode !== 'inactive',
        };
      };
    }
    if (mode === 'direct') r.route.resolve = async () => null as any;
    const f = fixture(t, r.route);
    const opening = f.open();
    if (mode === 'direct') {
      await tick();
      f.recipient();
      await tick();
      const child = f.children[0];
      f.event(child, 'ready', { requestId: child.requests[0].binding.requestId });
      await opening.result;
      assert.equal(child.requests[0].endpoint, undefined);
      assert.equal(r.releases(), 0);
    } else {
      await assert.rejects(opening.result);
      await tick();
      assert.equal(f.children.length, 0);
      assert.equal(r.releases(), mode === 'wrong-plan' ? 0 : 1);
    }
  }
});

test('sealed RDP startup callbacks cannot revive cancelled owners and control queues are bounded', async (t) => {
  const f = fixture(t),
    x = await f.opening();
  f.setEvent(() => f.setAllowed(false));
  f.event(x.child, 'ready', { requestId: x.child.requests[0].binding.requestId });
  await assert.rejects(x.result);
  await tick();
  assert.equal(f.backend.has(x.request.sessionId), false);
  const g = fixture(t),
    y = await g.connect();
  const pending = Array.from({ length: 128 }, () => {
    const task = g.backend.command(y.request.sessionId, { op: 'focus' });
    void task.catch(() => {});
    return task;
  });
  await assert.rejects(g.backend.command(y.request.sessionId, { op: 'focus' }));
  await g.backend.close(y.request.sessionId);
  await Promise.all(pending.map((task) => assert.rejects(task)));
});

test('sealed RDP rejects a changed protocol or inactive lease before launching a client', async (t) => {
  for (const mode of ['wrong-plan', 'wrong-lease', 'inactive', 'direct']) {
    const r = routeFixture(),
      original = r.route.broker.acquire;
    if (mode === 'wrong-plan') {
      const resolve = r.route.resolve;
      r.route.resolve = async (q) => ({ ...(await resolve(q)), protocol: 'ssh' });
    }
    if (mode === 'wrong-lease' || mode === 'inactive') {
      r.route.broker.acquire = async () => {
        const lease = await original();
        return {
          ...lease,
          binding: { ...lease.binding, ...(mode === 'wrong-lease' ? { protocol: 'ssh' } : {}) },
          active: mode !== 'inactive',
        };
      };
    }
    if (mode === 'direct') r.route.resolve = async () => null as any;
    const f = fixture(t, r.route);
    const opening = f.open();
    if (mode === 'direct') {
      await tick();
      f.recipient();
      await tick();
      const child = f.children[0];
      f.event(child, 'ready', { requestId: child.requests[0].binding.requestId });
      await opening.result;
      assert.equal(child.requests[0].endpoint, undefined);
      assert.equal(r.releases(), 0);
    } else {
      await assert.rejects(opening.result);
      await tick();
      assert.equal(f.children.length, 0);
      assert.equal(r.releases(), mode === 'wrong-plan' ? 0 : 1);
    }
  }
});

test('sealed RDP startup callbacks cannot revive cancelled owners and control queues are bounded', async (t) => {
  const f = fixture(t),
    x = await f.opening();
  f.setEvent(() => f.setAllowed(false));
  f.event(x.child, 'ready', { requestId: x.child.requests[0].binding.requestId });
  await assert.rejects(x.result);
  await tick();
  assert.equal(f.backend.has(x.request.sessionId), false);
  const g = fixture(t),
    y = await g.connect();
  const pending = Array.from({ length: 128 }, () => {
    const task = g.backend.command(y.request.sessionId, { op: 'focus' });
    void task.catch(() => {});
    return task;
  });
  await assert.rejects(g.backend.command(y.request.sessionId, { op: 'focus' }));
  await g.backend.close(y.request.sessionId);
  await Promise.all(pending.map((task) => assert.rejects(task)));
});

test('sealed RDP owns its tunnel lease, binds its exact revision and stops after route loss', async (t) => {
  const r = routeFixture(),
    f = fixture(t, r.route),
    x = await f.connect();
  assert.equal(x.child.requests[0].endpoint, '127.0.0.1:2345');
  assert.notEqual(x.child.requests[0].binding.tunnelConfigId, '');
  assert.equal(f.requests.length, 0);
  r.lose();
  await tick();
  await f.backend.closeAll();
  assert.equal(r.releases(), 1);
  assert.equal(f.backend.has(x.request.sessionId), false);
});

test('sealed RDP retains admission barriers until an unconfirmed route shutdown is retried', async (t) => {
  const r = routeFixture(),
    f = fixture(t, r.route),
    x = await f.connect();
  r.failRelease(true);
  await assert.rejects(f.backend.closeAll(), /shutdown/);
  assert.equal(f.backend.has(x.request.sessionId), true);
  await assert.rejects(f.open().result, /unavailable/);
  r.failRelease(false);
  await f.backend.closeAll();
  assert.equal(f.backend.has(x.request.sessionId), false);
  assert.equal(r.releases(), 2);
});

test('RDP keeps startup geometry and hidden intent while the recipient is pending', async (t) => {
  const f = fixture(t);
  const q = {
    sessionId: randomUUID(),
    nodeId: randomUUID(),
    ownerWindow: '123',
    requireContentProtection: true,
    bounds: { x: 0, y: 0, width: 800, height: 600 },
  } as const;
  const opened = f.backend.open(q, 1, () => true);
  void opened.catch(() => {});
  await tick();
  const bounds = { x: 50, y: -10, width: 1000, height: 700 };
  await f.backend.command(q.sessionId, { op: 'show', bounds });
  await f.backend.command(q.sessionId, { op: 'hide' });
  await f.backend.command(q.sessionId, { op: 'resize', bounds });
  await assert.rejects(f.backend.command(q.sessionId, { op: 'focus' }));
  f.recipient();
  await tick();
  assert.equal(f.children[0].requests[0].visible, false);
  assert.equal(f.children[0].requests[0].requireContentProtection, true);
  assert.deepEqual(f.children[0].requests[0].bounds, bounds);
  f.event(f.children[0], 'ready', { requestId: f.children[0].requests[0].binding.requestId });
  await opened;
});

test('temporary RDP relay binds prompt to native context and never asks for a saved password', async (t) => {
  for (const routed of [false, true]) {
    let direct = 0,
      prompts = 0,
      sealed = 0,
      released = 0,
      planned: any;
    const routeTemplate = routedRdpRequest();
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
        return rdpBundle({ ...q, publicKey: '' }).binding;
      },
      prompt: async (context, active, signal) => {
        prompts++;
        assert.equal(active(), true);
        assert.equal(signal.aborted, false);
        assert.equal(context.endpoint, routed ? routeTemplate.endpoint : undefined);
        return rdpBundle({
          ...context.binding,
          credentialOverride: '',
          publicKey: context.publicKey,
        }).bundle;
      },
      bundle: async (q) => {
        sealed++;
        return {
          binding: q.context.binding,
          bundle: { ...q.manual, ciphertext: Buffer.alloc(65552).toString('base64') },
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
    f.children[0].line({
      type: 'ready',
      sessionId: x.request.sessionId,
      lifecycleId: x.request.sessionId,
      requestId: f.children[0].requests[0].binding.requestId,
      external: false,
      backend: 'activex',
    });
    await x.result;
    await f.backend.close(x.request.sessionId);
    assert.equal(released, routed ? 1 : 0);
  }
});
test('temporary RDP pairs the protected document with the Bitwarden gateway and waits for cancellation', async (t) => {
  for (const mode of ['paired', 'ordinary', 'cancelled', 'resolver-failed']) {
    let fallback = 0;
    let finish!: () => void;
    let aborted = false;
    const f = fixture(t, undefined, 1000, {
      plan: async (q) => rdpBundle({ ...q, publicKey: '' }).binding,
      prompt: async (context) => ({
        ...rdpBundle({ ...context.binding, credentialOverride: '', publicKey: context.publicKey })
          .bundle,
        enc: Buffer.alloc(32, 15).toString('base64'),
      }),
      bitwarden: async (q, signal, accepted) => {
        assert.equal(q.manual.enc, Buffer.alloc(32, 15).toString('base64'));
        assert.equal(accepted(), true);
        if (mode === 'ordinary') return undefined;
        if (mode === 'resolver-failed') throw Error('private diagnostic');
        if (mode === 'cancelled') {
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
        }
        const saved = rdpBundle({
          ...q.context.binding,
          credentialOverride: '',
          publicKey: q.context.publicKey,
        });
        return {
          ...saved,
          bundle: { ...saved.bundle, ciphertext: Buffer.alloc(76, 5).toString('base64') },
          bitwarden: { ...saved.bundle, enc: Buffer.alloc(32, 11).toString('base64') },
        };
      },
      bundle: async (q) => {
        fallback++;
        return rdpBundle({
          ...q.context.binding,
          publicKey: q.context.publicKey,
          credentialOverride: '',
        });
      },
    });
    const opening = f.open(() => true, randomUUID(), true);
    await tick();
    f.recipient();
    await tick();
    const child = f.children[0];
    if (mode === 'cancelled') {
      let complete = false;
      const closing = f.backend.close(opening.request.sessionId).then(() => {
        complete = true;
      });
      await tick();
      assert.equal(aborted, true);
      assert.equal(complete, false);
      finish();
      await closing;
    }
    if (mode === 'cancelled' || mode === 'resolver-failed') {
      await assert.rejects(opening.result, /RDP connection stopped/);
      assert.equal(child.requests.length, 0);
    } else {
      assert.equal(child.requests.length, 1);
      const start = child.requests[0];
      assert.equal(Boolean(start.bitwarden), mode === 'paired');
      assert.equal('manual' in start, false);
      f.event(child, 'ready', { requestId: start.binding.requestId });
      await opening.result;
      await f.backend.close(opening.request.sessionId);
    }
    assert.equal(fallback, mode === 'ordinary' ? 1 : 0);
    assert.equal(f.requests.length, 0);
  }
});

test('temporary RDP relay cancels pending password entry and discards late crypto or authorization', async (t) => {
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
              return (planned = { ...routedRdpRequest().route, ...context });
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
          ? { ...rdpBundle({ ...q, publicKey: '' }).binding, nodeId: randomUUID() }
          : rdpBundle({ ...q, publicKey: '' }).binding,
      prompt: async (context, current, abort) => {
        signal = abort;
        active = current;
        if (mode === 'bad-envelope') return {} as any;
        if (mode === 'bad-bundle' || mode === 'late-bundle')
          return rdpBundle({
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
      await f.backend.close(x.request.sessionId);
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
    assert.equal(f.backend.has(x.request.sessionId), false);
  }
  const f = fixture(t);
  await assert.rejects(
    f.backend.open(
      {
        sessionId: randomUUID(),
        nodeId: randomUUID(),
        manualCredentials: true,
        ownerWindow: '1',
        bounds: { x: 0, y: 0, width: 800, height: 600 },
      },
      1,
    ),
    /unavailable/,
  );
});
