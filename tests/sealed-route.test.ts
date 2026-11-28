import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { tunnelAuthenticationEnvelope } from './fixtures/vault-tunnel-authentication.ts';
import { SealedRouteBroker } from '../electron/sealed-route.ts';
import type {
  VaultRoutePlanRequest,
  VaultRouteRequest,
  VaultRouteBinding,
  VaultRouteBundle,
} from '../electron/vault-route.ts';
import type {
  VaultTunnelFallbackPlanRequest,
  VaultTunnelFallbackRequest,
  VaultTunnelFallbackBinding,
  VaultTunnelFallbackBundle,
} from '../electron/vault-tunnel-fallback.ts';

const tick = async () => {
  for (let i = 0; i < 12; i++) await Promise.resolve();
  await new Promise<void>((r) => setImmediate(r));
};
class Child extends EventEmitter {
  exitCode: number | null = null;
  signalCode: string | null = null;
  stdout = new PassThrough();
  stderr = new PassThrough();
  requests: any[] = [];
  exitOnEnd = true;
  exitOnKill = true;
  kills = 0;
  writeError = false;
  stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      if (this.writeError) {
        callback(Error('private diagnostic'));
        return;
      }
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
    if (this.exitOnKill) this.exit();
    return true;
  }
  line(value: unknown) {
    this.stdout.write(JSON.stringify(value) + '\n');
  }
}
function fixture(
  t: TestContext,
  timeoutMs = 1000,
  authentication?: ConstructorParameters<typeof SealedRouteBroker>[0]['authentication'],
  fallbackEnabled = false,
) {
  let workspace: string | undefined = randomUUID(),
    allowed = true;
  const tunnel = randomUUID(),
    file = randomUUID(),
    children: Child[] = [],
    plans: VaultRoutePlanRequest[] = [],
    bundles: VaultRouteRequest[] = [];
  let revision = '1',
    config = '1',
    kind = 1,
    spawnError = false;
  const target = randomUUID(),
    fallbackPlans: VaultTunnelFallbackPlanRequest[] = [],
    fallbackBundles: VaultTunnelFallbackRequest[] = [],
    operations: string[] = [];
  let targetRow = '1',
    targetConfig = '1';
  const fallbackBinding = (q: VaultTunnelFallbackPlanRequest): VaultTunnelFallbackBinding => ({
    primary: { ...q.primary },
    fallback: {
      ...q.primary,
      kind: 2,
      requestId: q.fallbackRequestId,
      tunnelConfigId: target,
      rowVersion: targetRow,
      configurationVersion: targetConfig,
    },
  });
  let fallbackPlan = async (
    q: VaultTunnelFallbackPlanRequest,
  ): Promise<VaultTunnelFallbackBinding> => fallbackBinding(q);
  let fallbackBundle = async (
    q: VaultTunnelFallbackRequest,
  ): Promise<VaultTunnelFallbackBundle> => ({
    binding: structuredClone(q.binding),
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: q.publicKey,
      ciphertext: Buffer.alloc(32).toString('base64'),
    },
  });
  const binding = (q: VaultRoutePlanRequest): VaultRouteBinding => ({
    workspaceId: q.workspaceId,
    fileId: file,
    nodeId: q.nodeId,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: q.epoch,
    protocol: 'ssh',
    host: 'host.example',
    port: 22,
    tunnelConfigId: tunnel,
    useExternalClient: false,
    kind,
    rowVersion: revision,
    configurationVersion: config,
  });
  let plan = (q: VaultRoutePlanRequest) => Promise.resolve(binding(q));
  let bundle = (q: VaultRouteRequest): Promise<VaultRouteBundle> =>
    Promise.resolve({
      binding: binding(q),
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: q.publicKey,
        ciphertext: Buffer.alloc(32).toString('base64'),
      },
    });
  const broker = new SealedRouteBroker(
    {
      executable: () => '/native/backend',
      workspaceId: () => workspace,
      authorized: (epoch) => allowed && epoch === 1,
      plan: (q) => {
        plans.push(q);
        return plan(q);
      },
      bundle: (q) => {
        bundles.push(q);
        return bundle(q);
      },
      timeoutMs,
      authentication,
      ...(fallbackEnabled
        ? {
            fallback: {
              plan: (q: VaultTunnelFallbackPlanRequest) => {
                fallbackPlans.push(q);
                return fallbackPlan(q);
              },
              bundle: (q: VaultTunnelFallbackRequest) => {
                fallbackBundles.push(q);
                return fallbackBundle(q);
              },
            },
          }
        : {}),
    },
    (exe, args) => {
      assert.equal(exe, '/native/backend');
      if (!fallbackEnabled) assert.deepEqual(args, ['--operation', 'tunnel-sealed']);
      else
        assert.ok(
          ['tunnel-sealed', 'tunnel-primary-sealed', 'tunnel-fallback-sealed'].includes(args[1]),
        );
      operations.push(args[1]);
      if (spawnError) throw Error('private spawn path');
      const c = new Child();
      children.push(c);
      return c as unknown as ChildProcessWithoutNullStreams;
    },
  );
  t.after(async () => {
    for (const c of children) c.exit();
    await broker.closeAll().catch(() => {});
  });
  const acquire = (owner = () => true, sessionId = randomUUID(), credentialId?: string) => {
    const input = { sessionId, nodeId: randomUUID(), ...(credentialId ? { credentialId } : {}) };
    const promise = broker.acquire(input, 1, owner);
    void promise.catch(() => {});
    return { input, promise };
  };
  const recipient = (c: Child, byte = 7) =>
    c.line({ type: 'recipient', publicKey: Buffer.alloc(32, byte).toString('base64') });
  const ready = (c: Child) =>
    c.line({
      type: 'ready',
      sessionId: c.requests[0].binding.primary?.sessionId ?? c.requests[0].binding.sessionId,
      endpoint: '127.0.0.1:12345',
    });
  const connect = async () => {
    const x = acquire();
    await tick();
    const child = children.at(-1)!;
    recipient(child);
    await tick();
    ready(child);
    return { ...x, child, lease: await x.promise };
  };
  return {
    broker,
    children,
    plans,
    bundles,
    fallbackPlans,
    fallbackBundles,
    operations,
    fallbackBinding,
    binding,
    acquire,
    recipient,
    ready,
    connect,
    setFallbackPlan: (v: typeof fallbackPlan) => {
      fallbackPlan = v;
    },
    setFallbackBundle: (v: typeof fallbackBundle) => {
      fallbackBundle = v;
    },
    setTargetVersion: (row: string, config = row) => {
      targetRow = row;
      targetConfig = config;
    },
    setPlan: (v: typeof plan) => {
      plan = v;
    },
    setBundle: (v: typeof bundle) => {
      bundle = v;
    },
    setAllowed: (v: boolean) => {
      allowed = v;
    },
    setWorkspace: (v: string | undefined) => {
      workspace = v;
    },
    setVersion: (row: string, cfg = row) => {
      revision = row;
      config = cfg;
    },
    setKind: (v: number) => {
      kind = v;
    },
    setSpawnError: () => {
      spawnError = true;
    },
  };
}

test('route leases coalesce concurrent and subsequent consumers using fresh native plans', async (t) => {
  const f = fixture(t),
    a = f.acquire(),
    b = f.acquire();
  await tick();
  assert.equal(f.children.length, 1);
  assert.equal(f.plans.length, 2);
  const child = f.children[0];
  f.recipient(child);
  await tick();
  f.ready(child);
  const [la, lb] = await Promise.all([a.promise, b.promise]);
  assert.equal(f.bundles.length, 1);
  assert.equal(la.endpoint, lb.endpoint);
  assert.notEqual(la.binding.nodeId, lb.binding.nodeId);
  assert.equal(la.binding.sessionId, a.input.sessionId);
  assert.ok(la.active && lb.active);
  assert.ok(Object.isFrozen(la) && Object.isFrozen(la.binding));
  await la.release();
  await la.closed;
  assert.ok(!la.active && lb.active);
  assert.equal(child.exitCode, null);
  f.setVersion('2', '1');
  const c = f.acquire(),
    lc = await c.promise;
  assert.equal(f.children.length, 1);
  assert.equal(lc.binding.rowVersion, '2');
  assert.equal(f.plans.length, 3);
  await lb.release();
  assert.equal(child.exitCode, null);
  await lc.release();
  await lc.closed;
  assert.equal(child.exitCode, 0);
  await lc.release();
  await f.broker.close(randomUUID());
});

test('route pool separates configuration revisions, provider, file and authorization epoch', async (t) => {
  const f = fixture(t),
    first = await f.connect();
  f.setVersion('2');
  const x = f.acquire();
  await tick();
  assert.equal(f.children.length, 2);
  f.recipient(f.children[1]);
  await tick();
  f.ready(f.children[1]);
  const second = await x.promise;
  f.setKind(6);
  const third = f.acquire();
  await tick();
  assert.equal(f.children.length, 3);
  await f.broker.close(third.input.sessionId);
  await assert.rejects(third.promise);
  f.setPlan(async (q) => ({ ...f.binding(q), fileId: randomUUID() }));
  const fourth = f.acquire();
  await tick();
  assert.equal(f.children.length, 4);
  await f.broker.close(fourth.input.sessionId);
  await assert.rejects(fourth.promise);
  f.setAllowed(false);
  assert.ok(!first.lease.active && !second.active);
  await f.broker.closeAll();
  assert.equal(
    f.children.every((c) => c.exitCode === 0),
    true,
  );
});

test('route shutdown rejects pending planning and cannot revive a released or reused session', async (t) => {
  const f = fixture(t);
  let finish!: (v: VaultRouteBinding) => void;
  f.setPlan(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const old = f.acquire();
  await tick();
  const oldRequest = f.plans[0];
  await f.broker.close(old.input.sessionId);
  await assert.rejects(old.promise);
  f.setPlan(async (q) => f.binding(q));
  const replacement = f.acquire(() => true, old.input.sessionId);
  await tick();
  finish(f.binding(oldRequest));
  await tick();
  assert.equal(f.children.length, 1);
  f.recipient(f.children[0]);
  await tick();
  f.ready(f.children[0]);
  const lease = await replacement.promise;
  assert.ok(lease.active);
  const shutdown = f.broker.closeAll();
  await assert.rejects(f.acquire().promise);
  await shutdown;
  assert.ok(!lease.active);
  await lease.closed;
  const again = await f.connect();
  assert.ok(again.lease.active);
});

test('route failure fans out to every lease without fallback or restart', async (t) => {
  const f = fixture(t),
    a = await f.connect(),
    b = await f.acquire().promise;
  a.child.stderr.write('password private provider trace');
  a.child.exit();
  await Promise.all([a.lease.closed, b.closed]);
  await tick();
  assert.ok(!a.lease.active && !b.active);
  assert.equal(f.children.length, 1);
  const newRoute = await f.connect();
  assert.equal(f.children.length, 2);
  assert.ok(newRoute.lease.active);
});

test('route exit retires consumers before inherited stdio closes and cannot retire a replacement', async (t) => {
  const f = fixture(t),
    a = await f.connect(),
    b = await f.acquire().promise;
  // A descendant can keep a pipe open after the native route owner exits.
  // No close notification or EOF is available yet.
  a.child.exitCode = 0;
  a.child.emit('exit', 0, null);
  assert.equal(a.lease.active, false);
  assert.equal(b.active, false);
  await Promise.all([a.lease.closed, b.closed]);
  await tick();
  assert.equal(f.children.length, 1);
  const replacement = await f.connect();
  a.child.emit('close', 0, null);
  await tick();
  assert.equal(replacement.lease.active, true);
});

test('route exit while awaiting a recipient rejects admission without waiting for pipe closure', async (t) => {
  const f = fixture(t),
    pending = f.acquire();
  await tick();
  const child = f.children[0];
  child.exitCode = 0;
  child.emit('exit', 0, null);
  await assert.rejects(pending.promise, /closed/);
  await tick();
  assert.equal(f.children.length, 1);
});

test('route release checks live owners before and after asynchronous native handoff', async (t) => {
  for (const stage of ['plan', 'bundle', 'ready']) {
    const f = fixture(t);
    let owner = true;
    let release!: () => void;
    if (stage === 'plan')
      f.setPlan(async (q) => {
        await new Promise<void>((r) => {
          release = r;
        });
        return f.binding(q);
      });
    if (stage === 'bundle')
      f.setBundle(async (q) => {
        await new Promise<void>((r) => {
          release = r;
        });
        return {
          binding: f.binding(q),
          bundle: {
            formatVersion: 1,
            suiteId: 2,
            enc: q.publicKey,
            ciphertext: Buffer.alloc(32).toString('base64'),
          },
        };
      });
    const a = f.acquire(() => owner);
    await tick();
    if (stage !== 'plan') {
      f.recipient(f.children[0]);
      await tick();
    }
    owner = false;
    if (stage === 'ready') f.ready(f.children[0]);
    else release();
    await assert.rejects(a.promise);
    await tick();
    assert.ok(f.children.every((c) => c.exitCode === 0));
  }
  const f = fixture(t);
  await assert.rejects(
    f.acquire(() => {
      throw Error('destroyed');
    }).promise,
  );
  assert.equal(f.plans.length, 0);
});

test('a closing first owner does not cancel another authorized subscriber to the same route', async (t) => {
  const f = fixture(t);
  let firstAlive = true;
  const first = f.acquire(() => firstAlive),
    second = f.acquire();
  await tick();
  const child = f.children[0];
  firstAlive = false;
  await f.broker.close(first.input.sessionId);
  await assert.rejects(first.promise);
  f.recipient(child);
  await tick();
  f.ready(child);
  const lease = await second.promise;
  assert.ok(lease.active);
  assert.equal(f.children.length, 1);
  await lease.release();
});

test('cancellation between recipient arrival and queued release cannot request a bundle', async (t) => {
  const f = fixture(t),
    a = f.acquire();
  await tick();
  f.recipient(f.children[0]);
  await f.broker.close(a.input.sessionId);
  await assert.rejects(a.promise);
  await tick();
  assert.equal(f.bundles.length, 0);
  assert.equal(f.children[0].requests.length, 0);
});

test('route startup refuses changed native metadata and all substituted bundle contexts', async (t) => {
  for (const field of [
    'host',
    'port',
    'tunnelConfigId',
    'fileId',
    'kind',
    'rowVersion',
    'configurationVersion',
    'sessionId',
    'nodeId',
    'requestId',
    'epoch',
  ]) {
    const f = fixture(t);
    f.setBundle(async (q) => {
      const b: any = f.binding(q);
      b[field] =
        typeof b[field] === 'number'
          ? b[field] + 1
          : field.endsWith('Version')
            ? '2'
            : randomUUID();
      return {
        binding: b,
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: q.publicKey,
          ciphertext: Buffer.alloc(32).toString('base64'),
        },
      };
    });
    const a = f.acquire();
    await tick();
    f.recipient(f.children[0]);
    await assert.rejects(a.promise);
    await tick();
    assert.equal(f.children[0].requests.length, 0);
    assert.equal(f.children[0].exitCode, 0);
  }
});

test('route parser rejects malformed, replayed, oversized and out-of-order child frames', async (t) => {
  for (const mode of [
    'json',
    'utf8',
    'size',
    'fragments',
    'recipient-fields',
    'recipient-key',
    'early-ready',
    'second-recipient',
    'wrong-session',
    'remote-endpoint',
    'bad-port',
    'extra-ready',
    'duplicate-ready',
    'null',
  ]) {
    const f = fixture(t),
      a = f.acquire();
    await tick();
    const c = f.children[0];
    if (
      ['wrong-session', 'remote-endpoint', 'bad-port', 'extra-ready', 'duplicate-ready'].includes(
        mode,
      )
    ) {
      f.recipient(c);
      await tick();
    }
    switch (mode) {
      case 'json':
        c.stdout.write('{\n');
        break;
      case 'utf8':
        c.stdout.write(Buffer.from([0xff, 10]));
        break;
      case 'size':
        c.stdout.write('x'.repeat(32769));
        break;
      case 'fragments':
        for (let i = 0; i < 1025; i++) c.stdout.write('x');
        break;
      case 'recipient-fields':
        c.line({ type: 'recipient', publicKey: Buffer.alloc(32).toString('base64'), extra: 1 });
        break;
      case 'recipient-key':
        c.line({ type: 'recipient', publicKey: 'bad' });
        break;
      case 'second-recipient':
        f.recipient(c);
        f.recipient(c);
        break;
      case 'duplicate-ready':
        f.ready(c);
        f.ready(c);
        break;
      case 'null':
        c.line(null);
        break;
      default:
        c.line({
          type: 'ready',
          sessionId: mode === 'wrong-session' ? randomUUID() : a.input.sessionId,
          endpoint:
            mode === 'remote-endpoint'
              ? '10.0.0.1:22'
              : mode === 'bad-port'
                ? '127.0.0.1:65536'
                : '127.0.0.1:12345',
          ...(mode === 'extra-ready' ? { secret: 'bad' } : {}),
        });
    }
    if (mode === 'duplicate-ready') {
      const l = await a.promise;
      await l.closed;
      assert.ok(!l.active);
    } else await assert.rejects(a.promise);
    await tick();
    assert.equal(c.exitCode, 0);
  }
});

test('route errors, deadlines and shutdown confirmation are observable', async (t) => {
  for (const stage of [
    'plan',
    'spawn',
    'bundle',
    'stdin',
    'stdout',
    'stderr',
    'child',
    'write',
    'end',
    'authority',
  ]) {
    const f = fixture(t),
      error = Error('private detail');
    if (stage === 'plan')
      f.setPlan(async () => {
        throw error;
      });
    if (stage === 'spawn') f.setSpawnError();
    if (stage === 'bundle')
      f.setBundle(async () => {
        throw error;
      });
    const a = f.acquire();
    await tick();
    const c = f.children[0];
    if (stage === 'bundle') f.recipient(c);
    else if (stage === 'stdin' || stage === 'stdout' || stage === 'stderr')
      c[stage].emit('error', error);
    else if (stage === 'child') c.emit('error', error);
    else if (stage === 'write') {
      c.writeError = true;
      f.recipient(c);
    } else if (stage === 'end') c.stdout.end();
    else if (stage === 'authority') {
      f.setWorkspace(randomUUID());
      f.recipient(c);
    }
    await assert.rejects(a.promise, /Vault route closed/);
    await tick();
  }
  const f = fixture(t, 15);
  await assert.rejects(f.acquire().promise);
  await tick();
  assert.equal(f.children[0].exitCode, 0);
  const stuck = fixture(t),
    x = await stuck.connect();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  x.child.exitOnEnd = false;
  x.child.exitOnKill = false;
  const release = x.lease.release();
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(release, /could not be confirmed/);
  assert.equal(x.child.kills, 0);
  assert.ok(!x.lease.active);
  const failedShutdown = stuck.broker.closeAll();
  assert.equal(stuck.broker.closeAll(), failedShutdown);
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(failedShutdown, /could not be confirmed/);
  await assert.rejects(stuck.acquire().promise);
  x.child.exit();
  const retry = stuck.broker.closeAll();
  assert.equal(stuck.broker.closeAll(), retry);
  await retry;
  assert.equal(x.child.exitCode, 0);
  assert.equal(x.child.kills, 0);
  t.mock.timers.reset();
  await x.lease.release();
  const replacement = await stuck.connect();
  await replacement.lease.release();
});

test('route shutdown allows native sidecar retirement beyond the former controller kill deadline', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  x.child.exitOnEnd = false;
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let stopped = false;
  const pending = x.lease.release().then(() => {
    stopped = true;
  });
  await tick();
  t.mock.timers.tick(7500);
  await tick();
  assert.equal(stopped, false);
  assert.equal(x.child.kills, 0);
  assert.equal(x.child.exitCode, null);
  await assert.rejects(f.acquire().promise, /stopping|closed/);
  x.child.exit();
  await pending;
  assert.equal(stopped, true);
  assert.equal(x.child.kills, 0);
  t.mock.timers.reset();
});

test('an unconfirmed route blocks replacement revisions and providers until its original controller exits', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  x.child.exitOnEnd = false;
  x.child.exitOnKill = false;
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = x.lease.release();
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(pending, /could not be confirmed/);
  for (const kind of [1, 6]) {
    f.setVersion('2');
    f.setKind(kind);
    const replacement = f.acquire();
    await tick();
    assert.equal(f.children.length, 1, 'configuration changes cannot evade quarantine');
    await assert.rejects(replacement.promise, /closed|stopping/);
  }
  f.setPlan(async (q) => ({ ...f.binding(q), tunnelConfigId: randomUUID() }));
  const independent = f.acquire();
  await tick();
  assert.equal(f.children.length, 2, 'other tunnels retain independent ownership');
  await f.broker.close(independent.input.sessionId);
  await assert.rejects(independent.promise);
  x.child.exit();
  await f.broker.close(x.input.sessionId);
  f.setPlan(async (q) => f.binding(q));
  t.mock.timers.reset();
  const replacement = await f.connect();
  await replacement.lease.release();
});

test('route input and pool limits reject before creating excess processes', async (t) => {
  const f = fixture(t);
  for (const value of [
    null,
    {},
    [],
    { sessionId: randomUUID(), nodeId: randomUUID(), extra: 1 },
    { sessionId: 'bad', nodeId: randomUUID() },
    { sessionId: randomUUID(), nodeId: randomUUID(), credentialId: 'bad' },
  ])
    await assert.rejects(f.broker.acquire(value as any, 1));
  const input = { sessionId: randomUUID(), nodeId: randomUUID() };
  await assert.rejects(f.broker.acquire(input, 0));
  const a = f.acquire();
  await assert.rejects(f.broker.acquire(a.input, 1));
  await f.broker.close(a.input.sessionId);
  await assert.rejects(a.promise);
  f.setPlan(() => new Promise(() => {}));
  const pending = Array.from({ length: 128 }, () => f.acquire());
  await assert.rejects(f.acquire().promise);
  await f.broker.closeAll();
  await Promise.all(pending.map((x) => assert.rejects(x.promise)));
  f.setPlan(async (q) => ({ ...f.binding(q), tunnelConfigId: randomUUID() }));
  const routes = Array.from({ length: 32 }, () => f.acquire());
  await tick();
  assert.equal(f.children.filter((c) => c.exitCode === null).length, 32);
  await assert.rejects(f.acquire().promise);
  await f.broker.closeAll();
  await Promise.all(routes.map((x) => assert.rejects(x.promise)));
  for (const timeoutMs of [0, -1, NaN, 1.5, 360001])
    assert.throws(
      () =>
        new SealedRouteBroker({
          executable: () => '',
          workspaceId: () => undefined,
          authorized: () => true,
          plan: async () => ({}) as any,
          bundle: async () => ({}) as any,
          timeoutMs,
        }),
    );
});

test('ready notification rejects an expired owner while keeping other authorized leases alive', async (t) => {
  const f = fixture(t);
  let alive = true;
  const a = f.acquire(() => alive),
    b = f.acquire();
  await tick();
  f.recipient(f.children[0]);
  await tick();
  alive = false;
  f.ready(f.children[0]);
  await assert.rejects(a.promise);
  const lease = await b.promise;
  assert.ok(lease.active);
  assert.equal(f.children[0].exitCode, null);
  await lease.release();
  assert.equal(f.children[0].exitCode, 0);
});

function authenticationChallenge(c: Child) {
  return {
    type: 'authentication-required',
    sessionId: c.requests[0].binding.sessionId,
    challengeId: randomUUID(),
    publicKey: Buffer.alloc(32, 7).toString('base64'),
    usernameRequired: true,
  };
}
test('route prompts bind the origin and forward only one encrypted factor before readiness', async (t) => {
  const credentialId = randomUUID();
  let prompts = 0,
    closed = 0,
    finish!: (v: any) => void,
    active!: () => boolean;
  const f = fixture(t, 1000, {
    prompt: async (c, current, signal, request) => {
      prompts++;
      active = current;
      assert.equal(signal.aborted, false);
      assert.equal(c.binding.kind, 9);
      assert.equal(request.credentialOverride, credentialId);
      assert.equal(request.sessionId, c.binding.sessionId);
      assert.equal(request.requestId, c.binding.requestId);
      assert.ok(Object.isFrozen(request));
      return new Promise((r) => (finish = r));
    },
    close: async () => {
      closed++;
    },
  });
  f.setKind(9);
  const a = f.acquire(() => true, randomUUID(), credentialId),
    b = f.acquire(() => true, randomUUID(), credentialId);
  await tick();
  const c = f.children[0];
  f.recipient(c);
  await tick();
  const challenge = authenticationChallenge(c);
  c.line(challenge);
  await tick();
  assert.equal(prompts, 1);
  assert.ok(active());
  assert.equal(c.requests.length, 1);
  finish(tunnelAuthenticationEnvelope());
  await tick();
  assert.deepEqual(c.requests[1], {
    type: 'authentication',
    sessionId: challenge.sessionId,
    challengeId: challenge.challengeId,
    envelope: tunnelAuthenticationEnvelope(),
  });
  f.ready(c);
  const [la, lb] = await Promise.all([a.promise, b.promise]);
  await la.release();
  assert.equal(c.exitCode, null);
  await lb.release();
  assert.equal(closed, 1);
  assert.equal(c.exitCode, 0);
  assert.equal(active(), false);
});
test('route authentication rejects malformed, duplicate, unsupported and stale native requests', async (t) => {
  for (const mode of [
    'unsupported',
    'wrong-session',
    'wrong-kind',
    'extra',
    'duplicate',
    'early-ready',
    'invalid-envelope',
    'prompt-error',
    'stale-origin',
  ]) {
    let finish!: (v: any) => void,
      prompts = 0,
      owner = true;
    const f = fixture(
      t,
      1000,
      mode === 'unsupported'
        ? undefined
        : {
            prompt: async () => {
              prompts++;
              if (mode === 'prompt-error') throw Error('private factor');
              if (mode === 'invalid-envelope') return {} as any;
              return new Promise((r) => (finish = r));
            },
            close: async () => {
              finish?.(tunnelAuthenticationEnvelope());
            },
          },
    );
    if (mode !== 'wrong-kind') f.setKind(9);
    const a = f.acquire(() => owner);
    await tick();
    const c = f.children[0];
    f.recipient(c);
    await tick();
    const challenge = authenticationChallenge(c);
    if (mode === 'wrong-session') challenge.sessionId = randomUUID();
    if (mode === 'extra') (challenge as any).password = 'never';
    if (mode === 'stale-origin') owner = false;
    c.line(challenge);
    await tick();
    if (mode === 'duplicate') c.line(challenge);
    if (mode === 'early-ready') f.ready(c);
    await assert.rejects(a.promise, /closed/);
    await f.broker.closeAll();
    assert.equal(c.exitCode, 0, mode);
    assert.equal(
      prompts,
      ['duplicate', 'early-ready', 'invalid-envelope', 'prompt-error'].includes(mode) ? 1 : 0,
      mode,
    );
  }
});
test('cancelling an authenticating origin retires pooled consumers and waits for matching prompt cleanup', async (t) => {
  let finish!: (v: any) => void,
    release!: (v: void) => void,
    aborted = false;
  const f = fixture(t, 1000, {
    prompt: async (_c, _current, signal) => {
      signal.addEventListener('abort', () => {
        aborted = true;
        finish(tunnelAuthenticationEnvelope());
      });
      return new Promise((r) => (finish = r));
    },
    close: () => new Promise((r) => (release = r)),
  });
  f.setKind(9);
  const a = f.acquire(),
    b = f.acquire();
  await tick();
  const c = f.children[0];
  f.recipient(c);
  await tick();
  c.line(authenticationChallenge(c));
  await tick();
  let stopped = false;
  const stopping = f.broker.close(a.input.sessionId).then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(aborted, true);
  assert.equal(stopped, false);
  assert.equal(c.requests.length, 1);
  await Promise.all([assert.rejects(a.promise), assert.rejects(b.promise)]);
  release();
  await stopping;
  assert.equal(stopped, true);
  assert.equal(c.exitCode, 0);
});
test('unconfirmed factor document shutdown blocks admission until the same cleanup is retried', async (t) => {
  let finish!: (v: any) => void,
    deny = true,
    closes = 0;
  const f = fixture(t, 1000, {
    prompt: async () => new Promise((r) => (finish = r)),
    close: async () => {
      closes++;
      finish(tunnelAuthenticationEnvelope());
      if (deny) throw Error('private close failure');
    },
  });
  f.setKind(9);
  const a = f.acquire();
  await tick();
  const c = f.children[0];
  f.recipient(c);
  await tick();
  c.line(authenticationChallenge(c));
  await tick();
  await assert.rejects(f.broker.closeAll(), /shutdown/);
  await assert.rejects(a.promise);
  await assert.rejects(f.broker.close(a.input.sessionId), /shutdown/);
  await assert.rejects(f.acquire().promise, /unavailable/);
  deny = false;
  await f.broker.closeAll();
  assert.equal(closes, 3);
  const next = f.acquire();
  await tick();
  assert.equal(f.children.length, 2);
  await f.broker.closeAll();
  await assert.rejects(next.promise);
});

test('pending factor shutdown retries by session retain identity across failed cleanup', async (t) => {
  let finish!: (value: any) => void,
    deny = true,
    closes = 0;
  const f = fixture(t, 1000, {
    prompt: async () => new Promise((r) => (finish = r)),
    close: async () => {
      closes++;
      finish(tunnelAuthenticationEnvelope());
      if (deny) throw Error('private destroy failure');
    },
  });
  f.setKind(9);
  const a = f.acquire();
  await tick();
  const child = f.children[0];
  f.recipient(child);
  await tick();
  child.line(authenticationChallenge(child));
  await tick();
  await assert.rejects(f.broker.close(a.input.sessionId), /shutdown/);
  await assert.rejects(a.promise);
  await assert.rejects(f.broker.close(a.input.sessionId), /shutdown/);
  f.setVersion('2');
  await assert.rejects(f.acquire(() => true, a.input.sessionId).promise, /unavailable/);
  deny = false;
  await f.broker.close(a.input.sessionId);
  assert.ok(closes >= 3);
  const next = f.acquire(() => true, a.input.sessionId);
  await tick();
  assert.equal(f.children.length, 2);
  await f.broker.close(next.input.sessionId);
  await assert.rejects(next.promise);
});

function browserChallenge(c: Child) {
  return {
    ...authenticationChallenge(c),
    type: 'browser-authentication-required',
    usernameRequired: undefined,
    startURL: 'https://vpn.test:1001/saml?x=' + 'a'.repeat(3000),
    callbackURL: 'http://127.0.0.1:12345/',
    ignoreCertificateErrors: true,
  };
}
const browserEnvelope = () => ({
  ...tunnelAuthenticationEnvelope(),
  ciphertext: Buffer.alloc(50, 8).toString('base64'),
});
test('route browser challenge accepts a bounded SAML URL and forwards only its purpose-specific envelope', async (t) => {
  let prompts = 0,
    closes = 0;
  const f = fixture(t, 1000, {
    prompt: async (context) => {
      assert.ok('startURL' in context);
      prompts++;
      return browserEnvelope();
    },
    close: async () => {
      closes++;
    },
  });
  f.setKind(9);
  const a = f.acquire();
  await tick();
  const c = f.children[0];
  f.recipient(c);
  await tick();
  const challenge = browserChallenge(c);
  challenge.startURL = 'https://vpn.test:1001/saml?x=' + '&'.repeat(4000);
  c.stdout.write(JSON.stringify(challenge).replaceAll('&', '\\u0026') + '\n');
  await tick();
  assert.equal(prompts, 1);
  assert.deepEqual(c.requests[1], {
    type: 'browser-authentication',
    sessionId: challenge.sessionId,
    challengeId: challenge.challengeId,
    envelope: browserEnvelope(),
  });
  f.ready(c);
  const lease = await a.promise;
  await lease.release();
  assert.equal(closes, 1);
});
test('route browser requests reject foreign contexts and password envelopes', async (t) => {
  for (const mode of [
    'http',
    'foreign-callback',
    'wrong-session',
    'extra',
    'password-envelope',
    'duplicate',
  ]) {
    const f = fixture(t, 1000, {
      prompt: async () =>
        mode === 'password-envelope' ? tunnelAuthenticationEnvelope() : browserEnvelope(),
      close: async () => {},
    });
    f.setKind(9);
    const a = f.acquire();
    await tick();
    const c = f.children[0];
    f.recipient(c);
    await tick();
    const challenge = browserChallenge(c);
    if (mode === 'http') challenge.startURL = 'http://vpn.test/saml';
    if (mode === 'foreign-callback') challenge.callbackURL = 'http://attacker.test:12345/';
    if (mode === 'wrong-session') challenge.sessionId = contextID();
    if (mode === 'extra') (challenge as any).token = 'never';
    c.line(challenge);
    if (mode === 'duplicate') c.line(challenge);
    await assert.rejects(a.promise);
    await f.broker.closeAll();
    assert.equal(c.exitCode, 0);
  }
});
function contextID() {
  return randomUUID();
}

function cookieChallenge(c: Child) {
  return {
    type: 'cookie-authentication-required',
    sessionId: c.requests[0].binding.fallback?.sessionId ?? c.requests[0].binding.sessionId,
    challengeId: randomUUID(),
    publicKey: Buffer.alloc(32, 7).toString('base64'),
    startURL: 'https://vpn.test/remote/saml/start?realm=staff',
    ignoreCertificateErrors: true,
    cookieName: 'SVPNCOOKIE',
  };
}
const cookieEnvelope = () => ({
  ...tunnelAuthenticationEnvelope(),
  ciphertext: Buffer.alloc(16406, 7).toString('base64'),
});

function requireFallback(child: Child) {
  const binding = child.requests[0].binding;
  child.line({
    type: 'fallback-required',
    sessionId: binding.sessionId,
    requestId: binding.requestId,
  });
}

async function primaryAttempt(f: ReturnType<typeof fixture>) {
  f.setKind(9);
  const attempt = f.acquire();
  await tick();
  const child = f.children.at(-1)!;
  f.recipient(child);
  await tick();
  return { ...attempt, child };
}

async function fallbackAttempt(f: ReturnType<typeof fixture>) {
  const primary = await primaryAttempt(f);
  requireFallback(primary.child);
  await tick();
  const child = f.children.at(-1)!;
  assert.notEqual(child, primary.child);
  f.recipient(child, 8);
  await tick();
  return { ...primary, primary: primary.child, child };
}

test('fallback waits for original exit, uses a fresh purpose/recipient and keeps the logical primary lease', async (t) => {
  const f = fixture(t, 1000, undefined, true);
  const a = await primaryAttempt(f);
  a.child.exitOnEnd = false;
  requireFallback(a.child);
  await tick();
  assert.equal(f.children.length, 1);
  assert.equal(f.fallbackPlans.length, 0);
  assert.equal(a.child.kills, 0);
  a.child.exit();
  await tick();
  assert.deepEqual(f.operations, ['tunnel-primary-sealed', 'tunnel-fallback-sealed']);
  const child = f.children[1];
  f.recipient(child, 8);
  await tick();
  const packet = child.requests[0];
  assert.equal(packet.binding.primary.kind, 9);
  assert.equal(packet.binding.fallback.kind, 2);
  assert.equal(f.fallbackBundles[0].publicKey, Buffer.alloc(32, 8).toString('base64'));
  assert.notEqual(f.bundles[0].publicKey, f.fallbackBundles[0].publicKey);
  f.ready(child);
  const lease = await a.promise;
  assert.equal(lease.binding.kind, 9);
  assert.equal(lease.binding.nodeId, a.input.nodeId);
  assert.equal(lease.binding.tunnelConfigId, packet.binding.primary.tunnelConfigId);
  assert.notEqual(lease.binding.tunnelConfigId, packet.binding.fallback.tunnelConfigId);
  a.child.emit('error', Error('late original error'));
  a.child.stdout.emit('end');
  a.child.emit('close');
  assert.equal(lease.active, true);
  await lease.release();
  assert.equal(child.exitCode, 0);
});

test('every pending and ready fallback consumer independently authorizes the SSL source', async (t) => {
  const f = fixture(t, 1000, undefined, true);
  const a = await primaryAttempt(f),
    denied = f.acquire(),
    allowed = f.acquire();
  await tick();
  f.setFallbackPlan(async (q) => {
    if (q.nodeId === denied.input.nodeId) throw Error('target Use denied');
    return f.fallbackBinding(q);
  });
  requireFallback(a.child);
  await tick();
  await assert.rejects(denied.promise);
  assert.equal(f.children.length, 2);
  const child = f.children[1];
  f.recipient(child, 8);
  await tick();
  f.ready(child);
  const leases = [await a.promise, await allowed.promise];
  const late = f.acquire();
  await tick();
  leases.push(await late.promise);
  assert.equal(f.children.length, 2);
  assert.equal(f.fallbackPlans.length, 4);
  assert.deepEqual(
    new Set(f.fallbackPlans.map((q) => q.nodeId)),
    new Set([a.input.nodeId, denied.input.nodeId, allowed.input.nodeId, late.input.nodeId]),
  );
  assert.ok(leases.every((lease) => lease.active && lease.binding.kind === 9));
  for (const lease of leases) await lease.release();
  assert.equal(child.exitCode, 0);
});

test('secondary authentication receives the active SSL context and original request plus complete source pair', async (t) => {
  let prompts = 0,
    closes = 0;
  const f = fixture(
    t,
    1000,
    {
      prompt: async (context, current, _signal, request, pair) => {
        prompts++;
        assert.ok(current());
        assert.equal(context.binding.kind, 2);
        assert.equal(request.requestId, pair!.primary.requestId);
        assert.equal(context.binding.requestId, pair!.fallback.requestId);
        assert.notEqual(request.requestId, context.binding.requestId);
        assert.deepEqual(pair, f.fallbackBundles[0].binding);
        return cookieEnvelope();
      },
      close: async () => {
        closes++;
      },
    },
    true,
  );
  const a = await fallbackAttempt(f);
  a.child.line(cookieChallenge(a.child));
  await tick();
  assert.equal(a.child.requests[1].type, 'cookie-authentication');
  f.ready(a.child);
  await (await a.promise).release();
  assert.equal(prompts, 1);
  assert.equal(closes, 1);
});

test('cancelled primary ownership promotes only a current pending consumer after confirmed retirement', async (t) => {
  const f = fixture(t, 1000, undefined, true),
    a = await primaryAttempt(f),
    b = f.acquire();
  await tick();
  a.child.exitOnEnd = false;
  requireFallback(a.child);
  await tick();
  await f.broker.close(a.input.sessionId);
  await assert.rejects(a.promise);
  assert.equal(f.fallbackPlans.length, 0);
  a.child.exit();
  await tick();
  assert.equal(f.fallbackPlans[0].nodeId, b.input.nodeId);
  const secondary = f.children[1];
  f.recipient(secondary, 8);
  await tick();
  f.ready(secondary);
  assert.equal((await b.promise).binding.nodeId, b.input.nodeId);
  await f.broker.close(b.input.sessionId);
});

test('close joins a late fallback plan without creating a replacement recipient', async (t) => {
  const f = fixture(t, 1000, undefined, true),
    a = await primaryAttempt(f);
  let resume!: () => void;
  f.setFallbackPlan(
    (q) =>
      new Promise((resolve) => {
        resume = () => resolve(f.fallbackBinding(q));
      }),
  );
  requireFallback(a.child);
  await tick();
  let closed = false;
  const closing = f.broker.close(a.input.sessionId).then(() => {
    closed = true;
  });
  await tick();
  assert.equal(closed, false);
  resume();
  await closing;
  await assert.rejects(a.promise);
  assert.equal(f.children.length, 1);
  assert.equal(f.fallbackBundles.length, 0);
});

test('fallback source failure and lost authority cannot create a secondary recipient', async (t) => {
  for (const mode of ['denied', 'invalid', 'authority', 'owner', 'spawn']) {
    const f = fixture(t, 1000, undefined, true);
    let owned = true;
    f.setKind(9);
    const a = f.acquire(() => owned);
    await tick();
    const child = f.children[0];
    f.recipient(child);
    await tick();
    f.setFallbackPlan(async (q) => {
      assert.equal(child.exitCode, 0);
      if (mode === 'denied') throw Error('target Use denied');
      if (mode === 'authority') f.setAllowed(false);
      if (mode === 'owner') owned = false;
      if (mode === 'spawn') f.setSpawnError();
      const pair = f.fallbackBinding(q);
      if (mode === 'invalid') pair.fallback.nodeId = randomUUID();
      return pair;
    });
    requireFallback(child);
    await assert.rejects(a.promise);
    await f.broker.closeAll();
    assert.equal(f.children.length, 1);
    assert.equal(f.fallbackBundles.length, 0);
    assert.equal(child.kills, 0);
  }
});

test('late fallback consumers wait for their own target Use despite a ready shared endpoint', async (t) => {
  const f = fixture(t, 1000, undefined, true),
    a = await fallbackAttempt(f);
  f.ready(a.child);
  const first = await a.promise;
  let resume!: () => void;
  f.setFallbackPlan(
    (q) =>
      new Promise((resolve) => {
        resume = () => resolve(f.fallbackBinding(q));
      }),
  );
  const b = f.acquire();
  let published = false;
  void b.promise.then(() => {
    published = true;
  });
  await tick();
  assert.equal(published, false);
  assert.equal(first.active, true);
  assert.equal(f.children.length, 2);
  resume();
  const second = await b.promise;
  assert.equal(second.active, true);
  assert.equal(second.binding.nodeId, b.input.nodeId);
  assert.equal(second.endpoint, first.endpoint);
  await first.release();
  await second.release();
});

test('primary authentication documents must finish closing before target Use and secondary spawn', async (t) => {
  let closeAllowed = false,
    closes = 0;
  const f = fixture(
    t,
    1000,
    {
      prompt: async () => browserEnvelope(),
      close: async () => {
        closes++;
        if (!closeAllowed) throw Error('document shutdown unconfirmed');
      },
    },
    true,
  );
  const a = await primaryAttempt(f);
  a.child.line(browserChallenge(a.child));
  await tick();
  assert.equal(a.child.requests[1].type, 'browser-authentication');
  requireFallback(a.child);
  await assert.rejects(a.promise);
  await assert.rejects(f.broker.close(a.input.sessionId), /could not be confirmed/);
  assert.equal(f.fallbackPlans.length, 0);
  assert.equal(f.children.length, 1);
  assert.ok(closes >= 2);
  await assert.rejects(f.acquire().promise);
  closeAllowed = true;
  await f.broker.close(a.input.sessionId);
});

test('fallback retirement timeout quarantines the original and closeAll joins delayed admission', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t, 10000, undefined, true),
    a = await primaryAttempt(f);
  a.child.exitOnEnd = false;
  requireFallback(a.child);
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(a.promise);
  await tick();
  const closing = f.broker.closeAll();
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(closing, /could not be confirmed/);
  assert.equal(f.fallbackPlans.length, 0);
  assert.equal(f.children.length, 1);
  assert.equal(a.child.kills, 0);
  a.child.exit();
  await f.broker.closeAll();
  t.mock.timers.reset();

  const g = fixture(t, 1000, undefined, true),
    b = await primaryAttempt(g);
  let resume!: () => void;
  g.setFallbackPlan(
    (q) =>
      new Promise((resolve) => {
        resume = () => resolve(g.fallbackBinding(q));
      }),
  );
  requireFallback(b.child);
  await tick();
  let closed = false;
  const joined = g.broker.closeAll().then(() => {
    closed = true;
  });
  await tick();
  assert.equal(closed, false);
  resume();
  await joined;
  await assert.rejects(b.promise);
  assert.equal(g.children.length, 1);
});

test('fallback cannot reuse an edited target or cross an uncertain target cleanup reservation', async (t) => {
  const f = fixture(t, 1000, undefined, true),
    a = await fallbackAttempt(f);
  f.ready(a.child);
  const lease = await a.promise;
  f.setTargetVersion('2');
  const b = f.acquire();
  await tick();
  assert.equal(f.children.length, 3, 'an edited target cannot reuse the older SSL route');
  assert.equal(f.operations[2], 'tunnel-primary-sealed');
  await f.broker.close(b.input.sessionId);
  await assert.rejects(b.promise);
  a.child.exitOnEnd = false;
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const releasing = lease.release();
  await tick();
  t.mock.timers.tick(8000);
  await assert.rejects(releasing, /could not be confirmed/);
  const target = f.fallbackBundles[0].binding.fallback;
  f.setPlan(async (q) => ({ ...f.binding(q), kind: 2, tunnelConfigId: target.tunnelConfigId }));
  await assert.rejects(f.acquire().promise, /stopping|closed/);
  assert.equal(f.children.length, 3);
  assert.equal(a.child.kills, 0);
  a.child.exit();
  await f.broker.closeAll();
  t.mock.timers.reset();
});

test('fallback rejects a reused recipient, invalid packet and malformed or repeated failure markers', async (t) => {
  for (const mode of [
    'reused-key',
    'changed-packet',
    'wrong-session',
    'wrong-request',
    'extra',
    'trailing',
    'repeated',
    'secondary-failure',
  ]) {
    const f = fixture(t, 1000, undefined, true),
      a = await primaryAttempt(f);
    if (['wrong-session', 'wrong-request', 'extra', 'trailing', 'repeated'].includes(mode)) {
      const marker: any = {
        type: 'fallback-required',
        sessionId: a.child.requests[0].binding.sessionId,
        requestId: a.child.requests[0].binding.requestId,
      };
      if (mode === 'wrong-session') marker.sessionId = randomUUID();
      if (mode === 'wrong-request') marker.requestId = randomUUID();
      if (mode === 'extra') marker.target = randomUUID();
      if (mode === 'trailing') a.child.stdout.write(JSON.stringify(marker) + '\ninvalid');
      else {
        a.child.line(marker);
        if (mode === 'repeated') a.child.line(marker);
      }
    } else {
      if (mode === 'changed-packet')
        f.setFallbackBundle(async (q) => ({
          binding: { ...q.binding, fallback: { ...q.binding.fallback, rowVersion: '99' } },
          bundle: {
            formatVersion: 1,
            suiteId: 2,
            enc: q.publicKey,
            ciphertext: Buffer.alloc(32).toString('base64'),
          },
        }));
      requireFallback(a.child);
      await tick();
      const secondary = f.children[1];
      f.recipient(secondary, mode === 'reused-key' ? 7 : 8);
      await tick();
      if (mode === 'secondary-failure')
        secondary.line({
          type: 'fallback-required',
          sessionId: a.input.sessionId,
          requestId: f.fallbackPlans[0].fallbackRequestId,
        });
    }
    await assert.rejects(a.promise);
    await f.broker.closeAll();
    assert.ok(f.children.length <= 2);
    assert.ok(f.children.every((child) => child.exitCode === 0 && child.kills === 0));
  }
});
test('route SSL cookie handoff accepts the full native frame and keeps its original owner', async (t) => {
  let closes = 0;
  const f = fixture(t, 1000, {
    prompt: async (c) => {
      assert.ok('cookieName' in c);
      return cookieEnvelope();
    },
    close: async () => {
      closes++;
    },
  });
  f.setKind(2);
  const a = f.acquire();
  await tick();
  const child = f.children[0];
  f.recipient(child);
  await tick();
  const challenge = cookieChallenge(child);
  child.line(challenge);
  await tick();
  assert.deepEqual(child.requests[1], {
    type: 'cookie-authentication',
    sessionId: challenge.sessionId,
    challengeId: challenge.challengeId,
    envelope: cookieEnvelope(),
  });
  f.ready(child);
  const lease = await a.promise;
  await lease.release();
  assert.equal(closes, 1);
});
test('SSL cookie frames cannot substitute other browser results or unapproved cookie names', async (t) => {
  for (const mode of ['name', 'http', 'wrong-kind', 'extra', 'oversized', 'duplicate']) {
    const f = fixture(t, 1000, {
      prompt: async () =>
        mode === 'oversized'
          ? { ...cookieEnvelope(), ciphertext: Buffer.alloc(16407).toString('base64') }
          : cookieEnvelope(),
      close: async () => {},
    });
    f.setKind(mode === 'wrong-kind' ? 9 : 2);
    const a = f.acquire();
    await tick();
    const child = f.children[0];
    f.recipient(child);
    await tick();
    const challenge = cookieChallenge(child);
    if (mode === 'name') challenge.cookieName = 'OTHER';
    if (mode === 'http') challenge.startURL = 'http://vpn.test/remote/saml/start';
    if (mode === 'extra') (challenge as any).cookie = 'forbidden';
    child.line(challenge);
    if (mode === 'duplicate') child.line(challenge);
    await assert.rejects(a.promise);
    await f.broker.closeAll();
    assert.equal(child.exitCode, 0);
  }
});
