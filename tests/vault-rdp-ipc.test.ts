import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { VaultRdpIpc, parseVaultRdpOpenRequest } from '../electron/vault-rdp-ipc.ts';
import { VaultRdpController } from '../electron/vault-rdp-controller.ts';
import { vaultRdpConnectRequest, vaultRdpQuickTarget } from '../src/rdp-connect.ts';
const tick = () => new Promise<void>((r) => setImmediate(r));
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
class Owner extends EventEmitter {
  destroyed = false;
  isDestroyed() {
    return this.destroyed;
  }
  send() {}
}
function fixture(t: TestContext, requireContentProtection = false) {
  const owner = new Owner(),
    event = { sender: owner, trusted: true },
    other = { sender: new Owner(), trusted: true };
  let workspace = true,
    unlocked = true,
    auth: ReturnType<typeof deferred> | undefined,
    commit: ReturnType<typeof deferred> | undefined,
    failClose = false,
    failAll = false,
    noBounds = false,
    failTarget = false,
    missingQuick = false,
    targetGate: ReturnType<typeof deferred> | undefined;
  const opened: any[] = [],
    controls: any[] = [],
    forgotten: string[] = [],
    targets: any[] = [],
    released: string[] = [],
    active = new Map<string, () => boolean>(),
    geometry = new Map<string, any>();
  const controller = new VaultRdpController(
    (onEvent) => ({
      open: async (q, _epoch, live) => {
        opened.push(q);
        active.set(q.sessionId, live!);
        onEvent({
          type: 'ready',
          sessionId: q.sessionId,
          lifecycleId: q.sessionId,
          requestId: randomUUID(),
          external: false,
        });
      },
      command: async (id, q) => {
        controls.push([id, q]);
        return { type: 'ack', sessionId: id, lifecycleId: id };
      },
      close: async (id) => {
        if (failClose) throw Error('unconfirmed');
        active.delete(id);
      },
      closeAll: async () => {
        if (failAll) throw Error('unconfirmed');
        active.clear();
      },
    }),
    (epoch) => unlocked && epoch === 1,
  );
  const ipc = new VaultRdpIpc({
    controller,
    workspace: () => workspace,
    trusted: (e) => (e as any).trusted,
    unlocked: async () => {
      if (!unlocked) throw Error('locked');
    },
    authorize: async (run, cleanup) => {
      if (auth) await auth.promise;
      if (!unlocked) {
        await cleanup();
        throw Error('locked');
      }
      const result = await run(1);
      if (commit) await commit.promise;
      return result;
    },
    surface: (e, id, bounds) => {
      const existing = geometry.get(id);
      if (existing && existing.owner !== e.sender) throw Error('another window');
      if (bounds) geometry.set(id, { owner: e.sender, bounds: { ...bounds } });
      const current = geometry.get(id)?.bounds;
      return {
        ownerWindow: '456',
        ...(requireContentProtection ? { requireContentProtection: true as const } : {}),
        bounds:
          noBounds || !current
            ? undefined
            : {
                x: Math.round(current.x * 2),
                y: Math.round(current.y * 2),
                width: Math.round(current.width * 2),
                height: Math.round(current.height * 2),
              },
      };
    },
    quickTarget: async (target, sessionId, epoch, accepted) => {
      if (missingQuick) throw Error('unsupported owner');
      const id = randomUUID();
      targets.push({ target, sessionId, epoch, id, accepted });
      if (targetGate) await targetGate.promise;
      return {
        reference: { workspaceId: randomUUID(), id, sessionId, epoch },
        release: async () => {
          if (failTarget) throw Error('target retirement unconfirmed');
          if (!released.includes(id)) released.push(id);
        },
      };
    },
    forget: (id) => {
      forgotten.push(id);
      geometry.delete(id);
    },
  });
  t.after(async () => {
    failClose = failAll = failTarget = false;
    targetGate?.resolve();
    auth?.resolve();
    commit?.resolve();
    await ipc.closeAll();
  });
  const q = {
    sessionId: randomUUID(),
    nodeId: randomUUID(),
    bounds: { x: -1.5, y: 2.5, width: 800.25, height: 600.5 },
  };
  return {
    ipc,
    controller,
    event,
    other,
    q,
    active,
    opened,
    controls,
    forgotten,
    geometry,
    targets,
    released,
    holdTarget: () => {
      targetGate = deferred();
      return targetGate;
    },
    failTarget: (value: boolean) => (failTarget = value),
    missingQuick: () => (missingQuick = true),
    holdCommit: () => {
      commit = deferred();
      return commit;
    },
    hold: () => {
      auth = deferred();
      return auth;
    },
    workspace: (v: boolean) => (workspace = v),
    unlocked: (v: boolean) => (unlocked = v),
    failClose: (v: boolean) => (failClose = v),
    failAll: (v: boolean) => (failAll = v),
    noBounds: () => (noBounds = true),
  };
}

test('public RDP request and UI builder select node identity and geometry without forwarding profiles', () => {
  const q = {
    sessionId: randomUUID(),
    nodeId: randomUUID(),
    credentialId: randomUUID(),
    bounds: { x: -1.25, y: 0, width: 800, height: 600 },
  };
  assert.deepEqual(parseVaultRdpOpenRequest(q), q);
  const request = vaultRdpConnectRequest({
    ...q,
    host: 'untrusted',
    password: 'must not relay',
    profile: {},
  } as any);
  assert.deepEqual(request, q);
  request.bounds.width = 1;
  assert.equal(q.bounds.width, 800);
  assert.deepEqual(vaultRdpConnectRequest({ ...q, credentialId: undefined }), {
    sessionId: q.sessionId,
    nodeId: q.nodeId,
    bounds: q.bounds,
  });
  for (const patch of [
    { password: '' },
    { host: 'evil' },
    { ownerWindow: '123' },
    { requireContentProtection: true },
    { requireContentProtection: false },
    { profile: {} },
    { publicKey: 'secret' },
    { sessionId: '' },
    { nodeId: '' },
    { credentialId: '' },
    { bounds: { ...q.bounds, width: 0 } },
    { bounds: { ...q.bounds, extra: true } },
    { bounds: { ...q.bounds, x: Infinity } },
    { bounds: null },
  ])
    assert.equal(parseVaultRdpOpenRequest({ ...q, ...patch }), undefined);
  for (const value of [null, {}, [], 1]) assert.equal(parseVaultRdpOpenRequest(value), undefined);
  const temporary = {
    sessionId: q.sessionId,
    nodeId: q.nodeId,
    bounds: q.bounds,
    manualCredentials: true as const,
  };
  assert.deepEqual(parseVaultRdpOpenRequest(temporary), temporary);
  assert.deepEqual(
    vaultRdpConnectRequest({ sessionId: q.sessionId, nodeId: q.nodeId, bounds: q.bounds }, true),
    temporary,
  );
  for (const patch of [
    { manualCredentials: false },
    { manualCredentials: 'true' },
    { manualCredentials: null },
    { credentialId: q.credentialId },
  ])
    assert.equal(parseVaultRdpOpenRequest({ ...temporary, ...patch }), undefined);

  assert.throws(() => vaultRdpConnectRequest(q, true), /temporary/);
  for (const patch of [
    { sessionId: '' },
    { nodeId: undefined },
    { credentialId: '' },
    { bounds: undefined },
    { bounds: { ...q.bounds, width: 0 } },
  ])
    assert.throws(() => vaultRdpConnectRequest({ ...q, ...patch }));
});

test('vault RDP IPC derives the native surface in main and retains authority after the start receipt', async (t) => {
  const f = fixture(t),
    result = await f.ipc.open(f.event, f.q);
  assert.equal(f.opened[0].ownerWindow, '456');
  assert.equal(f.opened[0].bounds.width, 1601);
  assert.equal(f.active.get(f.q.sessionId)!(), true); // admission promise has already finished
  await f.ipc.input(f.event, {
    sessionId: f.q.sessionId,
    lifecycleId: result.lifecycleId,
    input: { kind: 'release' },
  });
  await f.ipc.resize(f.event, {
    sessionId: f.q.sessionId,
    bounds: { x: 1, y: 2, width: 400, height: 300 },
  });
  assert.deepEqual(f.controls.at(-1)[1], {
    op: 'resize',
    bounds: { x: 2, y: 4, width: 800, height: 600 },
  });
  for (const operation of ['show', 'hide', 'focus'])
    await f.ipc.command(f.event, { sessionId: f.q.sessionId, operation });
  f.workspace(false);
  assert.equal(f.ipc.handles(f.q), true);
  assert.equal(f.ipc.handles({ sessionId: randomUUID() }), false);
  const first = f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' });
  await first;
  assert.equal(f.active.size, 0);
  assert.equal(f.ipc.handles(f.q), false);
  assert.ok(f.forgotten.includes(f.q.sessionId));
});

test('disconnect cancels an authorization-pending open and waits until it cannot launch', async (t) => {
  const f = fixture(t),
    authorization = f.hold();
  const opening = f.ipc.open(f.event, f.q);
  void opening.catch(() => {});
  await assert.rejects(f.ipc.open(f.event, f.q), /busy/);
  let closed = false;
  const close = f.ipc
    .command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' })
    .then(() => {
      closed = true;
    });
  await tick();
  assert.equal(closed, false);
  assert.equal(f.opened.length, 0);
  authorization.resolve();
  await assert.rejects(opening);
  await close;
  assert.equal(f.opened.length, 0);
  assert.equal(f.geometry.has(f.q.sessionId), false);
});

test('pending RDP authorization observes geometry updates and owner retirement', async (t) => {
  const f = fixture(t),
    authorization = f.hold(),
    opening = f.ipc.open(f.event, f.q);
  await f.ipc.resize(f.event, {
    sessionId: f.q.sessionId,
    bounds: { x: 0, y: 0, width: 1000, height: 700 },
  });
  authorization.resolve();
  await opening;
  assert.equal(f.opened[0].bounds.width, 2000);
  for (const mode of ['reload', 'destroy', 'untrusted', 'lock', 'workspace', 'global']) {
    const g = fixture(t),
      gate = g.hold(),
      pending = g.ipc.open(g.event, g.q);
    void pending.catch(() => {});
    if (mode === 'reload') g.event.sender.emit('did-start-loading');
    if (mode === 'destroy') {
      g.event.sender.destroyed = true;
      g.event.sender.emit('destroyed');
    }
    if (mode === 'untrusted') g.event.trusted = false;
    if (mode === 'lock') g.unlocked(false);
    if (mode === 'workspace') g.workspace(false);
    const shutdown = mode === 'global' ? g.ipc.closeAll() : undefined;
    gate.resolve();
    await shutdown;
    await assert.rejects(pending);
    assert.equal(g.opened.length, 0, mode);
  }
});

test('RDP IPC rejects malformed controls, cross-window access and stale lifecycle input', async (t) => {
  const f = fixture(t),
    ready = await f.ipc.open(f.event, f.q);
  await assert.rejects(f.ipc.open(f.other, f.q), /owner/);
  for (const run of [
    () =>
      f.ipc.input(f.event, {
        sessionId: f.q.sessionId,
        lifecycleId: ready.lifecycleId,
        input: { kind: 'release', password: '' },
      }),
    () => f.ipc.input(f.event, { sessionId: '', lifecycleId: '', input: null }),
    () => f.ipc.resize(f.event, { sessionId: f.q.sessionId, bounds: {} }),
    () => f.ipc.resize(f.event, { sessionId: f.q.sessionId, extra: true }),
    () => f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'start' }),
    () =>
      f.ipc.command(f.event, {
        sessionId: f.q.sessionId,
        operation: 'disconnect',
        password: 'secret',
      }),
    () =>
      f.ipc.input(f.event, {
        sessionId: f.q.sessionId,
        lifecycleId: randomUUID(),
        input: { kind: 'release' },
      }),
    () => f.ipc.command(f.other, { sessionId: f.q.sessionId, operation: 'disconnect' }),
    () => f.ipc.resize(f.other, { sessionId: f.q.sessionId }),
  ])
    await assert.rejects(run());
  f.event.trusted = false;
  await assert.rejects(f.ipc.resize(f.event, { sessionId: f.q.sessionId }));
  f.event.trusted = true;
  f.unlocked(false);
  await assert.rejects(
    f.ipc.input(f.event, {
      sessionId: f.q.sessionId,
      lifecycleId: ready.lifecycleId,
      input: { kind: 'release' },
    }),
  );
  await assert.rejects(f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'show' }));
  await f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' }); // cleanup while locked
});

test('idle geometry and failed shutdown never open the legacy service or discard a cleanup barrier', async (t) => {
  const f = fixture(t);
  for (const operation of ['show', 'hide', 'focus', 'disconnect'])
    assert.equal(
      (await f.ipc.command(f.event, { sessionId: f.q.sessionId, operation })).type,
      'ack',
    );
  assert.equal(
    (await f.ipc.resize(f.event, { sessionId: f.q.sessionId, bounds: f.q.bounds })).type,
    'ack',
  );
  assert.equal(f.opened.length, 0);
  await f.ipc.open(f.event, f.q);
  f.failClose(true);
  await assert.rejects(
    f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' }),
    /confirmed/,
  );
  await assert.rejects(f.ipc.open(f.event, f.q), /busy/);
  f.failClose(false);
  await f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' });
  await f.ipc.open(f.event, f.q);
  f.failAll(true);
  const closing = f.ipc.closeAll();
  assert.equal(f.ipc.closeAll(), closing);
  await assert.rejects(closing);
  await assert.rejects(f.ipc.open(f.event, f.q), /busy/);
  f.failAll(false);
  await f.ipc.closeAll();
  await f.ipc.open(f.event, f.q);
  f.noBounds();
  await assert.rejects(f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'show' }));
  await assert.rejects(f.ipc.resize(f.event, { sessionId: f.q.sessionId }));
  await f.ipc.closeAll();
  await assert.rejects(f.ipc.open(f.event, f.q));
});

test('RDP IPC remembers pre-admission hide intent without accepting a renderer opening override', async (t) => {
  const f = fixture(t, true);
  await f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'hide' });
  await assert.rejects(f.ipc.command(f.other, { sessionId: f.q.sessionId, operation: 'show' }));
  await assert.rejects(f.ipc.open(f.event, { ...f.q, visible: true }));
  await f.ipc.open(f.event, f.q);
  assert.equal(f.opened[0].visible, false);
  assert.equal(f.opened[0].requireContentProtection, true);
});

test('RDP bounds idle and pending reservations and releases them when an owner closes', async (t) => {
  const f = fixture(t);
  for (let i = 0; i < 64; i++)
    await f.ipc.command(f.event, { sessionId: randomUUID(), operation: 'disconnect' });
  const ids = Array.from({ length: 32 }, () => randomUUID());
  for (const sessionId of ids) await f.ipc.resize(f.event, { sessionId, bounds: f.q.bounds });
  await assert.rejects(f.ipc.open(f.event, f.q), /Close a session/);
  await assert.rejects(
    f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'hide' }),
    /Close a session/,
  );
  await assert.rejects(
    f.ipc.resize(f.event, { sessionId: f.q.sessionId, bounds: f.q.bounds }),
    /Close a session/,
  );
  f.event.sender.emit('did-start-loading');
  await tick();
  assert.equal(f.geometry.size, 0);
  assert.equal(f.event.sender.listenerCount('did-start-loading'), 0);
  assert.equal(f.event.sender.listenerCount('destroyed'), 0);
  await f.ipc.open(f.event, f.q);
  f.event.sender.emit('destroyed');
  await tick();
  assert.equal(f.active.size, 0);
  assert.equal(f.controller.has(f.q.sessionId), false);
});

test('RDP cannot publish a successful start after cancellation during authorization commit', async (t) => {
  const f = fixture(t),
    commit = f.holdCommit();
  const opening = f.ipc.open(f.event, f.q);
  void opening.catch(() => {});
  await tick();
  assert.equal(f.active.size, 1);
  const closing = f.ipc.command(f.event, { sessionId: f.q.sessionId, operation: 'disconnect' });
  await tick();
  commit.resolve();
  await assert.rejects(opening);
  await closing;
  assert.equal(f.active.size, 0);
  assert.equal(f.event.sender.listenerCount('did-start-loading'), 0);
});

test('RDP IPC carries only manual intent to the native owner without credential overrides', async (t) => {
  const f = fixture(t);
  await f.ipc.open(f.event, { ...f.q, manualCredentials: true });
  assert.equal(f.opened[0].manualCredentials, true);
  assert.equal('password' in f.opened[0], false);
});

function quickRdp(f: ReturnType<typeof fixture>, manual = true): any {
  return {
    sessionId: f.q.sessionId,
    bounds: f.q.bounds,
    quickTarget: {
      protocol: 'rdp',
      host: 'quick.example',
      port: 0,
      credentialId: manual ? '' : randomUUID(),
      tunnelId: '',
      sshAutoSudo: false,
      httpPath: '',
      ignoreCertificateErrors: false,
      rdp: null,
    },
    ...(manual ? { manualCredentials: true } : {}),
  };
}
test('RDP Quick Connect accepts only public exclusive RDP metadata and registers under main epoch', async (t) => {
  const f = fixture(t),
    q = quickRdp(f);
  assert.deepEqual(parseVaultRdpOpenRequest(q), q);
  for (const patch of [
    { nodeId: randomUUID() },
    { credentialId: randomUUID() },
    { password: 'secret' },
    { quickTarget: null },
    { quickTarget: { ...q.quickTarget, protocol: 'ssh' } },
    { quickTarget: { ...q.quickTarget, credentialId: randomUUID() } },
    { quickTarget: { ...q.quickTarget, username: 'secret' } },
    { quickTarget: { ...q.quickTarget, host: 'bad\nhost' } },
  ])
    assert.equal(parseVaultRdpOpenRequest({ ...q, ...patch }), undefined);
  await f.ipc.open(f.event, q);
  assert.equal(f.targets.length, 1);
  assert.equal(f.targets[0].epoch, 1);
  assert.equal(f.targets[0].sessionId, q.sessionId);
  assert.equal(f.opened[0].nodeId, f.targets[0].id);
  assert.equal(f.opened[0].manualCredentials, true);
  assert.equal('quickTarget' in f.opened[0], false);
  await f.ipc.command(f.event, { sessionId: q.sessionId, operation: 'disconnect' });
  assert.deepEqual(f.released, [f.targets[0].id]);
  await f.ipc.open(f.event, quickRdp(f, false));
  assert.notEqual(f.targets[0].id, f.targets[1].id);
  assert.equal('manualCredentials' in f.opened[1], false);
});
test('RDP Quick admission waits for late registration retirement on disconnect, reload and global close', async (t) => {
  for (const mode of ['disconnect', 'reload', 'global']) {
    const f = fixture(t),
      gate = f.holdTarget(),
      q = quickRdp(f);
    const opening = f.ipc.open(f.event, q);
    void opening.catch(() => {});
    await tick();
    assert.equal(f.targets.length, 1);
    let done = false;
    if (mode === 'reload') f.event.sender.emit('did-start-loading');
    const closing =
      mode === 'global'
        ? f.ipc.closeAll()
        : f.ipc.command(f.event, { sessionId: q.sessionId, operation: 'disconnect' });
    void closing.then(() => (done = true));
    await tick();
    assert.equal(done, false);
    assert.equal(f.targets[0].accepted(), false);
    gate.resolve();
    await assert.rejects(opening);
    await closing;
    assert.equal(f.opened.length, 0);
    assert.deepEqual(f.released, [f.targets[0].id]);
    assert.equal(f.event.sender.listenerCount('did-start-loading'), 0);
  }
});
test('RDP Quick cleanup preserves failed native and target barriers and supports explicit retry', async (t) => {
  const f = fixture(t),
    q = quickRdp(f);
  await f.ipc.open(f.event, q);
  f.failClose(true);
  await assert.rejects(f.ipc.command(f.event, { sessionId: q.sessionId, operation: 'disconnect' }));
  assert.equal(f.released.length, 0);
  assert.equal(f.controller.has(q.sessionId), true);
  f.failClose(false);
  f.failTarget(true);
  await assert.rejects(f.ipc.closeAll());
  await assert.rejects(f.ipc.open(f.event, q), /busy/);
  assert.equal(f.geometry.has(q.sessionId), true);
  f.failTarget(false);
  await f.ipc.closeAll();
  assert.deepEqual(f.released, [f.targets[0].id]);
  assert.equal(f.controller.has(q.sessionId), false);
  await f.ipc.open(f.event, q);
  await f.ipc.open(f.event, q);
  assert.equal(f.released.length, 2, 'replacement retires the old admission');
  f.missingQuick();
  await assert.rejects(f.ipc.open(f.event, q));
  assert.equal(f.released.length, 3);
});

test('Quick RDP UI builder validates exclusive public metadata and owns normalized profile copies', (t) => {
  const f = fixture(t),
    q = quickRdp(f);
  for (const patch of [
    { nodeId: randomUUID() },
    { credentialId: randomUUID() },
    { quickTarget: null },
    { quickTarget: { ...q.quickTarget, protocol: 'vnc' } },
    { quickTarget: { ...q.quickTarget, credentialId: randomUUID() } },
  ])
    assert.throws(() => vaultRdpConnectRequest({ ...q, ...patch }, true));
  assert.deepEqual(vaultRdpConnectRequest(q, true), q);
  assert.throws(() => vaultRdpQuickTarget({ host: 'bad/path', rdp: null as any }));
  assert.throws(() => vaultRdpConnectRequest({ ...q, bounds: undefined }, true));
});
