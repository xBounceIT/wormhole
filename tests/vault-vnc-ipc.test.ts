import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { VaultVncIpc } from '../electron/vault-vnc-ipc.ts';
import { VaultVncController, parseVaultVncCommand } from '../electron/vault-vnc-controller.ts';
import { vaultVncQuickTarget, vncConnectRequest } from '../src/vnc-connect.ts';

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((yes) => {
    resolve = yes;
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
function fixture(t: TestContext) {
  const owner = new Owner(),
    event = { sender: owner, trusted: true },
    other = { sender: new Owner(), trusted: true };
  let workspace = true,
    unlocked = true,
    failClose = false,
    failAll = false,
    failRelease = false,
    failRegister = false,
    cleanupOnError = false,
    retireOnInput = false;
  let auth: ReturnType<typeof deferred> | undefined,
    admission: ReturnType<typeof deferred> | undefined,
    commit: ReturnType<typeof deferred> | undefined;
  let forward!: (event: any) => void;
  const calls: any[] = [],
    targets: any[] = [],
    active = new Set<string>(),
    liveTargets = new Set<string>();
  const controller = new VaultVncController(
    (receive) => {
      forward = receive;
      return {
        open: async (q, epoch, accepted) => {
          calls.push(['open', q, epoch, accepted]);
          active.add(q.sessionId);
        },
        send: (id, q) => {
          calls.push(['input', id, q]);
          if (retireOnInput) event.trusted = false;
        },
        close: async (id) => {
          calls.push(['close', id]);
          if (failClose) throw Error('unconfirmed native');
          active.delete(id);
        },
        closeAll: async () => {
          if (failAll) throw Error('unconfirmed all');
          active.clear();
        },
      };
    },
    (epoch) => unlocked && epoch === 3,
  );
  const ipc = new VaultVncIpc({
    controller,
    workspace: () => workspace,
    trusted: (e) => (e as any).trusted,
    authorize: async (run, cleanup) => {
      if (auth) await auth.promise;
      if (!unlocked) {
        await cleanup();
        throw Error('locked');
      }
      try {
        const result = await run(3);
        if (commit) await commit.promise;
        return result;
      } catch (error) {
        if (cleanupOnError) await cleanup();
        throw error;
      }
    },
    quickTarget: async (target, sessionId, epoch, accepted) => {
      if (failRegister) throw Error('unsupported owner');
      const id = randomUUID();
      targets.push({ id, target, sessionId, epoch, accepted });
      liveTargets.add(id);
      if (admission) await admission.promise;
      return {
        reference: { workspaceId: randomUUID(), id, sessionId, epoch },
        release: async () => {
          calls.push(['release', id]);
          if (failRelease) throw Error('unconfirmed release');
          liveTargets.delete(id);
        },
      };
    },
  });
  t.after(async () => {
    failClose = failAll = failRelease = false;
    auth?.resolve();
    admission?.resolve();
    commit?.resolve();
    await ipc.closeAll();
  });
  const q = { action: 'vnc.connect', sessionId: randomUUID(), nodeId: randomUUID() };
  return {
    ipc,
    controller,
    event,
    other,
    q,
    calls,
    targets,
    active,
    liveTargets,
    forward: (e: any) => forward(e),
    retireOnInput: () => {
      retireOnInput = true;
    },
    cleanupOnError: () => {
      cleanupOnError = true;
    },
    clearAuth: () => {
      auth = undefined;
    },
    holdAuth: () => {
      auth = deferred();
      return auth;
    },
    holdTarget: () => {
      admission = deferred();
      return admission;
    },
    holdCommit: () => {
      commit = deferred();
      return commit;
    },
    workspace: (v: boolean) => (workspace = v),
    unlock: (v: boolean) => (unlocked = v),
    failClose: (v: boolean) => (failClose = v),
    failAll: (v: boolean) => (failAll = v),
    failRelease: (v: boolean) => (failRelease = v),
    failRegister: () => (failRegister = true),
  };
}
const disconnect = (f: ReturnType<typeof fixture>) =>
  f.ipc.command(f.event, { action: 'vnc.disconnect', sessionId: f.q.sessionId });
function quick(f: ReturnType<typeof fixture>, saved = false): any {
  return {
    action: 'vnc.connect',
    sessionId: f.q.sessionId,
    quickTarget: vaultVncQuickTarget({
      host: 'quick.example',
      ...(saved ? { credentialId: randomUUID() } : {}),
    }),
    ...(saved ? {} : { manualPassword: true }),
  };
}

test('public VNC Quick commands contain only exclusive validated metadata and protected manual intent', async (t) => {
  const f = fixture(t),
    q = quick(f);
  assert.deepEqual(parseVaultVncCommand(q), q);
  for (const patch of [
    { nodeId: randomUUID() },
    { credentialId: randomUUID() },
    { password: 'secret' },
    { quickTarget: null },
    { quickTarget: { ...q.quickTarget, protocol: 'rdp' } },
    { quickTarget: { ...q.quickTarget, password: '' } },
    { quickTarget: { ...q.quickTarget, credentialId: randomUUID() } },
    { manualPassword: false },
  ])
    assert.equal(parseVaultVncCommand({ ...q, ...patch }), undefined);
  const request = vncConnectRequest(
    { id: q.sessionId, host: 'ignored', quickTarget: q.quickTarget },
    true,
    undefined,
    true,
  );
  assert.deepEqual(request, q);
  const absent = vncConnectRequest(
    { id: q.sessionId, host: 'ignored', quickTarget: q.quickTarget },
    true,
  );
  assert.equal(
    'manualPassword' in absent,
    false,
    'absence must remain distinct from explicit manual entry',
  );
  assert.throws(
    () =>
      vncConnectRequest({ id: q.sessionId, host: 'ignored', quickTarget: q.quickTarget }, true, ''),
    /protected/,
  );
  assert.throws(() => vaultVncQuickTarget({ host: 'bad/path' }));
  await f.ipc.command(f.event, request);
  const call = f.calls.find((c) => c[0] === 'open');
  assert.equal(call[1].nodeId, f.targets[0].id);
  assert.equal(call[2], 3);
  assert.equal(call[1].manualPassword, true);
  assert.equal('quickTarget' in call[1], false);
  assert.equal(f.targets[0].sessionId, q.sessionId);
  assert.equal(f.targets[0].epoch, 3);
  await disconnect(f);
  assert.equal(f.liveTargets.size, 0);
  assert.ok(
    f.calls.findIndex((c) => c[0] === 'close') < f.calls.findIndex((c) => c[0] === 'release'),
  );
  await f.ipc.command(f.event, quick(f, true));
  assert.notEqual(f.targets[0].id, f.targets[1].id);
  assert.equal('manualPassword' in f.calls.filter((c) => c[0] === 'open')[1][1], false);
});

test('VNC reserves before authorization and joins cancellation, reload, destruction and global shutdown', async (t) => {
  for (const stage of ['auth', 'target'])
    for (const mode of [
      'disconnect',
      'reload',
      'destroy',
      'global',
      'lock',
      'workspace',
      'trust',
    ]) {
      const f = fixture(t),
        gate = stage === 'auth' ? f.holdAuth() : f.holdTarget();
      const pending = f.ipc.command(f.event, quick(f));
      void pending.catch(() => {});
      await tick();
      await assert.rejects(f.ipc.command(f.event, quick(f)), /busy/);
      await assert.rejects(f.ipc.command(f.other, quick(f)), /owner/);
      let done = false;
      if (mode === 'reload') f.event.sender.emit('did-start-loading');
      if (mode === 'destroy') {
        f.event.sender.destroyed = true;
        f.event.sender.emit('destroyed');
      }
      if (mode === 'lock') f.unlock(false);
      if (mode === 'workspace') f.workspace(false);
      if (mode === 'trust') f.event.trusted = false;
      const closing =
        mode === 'global'
          ? f.ipc.closeAll()
          : mode === 'destroy' || mode === 'trust'
            ? undefined
            : disconnect(f);
      void closing?.then(() => (done = true));
      await tick();
      if (closing) assert.equal(done, false);
      gate.resolve();
      await assert.rejects(pending);
      await closing;
      await tick();
      assert.equal(
        f.calls.some((c) => c[0] === 'open'),
        false,
        stage + ':' + mode,
      );
      assert.equal(f.liveTargets.size, 0, stage + ':' + mode);
      assert.equal(f.event.sender.listenerCount('did-start-loading'), 0);
    }
});

test('VNC events, controls and cleanup remain bound to the owning main document after workspace retirement', async (t) => {
  const f = fixture(t);
  assert.equal(f.ipc.handles(null), true);
  await assert.rejects(f.ipc.command(f.event, null));
  f.event.trusted = false;
  await assert.rejects(f.ipc.command(f.event, f.q));
  f.event.trusted = true;
  await f.ipc.command(f.event, f.q);
  for (const action of [
    { action: 'vnc.pointer', x: 0, y: 1, buttons: 0 },
    { action: 'vnc.key', keysym: 65, down: true },
  ])
    await f.ipc.command(f.event, { ...action, sessionId: f.q.sessionId });
  assert.equal(f.calls.filter((c) => c[0] === 'input').length, 2);
  await assert.rejects(
    f.ipc.command(f.other, { action: 'vnc.key', sessionId: f.q.sessionId, keysym: 65, down: true }),
    /owner/,
  );
  f.workspace(false);
  assert.equal(f.ipc.handles(f.q), true);
  assert.equal(f.ipc.handles({ sessionId: randomUUID() }), false);
  await assert.rejects(
    f.ipc.command(f.event, { action: 'vnc.key', sessionId: f.q.sessionId, keysym: 65, down: true }),
  );
  await disconnect(f);
  assert.equal(f.ipc.handles(f.q), false);
  assert.equal(f.ipc.handles(null), false);
  await disconnect(f);
  await assert.rejects(f.ipc.command(f.event, f.q), /locked/);
  f.workspace(true);
  await f.ipc.command(f.event, quick(f));
  f.forward({ type: 'vnc.status', sessionId: f.q.sessionId, status: 'disconnected' });
  await tick();
  assert.equal(f.liveTargets.size, 0);
  assert.equal(f.controller.has(f.q.sessionId), false);
  await disconnect(f);
  assert.equal(f.event.sender.listenerCount('destroyed'), 0);
});

test('VNC failed native or target cleanup keeps reservations until confirmed retry', async (t) => {
  const f = fixture(t);
  await f.ipc.command(f.event, quick(f));
  f.failClose(true);
  await assert.rejects(disconnect(f));
  assert.equal(f.liveTargets.size, 1);
  await assert.rejects(f.ipc.command(f.event, quick(f)), /busy/);
  f.failClose(false);
  f.failRelease(true);
  await assert.rejects(f.ipc.closeAll());
  assert.equal(f.controller.has(f.q.sessionId), true);
  assert.equal(f.liveTargets.size, 1);
  f.failRelease(false);
  await f.ipc.closeAll();
  assert.equal(f.liveTargets.size, 0);
  await f.ipc.command(f.event, quick(f));
  await f.ipc.command(f.event, quick(f));
  assert.equal(f.liveTargets.size, 1);
  f.failRegister();
  await assert.rejects(f.ipc.command(f.event, quick(f)));
  assert.equal(f.liveTargets.size, 0);
  await f.ipc.command(f.event, f.q);
  f.failAll(true);
  await assert.rejects(f.ipc.closeAll());
  await assert.rejects(f.ipc.command(f.event, f.q), /busy/);
  f.failAll(false);
  await f.ipc.closeAll();
});

test('VNC close waits for authorization commit and rejects late success', async (t) => {
  const f = fixture(t),
    gate = f.holdCommit();
  const pending = f.ipc.command(f.event, quick(f));
  void pending.catch(() => {});
  await tick();
  assert.equal(f.active.size, 1);
  const closed = disconnect(f);
  await tick();
  gate.resolve();
  await assert.rejects(pending);
  await closed;
  assert.equal(f.active.size, 0);
  assert.equal(f.liveTargets.size, 0);
});

test('VNC owner capacity is bounded and reload retires every reservation', async (t) => {
  const f = fixture(t);
  f.event.sender.setMaxListeners(100);
  for (let i = 0; i < 32; i++) await f.ipc.command(f.event, { ...f.q, sessionId: randomUUID() });
  await assert.rejects(f.ipc.command(f.event, f.q), /Close a session/);
  f.event.sender.emit('did-start-loading');
  await tick();
  await tick();
  assert.equal(f.active.size, 0);
  assert.equal(f.event.sender.listenerCount('destroyed'), 0);
});

test('queued VNC input cannot cross a same-window session replacement', async (t) => {
  const f = fixture(t);
  await f.ipc.command(f.event, f.q);
  f.cleanupOnError();
  const gate = f.holdAuth();
  const input = f.ipc.command(f.event, {
    action: 'vnc.key',
    sessionId: f.q.sessionId,
    keysym: 65,
    down: true,
  });
  void input.catch(() => {});
  await tick();
  f.clearAuth();
  await f.ipc.command(f.event, f.q);
  gate.resolve();
  await assert.rejects(input);
  assert.equal(
    f.calls.filter((c) => c[0] === 'input').length,
    0,
    'old keyboard event must not reach the new native connection',
  );
  assert.equal(f.controller.has(f.q.sessionId), true);
});

test('VNC cannot acknowledge an input after its owner loses trust during the native send', async (t) => {
  const f = fixture(t);
  await f.ipc.command(f.event, quick(f));
  f.cleanupOnError();
  f.retireOnInput();
  await assert.rejects(
    f.ipc.command(f.event, { action: 'vnc.key', sessionId: f.q.sessionId, keysym: 65, down: true }),
    /cancelled/,
  );
  assert.equal(f.liveTargets.size, 0);
  assert.equal(f.active.size, 0);
});
