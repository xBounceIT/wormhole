import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { VaultWebIpc } from '../electron/vault-web-ipc.ts';
import { vaultWebQuickTarget, webConnectRequest } from '../src/web-connect.ts';
import { parseVaultWebRequest } from '../electron/vault-web-open.ts';

const tick = () => new Promise(setImmediate);
const defer = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function fixture(t: TestContext) {
  let workspace = true,
    trusted = true,
    destroyed = false,
    failClose = false,
    failAll = false;
  let auth: Promise<void> | undefined,
    native: Promise<void> | undefined,
    finalizing: Promise<void> | undefined,
    lost = false;
  const opens: any[] = [],
    closes: string[] = [],
    cleanups: (() => Promise<void>)[] = [];
  const owner = Object.assign(new EventEmitter(), { isDestroyed: () => destroyed });
  const other = Object.assign(new EventEmitter(), { isDestroyed: () => false });
  const event = { sender: owner };
  const ipc = new VaultWebIpc({
    workspace: () => workspace,
    trusted: () => trusted,
    authorize: async (run, cleanup) => {
      cleanups.push(cleanup);
      await auth;
      if (lost) {
        await cleanup();
        throw Error('locked');
      }
      return run();
    },
    open: async (sender, q, current) => {
      opens.push({ sender, q, current });
      await native;
      return { public: true };
    },
    close: async (sender, id) => {
      assert.equal(sender, owner);
      closes.push(id);
      await finalizing;
      if (failClose) throw Error('unconfirmed');
    },
    closeAll: async () => {
      if (failAll) throw Error('unconfirmed');
    },
  });
  t.after(async () => {
    failClose = failAll = false;
    await ipc.closeAll();
  });
  const input = { sessionId: randomUUID(), attempt: 1, nodeId: randomUUID() };
  return {
    ipc,
    input,
    owner,
    other,
    event,
    opens,
    closes,
    cleanups,
    open: (q: any = input) => ipc.open(event, q),
    state: (value: any) => {
      if ('workspace' in value) workspace = value.workspace;
      if ('trusted' in value) trusted = value.trusted;
      if ('destroyed' in value) destroyed = value.destroyed;
      if ('failClose' in value) failClose = value.failClose;
      if ('failAll' in value) failAll = value.failAll;
      if ('auth' in value) auth = value.auth;
      if ('native' in value) native = value.native;
      if ('finalizing' in value) finalizing = value.finalizing;
      if ('lost' in value) lost = value.lost;
    },
  };
}

test('trusted close retains only the existing browser authority until checkpoint or owner revocation', async (t) => {
  const f = fixture(t);
  await f.open();
  const lastWrite = defer();
  f.state({ finalizing: lastWrite.promise });
  const close = f.ipc.close(f.event, f.input.sessionId);
  await tick();
  assert.equal(f.opens[0].current(), true);
  await assert.rejects(f.open(), /unavailable/);
  f.owner.emit('did-start-loading');
  assert.equal(f.opens[0].current(), false);
  lastWrite.resolve();
  await close;
});

test('public browser input is exact, copied and never accepts userinfo or credential material', () => {
  const session = {
    id: randomUUID(),
    protocol: 'https',
    host: 'HTTPS://[::1]:8443/path%2Fpart?q=a#b',
  };
  const target = vaultWebQuickTarget({ ...session, ignoreCertificateErrors: true });
  assert.equal(target.host, session.host, 'Go owns address normalization');
  assert.equal(target.credentialId, '');
  assert.equal(target.ignoreCertificateErrors, true);
  const q = webConnectRequest({ ...session, quickTarget: target }, 2, true);
  assert.deepEqual(q, { sessionId: session.id, attempt: 2, quickTarget: target });
  target.host = 'changed';
  assert.equal(q.quickTarget!.host, session.host);
  const nodeId = randomUUID();
  assert.deepEqual(webConnectRequest({ ...session, webTargetNodeId: nodeId }, 3, true), {
    sessionId: session.id,
    attempt: 3,
    nodeId,
  });
  assert.deepEqual(webConnectRequest({ ...session, webTargetNodeId: nodeId }, 3, false), {
    sessionId: session.id,
    attempt: 3,
    nodeId,
  });
  assert.equal(webConnectRequest(session, 3, false).ignoreCertErrors, false);
  assert.equal(
    webConnectRequest({ ...session, webIgnoreCertErrors: true }, 3, false).ignoreCertErrors,
    true,
  );
  for (const value of [
    null,
    {},
    { ...q, attempt: 0 },
    { ...q, attempt: 1.1 },
    { ...q, attempt: Number.MAX_SAFE_INTEGER + 1 },
    { ...q, password: 'private' },
    { ...q, nodeId },
    { ...q, quickTarget: { ...q.quickTarget, recipient: {} } },
  ])
    assert.equal(parseVaultWebRequest(value), undefined);
  for (const value of [
    { ...session, host: 'https://user:password@host/path' },
    { ...session, host: 'user@host' },
    { ...session, host: 'a'.repeat(4097) },
    { ...session, host: 'bad host' },
    { ...session, host: 'host\\path' },
    { ...session, protocol: 'ssh' },
    { ...session, protocol: 'http', ignoreCertificateErrors: true },
    { ...session, tunnelId: 'bad' },
  ])
    assert.throws(() => vaultWebQuickTarget(value));
  assert.equal(
    vaultWebQuickTarget({ protocol: 'http', host: 'host/path@name', port: 80, tunnelId: nodeId })
      .tunnelId,
    nodeId,
  );
  for (const value of [session, { ...session, webTargetNodeId: nodeId, quickTarget: target }])
    assert.throws(() => webConnectRequest(value, 1, true));
});

test('web owner reservation precedes authorization and cancellation joins the queued open', async (t) => {
  const f = fixture(t),
    gate = defer();
  f.state({ auth: gate.promise });
  const opening = f.open();
  void opening.catch(() => {});
  assert.equal(f.ipc.handles(f.input.sessionId), true);
  await assert.rejects(f.open());
  let stopped = false;
  const closing = f.ipc.close(f.event, f.input.sessionId).then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(stopped, false);
  gate.resolve();
  await assert.rejects(opening);
  await closing;
  assert.equal(f.opens.length, 0);
  f.state({ workspace: false });
  assert.equal(f.ipc.handles(f.input.sessionId), false);
  await f.ipc.close(f.event, f.input.sessionId);
  f.state({ workspace: true, auth: undefined });
  await f.open();
});

test('web cancellation joins late native preparation and preserves failed cleanup for retry', async (t) => {
  const f = fixture(t),
    gate = defer();
  f.state({ native: gate.promise });
  const opening = f.open();
  void opening.catch(() => {});
  await tick();
  const closing = f.ipc.close(f.event, f.input.sessionId);
  assert.equal(f.ipc.close(f.event, f.input.sessionId), closing);
  let stopped = false;
  void closing.then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(stopped, false);
  gate.resolve();
  await assert.rejects(opening);
  await closing;
  assert.equal(f.opens[0].current(), false);
  f.state({ native: undefined });
  await f.open();
  f.state({ failClose: true });
  await assert.rejects(f.ipc.close(f.event, f.input.sessionId));
  await assert.rejects(f.open());
  f.state({ failClose: false });
  await f.ipc.close(f.event, f.input.sessionId);
  await f.open();
});

test('web admission rejects foreign owners, untrusted documents, malformed input and locked workspaces', async (t) => {
  const f = fixture(t);
  await assert.rejects(f.open(null));
  await assert.rejects(f.open({ ...f.input, password: 'private' }));
  for (const state of [{ trusted: false }, { destroyed: true }, { workspace: false }]) {
    f.state(state);
    await assert.rejects(f.open());
    f.state({ trusted: true, destroyed: false, workspace: true });
  }
  await f.open();
  await assert.rejects(f.ipc.open({ sender: f.other }, f.input));
  assert.throws(() => f.ipc.close({ sender: f.other }, f.input.sessionId));
  assert.throws(() => f.ipc.close(f.event, 'bad'));
  f.state({ trusted: false });
  assert.equal(f.opens[0].current(), false);
  assert.throws(() => f.ipc.close(f.event, f.input.sessionId));
  f.state({ trusted: true });
  await f.open();
  const count = f.closes.length;
  await f.cleanups[0]();
  assert.equal(f.closes.length, count, 'stale auth cleanup cannot close a replacement browser');
  assert.equal(f.opens[1].current(), true);
});

test('web root lifecycle retires all owned browsers and removes hooks after confirmed close', async (t) => {
  for (const name of ['did-start-loading', 'render-process-gone', 'destroyed']) {
    const f = fixture(t);
    await f.open();
    await f.open({ ...f.input, sessionId: randomUUID() });
    assert.equal(f.owner.listenerCount(name), 1);
    if (name === 'destroyed') f.state({ destroyed: true });
    f.owner.emit(name);
    await tick();
    assert.equal(
      f.opens.every((e) => !e.current()),
      true,
    );
    assert.equal(f.owner.listenerCount(name), 0);
  }
});

test('web global stop joins authorization, bounds admission and permits only an explicit confirmed retry', async (t) => {
  const f = fixture(t),
    gate = defer();
  f.state({ auth: gate.promise });
  const openings = Array.from({ length: 32 }, () =>
    f.open({ ...f.input, sessionId: randomUUID() }),
  );
  for (const p of openings) void p.catch(() => {});
  await assert.rejects(f.open());
  const shutdown = f.ipc.closeAll();
  assert.equal(f.ipc.closeAll(), shutdown);
  await assert.rejects(f.open());
  let stopped = false;
  void shutdown.then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(stopped, false);
  gate.resolve();
  await Promise.allSettled(openings);
  await shutdown;
  assert.equal(f.opens.length, 0);
  f.state({ auth: undefined });
  await f.open();
  f.state({ failAll: true });
  await assert.rejects(f.ipc.closeAll());
  await assert.rejects(f.open());
  f.state({ failAll: false });
  await f.ipc.closeAll();
  await f.open();
});

test('web failed authorization and native open cleanup do not release an uncertain reservation', async (t) => {
  const f = fixture(t);
  f.state({ lost: true });
  await assert.rejects(f.open());
  f.state({ lost: false });
  await f.open();
  await f.ipc.close(f.event, f.input.sessionId);
  f.state({ lost: true, failClose: true });
  await assert.rejects(f.open());
  await assert.rejects(f.open());
  f.state({ lost: false, failClose: false });
  await f.ipc.close(f.event, f.input.sessionId);
  await f.open({
    sessionId: f.input.sessionId,
    attempt: 2,
    quickTarget: vaultWebQuickTarget({ protocol: 'https', host: 'https://example/path?q=x#f' }),
  });
  assert.equal(f.opens.at(-1).q.quickTarget.host, 'https://example/path?q=x#f');
});
