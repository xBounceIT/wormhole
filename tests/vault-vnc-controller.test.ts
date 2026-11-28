import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { VaultVncController, parseVaultVncCommand } from '../electron/vault-vnc-controller.ts';
import { vncConnectRequest } from '../src/vnc-connect.ts';
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
class Owner extends EventEmitter {
  destroyed = false;
  sent: any[] = [];
  failSend = false;
  isDestroyed() {
    return this.destroyed;
  }
  send(channel: string, event: unknown) {
    if (this.failSend) throw Error('closed');
    this.sent.push({ channel, event });
  }
}
function fixture() {
  let forward!: (event: any) => void,
    allowed = true,
    trusted = true,
    failClose = false,
    failAll = false,
    hold = false;
  const calls: any[] = [],
    pending = new Map<string, { resolve: () => void; reject: (error: Error) => void }>();
  const controller = new VaultVncController(
    (receive) => {
      forward = receive;
      return {
        open: (q: any, epoch: number, current: () => boolean) => {
          calls.push(['open', q, epoch, current]);
          if (!hold) return Promise.resolve();
          return new Promise<void>((resolve, reject) =>
            pending.set(q.sessionId, { resolve, reject }),
          );
        },
        send: (id: string, value: unknown) => {
          calls.push(['send', id, value]);
        },
        close: (id: string) => {
          calls.push(['close', id]);
          pending.get(id)?.reject(Error('native stopped'));
          pending.delete(id);
          forward({ type: 'vnc.status', sessionId: id, status: 'disconnected' });
          return failClose ? Promise.reject(Error('unconfirmed')) : Promise.resolve();
        },
        closeAll: () => {
          calls.push(['all']);
          return failAll ? Promise.reject(Error('unconfirmed')) : Promise.resolve();
        },
      };
    },
    (epoch) => allowed && epoch === 1,
  );
  const owner = new Owner(),
    id = randomUUID(),
    q = { action: 'vnc.connect' as const, sessionId: id, nodeId: randomUUID() };
  const command = (value: any = q, source = owner) =>
    controller.command(source as any, () => trusted, value, 1);
  return {
    controller,
    calls,
    pending,
    owner,
    id,
    q,
    command,
    forward: (event: any) => forward(event),
    setAllowed: (v: boolean) => (allowed = v),
    setTrusted: (v: boolean) => (trusted = v),
    setHold: () => (hold = true),
    setFailClose: (value = true) => (failClose = value),
    setFailAll: (value = true) => (failAll = value),
  };
}

test('vault VNC command schema rejects overrides and preserves only exact public controls', () => {
  const id = randomUUID(),
    nodeId = randomUUID(),
    credentialId = randomUUID();
  for (const command of [
    { action: 'vnc.connect', sessionId: id, nodeId },
    { action: 'vnc.connect', sessionId: id, nodeId, manualPassword: true },
    { action: 'vnc.connect', sessionId: id, nodeId, credentialId },
    { action: 'vnc.disconnect', sessionId: id },
    { action: 'vnc.pointer', sessionId: id, x: 0, y: 65535, buttons: 255 },
    { action: 'vnc.key', sessionId: id, keysym: 0xffffffff, down: true },
  ])
    assert.deepEqual(parseVaultVncCommand(command), command);
  for (const value of [
    null,
    [],
    {},
    ...[false, 'true', null, 1].map((manualPassword) => ({
      action: 'vnc.connect',
      sessionId: id,
      nodeId,
      manualPassword,
    })),
    { action: 'other', sessionId: id },
    { action: 'vnc.connect', sessionId: id },
    { action: 'vnc.connect', sessionId: id, nodeId, credentialId: 'bad' },
    { action: 'vnc.connect', sessionId: id, nodeId, password: 'secret' },
    { action: 'vnc.connect', sessionId: id, nodeId, host: 'attacker' },
    { action: 'vnc.disconnect', sessionId: id, extra: true },
    { action: 'vnc.pointer', sessionId: id, x: -1, y: 0, buttons: 0 },
    { action: 'vnc.pointer', sessionId: id, x: 0, y: 0, buttons: 256 },
    { action: 'vnc.key', sessionId: id, keysym: 0, down: true },
    { action: 'vnc.key', sessionId: id, keysym: 1, down: 1 },
  ])
    assert.equal(parseVaultVncCommand(value), undefined);
  const session = {
    id,
    nodeId,
    credentialId,
    host: 'untrusted UI',
    port: 1,
    tunnelConfigId: randomUUID(),
  };
  assert.deepEqual(vncConnectRequest(session, true), {
    action: 'vnc.connect',
    sessionId: id,
    nodeId,
    credentialId,
  });
  assert.deepEqual(vncConnectRequest({ ...session, credentialId: undefined }, true), {
    action: 'vnc.connect',
    sessionId: id,
    nodeId,
  });
  assert.throws(
    () => vncConnectRequest({ ...session, nodeId: undefined }, true),
    /target is invalid/,
  );
  assert.throws(() => vncConnectRequest(session, true, 'secret'), /protected/);
  assert.deepEqual(vncConnectRequest(session, false, ''), {
    action: 'vnc.connect',
    sessionId: id,
    nodeId,
    credentialId,
    host: session.host,
    port: 1,
    tunnelConfigId: session.tunnelConfigId,
    password: '',
    passwordProvided: true,
  });
  assert.equal('password' in vncConnectRequest(session, false), false);
});

test('VNC controller binds session IDs, controls and events to the initiating window', async () => {
  const f = fixture(),
    other = new Owner();
  await f.command();
  assert.equal(f.calls[0][0], 'open');
  assert.equal(f.calls[0][2], 1);
  assert.equal(f.calls[0][3](), true);
  await f.command({ action: 'vnc.key', sessionId: f.id, keysym: 1, down: true });
  assert.deepEqual(f.calls.at(-1), [
    'send',
    f.id,
    { type: 'key', sessionId: f.id, keysym: 1, down: true },
  ]);
  await f.command({ action: 'vnc.pointer', sessionId: f.id, x: 0, y: 0, buttons: 1 });
  assert.equal(f.calls.at(-1)[2].type, 'pointer');
  for (const action of ['vnc.connect', 'vnc.disconnect', 'vnc.key'])
    await assert.rejects(f.command({ ...f.q, action }, other), /another window/);
  const frame = { type: 'vnc.frame', sessionId: f.id, width: 1, height: 1, image: 'public frame' };
  f.forward(frame);
  assert.deepEqual(f.owner.sent, [{ channel: 'backend:event', event: frame }]);
  assert.equal(other.sent.length, 0);
  f.forward({ ...frame, sessionId: randomUUID() });
  assert.equal(f.owner.sent.length, 1);
  await f.controller.closeForOwner(other as any, f.id);
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 0);
  await f.controller.closeForOwner(f.owner as any, f.id);
  assert.equal(f.owner.listenerCount('destroyed'), 0);
  assert.equal(f.owner.listenerCount('did-start-loading'), 0);
  await f.command({ action: 'vnc.disconnect', sessionId: f.id });
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 1);
});

test('VNC owner retirement, trust changes and lock drop events and close the native session', async () => {
  for (const mode of ['destroy', 'reload', 'untrusted', 'locked', 'send-error']) {
    const f = fixture();
    await f.command();
    if (mode === 'destroy') {
      f.owner.destroyed = true;
      f.owner.emit('destroyed');
    }
    if (mode === 'reload') f.owner.emit('did-start-loading');
    if (mode === 'untrusted') f.setTrusted(false);
    if (mode === 'locked') f.setAllowed(false);
    if (mode === 'send-error') f.owner.failSend = true;
    f.forward({
      type: 'vnc.frame',
      sessionId: f.id,
      width: 1,
      height: 1,
      image: 'must not forward',
    });
    await tick();
    assert.equal(f.calls.filter((c) => c[0] === 'close').length, 1, mode);
    assert.equal(f.owner.sent.length, 0, mode);
    await f.controller.closeAll();
  }
});

test('VNC reconnect replaces an opening generation without letting its late cleanup kill the replacement', async () => {
  const f = fixture();
  f.setHold();
  const first = f.command();
  void first.catch(() => {});
  const second = f.command();
  void second.catch(() => {});
  const third = f.command();
  void third.catch(() => {});
  await tick();
  assert.equal(f.calls.filter((c) => c[0] === 'open').length, 2);
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 2);
  f.pending.get(f.id)!.resolve();
  await third;
  await assert.rejects(first, /could not/);
  await assert.rejects(second, /could not/);
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 2);
  assert.equal(f.owner.sent.length, 0);
  await f.command({ action: 'vnc.disconnect', sessionId: f.id });
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 3);
});

test('VNC pending close, stale admission and terminal native events clean up exactly once', async () => {
  for (const mode of ['close', 'locked', 'untrusted', 'failed', 'disconnected']) {
    const f = fixture();
    f.setHold();
    const opening = f.command();
    void opening.catch(() => {});
    if (mode === 'close') await f.command({ action: 'vnc.disconnect', sessionId: f.id });
    if (mode === 'locked') {
      f.setAllowed(false);
      f.pending.get(f.id)!.resolve();
    }
    if (mode === 'untrusted') {
      f.setTrusted(false);
      f.pending.get(f.id)!.resolve();
    }
    if (mode === 'failed' || mode === 'disconnected')
      f.forward({ type: 'vnc.status', sessionId: f.id, status: mode });
    await assert.rejects(opening, /could not/);
    await tick();
    assert.equal(f.calls.filter((c) => c[0] === 'close').length, 1);
    assert.equal(f.owner.sent.length, mode === 'failed' || mode === 'disconnected' ? 1 : 0);
  }
});

test('VNC authorization and global shutdown gate access without blocking trusted cleanup', async () => {
  const f = fixture();
  f.setTrusted(false);
  await assert.rejects(f.command(), /owner/);
  f.setTrusted(true);
  f.owner.destroyed = true;
  await assert.rejects(f.command(), /owner/);
  f.owner.destroyed = false;
  f.setAllowed(false);
  await assert.rejects(f.command(), /locked/);
  await f.command({ action: 'vnc.disconnect', sessionId: f.id });
  f.setAllowed(true);
  await assert.rejects(
    f.command({ action: 'vnc.key', sessionId: f.id, keysym: 1, down: true }),
    /unavailable/,
  );
  await f.command();
  const closing = f.controller.closeAll();
  assert.equal(f.controller.closeAll(), closing);
  await assert.rejects(f.command(), /locked/);
  await closing;
  await f.command();
  f.setAllowed(false);
  await f.command({ action: 'vnc.disconnect', sessionId: f.id });
  assert.equal(f.owner.listenerCount('destroyed'), 0);
});

test('unconfirmed VNC cleanup remains visible and cannot silently allow another open', async () => {
  for (const mode of ['close', 'all']) {
    const f = fixture();
    await f.command();
    if (mode === 'close') f.setFailClose();
    else f.setFailAll();
    await assert.rejects(f.controller.closeAll(), /could not be confirmed/);
    await assert.rejects(f.command(), /locked/);
  }
});

test('temporary VNC selection reaches the relay and its password window follows the current owner', async () => {
  const f = fixture();
  assert.equal(f.controller.ownerForSession(f.id), undefined);
  const session = { id: f.id, nodeId: f.q.nodeId, host: 'untrusted', credentialId: randomUUID() };
  const request = vncConnectRequest(session, true, undefined, true);
  assert.equal('manualPassword' in request && request.manualPassword, true);
  await f.command(request);
  assert.deepEqual(f.calls[0][1], {
    sessionId: f.id,
    nodeId: f.q.nodeId,
    credentialId: session.credentialId,
    manualPassword: true,
  });
  assert.equal(f.controller.ownerForSession(f.id), f.owner);
  f.setTrusted(false);
  assert.equal(f.controller.ownerForSession(f.id), undefined);
  f.setTrusted(true);
  f.setAllowed(false);
  assert.equal(f.controller.ownerForSession(f.id), undefined);
  await f.controller.closeAll();
  assert.equal(f.controller.ownerForSession(f.id), undefined);
});

test('explicit VNC cleanup retries preserve quarantine until every stop is confirmed', async () => {
  for (const mode of ['close', 'all']) {
    const f = fixture();
    await f.command();
    if (mode === 'close') f.setFailClose();
    else f.setFailAll();
    await assert.rejects(f.controller.closeAll());
    await assert.rejects(f.command(), /locked/);
    if (mode === 'close') f.setFailClose(false);
    else f.setFailAll(false);
    await f.controller.closeAll();
    assert.equal(f.owner.listenerCount('destroyed'), 0);
    await f.command();
    assert.equal(f.controller.ownerForSession(f.id), f.owner);
    await f.controller.closeAll();
  }
  const f = fixture();
  await f.command();
  f.setFailClose();
  await assert.rejects(f.command({ action: 'vnc.disconnect', sessionId: f.id }));
  f.setFailClose(false);
  await f.command({ action: 'vnc.disconnect', sessionId: f.id });
  assert.equal(f.owner.listenerCount('destroyed'), 0);
});
