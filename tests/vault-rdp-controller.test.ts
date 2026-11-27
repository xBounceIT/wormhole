import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { VaultRdpController } from '../electron/vault-rdp-controller.ts';
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
class Owner extends EventEmitter {
  destroyed = false;
  sent: any[] = [];
  failSend = false;
  isDestroyed() {
    return this.destroyed;
  }
  send(channel: string, event: unknown) {
    if (this.failSend) throw Error('gone');
    this.sent.push({ channel, event });
  }
}
function fixture(certificate = true) {
  let allowed = true,
    trusted = true,
    held = false,
    failClose = false,
    failAll = false,
    failCommand = false,
    syncClose = false,
    missingInitial = false;
  let forward!: (event: any) => void;
  const owner = new Owner(),
    id = randomUUID(),
    calls: any[] = [],
    certificates: any[] = [],
    pending = new Map<string, { resolve: () => void; reject: (error: Error) => void }>();
  const initial = (sessionId: string) => {
    if (!missingInitial)
      forward({
        type: 'ready',
        sessionId,
        lifecycleId: sessionId,
        requestId: randomUUID(),
        external: false,
      });
  };
  const controller = new VaultRdpController(
    (receive) => {
      forward = receive;
      return {
        open: (q, epoch, active) => {
          calls.push(['open', q, epoch, active]);
          if (!held) {
            initial(q.sessionId);
            return Promise.resolve();
          }
          return new Promise<void>((resolve, reject) =>
            pending.set(q.sessionId, {
              resolve: () => {
                initial(q.sessionId);
                resolve();
              },
              reject,
            }),
          );
        },
        command: async (sessionId, q) => {
          calls.push(['command', sessionId, q]);
          if (failCommand) allowed = false;
          return { type: 'ack' as const, sessionId, lifecycleId: sessionId, external: false };
        },
        close: (sessionId) => {
          calls.push(['close', sessionId]);
          pending.get(sessionId)?.reject(Error('native stopped'));
          pending.delete(sessionId);
          forward({ type: 'exited', sessionId, lifecycleId: sessionId, external: false });
          if (syncClose) throw Error('synchronous stop error');
          return failClose ? Promise.reject(Error('unconfirmed')) : Promise.resolve();
        },
        closeAll: async () => {
          calls.push(['all']);
          if (failAll) throw Error('unconfirmed');
        },
      };
    },
    (epoch) => allowed && epoch === 1,
    certificate ? (e, o) => certificates.push([e, o]) : undefined,
    (e, o) => {
      assert.equal(o, owner);
      assert.equal(e.sessionId, id);
      assert.notEqual(e.lifecycleId, id);
    },
  );
  const request = {
    sessionId: id,
    nodeId: randomUUID(),
    ownerWindow: '123',
    bounds: { x: 0, y: 0, width: 800, height: 600 },
  };
  const open = (source = owner) => controller.open(source as any, () => trusted, request, 1);
  return {
    controller,
    owner,
    id,
    request,
    calls,
    certificates,
    pending,
    open,
    forward: (e: any) => forward(e),
    setAllowed: (v: boolean) => (allowed = v),
    setTrusted: (v: boolean) => (trusted = v),
    setHeld: () => (held = true),
    setFailClose: (v: boolean) => (failClose = v),
    setFailAll: (v: boolean) => (failAll = v),
    setSyncClose: (v: boolean) => (syncClose = v),
    setFailCommand: () => (failCommand = true),
    setMissingInitial: () => (missingInitial = true),
    trusted: () => trusted,
  };
}

test('RDP session ownership and fresh lifecycle tokens bind controls, receipts and events', async () => {
  const f = fixture(),
    other = new Owner();
  assert.equal(f.controller.has(f.id), false);
  const opened = await f.open(),
    life = opened.lifecycleId;
  assert.ok(life);
  assert.notEqual(life, f.id);
  assert.equal(f.controller.has(f.id), true);
  assert.equal(f.controller.ownerForSession(f.id), f.owner);
  assert.equal(f.calls[0][3](), true);
  const ack = await f.controller.control(f.owner as any, f.trusted, f.id, { op: 'focus' }, life);
  assert.equal(ack.lifecycleId, life);
  await assert.rejects(f.controller.control(other as any, () => true, f.id, { op: 'hide' }));
  await assert.rejects(
    f.controller.control(f.owner as any, f.trusted, f.id, { op: 'focus' }, randomUUID()),
  );
  await assert.rejects(f.open(other), /another window/);
  f.forward({ type: 'connected', sessionId: f.id, lifecycleId: f.id, external: false });
  assert.equal(f.owner.sent.at(-1).channel, 'rdp:event');
  assert.equal(f.owner.sent.at(-1).event.lifecycleId, life);
  const size = f.owner.sent.length;
  f.forward({ type: 'connected' });
  f.forward({ type: 'connected', sessionId: randomUUID() });
  assert.equal(f.owner.sent.length, size);
  await f.controller.closeForOwner(other as any, f.id);
  assert.equal(f.controller.has(f.id), true);
  await f.controller.closeForOwner(f.owner as any, f.id);
  assert.equal(f.controller.has(f.id), false);
  assert.equal(f.owner.listenerCount('destroyed'), 0);
  assert.equal(f.owner.listenerCount('did-start-loading'), 0);
  assert.equal(f.controller.ownerForSession(f.id), undefined);
  const retry = await f.open();
  assert.notEqual(retry.lifecycleId, life);
  await f.controller.closeAll();
});

test('RDP owner disappearance and authorization retirement close without forwarding stale output', async () => {
  for (const mode of ['destroy', 'reload', 'trust', 'lock', 'send', 'terminal']) {
    const f = fixture();
    await f.open();
    f.owner.sent = [];
    if (mode === 'destroy') {
      f.owner.destroyed = true;
      f.owner.emit('destroyed');
    }
    if (mode === 'reload') f.owner.emit('did-start-loading');
    if (mode === 'trust') f.setTrusted(false);
    if (mode === 'lock') f.setAllowed(false);
    if (mode === 'send') f.owner.failSend = true;
    f.forward({ type: mode === 'terminal' ? 'disconnected' : 'connected', sessionId: f.id });
    await tick();
    assert.equal(f.calls.filter((c) => c[0] === 'close').length, 1, mode);
    assert.equal(f.owner.sent.length, mode === 'terminal' ? 1 : 0, mode);
    await f.controller.closeAll();
  }
});

test('RDP certificates stay in the owning main flow and missing certificate support closes the session', async () => {
  for (const enabled of [true, false]) {
    const f = fixture(enabled);
    await f.open();
    f.owner.sent = [];
    f.forward({
      type: 'certificate',
      sessionId: f.id,
      lifecycleId: f.id,
      certificate: { host: 'host', fingerprint: 'fp' },
    });
    await tick();
    assert.equal(f.owner.sent.length, 0);
    assert.equal(f.certificates.length, enabled ? 1 : 0);
    if (enabled) {
      assert.equal(f.certificates[0][1], f.owner);
      assert.notEqual(f.certificates[0][0].lifecycleId, f.id);
    } else assert.equal(f.controller.has(f.id), false);
    await f.controller.closeAll();
  }
});

test('RDP concurrent replacements wait for shutdown and cannot retire the successful replacement', async () => {
  const f = fixture();
  f.setHeld();
  const first = f.open();
  void first.catch(() => {});
  const second = f.open();
  void second.catch(() => {});
  const third = f.open();
  void third.catch(() => {});
  await tick();
  f.pending.get(f.id)!.resolve();
  await third;
  await assert.rejects(first);
  await assert.rejects(second);
  assert.equal(f.calls.filter((c) => c[0] === 'close').length, 2);
  assert.equal(f.calls.filter((c) => c[0] === 'open').length, 2);
  assert.equal(f.controller.has(f.id), true);
  await f.controller.closeAll();
});

test('RDP admission errors, late replies and shutdown quarantine require confirmed cleanup', async () => {
  const f = fixture();
  f.setTrusted(false);
  await assert.rejects(f.open(), /owner/);
  f.setTrusted(true);
  f.owner.destroyed = true;
  await assert.rejects(f.open(), /owner/);
  f.owner.destroyed = false;
  f.setAllowed(false);
  await assert.rejects(f.open(), /locked/);
  f.setAllowed(true);
  await assert.rejects(f.controller.open(f.owner as any, () => true, {} as any, 1));
  f.setMissingInitial();
  await assert.rejects(f.open(), /could not/);
  for (const mode of ['close', 'all', 'sync']) {
    const g = fixture();
    await g.open();
    if (mode === 'close') g.setFailClose(true);
    else if (mode === 'all') g.setFailAll(true);
    else g.setSyncClose(true);
    const closing = g.controller.closeAll();
    assert.equal(g.controller.closeAll(), closing);
    await assert.rejects(closing, /confirmed/);
    await assert.rejects(g.open(), /locked/);
    g.setFailClose(false);
    g.setFailAll(false);
    g.setSyncClose(false);
    await g.controller.closeAll();
    await g.open();
    await g.controller.closeAll();
  }
  const held = fixture();
  held.setHeld();
  const opening = held.open();
  void opening.catch(() => {});
  held.setAllowed(false);
  held.pending.get(held.id)!.resolve();
  await assert.rejects(opening);
  const race = fixture();
  await race.open();
  race.setFailCommand();
  await assert.rejects(
    race.controller.control(race.owner as any, () => true, race.id, { op: 'focus' }),
    /cancelled/,
  );
  await race.controller.closeAll();
});
