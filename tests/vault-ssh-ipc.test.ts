import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { VaultSshIpc } from '../electron/vault-ssh-ipc.ts';
const tick = () => new Promise(setImmediate);
function fixture(t: TestContext) {
  let workspace = true,
    trusted = true,
    destroyed = false,
    lost = false;
  let failNative = false,
    failAll = false,
    failTarget = false,
    accepted = true;
  const gates: (() => void)[] = [];
  let auth: Promise<void> | undefined,
    registration: Promise<void> | undefined,
    ready: Promise<void> | undefined,
    commit: Promise<void> | undefined;
  const cohorts = new Map<string, any>(),
    admissions: any[] = [],
    registrations: any[] = [],
    cleanups: any[] = [];
  let releases = 0,
    ownerRetirements = 0;
  const workspaceId = randomUUID();
  const owner = Object.assign(new EventEmitter(), { isDestroyed: () => destroyed });
  const other = Object.assign(new EventEmitter(), { isDestroyed: () => false });
  const event = { sender: owner };
  const find = (id: string) => [...cohorts.values()].find((s) => s.id === id || s.members.has(id));
  const retire = async (s: any) => {
    if (!s) return;
    if (failNative) throw Error('private native failure');
    s.members.clear();
    await s.retired();
    cohorts.delete(s.id);
  };
  const ipc = new VaultSshIpc({
    workspace: () => workspace,
    trusted: () => trusted,
    authorize: async (run, cleanup) => {
      cleanups.push(cleanup);
      await auth;
      if (lost) {
        await cleanup();
        throw Error('locked');
      }
      const result = await run(5);
      await commit;
      if (lost) {
        await cleanup();
        throw Error('locked');
      }
      return result;
    },
    quickTarget: async (target, sessionId, epoch, current) => {
      let released = false;
      const reference = { workspaceId, id: randomUUID(), sessionId, epoch };
      const lease = {
        reference,
        release: async () => {
          if (released) return;
          assert.equal(
            find(sessionId)?.members.size ?? 0,
            0,
            'target outlives every native member',
          );
          if (failTarget) throw Error('private target failure');
          released = true;
          releases++;
        },
      };
      registrations.push({ target, reference, current });
      await registration;
      return lease;
    },
    native: {
      hasReservation: (id) => Boolean(find(id)),
      owns: (sender, id) => find(id)?.owner === sender,
      capture: ({ sender }, id) => {
        const s = find(id);
        const current = () => {
          if (!s || find(id) !== s || !s.members.has(id) || s.owner !== sender)
            throw Error('stale source');
        };
        current();
        return current;
      },
      share: async (sender, sourceId, id, current) => {
        const s = find(sourceId);
        assert.equal(s.owner, sender);
        assert.equal(current(), true);
        s.members.add(id);
        await ready;
        return {
          sessionId: id,
          host: 'ssh.example',
          port: 22,
          username: 'native',
          fingerprint: 'pin',
        };
      },
      admit: (sender, q, epoch, current, retired) => {
        admissions.push({ sender, q, epoch, current });
        if (!accepted)
          return { accepted: false, result: Promise.reject(Error('rejected admission')) };
        const s = { id: q.sessionId, owner: sender, members: new Set([q.sessionId]), retired };
        cohorts.set(q.sessionId, s);
        return {
          accepted: true,
          result: Promise.resolve().then(async () => {
            await ready;
            return {
              sessionId: q.sessionId,
              host: 'ssh.example',
              port: 22,
              username: 'native',
              fingerprint: 'pin',
            };
          }),
        };
      },
      close: async (sender, id) => {
        const s = find(id);
        if (!s) return;
        assert.equal(sender, s.owner);
        if (failNative) throw Error('private native failure');
        s.members.delete(id);
        if (!s.members.size) await retire(s);
      },
      retire: async (sender, id) => {
        const s = find(id);
        if (s) assert.equal(sender, s.owner);
        await retire(s);
      },
      retireOwner: async (sender) => {
        ownerRetirements++;
        const results = await Promise.allSettled(
          [...cohorts.values()].filter((s) => s.owner === sender).map(retire),
        );
        if (results.some((r) => r.status === 'rejected')) throw Error('private owner shutdown');
      },
      closeAll: async () => {
        if (failAll) throw Error('private global shutdown');
        const results = await Promise.allSettled([...cohorts.values()].map(retire));
        if (results.some((r) => r.status === 'rejected')) throw Error('private global shutdown');
      },
    },
  });
  t.after(async () => {
    for (const resolve of gates) resolve();
    failNative = failAll = failTarget = lost = false;
    await ipc.closeAll();
  });
  const q = { sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24 };
  const quick = {
    sessionId: q.sessionId,
    mode: 'terminal',
    columns: 80,
    rows: 24,
    quickTarget: {
      protocol: 'ssh',
      host: 'ssh.example',
      port: 22,
      credentialId: randomUUID(),
      tunnelId: '',
      sshAutoSudo: false,
      httpPath: '',
      ignoreCertificateErrors: false,
      rdp: null,
    },
  };
  return {
    ipc,
    q,
    quick,
    owner,
    other,
    event,
    workspaceId,
    admissions,
    registrations,
    cleanups,
    cohorts,
    open: (input: any = q) => ipc.open(event, input),
    get releases() {
      return releases;
    },
    get ownerRetirements() {
      return ownerRetirements;
    },
    alias: () => {
      const id = randomUUID();
      find(q.sessionId).members.add(id);
      return id;
    },
    block: (kind: string) => {
      let resolve!: () => void;
      const promise = new Promise<void>((r) => {
        resolve = r;
      });
      gates.push(resolve);
      if (kind === 'auth') auth = promise;
      else if (kind === 'registration') registration = promise;
      else if (kind === 'ready') ready = promise;
      else commit = promise;
      return resolve;
    },
    state: (v: any) => {
      if ('workspace' in v) workspace = v.workspace;
      if ('trusted' in v) trusted = v.trusted;
      if ('destroyed' in v) destroyed = v.destroyed;
      if ('lost' in v) lost = v.lost;
      if ('failNative' in v) failNative = v.failNative;
      if ('failAll' in v) failAll = v.failAll;
      if ('failTarget' in v) failTarget = v.failTarget;
      if ('accepted' in v) accepted = v.accepted;
    },
  };
}

test('Quick SSH hands native scope to one cohort and releases only after its last SFTP alias', async (t) => {
  const f = fixture(t);
  await f.open(f.quick);
  const admitted = f.admissions[0],
    ref = f.registrations[0].reference;
  assert.equal(admitted.q.nodeId, ref.id);
  assert.equal('quickTarget' in admitted.q, false);
  assert.equal('credentialId' in admitted.q, false, 'selection belongs in the admitted target');
  assert.equal(admitted.epoch, 5);
  const context = {
    workspaceId: ref.workspaceId,
    sessionId: ref.sessionId,
    nodeId: ref.id,
    epoch: ref.epoch,
  };
  assert.equal(f.ipc.isQuickTarget(context), true);
  for (const delta of [
    { workspaceId: randomUUID() },
    { sessionId: randomUUID() },
    { nodeId: randomUUID() },
    { epoch: 6 },
  ])
    assert.equal(f.ipc.isQuickTarget({ ...context, ...delta }), false);
  const alias = f.alias();
  await f.ipc.close(f.event, f.q.sessionId);
  assert.equal(f.releases, 0);
  assert.equal(f.cohorts.size, 1);
  assert.equal(f.ipc.isQuickTarget(context), false);
  await assert.rejects(f.open(f.quick));
  await f.ipc.close(f.event, alias);
  assert.equal(f.releases, 1);
  assert.equal(f.cohorts.size, 0);
  assert.equal(f.owner.listenerCount('destroyed'), 0);
  await f.open(f.quick);
});

test('SSH cancellation reserves before authorization and joins late native target registration', async (t) => {
  for (const stage of ['auth', 'registration', 'ready']) {
    const f = fixture(t),
      release = f.block(stage);
    const opening = f.open(f.quick);
    void opening.catch(() => {});
    await tick();
    await assert.rejects(f.open(f.quick));
    let stopped = false;
    const closing = f.ipc.close(f.event, f.q.sessionId);
    assert.equal(f.ipc.close(f.event, f.q.sessionId), closing);
    void closing.then(() => {
      stopped = true;
    });
    await tick();
    assert.equal(stopped, false);
    release();
    await assert.rejects(opening);
    await closing;
    assert.equal(f.releases, stage === 'auth' ? 0 : 1);
    assert.equal(f.cohorts.size, 0);
    f.state({ workspace: false });
    assert.equal(f.ipc.handles(f.q.sessionId), false);
  }
});

test('closing a connected primary during the public authorization commit preserves its already authorized SFTP alias', async (t) => {
  const f = fixture(t),
    release = f.block('commit');
  const opening = f.open(f.quick);
  void opening.catch(() => {});
  await tick();
  const alias = f.alias(),
    closing = f.ipc.close(f.event, f.q.sessionId);
  await tick();
  release();
  await assert.rejects(opening);
  await closing;
  assert.equal(f.cohorts.size, 1);
  assert.equal(f.releases, 0);
  await f.ipc.close(f.event, alias);
  assert.equal(f.releases, 1);
});

test('rejected native SSH handoff retains the target with the original caller and permits cleanup retry', async (t) => {
  const f = fixture(t);
  f.state({ accepted: false, failTarget: true });
  await assert.rejects(f.open(f.quick), /shutdown could not be confirmed/);
  await assert.rejects(f.open(f.quick));
  assert.equal(f.cohorts.size, 0);
  assert.equal(f.releases, 0);
  f.state({ failTarget: false });
  await f.ipc.close(f.event, f.q.sessionId);
  assert.equal(f.releases, 1);
  f.state({ accepted: true });
  await f.open(f.quick);
});

test('native or target retirement failure holds SSH identity until an explicit positive retry', async (t) => {
  for (const kind of ['failNative', 'failTarget']) {
    const f = fixture(t);
    await f.open(f.quick);
    f.state({ [kind]: true });
    await assert.rejects(f.ipc.close(f.event, f.q.sessionId), {
      message: 'SSH shutdown could not be confirmed.',
    });
    await assert.rejects(f.open(f.quick));
    assert.equal(f.releases, 0);
    f.state({ [kind]: false });
    await f.ipc.close(f.event, f.q.sessionId);
    assert.equal(f.releases, 1);
    await f.open(f.quick);
  }
});

test('SSH owner lifecycle retires whole cohorts and late admissions, including all file aliases', async (t) => {
  for (const name of ['did-start-loading', 'render-process-gone', 'destroyed']) {
    const f = fixture(t);
    await f.open(f.quick);
    f.alias();
    if (name === 'destroyed') f.state({ destroyed: true });
    f.owner.emit(name);
    f.owner.emit(name);
    await tick();
    assert.equal(f.ownerRetirements, 1);
    assert.equal(f.cohorts.size, 0);
    assert.equal(f.releases, 1);
    assert.equal(f.owner.listenerCount(name), 0);
  }
  const f = fixture(t),
    release = f.block('registration');
  const pending = f.open(f.quick);
  void pending.catch(() => {});
  await tick();
  f.owner.emit('did-start-loading');
  await tick();
  assert.equal(f.releases, 0);
  release();
  await assert.rejects(pending);
  await tick();
  assert.equal(f.releases, 1);
});

test('SSH owner failure blocks new document admissions until global cleanup confirms retirement', async (t) => {
  const f = fixture(t);
  await f.open(f.quick);
  f.alias();
  f.state({ failNative: true });
  f.owner.emit('did-start-loading');
  await tick();
  await assert.rejects(f.open({ ...f.q, sessionId: randomUUID() }));
  await assert.rejects(f.ipc.closeAll());
  f.state({ failNative: false });
  await f.ipc.closeAll();
  await f.open(f.quick);
});

test('SSH public owner and source contracts reject foreign, destroyed, locked and untrusted requests', async (t) => {
  const f = fixture(t);
  await assert.rejects(f.open(null));
  for (const state of [{ trusted: false }, { destroyed: true }, { workspace: false }]) {
    f.state(state);
    await assert.rejects(f.open());
    f.state({ trusted: true, destroyed: false, workspace: true });
  }
  await f.open();
  await assert.rejects(f.ipc.open({ sender: f.other }, f.q));
  assert.throws(() => f.ipc.close({ sender: f.other }, f.q.sessionId));
  const alias = f.alias();
  assert.throws(() => f.ipc.close({ sender: f.other }, alias));
  assert.throws(() => f.ipc.close(f.event, 'bad'));
  f.state({ trusted: false });
  assert.equal(f.admissions[0].current(), false);
  assert.throws(() => f.ipc.close(f.event, alias));
  f.state({ trusted: true });
  await f.ipc.close(f.event, randomUUID());
  f.state({ workspace: false });
  assert.equal(f.ipc.handles(alias), true);
});

test('global SSH shutdown joins auth/registration, bounds reservations and retains a failed barrier for retry', async (t) => {
  const f = fixture(t),
    release = f.block('auth');
  const openings = Array.from({ length: 32 }, () => f.open({ ...f.q, sessionId: randomUUID() }));
  for (const p of openings) void p.catch(() => {});
  await assert.rejects(f.open());
  const closing = f.ipc.closeAll();
  assert.equal(f.ipc.closeAll(), closing);
  let stopped = false;
  void closing.then(() => {
    stopped = true;
  });
  await tick();
  assert.equal(stopped, false);
  release();
  await Promise.allSettled(openings);
  await closing;
  await f.open(f.quick);
  f.state({ failAll: true });
  await assert.rejects(f.ipc.closeAll());
  await assert.rejects(f.open({ ...f.q, sessionId: randomUUID() }));
  f.state({ failAll: false });
  await f.ipc.closeAll();
  await f.open(f.quick);
});

test('authentication loss and stale cleanup cannot retire a replacement SSH cohort', async (t) => {
  const f = fixture(t);
  f.state({ lost: true });
  await assert.rejects(f.open(f.quick));
  f.state({ lost: false });
  await f.open(f.quick);
  await f.ipc.close(f.event, f.q.sessionId);
  await f.open(f.quick);
  const releases = f.releases;
  await f.cleanups[1]();
  assert.equal(f.releases, releases);
  const release = f.block('commit');
  await f.ipc.close(f.event, f.q.sessionId);
  const pending = f.open(f.quick);
  void pending.catch(() => {});
  await tick();
  f.alias();
  f.state({ lost: true });
  release();
  await assert.rejects(pending);
  assert.equal(f.cohorts.size, 0);
});

test('public SFTP sharing reserves before auth and retains the original Quick target through primary close', async (t) => {
  const f = fixture(t);
  await f.open(f.quick);
  const alias = randomUUID();
  await f.ipc.share(f.event, f.q.sessionId, alias);
  assert.equal(f.registrations.length, 1);
  await f.ipc.close(f.event, f.q.sessionId);
  const copy = randomUUID();
  await f.ipc.share(f.event, alias, copy);
  await f.ipc.close(f.event, alias);
  assert.equal(f.releases, 0);
  await f.ipc.close(f.event, copy);
  assert.equal(f.releases, 1);
  assert.equal(f.owner.listenerCount('destroyed'), 0);
});

test('SFTP close before authorization cancels its pending share and joins late native members', async (t) => {
  for (const stage of ['auth', 'ready']) {
    const f = fixture(t);
    await f.open(f.quick);
    const release = f.block(stage),
      alias = randomUUID();
    const pending = f.ipc.share(f.event, f.q.sessionId, alias);
    void pending.catch(() => {});
    await tick();
    let stopped = false;
    const close = f.ipc.close(f.event, alias).then(() => {
      stopped = true;
    });
    await tick();
    assert.equal(stopped, false);
    release();
    await assert.rejects(pending);
    await close;
    assert.equal(f.releases, 0);
    assert.equal(f.cohorts.get(f.q.sessionId).members.has(f.q.sessionId), true);
  }
});

test('SFTP sharing rejects stale source generations, owner substitution and ambiguous member identities', async (t) => {
  const f = fixture(t);
  await f.open(f.quick);
  for (const [event, source, id] of [
    [f.event, 'bad', randomUUID()],
    [f.event, f.q.sessionId, f.q.sessionId],
    [{ sender: f.other }, f.q.sessionId, randomUUID()],
    [f.event, randomUUID(), randomUUID()],
  ] as const)
    await assert.rejects(f.ipc.share(event, source, id));
  const release = f.block('auth'),
    alias = randomUUID();
  const pending = f.ipc.share(f.event, f.q.sessionId, alias);
  void pending.catch(() => {});
  await tick();
  await f.ipc.close(f.event, f.q.sessionId);
  release();
  await assert.rejects(pending);
  await f.open(f.quick);
  assert.equal(f.cohorts.get(f.q.sessionId).members.has(alias), false);
});

test('authorization loss during a shared file open retires the original whole cohort', async (t) => {
  const f = fixture(t);
  await f.open(f.quick);
  const release = f.block('commit'),
    alias = randomUUID();
  const pending = f.ipc.share(f.event, f.q.sessionId, alias);
  void pending.catch(() => {});
  await tick();
  f.state({ lost: true });
  release();
  await assert.rejects(pending);
  assert.equal(f.cohorts.size, 0);
  assert.equal(f.releases, 1);
});
