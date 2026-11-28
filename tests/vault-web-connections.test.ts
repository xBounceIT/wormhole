import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { VaultWebConnections, parseVaultWebOpen } from '../electron/vault-web-connections.ts';
import { webRequest, webPlan } from './fixtures/vault-web.ts';
import type { VaultWebView } from '../electron/vault-web.ts';
const tick = () => new Promise(setImmediate);
function fixture(t: TestContext, routed = false, timeoutMs = 1000, withArchive = false) {
  const seed = webPlan(webRequest(), routed),
    requests: any[] = [],
    calls: string[] = [];
  let allowed = true,
    workspace: string | undefined = seed.binding.workspaceId,
    owner = true,
    ownerThrows = false,
    routeActive = true,
    closeRoute!: () => void,
    releaseCount = 0,
    failRelease = false,
    failPendingClose = false,
    routeOwner: (() => boolean) | undefined,
    failAll = false,
    failTarget = false,
    targetReleases = 0;
  const registrations: any[] = [];
  let admit: (value: any) => Promise<any> = async (value) => value;
  let checkViews = async (_workspace: string, views: VaultWebView[]) => views.map(() => true);
  const closed = new Promise<void>((r) => (closeRoute = r));
  const makePlan = (q: any) => {
    const b = {
      ...seed.binding,
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
    };
    return {
      binding: b,
      route: seed.route ? { ...seed.route, ...b } : null,
      target: { ...seed.target },
      ...(withArchive ? { archiveBinding: 'a1'.repeat(32) } : {}),
      ...(registrations.some((r) => r.reference.id === q.nodeId) ? { temporary: true } : {}),
    };
  };
  let plan = (q: any) => Promise.resolve(makePlan(q)),
    acquire = async () => {
      const first = requests.at(-1),
        binding = { ...makePlan(first).route!, requestId: randomUUID() };
      return {
        binding,
        endpoint: '127.0.0.1:2345',
        get active() {
          return routeActive;
        },
        closed,
        release: async () => {
          releaseCount++;
          if (failRelease) throw Error('private release failure');
        },
      };
    };
  const coordinator = new VaultWebConnections({
    workspaceId: () => workspace,
    authorized: (e) => allowed && e === 1,
    archive: (_plan, current) => ({
      read: async () => {
        if (!current()) throw Error('archive retired');
        return { revision: '0' };
      },
      save: async () => '1',
      forget: async () => '1',
    }),
    plan: (q) => {
      requests.push(structuredClone(q));
      return plan(q);
    },
    checkViews: (workspace, views) => checkViews(workspace, views),
    routes: {
      acquire: async (q, epoch, current) => {
        assert.deepEqual(q, {
          sessionId: requests.at(-1).sessionId,
          nodeId: requests.at(-1).nodeId,
        });
        assert.equal(epoch, 1);
        routeOwner = current;
        calls.push('acquire');
        return acquire();
      },
      close: async () => {
        calls.push('close');
        if (failPendingClose) throw Error('pending close unconfirmed');
      },
      closeAll: async () => {
        calls.push('all');
        if (failAll) throw Error('private stop failure');
      },
    },
    quickTarget: async (target, sessionId, epoch, accepted) => {
      const reference = { workspaceId: workspace!, id: randomUUID(), sessionId, epoch };
      registrations.push({ reference, target, accepted });
      return admit({
        reference,
        release: async () => {
          if (failTarget) throw Error('target retirement unconfirmed');
          targetReleases++;
          calls.push('target-release');
        },
      });
    },
    timeoutMs,
  });
  t.after(() => coordinator.closeAll().catch(() => {}));
  const input = { sessionId: randomUUID(), nodeId: seed.binding.nodeId };
  let notices = 0,
    noticeThrows = false;
  const reasons: string[] = [];
  const open = (value: any = input, epoch = 1) =>
    coordinator.open(
      value,
      epoch,
      () => {
        if (ownerThrows) throw Error('owner disappeared');
        return owner;
      },
      (reason) => {
        notices++;
        reasons.push(reason);
        if (noticeThrows) throw Error('presentation gone');
      },
    );
  return {
    coordinator,
    input,
    quick: {
      sessionId: input.sessionId,
      quickTarget: {
        protocol: 'https',
        host: seed.binding.host,
        port: seed.binding.port,
        credentialId: '',
        tunnelId: seed.binding.tunnelConfigId,
        sshAutoSudo: false,
        httpPath: '/native%2Fpath',
        ignoreCertificateErrors: false,
        rdp: null,
      },
    },
    registrations,
    get targetReleases() {
      return targetReleases;
    },
    failTarget: (value = true) => (failTarget = value),
    setAdmission: (value: typeof admit) => (admit = value),
    requests,
    calls,
    open,
    makePlan,
    get notices() {
      return notices;
    },
    get routeOwner() {
      return routeOwner;
    },
    failPendingClose: (value = true) => (failPendingClose = value),
    get releases() {
      return releaseCount;
    },
    setOwner: (v: boolean) => (owner = v),
    throwOwner: () => (ownerThrows = true),
    setAllowed: (v: boolean) => (allowed = v),
    setWorkspace: (v: string | undefined) => (workspace = v),
    setActive: (v: boolean) => (routeActive = v),
    endRoute: () => closeRoute(),
    setPlan: (v: typeof plan) => (plan = v),
    setViewCheck: (check: typeof checkViews) => (checkViews = check),
    reasons,
    setAcquire: (v: typeof acquire) => (acquire = v),
    getAcquire: () => acquire,
    failRelease: (value = true) => (failRelease = value),
    failAll: (value = true) => (failAll = value),
    throwNotice: () => (noticeThrows = true),
  };
}

test('a shared View check retires only the affected browser generation and rejects stale receipts', async (t) => {
  const f = fixture(t, false, 1000, true);
  const node = f.input.nodeId;
  const unrelated = randomUUID();
  const originalGeneration = randomUUID();
  const nextGeneration = randomUUID();
  const independentGeneration = randomUUID();
  let generation = originalGeneration;
  f.setPlan(async (q) => ({
    ...f.makePlan(q),
    viewGeneration: q.nodeId === node ? generation : independentGeneration,
  }));
  const old = await f.open();
  const independent = await f.open({ sessionId: randomUUID(), nodeId: unrelated });
  const firstReply = Promise.withResolvers<boolean[]>();
  const seen: VaultWebView[][] = [];
  f.setViewCheck(async (workspace, views) => {
    assert.equal(workspace, f.requests[0].workspaceId);
    seen.push(views);
    if (seen.length === 1) return firstReply.promise;
    return views.map(({ generation }) => generation !== originalGeneration);
  });
  const pending = f.coordinator.verifyViews();
  await tick();
  await f.coordinator.close(f.input.sessionId);
  generation = nextGeneration;
  const reopened = await f.open();
  assert.equal(f.coordinator.verifyViews(), pending);
  firstReply.resolve([false, true]);
  await pending;
  assert.equal(seen.length, 2);
  assert.deepEqual(seen[0], [
    { nodeId: node, generation: originalGeneration },
    { nodeId: unrelated, generation: independentGeneration },
  ]);
  assert.deepEqual(seen[1], [
    { nodeId: unrelated, generation: independentGeneration },
    { nodeId: node, generation: nextGeneration },
  ]);
  assert.equal(old.active(), false);
  assert.equal(reopened.active(), true);
  assert.equal(independent.active(), true);
  assert.deepEqual(f.reasons, []);

  f.setViewCheck(async (_workspace, views) =>
    views.map(({ generation }) => generation !== nextGeneration),
  );
  await f.coordinator.verifyViews();
  assert.deepEqual(f.reasons, ['view-revoked']);
  assert.equal(reopened.active(), false);
  assert.equal(independent.active(), true);
  await assert.rejects(reopened.archive!.read(), /archive retired/);
});

test('live View check failures close only monitored browsers and distinguish an uncertain response', async (t) => {
  const f = fixture(t, true, 1000, true);
  const localNode = randomUUID(),
    viewGeneration = randomUUID();
  f.setPlan(async (q) => ({
    ...f.makePlan(q),
    ...(q.nodeId !== localNode ? { viewGeneration } : {}),
  }));
  const local = await f.open({ sessionId: randomUUID(), nodeId: localNode });
  const affected = await f.open();
  f.setViewCheck(async () => {
    throw Error('fixture transport failure');
  });
  f.throwNotice();
  await f.coordinator.verifyViews();
  await tick();
  assert.equal(f.releases, 1);
  assert.equal(affected.active(), false);
  assert.equal(local.active(), true);
  assert.deepEqual(f.reasons, ['view-unavailable']);
});

test('a live shared browser polls independently of catalog notifications', async (t) => {
  let poll: (() => void) | undefined;
  const nativeSetTimeout = setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback: () => void, delay?: number) => {
    if (delay !== 30_000) return nativeSetTimeout(callback, delay);
    poll = callback;
    return { unref() {} };
  });
  const f = fixture(t, false, 1000, true);
  const viewGeneration = randomUUID();
  f.setPlan(async (q) => ({ ...f.makePlan(q), viewGeneration }));
  f.setViewCheck(async () => [false]);
  const browser = await f.open();
  assert.equal(browser.active(), true);
  assert.ok(poll);
  poll();
  await tick();
  assert.equal(browser.active(), false);
  assert.deepEqual(f.reasons, ['view-revoked']);
});

test('a saved browser owns the only archive writer for its node until its route is retired', async (t) => {
  const f = fixture(t, true, 1000, true);
  const first = await f.open();
  assert.ok(first.archive);
  assert.deepEqual(await first.archive.read(), { revision: '0' });
  const secondId = randomUUID();
  const concurrent = await f.open({ ...f.input, sessionId: secondId });
  assert.equal(concurrent.archive, undefined);
  await f.coordinator.close(f.input.sessionId);
  await assert.rejects(first.archive.read(), /archive retired/);
  const next = await f.open({ ...f.input, sessionId: randomUUID() });
  assert.ok(next.archive);
});

test('phased browser retirement closes routes but holds target authority until owner cleanup confirms', async (t) => {
  for (const all of [false, true]) {
    const f = fixture(t, true);
    const opened = await f.open(f.quick);
    f.failRelease();
    const retire = () =>
      all ? f.coordinator.retireAllRoutes() : f.coordinator.retireRoute(f.input.sessionId);
    await assert.rejects(retire());
    assert.equal(opened.active(), false);
    assert.equal(f.targetReleases, 0);
    f.failRelease(false);
    await retire();
    assert.equal(f.targetReleases, 0);
    assert.equal(f.coordinator.has(f.input.sessionId), true);
    if (all) await assert.rejects(f.open({ ...f.quick, sessionId: randomUUID() }));
    await f.coordinator.closeAll();
    assert.equal(f.targetReleases, 1);
    await f.open(f.quick);
  }
  const f = fixture(t);
  await f.coordinator.retireRoute(randomUUID());
  f.failAll();
  await assert.rejects(f.coordinator.retireAllRoutes());
  await assert.rejects(f.open());
  f.failAll(false);
  await f.coordinator.closeAll();
  await f.open();
});

test('browser preparation cannot substitute a persisted target for a native temporary admission', async (t) => {
  const f = fixture(t);
  f.setPlan(async (q) => ({ ...f.makePlan(q), temporary: true }));
  await assert.rejects(f.open());
  f.setPlan(async (q) => {
    const plan = f.makePlan(q) as any;
    delete plan.temporary;
    return plan;
  });
  await assert.rejects(f.open(f.quick));
  assert.equal(f.targetReleases, 1);
});
test('web preparation returns an owned direct target or one exact native SOCKS route', async (t) => {
  for (const routed of [false, true]) {
    const f = fixture(t, routed),
      result = await f.open();
    assert.equal(result.active(), true);
    if (routed) {
      assert.equal(f.routeOwner!(), true);
      f.setOwner(false);
      assert.equal(f.routeOwner!(), false);
      f.setOwner(true);
    }
    assert.equal(result.route, routed ? 'socks5' : 'direct');
    assert.equal(result.target.proxyUrl, routed ? 'socks5://127.0.0.1:2345' : undefined);
    assert.equal(f.requests.length, routed ? 2 : 1);
    assert.equal(f.coordinator.has(f.input.sessionId), true);
    result.target.host = 'changed';
    assert.equal(f.makePlan(f.requests[0]).target.host, 'web.example');
    await f.coordinator.close(f.input.sessionId);
    assert.equal(result.active(), false);
    assert.equal(f.releases, routed ? 1 : 0);
    assert.equal(f.coordinator.has(f.input.sessionId), false);
    await f.coordinator.close(f.input.sessionId);
    assert.equal(f.releases, routed ? 1 : 0);
  }
});
test('web preparation rejects malformed authority, duplicates and capacity while keeping direct and routed decisions explicit', async (t) => {
  const f = fixture(t);
  for (const bad of [
    null,
    {},
    { ...f.input, nodeId: 'bad' },
    { ...f.input, host: 'redirect.example' },
    { ...f.input, credentialId: randomUUID() },
  ])
    await assert.rejects(f.open(bad), /unavailable/);
  for (const epoch of [0, 2, NaN, 2 ** 53])
    await assert.rejects(f.open(f.input, epoch), /unavailable/);
  f.setAllowed(false);
  await assert.rejects(f.open(), /unavailable/);
  f.setAllowed(true);
  f.setOwner(false);
  await assert.rejects(f.open(), /unavailable/);
  f.setOwner(true);
  f.setWorkspace(undefined);
  await assert.rejects(f.open(), /unavailable/);
  f.setWorkspace(webRequest().workspaceId);
  await f.open();
  await assert.rejects(f.open(), /unavailable/);
  for (let i = 1; i < 32; i++) await f.open({ ...f.input, sessionId: randomUUID() });
  await assert.rejects(f.open({ ...f.input, sessionId: randomUUID() }), /unavailable/);
  for (const timeoutMs of [0, NaN, 360001])
    assert.throws(
      () =>
        new VaultWebConnections({
          workspaceId: () => undefined,
          authorized: () => false,
          plan: async () => ({}) as any,
          routes: {} as any,
          timeoutMs,
        }),
      /timeout/,
    );
});
test('web owner, workspace and epoch changes invalidate prepared targets without admitting another route', async (t) => {
  for (const mode of ['owner', 'workspace', 'epoch', 'owner-throws']) {
    const f = fixture(t, true),
      result = await f.open();
    if (mode === 'owner') f.setOwner(false);
    if (mode === 'owner-throws') f.throwOwner();
    if (mode === 'workspace') f.setWorkspace(webRequest().workspaceId);
    if (mode === 'epoch') f.setAllowed(false);
    assert.equal(result.active(), false);
    await f.coordinator.closeAll();
    assert.equal(f.releases, 1);
  }
});
test('web metadata and route substitution fail closed, including changes while a tunnel opens', async (t) => {
  for (const mode of [
    'bad-plan',
    'bad-lease',
    'endpoint',
    'inactive',
    'bad-refresh',
    'target-change',
    'cert-change',
    'route-change',
    'missing-route',
    'route-loss',
  ]) {
    const f = fixture(t, true);
    if (mode === 'bad-plan') f.setPlan(async () => ({}) as any);
    if (
      mode === 'bad-refresh' ||
      mode === 'target-change' ||
      mode === 'cert-change' ||
      mode === 'route-change' ||
      mode === 'missing-route' ||
      mode === 'route-loss'
    ) {
      f.setPlan(async (q) => {
        const p = f.makePlan(q);
        if (f.requests.length > 1) {
          if (mode === 'bad-refresh') return {} as any;
          if (mode === 'target-change') p.target.url = 'https://web.example:8443/changed';
          if (mode === 'cert-change') p.target.ignoreCertErrors = true;
          if (mode === 'route-change') p.route!.rowVersion = '9223372036854775806';
          if (mode === 'missing-route') {
            p.route = null;
            p.binding.tunnelConfigId = '';
            delete p.target.tunnelConfigId;
          }
          if (mode === 'route-loss') {
            f.setActive(false);
            f.endRoute();
            await tick();
          }
        }
        return p;
      });
    }
    // The malformed lease cases wrap the original lease factory after planning.
    if (['bad-lease', 'endpoint', 'inactive'].includes(mode)) {
      const acquire = f.getAcquire();
      f.setAcquire(async () => {
        const lease = await acquire();
        if (mode === 'bad-lease') lease.binding.protocol = 'ssh';
        if (mode === 'endpoint') lease.endpoint = '192.0.2.1:2345';
        if (mode === 'inactive') f.setActive(false);
        return lease;
      });
    }
    await assert.rejects(f.open(), /could not be prepared/);
    assert.equal(f.coordinator.has(f.input.sessionId), false);
  }
});
test('web cancellation and timeout reject promptly and discard late native metadata or acquired leases', async (t) => {
  for (const mode of ['plan', 'acquire', 'timeout']) {
    const f = fixture(t, mode === 'acquire', mode === 'timeout' ? 10 : 1000);
    let release!: (value: any) => void, lateLease: any;
    if (mode === 'acquire') {
      const old = f.getAcquire();
      f.setAcquire(async () => {
        lateLease = await old();
        return new Promise((r) => (release = r));
      });
    } else f.setPlan(() => new Promise((r) => (release = r)));
    const pending = f.open();
    void pending.catch(() => {});
    await tick();
    if (mode !== 'timeout') await f.coordinator.close(f.input.sessionId);
    else await new Promise((r) => setTimeout(r, 25));
    await assert.rejects(pending, /could not be prepared/);
    assert.equal(f.coordinator.has(f.input.sessionId), false);
    release(mode === 'acquire' ? lateLease : f.makePlan(f.requests[0]));
    await tick();
    assert.equal(f.releases, mode === 'acquire' ? 1 : 0);
  }
});
test('closed routes notify the current presentation once and cannot revive retired browsers', async (t) => {
  const f = fixture(t, true);
  f.throwNotice();
  const result = await f.open();
  f.endRoute();
  await tick();
  assert.equal(f.notices, 1);
  assert.equal(result.active(), false);
  assert.equal(f.releases, 1);
  const retired = fixture(t, true);
  await retired.open();
  await retired.coordinator.closeAll();
  retired.endRoute();
  await tick();
  assert.equal(retired.notices, 0);
});
test('unconfirmed web route teardown reserves identity and global shutdown blocks new preparations', async (t) => {
  const f = fixture(t, true);
  await f.open();
  f.failRelease();
  await assert.rejects(f.coordinator.close(f.input.sessionId), /release/);
  assert.equal(f.coordinator.has(f.input.sessionId), true);
  await assert.rejects(f.open(), /unavailable/);
  const closing = f.coordinator.closeAll();
  await assert.rejects(f.open({ ...f.input, sessionId: randomUUID() }), /unavailable/);
  await assert.rejects(closing, /shutdown could not be confirmed/);
  const all = fixture(t);
  all.failAll();
  await assert.rejects(all.coordinator.closeAll(), /shutdown could not be confirmed/);
  await assert.rejects(all.open(), /unavailable/);
});

test('timeout during route acquisition retains identity when pending native close is unconfirmed', async (t) => {
  const f = fixture(t, true, 10),
    acquire = f.getAcquire();
  let release!: (value: any) => void, late: any;
  f.setAcquire(async () => {
    late = await acquire();
    return new Promise((r) => (release = r));
  });
  f.failPendingClose();
  const pending = f.open();
  void pending.catch(() => {});
  await new Promise((r) => setTimeout(r, 25));
  await assert.rejects(pending, /pending close unconfirmed/);
  assert.equal(f.coordinator.has(f.input.sessionId), true);
  release(late);
  await tick();
  assert.equal(f.releases, 1);
  await f.coordinator.closeAll();
  assert.equal(
    f.coordinator.has(f.input.sessionId),
    false,
    'late positive lease retirement permits cleanup retry',
  );
});

test('web route shutdown can retry uncertain cleanup without admitting a replacement prematurely', async (t) => {
  const f = fixture(t, true);
  await f.open();
  f.failRelease();
  await assert.rejects(f.coordinator.close(f.input.sessionId));
  await assert.rejects(f.open(), /unavailable/);
  f.failRelease(false);
  await f.coordinator.close(f.input.sessionId);
  assert.equal(f.coordinator.has(f.input.sessionId), false);
  await f.open();
  f.failAll();
  await assert.rejects(f.coordinator.closeAll());
  await assert.rejects(f.open({ ...f.input, sessionId: randomUUID() }), /unavailable/);
  f.failAll(false);
  await f.coordinator.closeAll();
  await f.open();
});

test('a failed late web lease release remains owned until a positive explicit retry', async (t) => {
  const f = fixture(t, true, 10),
    acquire = f.getAcquire();
  let reply!: (value: any) => void, late: any;
  f.setAcquire(async () => {
    late = await acquire();
    return new Promise((r) => (reply = r));
  });
  f.failPendingClose();
  f.failRelease();
  const opening = f.open();
  void opening.catch(() => {});
  await new Promise((r) => setTimeout(r, 25));
  await assert.rejects(opening, /pending close unconfirmed/);
  reply(late);
  await tick();
  assert.equal(f.releases, 1);
  await assert.rejects(f.coordinator.closeAll(), /shutdown could not be confirmed/);
  assert.equal(
    f.coordinator.has(f.input.sessionId),
    true,
    'unknown native lease must retain the browser identity',
  );
  f.failRelease(false);
  await f.coordinator.closeAll();
  assert.equal(f.coordinator.has(f.input.sessionId), false);
});

test('web Quick admission accepts only exact browser metadata and keeps private target authority until explicit close', async (t) => {
  for (const routed of [false, true]) {
    const f = fixture(t, routed),
      q = f.quick;
    assert.ok(parseVaultWebOpen(q));
    for (const patch of [
      { nodeId: randomUUID() },
      { quickTarget: null },
      { publicKey: 'invalid' },
      { password: '' },
      { quickTarget: { ...q.quickTarget, protocol: 'vnc' } },
      { quickTarget: { ...q.quickTarget, credentialId: randomUUID() } },
    ])
      assert.equal(parseVaultWebOpen({ ...q, ...patch }), undefined);
    const result = await f.open(q);
    assert.equal(result.active(), true);
    assert.equal(f.registrations.length, 1);
    const target = f.registrations[0];
    assert.equal(target.reference.sessionId, q.sessionId);
    assert.equal(target.reference.epoch, 1);
    assert.equal(f.requests[0].nodeId, target.reference.id);
    assert.equal(f.targetReleases, 0);
    if (routed) {
      f.endRoute();
      await tick();
      assert.equal(f.notices, 1);
      assert.equal(result.active(), false);
      assert.equal(f.targetReleases, 0, 'browser owns target until its views/profile close');
      assert.equal(f.coordinator.has(q.sessionId), true);
    }
    await f.coordinator.close(q.sessionId);
    assert.equal(f.targetReleases, 1);
    assert.equal(f.coordinator.has(q.sessionId), false);
  }
});

test('web Quick cancellation and global stop join late native admission before acknowledging retirement', async (t) => {
  for (const mode of ['close', 'global', 'owner']) {
    const f = fixture(t);
    let resolve!: (value: any) => void, late: any;
    f.setAdmission((value) => {
      late = value;
      return new Promise((r) => (resolve = r));
    });
    const pending = f.open(f.quick);
    void pending.catch(() => {});
    await tick();
    let stopped = false;
    const closing =
      mode === 'global'
        ? f.coordinator.closeAll()
        : mode === 'close'
          ? f.coordinator.close(f.input.sessionId)
          : undefined;
    if (mode === 'owner') f.setOwner(false);
    void closing?.then(() => (stopped = true));
    await tick();
    if (closing) assert.equal(stopped, false);
    resolve(late);
    await assert.rejects(pending);
    await closing;
    assert.equal(f.targetReleases, 1);
    assert.equal(f.requests.length, 0);
    assert.equal(f.coordinator.has(f.input.sessionId), false);
  }
});

test('web Quick target release failure remains retryable after route or target uncertainty', async (t) => {
  const f = fixture(t, true);
  await f.open(f.quick);
  f.failRelease();
  await assert.rejects(f.coordinator.close(f.input.sessionId));
  assert.equal(f.targetReleases, 0);
  f.failRelease(false);
  f.failTarget();
  await assert.rejects(f.coordinator.closeAll());
  assert.equal(f.coordinator.has(f.input.sessionId), true);
  await assert.rejects(f.open(), /unavailable/);
  f.failTarget(false);
  await f.coordinator.closeAll();
  assert.equal(f.targetReleases, 1);
  await f.open(f.quick);
  await f.coordinator.close(f.input.sessionId);
  assert.equal(f.targetReleases, 2);
});
