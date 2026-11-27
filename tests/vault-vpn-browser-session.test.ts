import assert from 'node:assert/strict';
import test from 'node:test';
import { VaultVPNBrowserSession } from '../electron/vault-vpn-browser-session.ts';
import { vpnSSOFixture } from './fixtures/vault-vpn-sso.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { randomUUID } from 'node:crypto';

const tick = () => new Promise(setImmediate);
function fixture() {
  const f = vpnSSOFixture(),
    calls: string[] = [],
    owned: Uint8Array[] = [];
  let accepted = true,
    destroyed = false,
    offline = true,
    memory = true,
    profile = 'standard',
    sequence = '3',
    fail = '';
  const security = () => ({
    sequence,
    workspace: profile,
    user: 'default',
    os: 'default',
    effective: profile,
    source: 'workspace',
  });
  const invoke = async (name: string) => {
    calls.push(name);
    if (name === fail) throw Error('private-fixture-error');
  };
  const capability: any = {
    offer: f.offer,
    take: async (index: number) => {
      await invoke('take');
      assert.equal(index, 0);
      return f.packet;
    },
    acknowledge: () => invoke('ack'),
    push: () => invoke('push'),
    commit: async () => {
      await invoke('commit');
      return { revision: '1', deleted: false, digest: Array(32).fill(8) };
    },
    cancel: () => invoke('cancel'),
  };
  const recipient: any = {
    get metadata() {
      return { profileId: f.q.profileId, publicKey: f.q.restorePublicKey, lockedMemory: memory };
    },
    restore: async (_offer: any, take: any) => {
      await invoke('restore');
      await take(0);
      const bytes = Buffer.from('restored-state');
      owned.push(bytes);
      return bytes;
    },
    capture: async (bytes: Uint8Array, push: any) => {
      await invoke('seal');
      assert.equal(Buffer.from(bytes).toString(), 'captured-state');
      await push(f.packet);
      return f.packet.manifest;
    },
    close: () => invoke('recipient-close'),
  };
  const driver: any = {
    get isOffline() {
      return offline;
    },
    permitsRequest: () => !offline,
    apply: async (bytes: Uint8Array) => {
      await invoke('apply');
      assert.equal(Buffer.from(bytes).toString(), 'restored-state');
    },
    publish: async () => {
      await invoke('publish');
      offline = false;
    },
    capture: async () => {
      await invoke('capture');
      offline = true;
      const bytes = Buffer.from('captured-state');
      owned.push(bytes);
      return bytes;
    },
    close: () => invoke('driver-close'),
  };
  const controller = new AbortController();
  const options: any = {
    window: { isDestroyed: () => destroyed },
    request: structuredClone(f.q.request),
    context: {
      binding: structuredClone(f.q.binding),
      challengeId: f.q.challengeId,
      publicKey: f.q.restorePublicKey,
      startURL: f.q.startURL,
      ignoreCertificateErrors: false,
      cookieName: 'SVPNCOOKIE',
    },
    signal: controller.signal,
    current: () => accepted,
    executable: 'original-backend',
    authority: {
      security: async () => {
        await invoke('security');
        return security();
      },
      begin: async (q: any) => {
        await invoke('begin');
        assert.deepEqual(q, f.q);
        return capability;
      },
    },
  };
  const adapters = {
    recipient: async (q: any) => {
      await invoke('recipient');
      assert.equal(q.executable, 'original-backend');
      assert.equal(q.current(), accepted);
      return recipient;
    },
    storage: async (q: any) => {
      await invoke('storage');
      assert.equal(q.window, options.window);
      assert.equal(q.attemptCookie, 'SVPNCOOKIE');
      return driver;
    },
  };
  const create = () => new VaultVPNBrowserSession(options, adapters);
  return {
    ...f,
    options,
    adapters,
    calls,
    owned,
    create,
    capability,
    recipient,
    driver,
    controller,
    deny: () => {
      accepted = false;
    },
    destroy: () => {
      destroyed = true;
    },
    fail: (name: string) => {
      fail = name;
    },
    memory: (value: boolean) => {
      memory = value;
    },
    profile: (value: string) => {
      profile = value;
    },
    sequence: (value: string) => {
      sequence = value;
    },
  };
}
test('native session restores before root acknowledgement/network and commits encrypted capture before close', async () => {
  const f = fixture(),
    session = f.create();
  assert.equal(session.isOffline, true);
  assert.equal(session.permitsRequest('https://idp.test/', 1, 'mainFrame'), false);
  await session.restore();
  assert.deepEqual(f.calls, [
    'security',
    'recipient',
    'begin',
    'storage',
    'restore',
    'take',
    'apply',
    'ack',
    'publish',
  ]);
  assert.equal(session.isOffline, false);
  assert.equal(session.permitsRequest('https://idp.test/', 1, 'mainFrame'), true);
  assert.ok(f.owned[0].every((b) => b === 0));
  await session.capture();
  assert.deepEqual(f.calls.slice(-4), ['capture', 'seal', 'push', 'commit']);
  assert.ok(f.owned.every((raw) => raw.every((b) => b === 0)));
  assert.equal(session.isOffline, true);
  await assert.rejects(session.capture());
  await session.close();
  await session.close();
  assert.ok(
    f.calls.includes('driver-close') &&
      f.calls.includes('cancel') &&
      f.calls.includes('recipient-close'),
  );
});
test('IPsec SAML uses the same original-root custody with a separately bound fresh callback', async () => {
  const f = fixture();
  f.q.binding.kind = 9;
  f.q.startURL = 'https://vpn.test:1001/saml?request=fixture';
  f.options.context = {
    binding: { ...f.q.binding },
    challengeId: f.q.challengeId,
    publicKey: f.q.restorePublicKey,
    startURL: f.q.startURL,
    callbackURL: 'http://127.0.0.1:12345/',
    ignoreCertificateErrors: false,
  };
  const session = f.create();
  await session.restore();
  await session.capture();
  await session.close();
  assert.ok(f.owned.every((raw) => raw.every((b) => b === 0)));
  f.options.context.cookieName = 'SVPNCOOKIE';
  assert.throws(f.create);
});

test('fallback browser custody snapshots the pair and retains the original request through capture', async () => {
  const f = fixture();
  const primary = { ...f.q.binding, kind: 9 };
  const active = { ...f.q.binding, requestId: randomUUID(), tunnelConfigId: randomUUID() };
  f.q.binding = active;
  f.q.fallback = { primary, fallback: active };
  f.options.context.binding = structuredClone(active);
  f.options.fallback = structuredClone(f.q.fallback);
  const session = f.create();
  f.options.fallback.primary.host = 'replacement';
  f.options.fallback.fallback.rowVersion = '99';
  await session.restore();
  assert.ok(f.calls.includes('begin') && f.calls.includes('publish'));
  await session.capture();
  await session.close();
  assert.equal(f.q.request.requestId, primary.requestId);
  assert.notEqual(f.q.request.requestId, active.requestId);
  for (const bad of [
    null,
    {},
    { ...f.q.fallback, primary: active },
    { ...f.q.fallback, fallback: { ...active, rowVersion: '99' } },
  ]) {
    f.options.fallback = bad;
    assert.throws(f.create, /unavailable/);
  }
});
test('session refuses policy, memory, source and every native action failure while consuming plaintext', async () => {
  for (const failure of [
    'security',
    'recipient',
    'begin',
    'storage',
    'restore',
    'take',
    'apply',
    'ack',
    'publish',
    'capture',
    'seal',
    'push',
    'commit',
  ]) {
    const f = fixture(),
      session = f.create();
    f.fail(failure);
    if (['capture', 'seal', 'push', 'commit'].includes(failure)) {
      await session.restore();
      await assert.rejects(session.capture());
    } else await assert.rejects(session.restore());
    assert.equal(session.isOffline, true);
    assert.equal(session.permitsRequest('https://idp.test/', 1, 'mainFrame'), false);
    await session.close();
    assert.ok(f.owned.every((raw) => raw.every((b) => b === 0)));
  }
  for (const mutate of [
    (f: ReturnType<typeof fixture>) => f.memory(false),
    (f: ReturnType<typeof fixture>) => f.profile('hardened'),
    (f: ReturnType<typeof fixture>) => f.profile('invalid'),
    (f: ReturnType<typeof fixture>) => f.sequence('4'),
  ]) {
    const f = fixture();
    mutate(f);
    const session = f.create();
    await assert.rejects(session.restore());
    await session.close();
    assert.equal(f.calls.includes('publish'), false);
  }
  const f = fixture();
  f.profile('default');
  f.memory(false);
  const session = f.create();
  await session.restore();
  await session.close();
});
test('original request, credential override, methods and executable are captured before asynchronous initialization', async () => {
  const f = fixture(),
    session = f.create();
  f.options.request.credentialOverride = 'replacement';
  f.options.executable = 'replacement';
  f.options.current = () => false;
  f.options.authority.begin = () => {
    throw Error('replacement root');
  };
  f.adapters.recipient = () => {
    throw Error('replacement native');
  };
  await session.restore();
  await session.close();
});
test('close joins a late root capability, bars concurrent work and retries uncertain cleanup', async () => {
  const f = fixture();
  let finish!: (value: any) => void;
  f.options.authority.begin = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  const session = f.create(),
    pending = session.restore();
  void pending.catch(() => {});
  await tick();
  await assert.rejects(session.restore());
  let closed = false;
  const closing = session.close().then(() => {
    closed = true;
  });
  await tick();
  assert.equal(closed, false);
  finish(f.capability);
  await assert.rejects(pending);
  await closing;
  assert.equal(closed, true);
  assert.ok(f.calls.includes('cancel'));
  const retry = fixture(),
    other = retry.create();
  await other.restore();
  retry.fail('recipient-close');
  await assert.rejects(other.close());
  retry.fail('');
  await other.close();
});
test('failed asynchronous admission retains every reserved native handle until cleanup succeeds', async () => {
  for (const kind of ['recipient', 'storage', 'root']) {
    const f = fixture();
    const failAdmission = async (_q: any, reserved: any) => {
      reserved(kind === 'recipient' ? f.recipient : kind === 'storage' ? f.driver : f.capability);
      throw Error('fixture late admission failure');
    };
    if (kind === 'root') f.options.authority.begin = failAdmission;
    else f.adapters[kind as 'recipient' | 'storage'] = failAdmission;
    const session = f.create();
    await assert.rejects(session.restore());
    const cleanup =
      kind === 'root' ? 'cancel' : kind === 'storage' ? 'driver-close' : 'recipient-close';
    f.fail(cleanup);
    await assert.rejects(session.close());
    assert.ok(f.calls.includes(cleanup));
    f.fail('');
    await session.close();
  }
});
test('lost authority and abort cannot publish, save or forward native network requests', async () => {
  for (const action of ['deny', 'destroy', 'abort', 'throw']) {
    const f = fixture();
    if (action === 'throw')
      f.options.current = () => {
        throw Error('private');
      };
    if (action === 'throw') {
      assert.throws(f.create);
      continue;
    }
    const session = f.create();
    await session.restore();
    if (action === 'deny') f.deny();
    if (action === 'destroy') f.destroy();
    if (action === 'abort') f.controller.abort();
    assert.equal(session.permitsRequest('https://idp.test/', 1, 'mainFrame'), false);
    await assert.rejects(session.capture());
    await session.close();
  }
  for (const mutate of [
    (o: any) => {
      o.request = null;
    },
    (o: any) => {
      o.context = null;
    },
    (o: any) => {
      o.context.binding.sessionId = '11111111-1111-4111-8111-111111111111';
    },
    (o: any) => {
      o.executable = '';
    },
  ]) {
    const f = fixture();
    mutate(f.options);
    assert.throws(f.create);
  }
});
test('native invalidation immediately retires custody and notifies its original browser actor', async () => {
  const f = fixture();
  let invalidate!: () => void;
  const storage = f.adapters.storage;
  f.adapters.storage = async (q: any) => {
    invalidate = q.invalidated;
    return storage(q);
  };
  f.options.failed = () => {
    f.calls.push('original-failed');
  };
  const session = f.create();
  await session.restore();
  invalidate();
  assert.equal(session.isOffline, true);
  assert.equal(f.calls.at(-1), 'original-failed');
  assert.equal(session.permitsRequest('https://idp.test/', 1, 'mainFrame'), false);
  await session.close();
});
test('reserved host authority refuses root replacement before begin and cancels late replies on the original root', async (t) => {
  const profiler =
    process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE
      ? undefined
      : new Session();
  if (profiler) {
    profiler.connect();
    t.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }
  const f = fixture();
  let securityFinish!: (v: any) => void;
  const client: any = {
    security: async () => ({ effective: 'default' }),
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    beginVPNSSO: async () => f.offer,
    cancelVPNSSO: async () => {
      f.calls.push('original-cancel');
      return { cancelled: true };
    },
  };
  let nativeClient: any;
  const host = new VaultBackendHost(
    () => {
      nativeClient = { ...client };
      return nativeClient;
    },
    () => true,
  );
  assert.throws(() => host.vpnSSOAuthority(() => true));
  const unlock = () =>
    host.unlock({
      vaultId: f.q.request.workspaceId,
      slotId: f.q.challengeId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
  await unlock();
  const authority = host.vpnSSOAuthority(() => true);
  assert.throws(() => authority.begin(null));
  assert.deepEqual(await authority.security(), { effective: 'default' });
  assert.throws(() =>
    authority.begin({ ...f.q, request: { ...f.q.request, workspaceId: f.q.binding.fileId } }),
  );
  const handle = await authority.begin(f.q);
  await handle.cancel();
  nativeClient.security = () =>
    new Promise((resolve) => {
      securityFinish = resolve;
    });
  const pending = authority.security();
  await host.stop();
  securityFinish({ effective: 'default' });
  await assert.rejects(pending);
  client.security = async () => ({ effective: 'default' });
  await unlock();
  await assert.rejects(authority.security());
  assert.throws(() => authority.begin(f.q));
  let accepted = true;
  const next = host.vpnSSOAuthority(() => accepted);
  accepted = false;
  await assert.rejects(next.security());
  assert.throws(() => next.begin(f.q));
  await host.stop();
  await unlock();
  const oldClient = nativeClient,
    oldAuthority = host.vpnSSOAuthority(() => true);
  const active = await oldAuthority.begin(f.q),
    stale = await oldAuthority.begin(f.q);
  oldClient.cancelVPNSSO = async () => {
    throw Error('fixture unavailable root');
  };
  let exit!: () => void;
  oldClient.lock = () =>
    new Promise<void>((resolve) => {
      exit = resolve;
    });
  const closing = active.cancel();
  await tick();
  assert.equal(host.unlockedWorkspaceId, undefined);
  exit();
  await closing;
  oldClient.lock = async () => {
    f.calls.push('old-root-exit');
  };
  await unlock();
  const replacement = nativeClient;
  await stale.cancel();
  assert.ok(f.calls.includes('old-root-exit'));
  assert.equal(nativeClient, replacement);
  assert.equal(host.unlockedWorkspaceId, f.q.request.workspaceId);
  await host.stop();
  if (profiler) {
    const report = await profiler.post('Profiler.takePreciseCoverage');
    const script = report.result.find((s) => s.url.endsWith('/electron/vault-host.ts'));
    assert.ok(script);
    const method = script.functions.find((f) => f.functionName === 'vpnSSOAuthority');
    assert.ok(method);
    const extent = method.ranges[0];
    const blocks = script.functions
      .filter(
        (f) =>
          f.ranges[0].startOffset >= extent.startOffset &&
          f.ranges[0].endOffset <= extent.endOffset,
      )
      .flatMap((f) => f.ranges);
    const percent = (100 * blocks.filter((r) => r.count > 0).length) / blocks.length;
    t.diagnostic('reserved SSO host ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
  }
});
