import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import {
  parseVaultWebRequest,
  parseVaultWebPlan,
  parseVaultWebViews,
  parseVaultWebViewReply,
} from '../electron/vault-web.ts';
import { randomUUID } from 'node:crypto';
import {
  maxWebSessionArchiveBytes,
  parseWebSessionArchiveReply,
  parseWebSessionArchiveWrite,
  webSessionArchiveWriteRevision,
} from '../electron/vault-web-session-archive.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import { VaultWebCookieCheckpoint } from '../electron/vault-web-cookies.ts';
import { webRequest, webPlan } from './fixtures/vault-web.ts';
const tick = () => new Promise(setImmediate);

test('shared browser generations stay in the native plan and use an exact bounded receipt', () => {
  const request = webRequest(),
    plan = webPlan(request);
  const pin = { nodeId: request.nodeId, generation: randomUUID() };
  const tracked = { ...plan, archiveBinding: 'af'.repeat(32), viewGeneration: pin.generation };
  assert.deepEqual(parseVaultWebPlan(tracked, request), tracked);
  assert.equal(parseVaultWebPlan({ ...tracked, archiveBinding: undefined }, request), undefined);
  assert.equal(parseVaultWebPlan({ ...tracked, viewGeneration: 'invalid' }, request), undefined);
  assert.equal(parseVaultWebPlan({ ...tracked, temporary: true }, request), undefined);
  assert.deepEqual(parseVaultWebViews([pin]), [pin]);
  assert.notEqual(parseVaultWebViews([pin])?.[0], pin);
  for (const value of [
    null,
    [],
    Array(33).fill(pin),
    [null],
    [{ ...pin, generation: null }],
    [{ ...pin, extra: true }],
  ])
    assert.equal(parseVaultWebViews(value), undefined);
  assert.deepEqual(parseVaultWebViewReply({ current: [false, true] }, 2), [false, true]);
  for (const value of [
    null,
    {},
    { current: [true] },
    { current: ['false', true] },
    { current: Array(2) },
    { current: [true, true], extra: true },
  ])
    assert.equal(parseVaultWebViewReply(value, 2), undefined);
});

const cookieOrigin = 'https://portal.example:8443';
const cookieURL = cookieOrigin + '/app';
function portalCookie(patch: Record<string, unknown> = {}) {
  return {
    name: 'test_auth',
    value: 'synthetic fixture',
    domain: 'portal.example',
    path: '/app',
    secure: true,
    httpOnly: true,
    sourceScheme: 'Secure',
    sourcePort: 8443,
    expires: -1,
    priority: 'High',
    sameSite: 'Strict',
    ...patch,
  };
}

function cookieCheckpointFixture(seed?: Uint8Array) {
  const writes: { revision: string; contents: any; bytes: Uint8Array }[] = [];
  const erases: string[] = [];
  const calls: [string, any][] = [];
  let authorized = true;
  let attached = false;
  let detachCount = 0;
  let url = cookieURL;
  let destroyed = false;
  let cookies: unknown[] = [portalCookie()];
  let paths = [{ domain: 'portal.example', path: '/app' }];
  let receipt = { success: true };
  let current = seed ? 1n : 0n;
  let gate: Promise<void> | undefined;
  let saveGate: Promise<void> | undefined;
  let failure = false;
  const jar = Object.assign(new EventEmitter(), {
    get: async (filter: unknown) => {
      assert.deepEqual(filter, { domain: 'portal.example' });
      await gate;
      return paths;
    },
  });
  const view = {
    getURL: () => url,
    isDestroyed: () => destroyed,
    loadURL: async (value: string) => {
      url = value;
    },
    debugger: {
      isAttached: () => attached,
      attach: (protocol: string) => {
        assert.equal(protocol, '1.3');
        assert.equal(attached, false);
        attached = true;
      },
      detach: () => {
        attached = false;
        detachCount++;
      },
      sendCommand: async (method: string, payload: any) => {
        assert.equal(attached, true);
        calls.push([method, payload]);
        return method === 'Network.getCookies' ? { cookies } : receipt;
      },
    },
  } as unknown as Electron.WebContents;
  const advance = (revision: string) => {
    assert.equal(revision, current.toString());
    return (++current).toString();
  };
  const checkpoint = new VaultWebCookieCheckpoint({
    url: cookieURL,
    jar: jar as unknown as Electron.Cookies,
    views: () => [view],
    authorized: () => authorized,
    store: {
      async read() {
        return { revision: current.toString(), ...(seed ? { bytes: seed } : {}) };
      },
      async save(revision, bytes) {
        if (failure) throw Error('private fixture error');
        writes.push({ revision, contents: JSON.parse(new TextDecoder().decode(bytes)), bytes });
        await saveGate;
        return advance(revision);
      },
      async forget(revision) {
        erases.push(revision);
        return advance(revision);
      },
    },
  });
  return {
    checkpoint,
    view,
    writes,
    erases,
    calls,
    jar,
    navigate: (next: string) => {
      url = next;
    },
    change: (domain = 'portal.example') => jar.emit('changed', {}, { domain }),
    cookies: (next: unknown[]) => {
      cookies = next;
    },
    paths: (next: typeof paths) => {
      paths = next;
    },
    revoke: () => {
      authorized = false;
    },
    destroy: () => {
      destroyed = true;
    },
    gate: (next: Promise<void>) => {
      gate = next;
    },
    holdSave: (next: Promise<void>) => {
      saveGate = next;
    },
    fail: () => {
      failure = true;
    },
    detachCount: () => detachCount,
    refuseRestoredCookie: () => {
      receipt = { success: false };
    },
  };
}

const cookieBytes = (cookies: unknown[]) =>
  new TextEncoder().encode(JSON.stringify({ version: 1, cookies }));
const archiveKey = { topLevelSite: 'https://portal.example', hasCrossSiteAncestor: false };

test('vault web cookies preserve first-party source and partition attributes during restore and capture', async (t) => {
  const seed = cookieBytes([
    portalCookie({ partitionKey: archiveKey }),
    portalCookie({ name: 'gone', expires: 1 }),
    portalCookie({
      name: 'domain_cookie',
      domain: '.portal.example',
      expires: 4102444800,
      sameSite: undefined,
    }),
  ]);
  const f = cookieCheckpointFixture(seed);
  t.after(() => f.checkpoint.stop());
  await f.checkpoint.restore(f.view);
  assert.deepEqual(f.erases, ['1']);
  assert.ok(seed.every((value) => value === 0));
  assert.equal(f.detachCount(), 1);
  assert.equal(f.calls[0][0], 'Network.setCookie');
  assert.equal(f.calls[0][1].url, cookieOrigin);
  assert.equal(f.calls[0][1].sourcePort, 8443);
  assert.equal(f.calls[0][1].httpOnly, true);
  assert.deepEqual(f.calls[0][1].partitionKey, archiveKey);
  assert.equal('domain' in f.calls[0][1], false);
  assert.equal('expires' in f.calls[0][1], false);
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[1][1].domain, '.portal.example');
  assert.equal(f.calls[1][1].expires, 4102444800);
  f.navigate(cookieURL);
  f.paths([
    { domain: 'portal.example', path: '/app' },
    { domain: 'other.example', path: '/foreign' },
    { domain: '.portal.example', path: '/' },
    { domain: 'portal.example', path: 'not-a-path' },
    { domain: 'portal.example', path: '/app' },
  ]);
  f.cookies([
    portalCookie({ partitionKey: archiveKey }),
    portalCookie({ domain: 'other.example' }),
    portalCookie({ sourcePort: 443 }),
    portalCookie({ partitionKeyOpaque: true }),
    portalCookie({ partitionKey: { ...archiveKey, hasCrossSiteAncestor: true } }),
    portalCookie({ partitionKey: { ...archiveKey, topLevelSite: 'https://other.example' } }),
    portalCookie({ partitionKey: { ...archiveKey, topLevelSite: cookieOrigin } }),
    portalCookie({
      partitionKey: { ...archiveKey, topLevelSite: archiveKey.topLevelSite + '/path' },
    }),
    null,
  ]);
  await f.checkpoint.checkpointNow();
  assert.equal(f.jar.listenerCount('changed'), 1);
  await f.checkpoint.flush();
  assert.deepEqual(f.calls[2], [
    'Network.getCookies',
    { urls: [cookieOrigin + '/app', cookieOrigin + '/'] },
  ]);
  assert.deepEqual(
    f.writes.map(({ revision, contents }) => ({ revision, contents })),
    [
      {
        revision: '2',
        contents: { version: 1, cookies: [portalCookie({ partitionKey: archiveKey })] },
      },
    ],
  );
  assert.ok(f.writes[0].bytes.every((value) => value === 0));
  assert.equal(f.jar.listenerCount('changed'), 0);
  assert.equal(f.detachCount(), 2);
});

test(
  'vault web cookie logout erases the previous checkpoint and leaves it erased',
  { timeout: 3000 },
  async (t) => {
    const f = cookieCheckpointFixture();
    t.after(() => f.checkpoint.stop());
    await f.checkpoint.restore(f.view);
    f.change('unrelated.example');
    f.checkpoint.ready();
    assert.deepEqual(f.calls, []);
    f.change();
    f.checkpoint.ready();
    for (let attempt = 0; !f.writes.length && attempt < 20; attempt++)
      await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(f.writes.length, 1);
    f.paths([]);
    f.change();
    await f.checkpoint.flush();
    assert.deepEqual(f.erases, ['1']);
    assert.equal(f.writes.length, 1);
  },
);

test('a logout overlapping a completed vault web write invalidates its receipt', async (t) => {
  const f = cookieCheckpointFixture();
  t.after(() => f.checkpoint.stop());
  await f.checkpoint.restore(f.view);
  const saving = Promise.withResolvers<void>();
  f.holdSave(saving.promise);
  f.change();
  const checkpoint = f.checkpoint.checkpointNow();
  await tick();
  assert.equal(f.writes.length, 1);
  f.paths([]);
  f.change();
  saving.resolve();
  await checkpoint;
  await f.checkpoint.flush();
  assert.deepEqual(f.erases, ['1']);
  assert.equal(f.writes.length, 1);
});

test('vault web cookie retirement and failures discard outstanding plaintext', async () => {
  const bad = cookieBytes([portalCookie({ path: 'redirect' })]);
  const malformed = cookieCheckpointFixture(bad);
  await assert.rejects(malformed.checkpoint.restore(malformed.view), /Invalid web cookie archive/);
  assert.ok(bad.every((value) => value === 0));
  assert.deepEqual(malformed.erases, ['1']);
  const denied = cookieCheckpointFixture(cookieBytes([portalCookie()]));
  denied.revoke();
  await assert.rejects(denied.checkpoint.restore(denied.view), /superseded/);
  assert.deepEqual(denied.erases, []);
  const refused = cookieCheckpointFixture(cookieBytes([portalCookie()]));
  refused.refuseRestoredCookie();
  await assert.rejects(refused.checkpoint.restore(refused.view), /Could not restore/);
  assert.equal(refused.detachCount(), 1);
  const retired = cookieCheckpointFixture();
  await retired.checkpoint.restore(retired.view);
  let release!: () => void;
  retired.gate(
    new Promise((resolve) => {
      release = resolve;
    }),
  );
  retired.change();
  const pending = retired.checkpoint.flush();
  await tick();
  retired.revoke();
  retired.checkpoint.stop();
  release();
  await pending;
  assert.deepEqual(retired.writes, []);
  assert.deepEqual(retired.calls, []);
  const rejected = cookieCheckpointFixture();
  await rejected.checkpoint.restore(rejected.view);
  rejected.change();
  rejected.fail();
  await assert.rejects(rejected.checkpoint.flush(), /^Error: Web cookie checkpoint failed\.$/);
  assert.equal(rejected.jar.listenerCount('changed'), 0);
  const gone = cookieCheckpointFixture();
  await gone.checkpoint.restore(gone.view);
  gone.destroy();
  gone.change();
  await gone.checkpoint.flush();
  assert.deepEqual(gone.calls, []);
});
test('web archive receipts reject unbounded, noncanonical and cross-operation data', () => {
  const bundle = {
    formatVersion: 1,
    suiteId: 2,
    enc: Buffer.alloc(32).toString('base64'),
    ciphertext: Buffer.alloc(17).toString('base64'),
  };
  assert.deepEqual(parseWebSessionArchiveReply({ revision: '1', bundle }), {
    revision: '1',
    bundle: { enc: Buffer.alloc(32), ciphertext: Buffer.alloc(17) },
  });
  for (const patch of [
    { formatVersion: 2 },
    { suiteId: 1 },
    { enc: 0 },
    { enc: 'a' },
    { enc: bundle.enc.replace(/A/, '_') },
    { ciphertext: 0 },
    { ciphertext: Buffer.alloc(16).toString('base64') },
    { ciphertext: 'AAAA' },
    { ciphertext: Buffer.alloc(maxWebSessionArchiveBytes + 17).toString('base64') },
    { ciphertext: bundle.ciphertext.replace(/A/, '_') },
    { plaintext: 'unexpected' },
  ])
    assert.equal(
      parseWebSessionArchiveReply({ revision: '1', bundle: { ...bundle, ...patch } }),
      undefined,
    );
  for (const reply of [
    null,
    {},
    { revision: 1 },
    { revision: '01' },
    { revision: '0', bundle },
    { revision: '1', bundle: null },
  ]) {
    assert.equal(parseWebSessionArchiveReply(reply), undefined);
    assert.equal(parseWebSessionArchiveWrite(reply, '0'), undefined);
  }
  assert.equal(parseWebSessionArchiveWrite({ revision: '3' }, '1'), undefined);
  assert.equal(parseWebSessionArchiveWrite({ revision: '2' }, '1'), '2');
  assert.equal(
    parseWebSessionArchiveWrite({ revision: '9223372036854775807' }, '9223372036854775806'),
    '9223372036854775807',
  );
  assert.equal(webSessionArchiveWriteRevision('9223372036854775807'), false);
});
test('web plan binds a public saved target and exact optional tunnel snapshot without accepting overrides', () => {
  const q = webRequest();
  assert.deepEqual(parseVaultWebRequest(q), q);
  for (const bad of [
    null,
    {},
    { ...q, credentialOverride: q.nodeId },
    { ...q, publicKey: 'key' },
    { ...q, epoch: 0 },
  ])
    assert.equal(parseVaultWebRequest(bad), undefined);
  for (const routed of [false, true]) {
    const value = webPlan(q, routed);
    assert.deepEqual(parseVaultWebPlan(value, q), value);
    const archiveBinding = 'a1'.repeat(32);
    assert.equal(
      parseVaultWebPlan({ ...value, archiveBinding }, q)?.archiveBinding,
      archiveBinding,
    );
    for (const malformed of [null, '', archiveBinding.toUpperCase(), 'g'.repeat(64)])
      assert.equal(parseVaultWebPlan({ ...value, archiveBinding: malformed }, q), undefined);
    const copy = parseVaultWebPlan(value, q)!;
    copy.binding.host = 'changed';
    copy.target.url = 'changed';
    if (copy.route) copy.route.rowVersion = '1';
    assert.equal(value.binding.host, 'web.example');
    assert.equal(value.target.url, 'https://web.example:8443/native%2Fpath');
    const ephemeral = {
      ...value,
      temporary: true,
      target: { ...value.target, url: value.target.url + '?q=temporary#page' },
    };
    assert.deepEqual(parseVaultWebPlan(ephemeral, q), ephemeral);
    assert.equal(parseVaultWebPlan({ ...ephemeral, archiveBinding }, q), undefined);
    for (const temporary of [false, null, 1, 'true'])
      assert.equal(parseVaultWebPlan({ ...ephemeral, temporary }, q), undefined);
    if (value.route) assert.equal(value.route.rowVersion, '9223372036854775807');
    for (const target of ['root', 'binding', 'target', 'route']) {
      if (target === 'route' && !routed) continue;
      const bad = structuredClone(value) as any;
      (target === 'root' ? bad : bad[target]).password = 'not-metadata';
      assert.equal(parseVaultWebPlan(bad, q), undefined);
    }
    for (const key of Object.keys(value.binding)) {
      const bad = structuredClone(value) as any;
      bad.binding[key] =
        key === 'host'
          ? 'bad host'
          : key === 'port'
            ? 0
            : key === 'epoch'
              ? 2
              : key === 'useExternalClient'
                ? true
                : webRequest().nodeId;
      assert.equal(parseVaultWebPlan(bad, q), undefined, key);
    }
    for (const delta of [
      null,
      { ...value.target, protocol: 'http' },
      { ...value.target, host: 'redirect.example' },
      { ...value.target, port: 443 },
      { ...value.target, ignoreCertErrors: 'false' },
      { ...value.target, tunnelConfigId: null },
      { ...value.target, tunnelConfigId: '' },
      ...[
        'data:text/html,hello',
        'not a URL',
        'https://user:password@web.example:8443/',
        'https://other.example:8443/',
        'http://web.example:8443/',
        'https://web.example:8443/path?token=not-persisted',
        'https://web.example:8443/#page',
        'x'.repeat(8193),
      ].map((url) => ({ ...value.target, url })),
    ])
      assert.equal(parseVaultWebPlan({ ...value, target: delta }, q), undefined);
    for (const delta of [
      null,
      {},
      { ...value, route: routed ? null : {} },
      { ...value, binding: null },
      { ...value, target: null },
    ])
      assert.equal(parseVaultWebPlan(delta, q), undefined);
    if (value.route) {
      for (const delta of [
        { ...value.route, host: 'redirect.example' },
        { ...value.route, protocol: 'ssh' },
        { ...value.route, configurationVersion: '9223372036854775808' },
        { ...value.route, workspaceId: webRequest().workspaceId },
      ])
        assert.equal(parseVaultWebPlan({ ...value, route: delta }, q), undefined);
    }
  }
  const value = webPlan(q);
  value.binding.protocol = 'http';
  value.binding.port = 80;
  value.target = { ...value.target, url: 'http://web.example:80/', port: 80, protocol: 'http' };
  assert.deepEqual(parseVaultWebPlan(value, q), value);
  assert.equal(
    parseVaultWebPlan({ ...value, target: { ...value.target, ignoreCertErrors: true } }, q),
    undefined,
  );
  assert.equal(
    parseVaultWebPlan(value, { ...q, workspaceId: webRequest().workspaceId }),
    undefined,
  );
});
test('web host confines planning to the unlocked current owner and exposes no general IPC endpoint', async () => {
  const q = webRequest(),
    expected = webPlan(q);
  let allowed = true,
    delayed = false,
    malformed = false,
    release!: () => void;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
    readWebSessionArchive: async () => {
      await new Promise<void>((r) => (release = r));
      return { revision: '1', bytes };
    },
    saveWebSessionArchive: async () => '2',
    forgetWebSessionArchive: async () => '2',
    webPlan: async (input: unknown) => {
      assert.deepEqual(input, q);
      if (delayed) await new Promise<void>((r) => (release = r));
      return malformed ? {} : expected;
    },
  };
  const bytes = new Uint8Array([42]);
  const host = new VaultBackendHost(
      () => client,
      () => true,
    ),
    invoke = (value: unknown = q) => host.webPlan(value, () => allowed);
  await assert.rejects(invoke(null), /Invalid/);
  await assert.rejects(invoke(), /locked/);
  const unlock = () =>
    host.unlock({
      vaultId: q.workspaceId,
      slotId: q.nodeId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
  await unlock();
  const archive = host.webSessionArchive(
    { ...expected, archiveBinding: 'a'.repeat(64) },
    () => allowed,
  )!;
  const pendingRead = archive.read();
  await tick();
  allowed = false;
  release();
  await assert.rejects(pendingRead, /closed/);
  assert.equal(bytes[0], 0, 'a late archive reply must not survive loss of access');
  allowed = true;
  assert.deepEqual(await invoke(), expected);
  await assert.rejects(invoke({ ...q, workspaceId: webRequest().workspaceId }), /locked/);
  allowed = false;
  await assert.rejects(invoke(), /locked/);
  allowed = true;
  malformed = true;
  await assert.rejects(invoke(), /Invalid/);
  malformed = false;
  for (const stop of [false, true]) {
    delayed = true;
    const pending = invoke();
    await tick();
    if (stop) await host.stop();
    else allowed = false;
    release();
    await assert.rejects(pending, /locked/);
    allowed = true;
    delayed = false;
    if (stop) await unlock();
  }
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
  assert.equal(channels.includes('vault:web-plan'), false);
  assert.equal(
    channels.some((name) => name.startsWith('vault:web-session-')),
    false,
  );
  await host.stop();
});
