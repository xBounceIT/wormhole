import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { createContext, Script } from 'node:vm';
import { VaultBitwardenDocumentEndpoint } from '../electron/vault-bitwarden-endpoint.ts';
import { createBitwardenDocumentEndpoint } from '../src/vault-bitwarden-document-endpoint.ts';
import type { BitwardenExtensionBridge } from '../electron/vault-bitwarden-bridge-contract.ts';
import type {
  BrowserTransferContext,
  BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';

const tick = () => new Promise<void>((r) => setImmediate(r));
const unavailable = /^Error: Bitwarden document is unavailable\.$/;
function fixture() {
  const owner = { workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 },
    url = `chrome-extension://${'a'.repeat(32)}/background.html`,
    session = {};
  const q = {
    ...owner,
    requestId: randomUUID(),
    action: 'hydrate' as const,
    sourceRevision: '0',
    restorePublicKey: Buffer.alloc(32, 1).toString('base64'),
  };
  const c: BrowserTransferContext = {
    ...q,
    fileId: randomUUID(),
    transferId: randomUUID(),
    policySequence: '1',
    capturePublicKey: Buffer.alloc(32, 2).toString('base64'),
  };
  const manifest = { bytes: 14, revision: '0', restore: false };
  const packet: BrowserTransferPacket = {
    context: c,
    direction: 'capture',
    manifest,
    index: 0,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 3).toString('base64'),
      ciphertext: Buffer.alloc(30, 4).toString('base64'),
    },
  };
  const calls: string[] = [],
    scripts: string[] = [],
    results: unknown[] = [];
  let alive = true,
    destroyed = false,
    frameDead = false,
    sandboxed = true,
    kind = 'backgroundPage',
    installed = false;
  let documentCall: ReturnType<typeof createBitwardenDocumentEndpoint>, token: string;
  const bridge: BitwardenExtensionBridge = {
    prepare: async () => {
      calls.push('prepare');
      return q;
    },
    bind: async () => {
      calls.push('bind');
      return { chunks: 1, manifest };
    },
    next: async () => {
      calls.push('next');
      return packet;
    },
    accept: async () => {
      calls.push('accept');
      return { complete: true, revision: '0', restore: false };
    },
    cancel: async () => {
      calls.push('cancel');
      return { cancelled: true };
    },
    dispose: async () => {
      calls.push('dispose');
      return { closed: true };
    },
  };
  const world = createContext({
    Date,
    isSecureContext: true,
    location: { href: url },
    document: {},
    installFixture(value: any, nonce: string, target: string) {
      assert.deepEqual(JSON.parse(JSON.stringify(value)), owner);
      assert.equal(target, url);
      if (installed) throw Error('duplicate private document');
      installed = true;
      token = nonce;
      const document = world.document;
      documentCall = createBitwardenDocumentEndpoint(
        value,
        bridge,
        () => world.document === document && world.location.href === url,
      );
      return '{"ready":true,"version":1}';
    },
    invokeFixture(
      nonce: string,
      ...args: Parameters<ReturnType<typeof createBitwardenDocumentEndpoint>>
    ) {
      if (nonce !== token) throw Error('wrong private token');
      return documentCall(...args);
    },
  });
  const asset =
    'var WormholeVaultBitwarden={install:(...args)=>installFixture(...args),invoke:(...args)=>invokeFixture(...args)};';
  const frame: any = {
    processId: 2,
    osProcessId: 200,
    routingId: 3,
    frameToken: randomUUID(),
    detached: false,
    url,
    isDestroyed: () => frameDead,
    executeJavaScript: async (source: string) => {
      scripts.push(source);
      const result = await new Script(source).runInContext(world);
      results.push(result);
      return result;
    },
  };
  const contents: any = Object.assign(new EventEmitter(), {
    mainFrame: frame,
    session,
    getType: () => kind,
    isLoadingMainFrame: () => false,
    isDestroyed: () => destroyed,
  });
  const options = {
    owner,
    url,
    session: session as any,
    contents,
    asset,
    current: () => alive,
    sandboxed: (identity: any) => {
      assert.ok(Object.isFrozen(identity));
      assert.equal(identity.osProcessId, 200);
      return sandboxed;
    },
  };
  const endpoint = new VaultBitwardenDocumentEndpoint(options);
  return {
    owner,
    q,
    c,
    manifest,
    packet,
    bridge,
    calls,
    scripts,
    results,
    world,
    frame,
    contents,
    options,
    endpoint,
    lose: () => {
      alive = false;
    },
    noSandbox: () => {
      sandboxed = false;
    },
    frameDead: () => {
      frameDead = true;
    },
    kind: (value: string) => {
      kind = value;
    },
    destroy: () => {
      destroyed = true;
      contents.emit('destroyed');
    },
  };
}

test('main binds one exact sandboxed background and exchanges only typed ciphertext/metadata', async () => {
  const f = fixture();
  const initialized = f.endpoint.initialize();
  assert.equal(f.endpoint.initialize(), initialized);
  await initialized;
  await f.endpoint.initialize();
  assert.deepEqual(await f.endpoint.prepare(), f.q);
  assert.deepEqual(await f.endpoint.bind(f.c), { chunks: 1, manifest: f.manifest });
  assert.deepEqual(await f.endpoint.next(), f.packet);
  assert.deepEqual(await f.endpoint.accept({ ...f.packet, direction: 'restore' }), {
    complete: true,
    revision: '0',
    restore: false,
  });
  const canceled = f.endpoint.cancel();
  assert.equal(f.endpoint.cancel(), canceled);
  await canceled;
  await f.endpoint.prepare();
  const closing = f.endpoint.dispose();
  assert.equal(f.endpoint.dispose(), closing);
  const cancelAfterClose = f.endpoint.cancel();
  assert.deepEqual(await closing, { closed: true });
  assert.deepEqual(await cancelAfterClose, { cancelled: true });
  assert.deepEqual(await f.endpoint.dispose(), { closed: true });
  assert.deepEqual(await f.endpoint.cancel(), { cancelled: true });
  await assert.rejects(f.endpoint.prepare(), unavailable);
  assert.equal(f.contents.listenerCount('did-start-navigation'), 0);
  assert.equal(f.world.process, undefined);
  assert.equal(f.world.require, undefined);
});

test('constructor rejects foreign origins, sessions, frames and unknown sandbox ownership', async () => {
  const f = fixture();
  const invalid = [
    { owner: null },
    { url: 'https://example.test/background.html' },
    { url: `chrome-extension://${'z'.repeat(32)}/background.html` },
    { url: f.options.url + '?foreign' },
    { url: f.options.url + '#foreign' },
    { url: `chrome-extension://user@${'a'.repeat(32)}/background.html` },
    { url: `chrome-extension://${'a'.repeat(32)}:123/background.html` },
    { url: 'bad' },
    { asset: '' },
    { asset: 'x'.repeat(1024 * 1024 + 1) },
    { session: {} },
    { current: () => false },
    { sandboxed: () => false },
    {
      sandboxed: () => {
        throw Error('private');
      },
    },
  ];
  for (const overrides of invalid)
    assert.throws(
      () => new VaultBitwardenDocumentEndpoint({ ...f.options, ...overrides } as any),
      unavailable,
    );
  f.contents.isLoadingMainFrame = () => true;
  assert.throws(() => new VaultBitwardenDocumentEndpoint(f.options), unavailable);
  f.contents.isLoadingMainFrame = () => false;
  f.kind('window');
  assert.throws(() => new VaultBitwardenDocumentEndpoint(f.options), unavailable);
  f.kind('backgroundPage');
  f.frameDead();
  assert.throws(() => new VaultBitwardenDocumentEndpoint(f.options), unavailable);
  f.destroy();
  await f.endpoint.dispose();
});

test('privileged main worlds, failed probes and malformed bootstrap receipts never receive a bridge', async () => {
  for (const key of ['process', 'require', 'wormhole']) {
    const f = fixture();
    f.world[key] = {};
    await assert.rejects(f.endpoint.initialize(), unavailable);
    assert.equal(f.scripts.length, 1);
    assert.deepEqual(f.calls, []);
    await assert.rejects(f.endpoint.initialize(), unavailable);
    await f.endpoint.dispose();
  }
  for (const value of [
    null,
    {},
    'bad',
    '{}',
    '{"ready":true,"version":2}',
    '{"ready":true,"version":1,"private":"value"}',
    'x'.repeat(65),
  ]) {
    const f = fixture(),
      execute = f.frame.executeJavaScript;
    f.frame.executeJavaScript = async (script: string) =>
      script.includes('var Wormhole') ? value : execute(script);
    await assert.rejects(f.endpoint.initialize(), unavailable);
    f.destroy();
    await f.endpoint.dispose();
  }
  const f = fixture();
  await f.endpoint.dispose();
  await assert.rejects(f.endpoint.initialize(), unavailable);
});

test('all native ownership changes revoke access and cleanup waits for the original document to be gone', async () => {
  for (const mutate of [
    (f: ReturnType<typeof fixture>) =>
      f.contents.emit('did-start-navigation', { isMainFrame: true }, f.options.url, true, true),
    (f: ReturnType<typeof fixture>) =>
      f.contents.emit('did-start-navigation', {}, f.options.url, false, true),
    (f: ReturnType<typeof fixture>) => f.contents.emit('render-process-gone', {}),
    (f: ReturnType<typeof fixture>) => {
      f.frame.detached = true;
    },
    (f: ReturnType<typeof fixture>) => {
      f.frame.url += '#new';
    },
    (f: ReturnType<typeof fixture>) => {
      f.frame.frameToken = randomUUID();
    },
    (f: ReturnType<typeof fixture>) => {
      f.frame.processId++;
    },
    (f: ReturnType<typeof fixture>) => {
      f.frame.osProcessId++;
    },
    (f: ReturnType<typeof fixture>) => {
      f.frame.routingId++;
    },
    (f: ReturnType<typeof fixture>) => {
      f.contents.mainFrame = { ...f.frame };
    },
    (f: ReturnType<typeof fixture>) => {
      f.contents.session = {};
    },
    (f: ReturnType<typeof fixture>) => f.noSandbox(),
  ]) {
    const f = fixture();
    await f.endpoint.initialize();
    mutate(f);
    await assert.rejects(f.endpoint.prepare(), unavailable);
    await assert.rejects(f.endpoint.dispose(), unavailable);
    f.destroy();
    assert.deepEqual(await f.endpoint.dispose(), { closed: true });
  }
  const f = fixture();
  await f.endpoint.initialize();
  f.contents.emit('did-start-navigation', { isMainFrame: false }, 'subframe', false, false);
  assert.deepEqual(await f.endpoint.prepare(), f.q);
  f.lose();
  await assert.rejects(f.endpoint.next(), unavailable);
  await assert.rejects(f.endpoint.initialize(), unavailable);
  // Trusted cleanup is still allowed on this exact original document after lock.
  assert.deepEqual(await f.endpoint.dispose(), { closed: true });
});

test('invalid command inputs and private browser results fail closed without serializing secrets', async () => {
  for (const action of ['bind', 'accept']) {
    const f = fixture();
    await f.endpoint.initialize();
    await f.endpoint.prepare();
    const before = f.scripts.length;
    await assert.rejects(
      (f.endpoint as any)[action]({ privateValue: 'private-endpoint-secret' }),
      unavailable,
    );
    assert.equal(f.scripts.length, before);
    await f.endpoint.dispose();
  }
  for (const name of ['prepare', 'bind', 'next', 'accept'] as const) {
    const f = fixture();
    await f.endpoint.initialize();
    if (name !== 'prepare') await f.endpoint.prepare();
    if (name === 'next' || name === 'accept') await f.endpoint.bind(f.c);
    const original = (f.bridge[name] as any).bind(f.bridge);
    (f.bridge as any)[name] = async (...args: any[]) => ({
      ...(await original(...args)),
      privateValue: 'private-endpoint-secret',
    });
    const input =
      name === 'bind' ? f.c : name === 'accept' ? { ...f.packet, direction: 'restore' } : undefined;
    await assert.rejects((f.endpoint as any)[name](input), unavailable);
    assert.ok(!f.results.some((value) => String(value).includes('private-endpoint-secret')));
    await f.endpoint.dispose();
  }
});

test('cancel prevents a not-yet-dispatched operation from starting after its positive acknowledgement', async () => {
  const f = fixture();
  await f.endpoint.initialize();
  const old = assert.rejects(f.endpoint.prepare(), unavailable),
    cancel = f.endpoint.cancel();
  await cancel;
  await old;
  assert.deepEqual(f.calls, ['cancel']);
  assert.deepEqual(await f.endpoint.prepare(), f.q);
  await f.endpoint.dispose();
});

test('queued execution and late old results cannot modify the replacement transfer generation', async () => {
  const f = fixture();
  await f.endpoint.initialize();
  const execute = f.frame.executeJavaScript;
  let release!: () => void;
  f.frame.executeJavaScript = (script: string) => {
    f.frame.executeJavaScript = execute;
    return new Promise((yes, no) => {
      release = () => {
        void execute(script).then(yes, no);
      };
    });
  };
  const old = assert.rejects(f.endpoint.prepare(), unavailable);
  await tick();
  await f.endpoint.cancel();
  assert.deepEqual(await f.endpoint.prepare(), f.q);
  release();
  await old;
  await tick();
  assert.equal(f.calls.filter((x) => x === 'prepare').length, 1);
  assert.deepEqual(await f.endpoint.bind(f.c), { chunks: 1, manifest: f.manifest });
  await f.endpoint.dispose();
});

test('timed-out bootstrap remains reserved until its real execution settles or the document is destroyed', async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 1700000000000 });
  const f = fixture(),
    execute = f.frame.executeJavaScript;
  let release!: () => void;
  f.frame.executeJavaScript = (script: string) => {
    if (!script.includes('var Wormhole')) return execute(script);
    return new Promise((yes, no) => {
      release = () => {
        void execute(script).then(yes, no);
      };
    });
  };
  const init = assert.rejects(f.endpoint.initialize(), unavailable);
  await tick();
  t.mock.timers.tick(30001);
  await init;
  await assert.rejects(f.endpoint.dispose(), unavailable);
  release();
  await tick();
  await assert.rejects(f.endpoint.prepare(), unavailable);
  f.destroy();
  await f.endpoint.dispose();
});

test('unconfirmed cleanup is retryable and destruction is stronger than a stalled cleanup response', async () => {
  const f = fixture();
  await f.endpoint.initialize();
  let good = false;
  f.bridge.dispose = async () => (good ? { closed: true } : ({ closed: false } as any));
  await assert.rejects(f.endpoint.dispose(), unavailable);
  good = true;
  assert.deepEqual(await f.endpoint.dispose(), { closed: true });
  const stalled = fixture();
  await stalled.endpoint.initialize();
  stalled.bridge.dispose = () => new Promise(() => {});
  const closing = stalled.endpoint.dispose();
  await tick();
  stalled.destroy();
  assert.deepEqual(await closing, { closed: true });
});
