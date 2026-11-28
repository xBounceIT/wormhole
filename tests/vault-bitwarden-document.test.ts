import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { createBitwardenDocumentEndpoint } from '../src/vault-bitwarden-document-endpoint.ts';
import { install, invoke } from '../src/vault-bitwarden-extension-entry.ts';
import type { BitwardenExtensionBridge } from '../electron/vault-bitwarden-bridge-contract.ts';
import type {
  BrowserTransferContext,
  BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';

const tick = () => new Promise<void>((r) => setImmediate(r));
function fixture() {
  const owner = { workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 };
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
  const calls: string[] = [];
  let current = true,
    id = 0;
  const bridge: BitwardenExtensionBridge = {
    prepare: async () => {
      calls.push('prepare');
      return { ...q };
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
  const endpoint = createBitwardenDocumentEndpoint(owner, bridge, () => current);
  const call = async (op: string, input: unknown = null) =>
    JSON.parse(await endpoint(++id, op, input, Date.now() + 1000));
  return {
    owner,
    q,
    c,
    packet,
    manifest,
    calls,
    bridge,
    endpoint,
    call,
    lose: () => {
      current = false;
    },
  };
}

test('document serializes only typed metadata/ciphertext and retires its state on completion/disposal', async () => {
  const f = fixture();
  assert.deepEqual(await f.call('prepare'), f.q);
  assert.deepEqual(await f.call('bind', f.c), { chunks: 1, manifest: f.manifest });
  assert.deepEqual(await f.call('next'), f.packet);
  assert.deepEqual(await f.call('accept', { ...f.packet, direction: 'restore' }), {
    complete: true,
    revision: '0',
    restore: false,
  });
  await f.call('prepare');
  await f.call('cancel');
  await f.call('prepare');
  await f.call('dispose');
  await assert.rejects(f.call('prepare'), /document is unavailable/);
  assert.deepEqual(await f.call('dispose'), { closed: true });
  assert.deepEqual(await f.call('cancel'), { cancelled: true });
});

test('malformed, reordered, expired and replayed document calls cannot reach storage', async () => {
  const f = fixture();
  assert.throws(() => createBitwardenDocumentEndpoint(null, f.bridge, () => true), /unavailable/);
  for (const [id, op, deadline] of [
    [0, 'prepare', Date.now() + 1000],
    [1.1, 'prepare', Date.now() + 1000],
    [1, 'raw-storage', Date.now() + 1000],
    [1, 'prepare', NaN],
    [1, 'prepare', Date.now() - 1],
    [1, 'prepare', Number.MAX_SAFE_INTEGER],
  ])
    await assert.rejects(f.endpoint(id, op, null, deadline), /unavailable/);
  assert.deepEqual(f.calls, []);
  await f.endpoint(2, 'prepare', null, Date.now() + 1000);
  await assert.rejects(f.endpoint(2, 'cancel', null, Date.now() + 1000), /unavailable/);
  assert.deepEqual(f.calls, ['prepare']);
  await f.endpoint(3, 'dispose', null, Date.now() + 1000);
  for (const [op, setup, input] of [
    ['bind', false, {}],
    ['next', false, null],
    ['accept', false, {}],
    ['prepare', false, {}],
    ['cancel', false, {}],
    ['dispose', false, {}],
    ['prepare', true, null],
    ['bind', true, { ...f.c, profileId: randomUUID() }],
  ] as const) {
    const next = fixture();
    if (setup) await next.call('prepare');
    await assert.rejects(next.call(op, input), /unavailable/);
    await next.call('dispose');
  }
  const next = fixture();
  await next.call('prepare');
  await next.call('bind', next.c);
  await assert.rejects(next.call('bind', next.c), /unavailable/);
  await assert.rejects(next.call('next', {}), /unavailable/);
  await assert.rejects(
    next.call('accept', { ...next.packet, context: f.c, direction: 'restore' }),
    /unavailable/,
  );
  await next.call('dispose');
});

test('private errors and extra secret fields are rejected before result serialization', async () => {
  for (const name of ['prepare', 'bind', 'next', 'accept', 'cancel', 'dispose'] as const) {
    for (const mode of ['throw', 'extra', 'negative']) {
      const f = fixture();
      if (name === 'bind' || name === 'next' || name === 'accept') await f.call('prepare');
      if (name === 'next' || name === 'accept') await f.call('bind', f.c);
      const original = (f.bridge[name] as (...args: any[]) => Promise<any>).bind(f.bridge);
      let serialized = false;
      (f.bridge as any)[name] = async (...args: any[]) => {
        if (mode === 'throw') throw Error('private-document-secret');
        if (mode === 'negative') return null;
        return {
          ...(await original(...args)),
          privateValue: 'private-document-secret',
          toJSON() {
            serialized = true;
            throw Error('private');
          },
        };
      };
      await assert.rejects(
        f.call(
          name,
          name === 'bind' ? f.c : name === 'accept' ? { ...f.packet, direction: 'restore' } : null,
        ),
        /^Error: Bitwarden document is unavailable\.$/,
      );
      assert.equal(serialized, false);
    }
  }
  const f = fixture();
  f.bridge.prepare = async () => ({ ...f.q, profileId: randomUUID() });
  await assert.rejects(f.call('prepare'), /unavailable/);
  await f.call('dispose');
  const bad = fixture();
  await bad.call('prepare');
  bad.bridge.bind = async () => ({ chunks: 5, manifest: bad.manifest });
  await assert.rejects(bad.call('bind', bad.c), /unavailable/);
  await bad.call('dispose');
});

test('cancel fences in-flight results and deferred calls before admitting a later generation', async () => {
  const f = fixture(),
    original = f.bridge.prepare;
  let release!: (value: typeof f.q) => void;
  f.bridge.prepare = () =>
    new Promise((r) => {
      release = r;
    });
  const old = assert.rejects(f.call('prepare'), /unavailable/);
  await tick();
  await assert.rejects(f.call('next'), /unavailable/);
  await f.call('cancel');
  f.bridge.prepare = original;
  assert.deepEqual(await f.call('prepare'), f.q);
  release(f.q);
  await old;
  assert.deepEqual(await f.call('bind', f.c), { chunks: 1, manifest: f.manifest });
  f.bridge.accept = async () => ({ complete: false });
  assert.deepEqual(await f.call('accept', { ...f.packet, direction: 'restore' }), {
    complete: false,
  });
  await f.call('dispose');
  const lost = fixture();
  lost.bridge.prepare = async () => {
    lost.lose();
    return lost.q;
  };
  await assert.rejects(lost.call('prepare'), /unavailable/);
});

test('packaged entry admits one token in one browser document and retains a disposal tombstone', async (t) => {
  const id = 'a'.repeat(32),
    url = `chrome-extension://${id}/background.html`,
    token = randomUUID();
  const descriptors = new Map<string, PropertyDescriptor | undefined>();
  const set = (key: string, value: unknown) => {
    if (!descriptors.has(key))
      descriptors.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  };
  const nativeProcess = globalThis.process;
  const browserCall = <T>(call: () => T): T => {
    Object.defineProperty(globalThis, 'process', {
      value: undefined,
      configurable: true,
      writable: true,
    });
    try {
      return call();
    } finally {
      Object.defineProperty(globalThis, 'process', {
        value: nativeProcess,
        configurable: true,
        writable: true,
      });
    }
  };
  t.after(() => {
    delete (globalThis as any).__wormhole_vault_bitwarden_document_v1__;
    for (const [key, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete (globalThis as any)[key];
    }
  });
  const area = {
    get: (_key: unknown, done: (v: unknown) => void) => done({}),
    set: (_values: unknown, done: () => void) => done(),
    remove: (_key: string, done: () => void) => done(),
  };
  set('isSecureContext', true);
  set('location', { href: url, protocol: 'chrome-extension:', hostname: id });
  set('document', {});
  set('chrome', {
    runtime: { id, getManifest: () => ({ manifest_version: 2 }) },
    storage: { local: area },
  });
  set('bitwardenMain', {
    memoryStorageForStateProviders: { store: {}, save: async () => {}, remove: async () => {} },
  });
  const owner = fixture().owner;
  assert.throws(() => install(owner, token, url), /unavailable/);
  for (const [key, value] of [
    ['require', () => {}],
    ['wormhole', {}],
  ] as const) {
    set(key, value);
    assert.throws(() => browserCall(() => install(owner, token, url)), /unavailable/);
    set(key, undefined);
  }
  for (const [o, tok, target] of [
    [null, token, url],
    [owner, 'invalid', url],
    [owner, token, url + '?foreign'],
  ])
    assert.throws(() => browserCall(() => install(o, tok, target)), /unavailable/);
  assert.deepEqual(JSON.parse(browserCall(() => install(owner, token, url))), {
    ready: true,
    version: 1,
  });
  assert.equal(
    Object.getOwnPropertyDescriptor(globalThis, '__wormhole_vault_bitwarden_document_v1__')
      ?.enumerable,
    false,
  );
  await assert.rejects(invoke(randomUUID(), 1, 'prepare', null, Date.now() + 1000), /unavailable/);
  const q = JSON.parse(await invoke(token, 1, 'prepare', null, Date.now() + 1000));
  assert.equal(q.workspaceId, owner.workspaceId);
  assert.equal(q.sourceRevision, '0');
  assert.deepEqual(JSON.parse(await invoke(token, 2, 'cancel', null, Date.now() + 1000)), {
    cancelled: true,
  });
  assert.deepEqual(JSON.parse(await invoke(token, 3, 'dispose', null, Date.now() + 1000)), {
    closed: true,
  });
  assert.throws(() => browserCall(() => install(owner, randomUUID(), url)), /unavailable/);
  await assert.rejects(invoke(token, 4, 'prepare', null, Date.now() + 1000), /unavailable/);
  await assert.rejects(invoke(token, 0, 'cancel', null, Date.now() + 1000), /unavailable/);
});
