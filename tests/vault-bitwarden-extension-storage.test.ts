import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createBitwardenExtensionStorage,
  type ExtensionStorageArea,
  type BitwardenStorageEnvironment,
  type ExtensionStorageCapture,
} from '../src/vault-bitwarden-extension-storage.ts';
import { browserTransferAreaBytes } from '../electron/vault-bitwarden-transfer.ts';
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const capture = (local: unknown, session: unknown): ExtensionStorageCapture => ({
  localJSON: encode(local),
  sessionJSON: encode(session),
});
const unpack = (state: ExtensionStorageCapture) => ({
  local: JSON.parse(new TextDecoder().decode(state.localJSON)),
  session: JSON.parse(new TextDecoder().decode(state.sessionJSON)),
});
const tick = () => new Promise<void>((r) => setImmediate(r));
const live = () => new AbortController().signal;
function fixture(
  version: 2 | 3 = 2,
  local: Record<string, unknown> = {},
  session: Record<string, unknown> = {},
) {
  const events: string[] = [],
    raw: Record<string, string> = Object.create(null);
  const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
  const area = (name: string, initial: Record<string, unknown>) => {
    const values = clone(initial),
      controls = { fail: false, hang: false, throw: false };
    const storage: ExtensionStorageArea = {
      get: (key, done) => {
        events.push(name + ':get:' + (key ?? '*'));
        if (controls.throw) throw Error('private-storage-secret');
        if (controls.hang) return;
        const result =
          key === null
            ? clone(values)
            : Object.hasOwn(values, key)
              ? { [key]: clone(values[key]) }
              : {};
        queueMicrotask(() => done(result));
      },
      set: (next, done) => {
        for (const key of Object.keys(next)) {
          events.push(name + ':set:' + key);
          Object.defineProperty(values, key, {
            value: clone(next[key]),
            enumerable: true,
            configurable: true,
            writable: true,
          });
        }
        queueMicrotask(done);
      },
      remove: (key, done) => {
        events.push(name + ':remove:' + key);
        delete values[key];
        queueMicrotask(done);
      },
    };
    return { storage, values, controls };
  };
  for (const [key, value] of Object.entries(session)) raw[key] = JSON.stringify(value);
  const localArea = area('local', local),
    sessionArea = area('session', session);
  const memory = {
    store: raw,
    save: async (key: string, value: unknown) => {
      events.push('memory:set:' + key);
      raw[key] = JSON.stringify(value);
    },
    remove: async (key: string) => {
      events.push('memory:remove:' + key);
      delete raw[key];
    },
  };
  const env: BitwardenStorageEnvironment = {
    manifestVersion: version,
    local: localArea.storage,
    session: sessionArea.storage,
    memory,
    lastError: () =>
      localArea.controls.fail || sessionArea.controls.fail
        ? Error('private-storage-secret')
        : undefined,
  };
  return { env, events, localArea, sessionArea, memory };
}

test('MV2 captures actual background memory and never reads chrome.storage.session', async () => {
  const f = fixture(2, { account: 'synthetic-local' }, { session: 'synthetic-memory' }),
    store = createBitwardenExtensionStorage(f.env);
  f.sessionArea.values.session = 'wrong-MV2-area';
  const state = await store.capture(live());
  assert.deepEqual(unpack(state), {
    local: { account: 'synthetic-local' },
    session: { session: 'synthetic-memory' },
  });
  assert.deepEqual(f.events, ['local:get:*']);
  state.localJSON.fill(0);
  state.sessionJSON.fill(0);
  for (const env of [
    { ...f.env, memory: undefined },
    { ...f.env, memory: { store: {}, save: undefined, remove: () => {} } },
    { ...f.env, manifestVersion: 1 },
    { ...f.env, manifestVersion: 3, session: undefined },
  ])
    assert.throws(() => createBitwardenExtensionStorage(env as any), /failed/);
});

for (const version of [2, 3] as const)
  test(`MV${version} restores session first, applies per-key deltas and preserves concurrent edits`, async () => {
    const local = {
        same: 'unchanged',
        replace: 'old',
        remove: 'old',
        changed: 'newer',
        concurrent: 'new',
      },
      session = {
        same: 'unchanged',
        replace: 'old',
        remove: 'old',
        changed: 'newer',
        concurrent: 'new',
      },
      expected = {
        same: 'unchanged',
        replace: 'old',
        remove: 'old',
        changed: 'old',
        removedElsewhere: 'old',
      },
      desired = {
        same: 'unchanged',
        replace: 'next',
        added: 'new',
        changed: 'stale',
        removedElsewhere: 'stale',
      };
    const f = fixture(version, local, session),
      store = createBitwardenExtensionStorage(f.env);
    const wanted = capture(desired, desired),
      witness = capture(expected, expected);
    await store.restore(wanted, witness, live());
    const actual = await store.capture(live()),
      result = {
        same: 'unchanged',
        replace: 'next',
        changed: 'newer',
        concurrent: 'new',
        added: 'new',
      };
    assert.deepEqual(unpack(actual), { local: result, session: result });
    const mutations = f.events.filter((x) => x.includes(':set:') || x.includes(':remove:'));
    assert.deepEqual(mutations, [
      ...(version === 2
        ? ['memory:set:replace', 'memory:set:added', 'memory:remove:remove']
        : ['session:set:replace', 'session:set:added', 'session:remove:remove']),
      'local:set:replace',
      'local:set:added',
      'local:remove:remove',
    ]);
    assert.deepEqual(unpack(witness), { local: expected, session: expected });
    assert.deepEqual(unpack(wanted), { local: desired, session: desired });
  });

test('background memory safely preserves reserved JSON property names', async () => {
  const original = JSON.parse('{"__proto__":{"token":"old"},"constructor":"old","remove":"old"}'),
    next = JSON.parse('{"__proto__":{"token":"new"},"constructor":"new"}');
  const f = fixture(2, original, original),
    store = createBitwardenExtensionStorage(f.env);
  await store.restore(capture(next, next), capture(original, original), live());
  assert.deepEqual(unpack(await store.capture(live())), { local: next, session: next });
  assert.equal(({} as any).token, undefined);
});

for (const version of [2, 3] as const)
  test(`MV${version} does not overwrite a refresh queued between a read and an awaited mutation`, async () => {
    const f = fixture(version, {}, { token: 'old' }),
      store = createBitwardenExtensionStorage(f.env);
    if (version === 2) {
      queueMicrotask(() => {
        f.memory.store.token = JSON.stringify('fresh');
      });
    } else {
      // Chrome calls back with a snapshot; another callback may already be queued.
      f.env.session!.get = (_key, done) =>
        queueMicrotask(() => {
          done({ token: 'old' });
          f.sessionArea.values.token = 'fresh';
        });
    }
    await store.restore(capture({}, { token: 'restored' }), capture({}, { token: 'old' }), live());
    assert.equal(
      version === 2 ? JSON.parse(f.memory.store.token) : f.sessionArea.values.token,
      'fresh',
    );
  });

test('cancel, timeout, synchronous native error and late callbacks fail closed', async (t) => {
  const f = fixture(3, { token: 'private-storage-secret' }, {}),
    store = createBitwardenExtensionStorage(f.env),
    aborted = new AbortController();
  aborted.abort();
  await assert.rejects(store.capture(aborted.signal), /cancelled/);
  assert.equal(f.events.length, 0);
  f.localArea.controls.throw = true;
  await assert.rejects(
    store.capture(live()),
    (e) =>
      e instanceof Error &&
      /failed/.test(e.message) &&
      !e.message.includes('private-storage-secret'),
  );
  f.localArea.controls.throw = false;
  f.localArea.controls.fail = true;
  await assert.rejects(store.capture(live()), /failed/);
  f.localArea.controls.fail = false;
  let complete!: (values: Record<string, unknown>) => void;
  f.env.local.get = (_key, done) => {
    complete = done;
  };
  const controller = new AbortController(),
    pending = store.capture(controller.signal),
    rejected = assert.rejects(pending, /cancelled/);
  controller.abort();
  await rejected;
  complete({ token: 'late' });
  await tick();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const timeout = assert.rejects(store.capture(live()), /cancelled/);
  t.mock.timers.tick(10001);
  await timeout;
});

test('capture wipes already allocated areas on cancellation after the final read', async (t) => {
  const f = fixture(3, { token: 'wipe-local' }, { session: 'wipe-session' }),
    controller = new AbortController(),
    borrowed: Uint8Array[] = [];
  const original = TextEncoder.prototype.encode;
  t.mock.method(TextEncoder.prototype, 'encode', function (this: TextEncoder, value?: string) {
    const raw = original.call(this, value);
    if (value?.includes('wipe-local') || value?.includes('wipe-session')) borrowed.push(raw);
    return raw;
  });
  f.env.session!.get = (_key, done) =>
    queueMicrotask(() => {
      done({ session: 'wipe-session' });
      queueMicrotask(() => controller.abort());
    });
  await assert.rejects(
    createBitwardenExtensionStorage(f.env).capture(controller.signal),
    /cancelled/,
  );
  assert.equal(borrowed.length, 2);
  assert.ok(borrowed.every((a) => a.every((x) => x === 0)));
});

test('memory promise failures and cancellation cannot advance later storage writes', async () => {
  const f = fixture(2, { old: true }, { old: true }),
    store = createBitwardenExtensionStorage(f.env),
    witness = capture({ old: true }, { old: true }),
    desired = capture({ next: true }, { next: true });
  f.memory.save = async () => {
    throw Error('private-storage-secret');
  };
  await assert.rejects(
    store.restore(desired, witness, live()),
    (e) =>
      e instanceof Error &&
      /failed/.test(e.message) &&
      !e.message.includes('private-storage-secret'),
  );
  assert.equal(
    f.events.some((x) => x.startsWith('local:set:')),
    false,
  );
  let finish!: () => void;
  const abort = new AbortController();
  f.memory.save = () => new Promise<void>((r) => (finish = r));
  const pending = store.restore(desired, witness, abort.signal);
  await tick();
  const rejected = assert.rejects(pending, /cancelled/);
  abort.abort();
  await rejected;
  finish();
  await tick();
  assert.equal(
    f.events.some((x) => x.includes(':remove:') || x.startsWith('local:set:')),
    false,
  );
});

test('Chrome mutation errors are sanitized and preserve unattempted keys', async () => {
  const f = fixture(3, { old: true }, { old: true }),
    store = createBitwardenExtensionStorage(f.env);
  f.env.session!.set = (_value, done) => {
    f.sessionArea.controls.fail = true;
    queueMicrotask(done);
  };
  await assert.rejects(
    store.restore(
      capture({ next: true }, { next: true }),
      capture({ old: true }, { old: true }),
      live(),
    ),
    /failed/,
  );
  assert.equal(
    f.events.some((x) => x.startsWith('local:')),
    false,
  );
});

test('invalidated runtime getters and late callbacks never throw outside the owning operation', async () => {
  const f = fixture(3),
    store = createBitwardenExtensionStorage(f.env);
  f.env.lastError = () => {
    throw Error('private-runtime-secret');
  };
  await assert.rejects(store.capture(live()), /failed/);
  let complete!: (value: Record<string, unknown>) => void;
  f.env.local.get = (_key, callback) => {
    complete = callback;
  };
  const controller = new AbortController(),
    pending = store.capture(controller.signal);
  const rejected = assert.rejects(pending, /cancelled/);
  controller.abort();
  await rejected;
  assert.doesNotThrow(() => complete({}));
  f.env.lastError = () => undefined;
  assert.doesNotThrow(() => complete({}));
  const malformed = fixture(3);
  malformed.env.local.get = (_key, callback) => queueMicrotask(() => callback([] as any));
  await assert.rejects(createBitwardenExtensionStorage(malformed.env).capture(live()), /failed/);
  malformed.env.session!.get = (_key, callback) => queueMicrotask(() => callback([] as any));
  malformed.env.local.get = (_key, callback) => queueMicrotask(() => callback({}));
  await assert.rejects(
    createBitwardenExtensionStorage(malformed.env).restore(
      capture({}, { token: 'new' }),
      capture({}, {}),
      live(),
    ),
    /failed/,
  );
});

test('area/key bounds, invalid encodings and corrupt memory fail without native edits', async () => {
  const f = fixture(),
    store = createBitwardenExtensionStorage(f.env);
  const invalid = [
    new Uint8Array(),
    encode(null),
    encode([]),
    new Uint8Array([255, 255]),
    new TextEncoder().encode('{bad'),
    new Uint8Array(browserTransferAreaBytes + 1),
  ];
  for (const bytes of invalid)
    await assert.rejects(
      store.restore({ localJSON: bytes, sessionJSON: encode({}) }, capture({}, {}), live()),
      /failed/,
    );
  f.memory.store.invalid = '{private-storage-secret';
  await assert.rejects(store.capture(live()), /failed/);
  delete f.memory.store.invalid;
  (f.memory.store as any).token = 12;
  await assert.rejects(
    store.restore(capture({}, { token: 'new' }), capture({}, { token: 'old' }), live()),
    /failed/,
  );
  delete f.memory.store.token;
  (f.memory.store as any).invalid = 12;
  await assert.rejects(store.capture(live()), /failed/);
  delete f.memory.store.invalid;
  f.localArea.values.large = 'x'.repeat(browserTransferAreaBytes);
  await assert.rejects(store.capture(live()), /failed/);
  delete f.localArea.values.large;
  f.memory.store.large = JSON.stringify('x'.repeat(browserTransferAreaBytes));
  await assert.rejects(store.capture(live()), /failed/);
  delete f.memory.store.large;
  for (let i = 0; i < 65537; i++) f.memory.store[String(i)] = '0';
  await assert.rejects(store.capture(live()), /failed/);
  const oversized = fixture(3);
  for (let i = 0; i < 65537; i++) oversized.localArea.values[String(i)] = 0;
  await assert.rejects(createBitwardenExtensionStorage(oversized.env).capture(live()), /failed/);
});

test('two maximum-size areas stay inside the isolated adapter', async () => {
  const value = { v: 'x'.repeat(browserTransferAreaBytes - 8) },
    f = fixture(2, value, value),
    store = createBitwardenExtensionStorage(f.env),
    state = await store.capture(live());
  assert.equal(state.localJSON.length, browserTransferAreaBytes);
  assert.equal(state.sessionJSON.length, browserTransferAreaBytes);
  assert.deepEqual(unpack(state), { local: value, session: value });
  state.localJSON.fill(0);
  state.sessionJSON.fill(0);
});
