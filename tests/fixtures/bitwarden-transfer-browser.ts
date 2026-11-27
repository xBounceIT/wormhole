import { createBitwardenExtensionBridge } from '../../src/vault-bitwarden-extension-bridge.ts';

import {
  createBitwardenExtensionStorage,
  type ExtensionStorageArea,
} from '../../src/vault-bitwarden-extension-storage.ts';

// Synthetic Chrome API in a real sandboxed document. No state leaves this
// owning world; the native test receives only the final boolean assertion.
export async function verifyExtensionStorageInPage() {
  const local: Record<string, unknown> = { account: 'page-old', remove: 'old' },
    memory: Record<string, string> = { token: JSON.stringify('page-session-old') };
  const area: ExtensionStorageArea = {
    get: (key, done) =>
      queueMicrotask(() =>
        done(key === null ? { ...local } : Object.hasOwn(local, key) ? { [key]: local[key] } : {}),
      ),
    set: (values, done) => {
      Object.assign(local, values);
      queueMicrotask(done);
    },
    remove: (key, done) => {
      delete local[key];
      queueMicrotask(done);
    },
  };
  const storage = createBitwardenExtensionStorage({
    manifestVersion: 2,
    local: area,
    lastError: () => undefined,
    memory: {
      store: memory,
      save: async (key, value) => {
        memory[key] = JSON.stringify(value);
      },
      remove: async (key) => {
        delete memory[key];
      },
    },
  });
  const controller = new AbortController(),
    before = await storage.capture(controller.signal);
  const desired = {
    localJSON: new TextEncoder().encode('{"account":"page-new"}'),
    sessionJSON: new TextEncoder().encode('{"token":"page-session-new"}'),
  };
  await storage.restore(desired, before, controller.signal);
  before.localJSON.fill(0);
  before.sessionJSON.fill(0);
  const after = await storage.capture(controller.signal);
  const correct =
    new TextDecoder().decode(after.localJSON) === '{"account":"page-new"}' &&
    new TextDecoder().decode(after.sessionJSON) === '{"token":"page-session-new"}';
  after.localJSON.fill(0);
  after.sessionJSON.fill(0);
  desired.localJSON.fill(0);
  desired.sessionJSON.fill(0);
  controller.abort();
  let cancelled = false;
  try {
    await storage.capture(controller.signal);
  } catch {
    cancelled = true;
  }
  return (
    correct &&
    cancelled &&
    before.localJSON.every((x) => x === 0) &&
    before.sessionJSON.every((x) => x === 0)
  );
}
export async function makeBridge() {
  const local: Record<string, unknown> = { capture: 'synthetic-🔑', n: '9007199254740993' },
    memory: Record<string, string> = { session: JSON.stringify('temporary') };
  const area: ExtensionStorageArea = {
    get: (key, done) =>
      queueMicrotask(() =>
        done(key === null ? { ...local } : Object.hasOwn(local, key) ? { [key]: local[key] } : {}),
      ),
    set: (values, done) => {
      Object.assign(local, values);
      queueMicrotask(done);
    },
    remove: (key, done) => {
      delete local[key];
      queueMicrotask(done);
    },
  };
  const actual = createBitwardenExtensionStorage({
    manifestVersion: 2,
    local: area,
    lastError: () => undefined,
    memory: {
      store: memory,
      save: async (key, value) => {
        memory[key] = JSON.stringify(value);
      },
      remove: async (key) => {
        delete memory[key];
      },
    },
  });
  const borrowed: Uint8Array[] = [];
  const storage = {
    capture: async (signal: AbortSignal) => {
      const state = await actual.capture(signal);
      borrowed.push(state.localJSON, state.sessionJSON);
      return state;
    },
    restore: async (
      state: Parameters<typeof actual.restore>[0],
      witness: Parameters<typeof actual.restore>[1],
      signal: AbortSignal,
    ) => {
      borrowed.push(state.localJSON, state.sessionJSON, witness.localJSON, witness.sessionJSON);
      await actual.restore(state, witness, signal);
    },
  };
  const controller = createBitwardenExtensionBridge(
      { workspaceId: crypto.randomUUID(), profileId: crypto.randomUUID(), epoch: 2 },
      storage,
    ),
    request = await controller.prepare();
  let chunks = 0;
  return {
    request,
    bind: async (context: unknown) => {
      const capture = await controller.bind(context);
      chunks = capture.chunks;
      return capture;
    },
    accept: (packet: unknown) => controller.accept(packet),
    capture: async () => ({ chunks, next: () => controller.next() }),
    wiped: () =>
      borrowed.length === 6 &&
      borrowed.every((p) => p.every((x) => x === 0)) &&
      JSON.stringify(local) === '{"restore":"synthetic-saved"}' &&
      memory.session === JSON.stringify('ready'),
  };
}
