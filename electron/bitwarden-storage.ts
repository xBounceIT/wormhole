import { randomUUID } from 'node:crypto';
import type { WebContents } from 'electron';

const operationTimeoutMs = 10_000;
const pollIntervalMs = 25;
const maxJsonBytes = 8 * 1024 * 1024;

type StorageContents = Pick<WebContents, 'executeJavaScript' | 'isDestroyed'>;
type StorageSnapshot = { localJson: string; sessionJson: string };

// Bitwarden's MV2 build keeps vault session state in BackgroundMemoryStorageService,
// accessed by ForegroundMemoryStorageService through the extension's "session" port.
// It is not exposed as chrome.storage.session, even when the background page is alive.
const sessionStorageBridge = `
  const active = () => globalThis[key]?.status === 'pending';
  const changes = (current, values) => Object.fromEntries(Object.keys(values)
    .filter((entry) => JSON.stringify(current[entry]) !== JSON.stringify(values[entry]))
    .map((entry) => [entry, values[entry]]));
  const replaceArea = (area, values, complete, fail) => {
    if (!active()) return;
    const checked = (next) => (...args) => {
      if (!active()) return;
      if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
      try { next(...args); } catch (error) { fail(error); }
    };
    area.get(null, checked((current) => {
      const updates = changes(current, values);
      const removals = Object.keys(current).filter((entry) => !Object.hasOwn(values, entry));
      const entries = Object.keys(updates);
      let index = 0;
      const next = () => {
        if (index < entries.length) {
          const entry = entries[index++];
          area.set({ [entry]: updates[entry] }, checked(next));
        } else if (index < entries.length + removals.length) {
          area.remove(removals[index++ - entries.length], checked(next));
        } else complete({});
      };
      // Never clear a live account before putting its replacement back: Bitwarden observes
      // storage changes and would see a transient logged-out account even on an identical restore.
      // Its observable storage ignores bulk changes, so publish one changed key per operation.
      next();
    }));
  };
  const sessionStorage = (values, complete, fail) => {
    const decode = (value) => {
      try { return JSON.parse(value); }
      catch { throw new Error('Bitwarden memory storage returned invalid JSON.'); }
    };
    const area = chrome.storage.session;
    if (area?.get && area?.remove && area?.set) {
      const checked = (next) => (...args) => {
        if (!active()) return;
        if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
        next(...args);
      };
      if (values === null) { area.get(null, checked(complete)); return; }
      replaceArea(area, values, complete, fail);
      return;
    }
    // A background page cannot open a runtime port to itself in Electron. Bitwarden exports its
    // background services for MV2; use the same memory store and its observable mutation methods.
    const memory = globalThis.bitwardenMain?.memoryStorageForStateProviders;
    if (memory?.store && memory?.save && memory?.remove) {
      if (values === null) {
        const result = Object.fromEntries(Object.entries(memory.store)
          .map(([entry, value]) => [entry, decode(value)]));
        complete(result);
        return;
      }
      const removals = Object.keys(memory.store).filter((entry) => !Object.hasOwn(values, entry));
      const updates = Object.fromEntries(Object.keys(values)
        .filter((entry) => memory.store[entry] !== JSON.stringify(values[entry]))
        .map((entry) => [entry, values[entry]]));
      let pending = removals.length + Object.keys(updates).length;
      if (!pending) { complete({}); return; }
      const done = () => { if (active() && --pending === 0) complete({}); };
      const failed = () => fail(new Error('Bitwarden memory storage update failed.'));
      for (const entry of Object.keys(updates)) memory.save(entry, updates[entry]).then(done, failed);
      for (const entry of removals) memory.remove(entry).then(done, failed);
      return;
    }
    const port = chrome.runtime.connect({ name: 'session' });
    const pending = new Map();
    const result = {};
    let initialized = false;
    let existingKeys = [];
    let reading = true;
    let sequence = 0;
    let finished = false;
    const disconnect = () => {
      if (finished) return;
      finished = true;
      port.disconnect();
    };
    globalThis[key + 'Cleanup'] = disconnect;
    const finish = () => {
      disconnect();
      complete(result);
    };
    const send = (requests) => {
      for (const request of requests) pending.set(String(++sequence), request);
      for (const [id, request] of pending) port.postMessage({ ...request, id, originator: 'foreground' });
    };
    const advance = () => {
      if (!reading || values === null) { finish(); return; }
      reading = false;
      const updates = changes(result, values);
      const requests = [
        ...Object.keys(updates).map((entry) => ({ action: 'save', key: entry, data: JSON.stringify(updates[entry]) })),
        ...existingKeys.filter((entry) => !Object.hasOwn(values, entry))
          .map((entry) => ({ action: 'remove', key: entry })),
      ];
      if (!requests.length) { finish(); return; }
      send(requests);
    };
    port.onDisconnect.addListener(() => {
      if (!finished) {
        finished = true;
        fail(new Error('Bitwarden memory storage disconnected before completion.'));
      }
    });
    port.onMessage.addListener((message) => {
      if (finished || !active() || message.originator !== 'background') return;
      try {
        if (message.action === 'initialization' && !initialized) {
          initialized = true;
          if (!Array.isArray(message.data) || message.data.some((entry) => typeof entry !== 'string')) {
            throw new Error('Bitwarden memory storage returned invalid keys.');
          }
          existingKeys = message.data;
          const requests = existingKeys.filter((entry) => values === null || Object.hasOwn(values, entry))
            .map((entry) => ({ action: 'get', key: entry }));
          if (!requests.length) { advance(); return; }
          send(requests);
          return;
        }
        const request = pending.get(message.id);
        if (!request) return;
        if (request.action === 'get') {
          Object.defineProperty(result, request.key, {
            value: decode(message.data), enumerable: true,
          });
        }
        pending.delete(message.id);
        if (!pending.size) advance();
      } catch (error) {
        disconnect();
        fail(error);
      }
    });
  };
`;

export async function captureBitwardenExtensionStorage(
  contents: StorageContents,
): Promise<StorageSnapshot> {
  const deadline = Date.now() + operationTimeoutMs;
  const timeoutMessage = 'Bitwarden browser storage capture timed out.';
  const operationKey = `__wormholeBitwardenCapture${randomUUID().replaceAll('-', '')}`;
  const serializedKey = JSON.stringify(operationKey);
  const script = `
    (() => {
      const key = ${serializedKey};
      const complete = (local, session) => {
        if (globalThis[key]?.status !== 'pending') return;
        try {
          if (Array.isArray(local) || Array.isArray(session)) {
            throw new Error('Invalid storage object.');
          }
          const localJson = JSON.stringify(local && typeof local === 'object' ? local : {});
          const sessionJson = JSON.stringify(session && typeof session === 'object' ? session : {});
          const encoder = new TextEncoder();
          if (encoder.encode(localJson).byteLength > ${maxJsonBytes} ||
              encoder.encode(sessionJson).byteLength > ${maxJsonBytes}) {
            fail(new Error('Bitwarden browser storage exceeded the safety limit.'));
            return;
          }
          globalThis[key] = { status: 'complete', localJson, sessionJson };
        } catch {
          fail(new Error('Bitwarden extension returned invalid browser storage.'));
        }
      };
      const fail = (error) => {
        if (globalThis[key]?.status !== 'pending') return;
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending' };
      ${sessionStorageBridge}
      try {
        chrome.storage.local.get(null, (local) => {
          if (globalThis[key]?.status !== 'pending') return;
          if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
          try { sessionStorage(null, (session) => complete(local, session), fail); }
          catch (error) { fail(error); }
        });
      } catch (error) { fail(error); }
      return true;
    })()
  `;
  const captured = await runPageOperation(contents, operationKey, script, deadline, timeoutMessage);
  if (typeof captured.localJson !== 'string' || typeof captured.sessionJson !== 'string') {
    throw new Error('Bitwarden extension returned invalid browser storage.');
  }
  const { localJson, sessionJson } = captured;
  if (
    Buffer.byteLength(localJson, 'utf8') > maxJsonBytes ||
    Buffer.byteLength(sessionJson, 'utf8') > maxJsonBytes
  ) {
    throw new Error('Bitwarden browser storage exceeded the safety limit.');
  }
  return { localJson, sessionJson };
}

export async function restoreBitwardenExtensionStorage(
  contents: StorageContents,
  snapshot: StorageSnapshot,
): Promise<void> {
  const deadline = Date.now() + operationTimeoutMs;
  const timeoutMessage = 'Bitwarden browser storage restore timed out.';
  const operationKey = `__wormholeBitwardenRestore${randomUUID().replaceAll('-', '')}`;
  const serializedKey = JSON.stringify(operationKey);
  const local = JSON.stringify(snapshot.localJson);
  const session = JSON.stringify(snapshot.sessionJson);
  const script = `
    (() => {
      const key = ${serializedKey};
      const complete = () => {
        if (globalThis[key]?.status === 'pending') globalThis[key] = { status: 'complete' };
      };
      const fail = (error) => {
        if (globalThis[key]?.status !== 'pending') return;
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending' };
      ${sessionStorageBridge}
      try {
        const local = JSON.parse(${local});
        const session = JSON.parse(${session});
        // Account observers must be able to find their session token when disk state changes.
        sessionStorage(session, () => replaceArea(chrome.storage.local, local, complete, fail), fail);
      } catch (error) { fail(error); }
      return true;
    })()
  `;
  await runPageOperation(contents, operationKey, script, deadline, timeoutMessage);
}

async function runPageOperation(
  contents: StorageContents,
  operationKey: string,
  script: string,
  deadline: number,
  timeoutMessage: string,
): Promise<Record<string, unknown>> {
  const serializedKey = JSON.stringify(operationKey);
  try {
    await executePageScript(contents, script, deadline, timeoutMessage);
    while (!contents.isDestroyed()) {
      const result = await executePageScript(
        contents,
        `globalThis[${serializedKey}]`,
        deadline,
        timeoutMessage,
      );
      if (isRecord(result)) {
        if (result.status === 'complete') return result;
        if (result.status === 'error') {
          throw new Error(
            typeof result.message === 'string'
              ? result.message
              : 'Bitwarden browser storage operation failed.',
          );
        }
      }
      if (Date.now() >= deadline) throw new Error(timeoutMessage);
      await new Promise<void>((resolve) => setTimeout(resolve, pollIntervalMs));
    }
    throw new Error('Bitwarden browser storage page closed before the operation completed.');
  } finally {
    if (!contents.isDestroyed()) {
      // Queue cleanup even after the deadline, but never wait on an unresponsive renderer.
      try {
        void contents
          .executeJavaScript(`
          globalThis[${serializedKey} + 'Cleanup']?.();
          delete globalThis[${serializedKey} + 'Cleanup'];
          delete globalThis[${serializedKey}];
        `)
          .catch(() => undefined);
      } catch {
        // The extension page can be destroyed between the lifetime check and cleanup dispatch.
      }
    }
  }
}

async function executePageScript(
  contents: StorageContents,
  script: string,
  deadline: number,
  timeoutMessage: string,
): Promise<unknown> {
  const remainingMs = deadline - Date.now();
  if (remainingMs <= 0) throw new Error(timeoutMessage);
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      contents.executeJavaScript(script),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(timeoutMessage)), remainingMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
