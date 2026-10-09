import { randomUUID } from 'node:crypto';
import type { WebContents } from 'electron';

const operationTimeoutMs = 10_000;
const pollIntervalMs = 25;
const maxJsonBytes = 8 * 1024 * 1024;
const profileRevisionKey = '__wormholeBitwardenProfileRevision';

type StorageContents = Pick<WebContents, 'executeJavaScript' | 'isDestroyed'>;
export type StorageSnapshot = { localJson: string; sessionJson: string; nativeRevision?: number };

const pageOperationGuard = `
  const active = () => globalThis[key]?.status === 'pending' &&
    Date.now() < globalThis[key].deadline;
`;

// Bitwarden's MV2 build keeps vault session state in BackgroundMemoryStorageService,
// accessed by ForegroundMemoryStorageService through the extension's "session" port.
// It is not exposed as chrome.storage.session, even when the background page is alive.
const sessionStorageBridge = `
  const unchanged = (current, expected, entry) => expected === undefined ||
    JSON.stringify(current[entry]) === JSON.stringify(expected[entry]);
  const changes = (current, values, expected) => Object.fromEntries(Object.keys(values)
    .filter((entry) => unchanged(current, expected, entry) &&
      JSON.stringify(current[entry]) !== JSON.stringify(values[entry]))
    .map((entry) => [entry, values[entry]]));
  const replaceArea = (area, values, complete, fail, expected) => {
    if (!active()) return;
    const checked = (next) => (...args) => {
      if (!active()) return;
      if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
      try { next(...args); } catch (error) { fail(error); }
    };
    area.get(null, checked((current) => {
      const updates = changes(current, values, expected);
      const removals = Object.keys(current).filter((entry) => entry !== ${JSON.stringify(profileRevisionKey)} && !Object.hasOwn(values, entry) &&
        unchanged(current, expected, entry));
      const entries = Object.keys(updates);
      let index = 0;
      const next = () => {
        const update = (entry, mutate) => {
          if (expected === undefined) { mutate(); return; }
          area.get(entry, checked((latest) => {
            if (unchanged(latest, expected, entry)) mutate();
            else next();
          }));
        };
        if (index < entries.length) {
          const entry = entries[index++];
          update(entry, () => area.set({ [entry]: updates[entry] }, checked(next)));
        } else if (index < entries.length + removals.length) {
          const entry = removals[index++ - entries.length];
          update(entry, () => area.remove(entry, checked(next)));
        } else complete({});
      };
      // Never clear a live account before putting its replacement back: Bitwarden observes
      // storage changes and would see a transient logged-out account even on an identical restore.
      // Its observable storage ignores bulk changes, so publish one changed key per operation.
      next();
    }));
  };
  const sessionStorage = (values, complete, fail, expected) => {
    const decode = (value) => {
      try { return JSON.parse(value); }
      catch { throw new Error('Bitwarden memory storage returned invalid JSON.'); }
    };
    const memory = globalThis.bitwardenMain?.memoryStorageForStateProviders;
    const area = chrome.storage.session;
    const mv2 = chrome.runtime.getManifest?.().manifest_version === 2;
    if (!mv2 && !memory?.store && area?.get && area?.remove && area?.set) {
      const checked = (next) => (...args) => {
        if (!active()) return;
        if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
        next(...args);
      };
      if (values === null) { area.get(null, checked(complete)); return; }
      replaceArea(area, values, complete, fail, expected);
      return;
    }
    // A background page cannot open a runtime port to itself in Electron. Bitwarden exports its
    // background services for MV2; use the same memory store and its observable mutation methods.
    if (memory?.store && memory?.save && memory?.remove) {
      if (values === null) {
        const result = Object.fromEntries(Object.entries(memory.store)
          .map(([entry, value]) => [entry, decode(value)]));
        complete(result);
        return;
      }
      const canReplace = (entry) => expected === undefined ||
        memory.store[entry] === JSON.stringify(expected[entry]);
      const removals = Object.keys(memory.store).filter((entry) => !Object.hasOwn(values, entry) && canReplace(entry));
      const updates = Object.fromEntries(Object.keys(values)
        .filter((entry) => canReplace(entry) && memory.store[entry] !== JSON.stringify(values[entry]))
        .map((entry) => [entry, values[entry]]));
      let pending = removals.length + Object.keys(updates).length;
      if (!pending) { complete({}); return; }
      const done = () => { if (active() && --pending === 0) complete({}); };
      const failed = () => fail(new Error('Bitwarden memory storage update failed.'));
      for (const entry of Object.keys(updates)) {
        if (canReplace(entry)) memory.save(entry, updates[entry]).then(done, failed);
        else done();
      }
      for (const entry of removals) {
        if (canReplace(entry)) memory.remove(entry).then(done, failed);
        else done();
      }
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
      const updates = changes(result, values, expected);
      const requests = [
        ...Object.keys(updates).map((entry) => ({ action: 'save', key: entry, data: JSON.stringify(updates[entry]) })),
        ...existingKeys.filter((entry) => !Object.hasOwn(values, entry) && unchanged(result, expected, entry))
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
          const requests = existingKeys.filter((entry) => values === null || expected !== undefined || Object.hasOwn(values, entry))
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

export async function readBitwardenStorageRevision(contents: StorageContents): Promise<number> {
  const result = await executePageScript(
    contents,
    `(() => {
      const memory = globalThis.bitwardenMain?.memoryStorageForStateProviders;
      if (chrome.runtime.getManifest?.().manifest_version === 2 && !memory?.updates$) return null;
      if (!memory?.updates$ && !chrome.storage.session) return null;
      const key = '__wormholeBitwardenStorageChanges';
      if (!globalThis[key]) {
        const state = { revision: 0 };
        const changed = () => { state.revision++; };
        chrome.storage.local.onChanged.addListener(changed);
        if (memory?.updates$) memory.updates$.subscribe(changed);
        else chrome.storage.session.onChanged.addListener(changed);
        globalThis[key] = state;
      }
      return globalThis[key].revision;
    })()`,
    Date.now() + operationTimeoutMs,
    'Bitwarden browser storage monitoring timed out.',
  );
  if (!Number.isSafeInteger(result) || (result as number) < 0) {
    throw new Error('Bitwarden background storage is not ready.');
  }
  return result as number;
}

export async function prepareBitwardenStorageMigrations(
  contents: StorageContents,
  restored = false,
): Promise<void> {
  const key = `__wormholeBitwardenMigrations${randomUUID().replaceAll('-', '')}`;
  const deadline = Date.now() + operationTimeoutMs;
  await runPageOperation(
    contents,
    key,
    `(() => {
    const key = ${JSON.stringify(key)};
    globalThis[key] = { status: 'pending', deadline: ${deadline} };
    ${pageOperationGuard}
    const complete = () => {
      if (active()) globalThis[key] = { status: 'complete' };
    };
    const fail = () => {
      if (active()) globalThis[key] = {
        status: 'error', message: 'Bitwarden browser storage migration failed.',
      };
    };
    const runner = globalThis.bitwardenMain?.migrationRunner;
    const method = ${JSON.stringify(restored ? 'run' : 'waitForCompletion')};
    try {
      if (typeof runner?.[method] === 'function') runner[method]().then(complete, fail);
      else complete();
    } catch { fail(); }
    return true;
  })()`,
    deadline,
    'Bitwarden browser storage migration timed out.',
  );
}

export async function markBitwardenStorageRevision(
  contents: StorageContents,
  revision: number,
): Promise<void> {
  if (!Number.isSafeInteger(revision) || revision < 0)
    throw new Error('Invalid Bitwarden storage revision.');
  const key = `__wormholeBitwardenMarker${randomUUID().replaceAll('-', '')}`;
  const deadline = Date.now() + operationTimeoutMs;
  await runPageOperation(
    contents,
    key,
    `(() => {
    const key = ${JSON.stringify(key)};
    const marker = ${JSON.stringify(profileRevisionKey)};
    globalThis[key] = { status: 'pending', deadline: ${deadline} };
    ${pageOperationGuard}
    const complete = () => {
      if (!active()) return;
      globalThis[key] = chrome.runtime.lastError
        ? { status: 'error', message: 'Bitwarden storage revision could not be saved.' }
        : { status: 'complete' };
    };
    chrome.storage.local.get(marker, current => {
      if (!active()) return;
      if (chrome.runtime.lastError || current[marker] === ${revision}) { complete(); return; }
      chrome.storage.local.set({ [marker]: ${revision} }, complete);
    });
    return true;
  })()`,
    deadline,
    'Bitwarden storage revision save timed out.',
  );
}

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
      ${pageOperationGuard}
      const complete = (local, session) => {
        if (!active()) return;
        try {
          if (Array.isArray(local) || Array.isArray(session)) {
            throw new Error('Invalid storage object.');
          }
          const marker = local?.[${JSON.stringify(profileRevisionKey)}];
          const nativeRevision = Number.isSafeInteger(marker) && marker >= 0 ? marker : undefined;
          if (local && typeof local === 'object') delete local[${JSON.stringify(profileRevisionKey)}];
          const localJson = JSON.stringify(local && typeof local === 'object' ? local : {});
          const sessionJson = JSON.stringify(session && typeof session === 'object' ? session : {});
          const encoder = new TextEncoder();
          if (encoder.encode(localJson).byteLength > ${maxJsonBytes} ||
              encoder.encode(sessionJson).byteLength > ${maxJsonBytes}) {
            fail(new Error('Bitwarden browser storage exceeded the safety limit.'));
            return;
          }
          globalThis[key] = { status: 'complete', localJson, sessionJson, nativeRevision };
        } catch {
          fail(new Error('Bitwarden extension returned invalid browser storage.'));
        }
      };
      const fail = (error) => {
        if (!active()) return;
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending', deadline: ${deadline} };
      ${sessionStorageBridge}
      try {
        chrome.storage.local.get(null, (local) => {
          if (!active()) return;
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
  return {
    localJson,
    sessionJson,
    ...(Number.isSafeInteger(captured.nativeRevision) && (captured.nativeRevision as number) >= 0
      ? { nativeRevision: captured.nativeRevision as number }
      : {}),
  };
}

export async function restoreBitwardenExtensionStorage(
  contents: StorageContents,
  snapshot: StorageSnapshot,
  expected?: StorageSnapshot,
): Promise<void> {
  for (const json of [
    snapshot.localJson,
    snapshot.sessionJson,
    ...(expected ? [expected.localJson, expected.sessionJson] : []),
  ]) {
    if (Buffer.byteLength(json, 'utf8') > maxJsonBytes || !isRecord(JSON.parse(json))) {
      throw new Error('Bitwarden browser storage restore requires bounded JSON objects.');
    }
  }
  const deadline = Date.now() + operationTimeoutMs;
  const timeoutMessage = 'Bitwarden browser storage restore timed out.';
  const operationKey = `__wormholeBitwardenRestore${randomUUID().replaceAll('-', '')}`;
  const serializedKey = JSON.stringify(operationKey);
  const local = JSON.stringify(snapshot.localJson);
  const session = JSON.stringify(snapshot.sessionJson);
  const script = `
    (() => {
      const key = ${serializedKey};
      ${pageOperationGuard}
      const complete = () => {
        if (active()) globalThis[key] = { status: 'complete' };
      };
      const fail = (error) => {
        if (!active()) return;
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending', deadline: ${deadline} };
      ${sessionStorageBridge}
      try {
        const local = JSON.parse(${local});
        const session = JSON.parse(${session});
        const expected = ${JSON.stringify(expected)};
        // Account observers must be able to find their session token when disk state changes.
        sessionStorage(session, () => replaceArea(chrome.storage.local, local, complete, fail,
          expected && JSON.parse(expected.localJson)), fail, expected && JSON.parse(expected.sessionJson));
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
      // executeJavaScript can stay queued while the renderer is stalled. A main-process
      // timeout alone cannot cancel it; the page must refuse to start expired work too.
      contents.executeJavaScript(`Date.now() < ${deadline} ? (${script}) : undefined`),
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
