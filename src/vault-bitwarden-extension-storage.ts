// Runs only inside the owning extension background context. No React/main/preload
// API imports this adapter; its borrowed bytes go directly into the sealed helper.
import { browserTransferAreaBytes } from '../electron/vault-bitwarden-transfer.ts';

type Values = Record<string, unknown>;
export type ExtensionStorageArea = {
  get(keys: string | null, callback: (values: Values) => void): void;
  set(values: Values, callback: () => void): void;
  remove(key: string, callback: () => void): void;
};
export type BitwardenBackgroundMemory = {
  store: Record<string, string>;
  save(key: string, value: unknown): Promise<unknown>;
  remove(key: string): Promise<unknown>;
};
export type BitwardenStorageEnvironment = {
  manifestVersion: 2 | 3;
  local: ExtensionStorageArea;
  session?: ExtensionStorageArea;
  memory?: BitwardenBackgroundMemory;
  lastError(): unknown;
};
export type ExtensionStorageCapture = { localJSON: Uint8Array; sessionJSON: Uint8Array };
const encoder = new TextEncoder(),
  decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const maxKeys = 65536,
  operationTimeoutMs = 10000;
const failure = () => Error('Bitwarden extension storage operation failed.');
const cancelled = () => Error('Bitwarden extension storage operation cancelled.');
function object(value: unknown): value is Values {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length <= maxKeys
  );
}
function encoded(value: Values): Uint8Array {
  if (!object(value)) throw failure();
  const bytes = encoder.encode(JSON.stringify(value));
  if (bytes.length < 2 || bytes.length > browserTransferAreaBytes) {
    bytes.fill(0);
    throw failure();
  }
  return bytes;
}
function decoded(raw: Uint8Array): Values {
  if (!(raw instanceof Uint8Array) || raw.length < 2 || raw.length > browserTransferAreaBytes)
    throw failure();
  const value: unknown = JSON.parse(decoder.decode(raw));
  if (!object(value)) throw failure();
  return value;
}
function same(a: Values, b: Values, key: string): boolean {
  return (
    Object.hasOwn(a, key) === Object.hasOwn(b, key) &&
    JSON.stringify(a[key]) === JSON.stringify(b[key])
  );
}

class StorageScope {
  private readonly controller = new AbortController();
  private readonly abort = () => this.controller.abort();
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly source: AbortSignal;
  constructor(source: AbortSignal) {
    this.source = source;
    source.addEventListener('abort', this.abort, { once: true });
    this.timer = setTimeout(this.abort, operationTimeoutMs);
    if (source.aborted) this.abort();
  }
  get aborted() {
    return this.controller.signal.aborted;
  }
  check() {
    if (this.aborted) throw cancelled();
  }
  wait<T>(start: (complete: (value: T) => void, fail: () => void) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (value: T, error?: Error) => {
        if (settled) return;
        settled = true;
        this.controller.signal.removeEventListener('abort', abort);
        if (error) reject(error);
        else resolve(value);
      };
      const abort = () => finish(undefined as T, cancelled());
      this.controller.signal.addEventListener('abort', abort, { once: true });
      if (this.controller.signal.aborted) {
        abort();
        return;
      }
      try {
        start(
          (value) => finish(value),
          () => finish(undefined as T, failure()),
        );
      } catch {
        finish(undefined as T, failure());
      }
    });
  }
  close() {
    this.source.removeEventListener('abort', this.abort);
    clearTimeout(this.timer);
    this.abort();
  }
}
type Area = {
  all(): Promise<Values>;
  edit(key: string, desired: Values, expected: Values): Promise<void>;
};
function change(
  current: Values,
  desired: Values,
  expected: Values,
  key: string,
): 'set' | 'remove' | undefined {
  if (!same(current, expected, key) || same(current, desired, key)) return undefined;
  return Object.hasOwn(desired, key) ? 'set' : 'remove';
}
function chromeArea(
  area: ExtensionStorageArea,
  env: BitwardenStorageEnvironment,
  scope: StorageScope,
): Area {
  const checked = (no: () => void, accept: () => void) => {
    try {
      // Read lastError inside its callback even after cancellation, without
      // forwarding raw diagnostics or throwing from a late native callback.
      const error = env.lastError();
      if (scope.aborted) return;
      if (error) no();
      else accept();
    } catch {
      no();
    }
  };
  const get = (key: string | null) =>
    scope.wait<Values>((yes, no) =>
      area.get(key, (values) => checked(no, () => (object(values) ? yes(values) : no()))),
    );
  return {
    all: () => get(null),
    edit: (key, desired, expected) =>
      scope.wait<void>((yes, no) => {
        area.get(key, (current) =>
          checked(no, () => {
            if (!object(current)) {
              no();
              return;
            }
            const next = change(current, desired, expected, key);
            if (!next) {
              yes();
              return;
            }
            scope.check();
            const done = () => checked(no, () => yes());
            // Check and issue the conditional mutation within this native callback,
            // without yielding another JavaScript turn between read and write.
            if (next === 'set') area.set({ [key]: desired[key] }, done);
            else area.remove(key, done);
          }),
        );
      }),
  };
}
function memoryArea(memory: BitwardenBackgroundMemory, scope: StorageScope): Area {
  const get = (key: string): Values => {
    scope.check();
    const values: Values = Object.create(null);
    if (Object.hasOwn(memory.store, key)) {
      const raw = memory.store[key];
      if (typeof raw !== 'string' || encoder.encode(raw).length > browserTransferAreaBytes)
        throw failure();
      Object.defineProperty(values, key, { value: JSON.parse(raw), enumerable: true });
    }
    return values;
  };
  return {
    all: async () => {
      const keys = Object.keys(memory.store);
      if (keys.length > maxKeys) throw failure();
      const values: Values = Object.create(null);
      let bytes = 2;
      for (const key of keys) {
        const raw = memory.store[key];
        if (typeof raw !== 'string') throw failure();
        bytes +=
          encoder.encode(JSON.stringify(key)).length +
          1 +
          encoder.encode(raw).length +
          (bytes === 2 ? 0 : 1);
        if (bytes > browserTransferAreaBytes) throw failure();
        scope.check();
        Object.defineProperty(values, key, { value: JSON.parse(raw), enumerable: true });
      }
      return values;
    },
    edit: (key, desired, expected) =>
      scope.wait<void>((yes, no) => {
        const next = change(get(key), desired, expected, key);
        if (!next) {
          yes();
          return;
        }
        scope.check();
        const result = next === 'set' ? memory.save(key, desired[key]) : memory.remove(key);
        Promise.resolve(result).then(() => yes(), no);
      }),
  };
}

export function createBitwardenExtensionStorage(env: BitwardenStorageEnvironment) {
  // MV2 session state is never chrome.storage.session. Fail closed until the
  // owning background service is ready; no plaintext foreground/main fallback.
  if (
    (env.manifestVersion !== 2 && env.manifestVersion !== 3) ||
    (env.manifestVersion === 2
      ? !env.memory?.store ||
        typeof env.memory.save !== 'function' ||
        typeof env.memory.remove !== 'function'
      : !env.session)
  )
    throw failure();
  const scoped = async <T>(
    signal: AbortSignal,
    run: (local: Area, session: Area, scope: StorageScope) => Promise<T>,
  ): Promise<T> => {
    const scope = new StorageScope(signal);
    try {
      scope.check();
      const local = chromeArea(env.local, env, scope),
        session =
          env.manifestVersion === 2
            ? memoryArea(env.memory!, scope)
            : chromeArea(env.session!, env, scope);
      const result = await run(local, session, scope);
      scope.check();
      return result;
    } catch {
      throw scope.aborted ? cancelled() : failure();
    } finally {
      scope.close();
    }
  };
  return {
    capture: async (signal: AbortSignal): Promise<ExtensionStorageCapture> => {
      let localJSON: Uint8Array | undefined, sessionJSON: Uint8Array | undefined;
      try {
        return await scoped(signal, async (local, session, scope) => {
          localJSON = encoded(await local.all());
          scope.check();
          sessionJSON = encoded(await session.all());
          scope.check();
          return { localJSON, sessionJSON };
        });
      } catch (error) {
        localJSON?.fill(0);
        sessionJSON?.fill(0);
        throw error;
      }
    },
    restore: (
      desired: ExtensionStorageCapture,
      witness: ExtensionStorageCapture,
      signal: AbortSignal,
    ): Promise<void> =>
      scoped(signal, async (local, session, scope) => {
        const desiredLocal = decoded(desired.localJSON),
          desiredSession = decoded(desired.sessionJSON),
          expectedLocal = decoded(witness.localJSON),
          expectedSession = decoded(witness.sessionJSON);
        const apply = async (area: Area, values: Values, expected: Values) => {
          // Never clear a live account. Each area checks its current key and
          // issues the conditional edit together, without an intervening await.
          for (const key of Object.keys(values)) {
            await area.edit(key, values, expected);
            scope.check();
          }
          for (const key of Object.keys(expected)) {
            if (Object.hasOwn(values, key)) continue;
            await area.edit(key, values, expected);
            scope.check();
          }
        };
        await apply(session, desiredSession, expectedSession);
        await apply(local, desiredLocal, expectedLocal);
      }),
  };
}
