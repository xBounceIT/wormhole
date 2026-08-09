import { randomUUID } from 'node:crypto';
import type { WebContents } from 'electron';

const operationTimeoutMs = 10_000;
const pollIntervalMs = 25;
const maxJsonBytes = 8 * 1024 * 1024;

type StorageContents = Pick<WebContents, 'executeJavaScript' | 'isDestroyed'>;
type StorageSnapshot = { localJson: string; sessionJson: string };

export async function captureBitwardenExtensionStorage(
  contents: StorageContents,
): Promise<StorageSnapshot> {
  const operationKey = `__wormholeBitwardenCapture${randomUUID().replaceAll('-', '')}`;
  const serializedKey = JSON.stringify(operationKey);
  await contents.executeJavaScript(`
    (() => {
      const key = ${serializedKey};
      const complete = (local, session) => {
        globalThis[key] = {
          status: 'complete',
          local: local && typeof local === 'object' ? local : {},
          session: session && typeof session === 'object' ? session : {},
        };
      };
      const fail = (error) => {
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending' };
      try {
        chrome.storage.local.get(null, (local) => {
          if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
          const sessionArea = chrome.storage.session;
          if (!sessionArea?.get) { complete(local, {}); return; }
          sessionArea.get(null, (session) => {
            if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
            complete(local, session);
          });
        });
      } catch (error) { fail(error); }
      return true;
    })()
  `);
  const captured = await waitForPageOperation(
    contents,
    operationKey,
    'Bitwarden browser storage capture timed out.',
  );
  if (!isRecord(captured.local) || !isRecord(captured.session)) {
    throw new Error('Bitwarden extension returned invalid browser storage.');
  }
  const localJson = JSON.stringify(captured.local);
  const sessionJson = JSON.stringify(captured.session);
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
  const operationKey = `__wormholeBitwardenRestore${randomUUID().replaceAll('-', '')}`;
  const serializedKey = JSON.stringify(operationKey);
  const local = JSON.stringify(snapshot.localJson);
  const session = JSON.stringify(snapshot.sessionJson);
  await contents.executeJavaScript(`
    (() => {
      const key = ${serializedKey};
      const complete = () => { globalThis[key] = { status: 'complete' }; };
      const fail = (error) => {
        globalThis[key] = {
          status: 'error',
          message: error?.message || String(error || 'storage operation failed'),
        };
      };
      globalThis[key] = { status: 'pending' };
      try {
        chrome.storage.local.clear(() => {
          if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
          chrome.storage.local.set(JSON.parse(${local}), () => {
            if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
            const sessionArea = chrome.storage.session;
            if (!sessionArea?.clear || !sessionArea?.set) { complete(); return; }
            sessionArea.clear(() => {
              if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
              sessionArea.set(JSON.parse(${session}), () => {
                if (chrome.runtime.lastError) { fail(chrome.runtime.lastError); return; }
                complete();
              });
            });
          });
        });
      } catch (error) { fail(error); }
      return true;
    })()
  `);
  await waitForPageOperation(
    contents,
    operationKey,
    'Bitwarden browser storage restore timed out.',
  );
}

async function waitForPageOperation(
  contents: StorageContents,
  operationKey: string,
  timeoutMessage: string,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + operationTimeoutMs;
  const serializedKey = JSON.stringify(operationKey);
  try {
    while (!contents.isDestroyed()) {
      const result: unknown = await contents.executeJavaScript(`globalThis[${serializedKey}]`);
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
      await contents
        .executeJavaScript(`delete globalThis[${serializedKey}]`)
        .catch(() => undefined);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
