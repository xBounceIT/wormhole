import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {
  captureBitwardenExtensionStorage,
  restoreBitwardenExtensionStorage,
} from '../electron/bitwarden-storage.ts';

type StorageValues = Record<string, unknown>;

class FakeExtensionContents {
  private readonly context: vm.Context;

  constructor(localValues: StorageValues) {
    const local = { ...localValues };
    this.context = vm.createContext({
      Promise: class UnsupportedPagePromise {
        constructor() {
          throw new Error('The storage bridge must not use the extension page Promise.');
        }
      },
      chrome: {
        runtime: { lastError: null },
        storage: {
          local: {
            clear(callback: () => void) {
              for (const key of Object.keys(local)) delete local[key];
              callback();
            },
            get(_keys: null, callback: (value: StorageValues) => void) {
              callback({ ...local });
            },
            set(value: StorageValues, callback: () => void) {
              Object.assign(local, value);
              callback();
            },
          },
        },
      },
    });
  }

  executeJavaScript<T>(script: string): Promise<T> {
    return globalThis.Promise.resolve(vm.runInContext(script, this.context) as T);
  }

  isDestroyed(): boolean {
    return false;
  }
}

test('Bitwarden storage capture does not depend on the popup Promise implementation', async () => {
  const contents = new FakeExtensionContents({ account: 'encrypted-value', revision: 7 });

  const snapshot = await captureBitwardenExtensionStorage(contents);

  assert.deepEqual(JSON.parse(snapshot.localJson), {
    account: 'encrypted-value',
    revision: 7,
  });
  assert.deepEqual(JSON.parse(snapshot.sessionJson), {});
});

test('Bitwarden storage restore supports MV2 without chrome.storage.session', async () => {
  const contents = new FakeExtensionContents({ stale: true });

  await restoreBitwardenExtensionStorage(contents, {
    localJson: JSON.stringify({ account: 'restored', revision: 8 }),
    sessionJson: JSON.stringify({ ignored: true }),
  });
  const snapshot = await captureBitwardenExtensionStorage(contents);

  assert.deepEqual(JSON.parse(snapshot.localJson), { account: 'restored', revision: 8 });
  assert.deepEqual(JSON.parse(snapshot.sessionJson), {});
});
