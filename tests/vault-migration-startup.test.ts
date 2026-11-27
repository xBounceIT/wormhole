import assert from 'node:assert/strict';
import test from 'node:test';
import {
  mountVaultMigrationStartup,
  mountVaultRootRotationStartup,
  mountVaultOSMigrationStartup,
} from '../src/vault-migration-startup.ts';

class Element extends EventTarget {
  children: Element[] = [];
  textContent = '';
  disabled = false;
  attributes = new Map<string, string>();
  readonly tag: string;
  constructor(tag: string) {
    super();
    this.tag = tag;
  }
  setAttribute(key: string, value: string) {
    this.attributes.set(key, value);
  }
  replaceChildren(...children: Element[]) {
    this.children = children;
  }
}
const tick = () => new Promise(setImmediate);
test('migration startup handles admission, cancellation and opening retries without resubmitting a completed migration', async (t) => {
  const original = globalThis.document;
  globalThis.document = { createElement: (tag: string) => new Element(tag) } as any;
  t.after(() => {
    globalThis.document = original;
  });
  for (const kind of ['migration', 'rotation', 'os'])
    for (const mode of [
      'success',
      'cancel',
      'error',
      'open retry',
      'disposed success',
      'disposed error',
    ]) {
      let resolve!: (value: boolean) => void,
        reject!: (error: Error) => void,
        calls = 0,
        ready = 0,
        opens = 0;
      const card = new Element('section');
      const resume = () => {
        calls++;
        return new Promise<boolean>((yes, no) => {
          resolve = yes;
          reject = no;
        });
      };
      const dispose = (
        kind === 'migration'
          ? mountVaultMigrationStartup
          : kind === 'os'
            ? mountVaultOSMigrationStartup
            : mountVaultRootRotationStartup
      )(
        card as any,
        {
          resumeVaultMigration: () => {
            assert.equal(kind, 'migration');
            return resume();
          },
          resumeVaultRootRotation: () => {
            assert.equal(kind, 'rotation');
            return resume();
          },
          resumeVaultOSMigration: () => {
            assert.equal(kind, 'os');
            return resume();
          },
          markStartupReady: () => {
            ready++;
          },
        },
        async () => {
          opens++;
          if (mode === 'open retry' && opens === 1) throw Error('private loading error');
        },
      );
      const button = card.children.find((n) => n.tag === 'button')!;
      const status = card.children.find((n) => n.attributes.get('role') === 'status')!;
      button.dispatchEvent(new Event('click'));
      button.dispatchEvent(new Event('click'));
      assert.equal(calls, 1);
      assert.equal(ready, 1);
      assert.equal(button.disabled, true);
      if (mode.startsWith('disposed')) dispose();
      if (mode === 'error' || mode === 'disposed error') reject(Error('private native diagnostic'));
      else resolve(mode !== 'cancel');
      await tick();
      assert.equal(status.textContent.includes('private'), false);
      if (mode.startsWith('disposed')) {
        assert.equal(opens, 0);
        assert.equal(button.disabled, true);
      } else if (mode === 'cancel' || mode === 'error') {
        assert.equal(opens, 0);
        assert.match(status.textContent, /not completed/);
        assert.equal(button.disabled, false);
      } else {
        assert.equal(opens, 1);
        if (mode === 'open retry') {
          assert.equal(button.textContent, 'Open workspace');
          assert.match(
            status.textContent,
            kind !== 'rotation' ? /Migration finished/ : /Protection was updated/,
          );
          button.dispatchEvent(new Event('click'));
          await tick();
          assert.equal(opens, 2);
          assert.equal(calls, 1);
        }
      }
      dispose();
      button.dispatchEvent(new Event('click'));
      assert.equal(calls, 1);
    }
});
