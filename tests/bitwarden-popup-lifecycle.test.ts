import assert from 'node:assert/strict';
import test from 'node:test';
import {
  afterBitwardenPopupInputEvent,
  closeBitwardenPopupContents,
} from '../electron/bitwarden-popup-lifecycle.ts';

test('popup teardown waits until the current Blink input event has completed', async () => {
  let ran = false;
  const pending = afterBitwardenPopupInputEvent(async () => {
    ran = true;
  });
  assert.equal(ran, false);
  await pending;
  assert.equal(ran, true);
});

test('closing is a no-op after Bitwarden has destroyed its popup contents', () => {
  assert.doesNotThrow(() => closeBitwardenPopupContents({ webContents: undefined }));
});

test('closing ignores contents that Electron already marked as destroyed', () => {
  let closes = 0;
  closeBitwardenPopupContents({
    webContents: {
      isDestroyed: () => true,
      close: () => {
        closes += 1;
      },
    },
  });
  assert.equal(closes, 0);
});

test('closing live popup contents happens exactly once', () => {
  let closes = 0;
  closeBitwardenPopupContents({
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  });
  assert.equal(closes, 1);
});

test('closing tolerates Electron invalidating the view during inspection', () => {
  assert.doesNotThrow(() =>
    closeBitwardenPopupContents({
      webContents: {
        isDestroyed: () => {
          throw new TypeError('target closed');
        },
        close: () => assert.fail('destroyed popup must not be closed again'),
      },
    }),
  );
});
