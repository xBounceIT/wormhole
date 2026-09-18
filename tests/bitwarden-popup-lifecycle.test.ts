import assert from 'node:assert/strict';
import test from 'node:test';
import {
  afterBitwardenPopupInputEvent,
  closeBitwardenPopupContents,
  flushAndCloseBitwardenPopupContents,
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

test('popup storage finishes flushing before its live contents close', async () => {
  let closes = 0;
  let finishFlush!: () => void;
  const flushPending = new Promise<void>((resolve) => {
    finishFlush = resolve;
  });
  const popup = {
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  };

  const closing = flushAndCloseBitwardenPopupContents(popup, () => flushPending);
  await Promise.resolve();
  assert.equal(closes, 0);

  finishFlush();
  assert.equal(await closing, true);
  assert.equal(closes, 1);
});

test('popup contents still close when their storage flush fails', async () => {
  let closes = 0;
  const popup = {
    webContents: {
      isDestroyed: () => false,
      close: () => {
        closes += 1;
      },
    },
  };

  await assert.rejects(
    flushAndCloseBitwardenPopupContents(popup, async () => {
      throw new Error('capture failed');
    }),
    /capture failed/,
  );
  assert.equal(closes, 1);
});

test('destroyed popup contents request a storage fallback without flushing', async () => {
  let flushes = 0;
  const flushed = await flushAndCloseBitwardenPopupContents(
    {
      webContents: {
        isDestroyed: () => true,
        close: () => assert.fail('destroyed popup must not be closed again'),
      },
    },
    async () => {
      flushes += 1;
    },
  );

  assert.equal(flushed, false);
  assert.equal(flushes, 0);
});

test('popup invalidation during flush inspection requests the storage fallback', async () => {
  let flushes = 0;
  const flushed = await flushAndCloseBitwardenPopupContents(
    {
      webContents: {
        isDestroyed: () => {
          throw new TypeError('target closed');
        },
        close: () => assert.fail('invalidated popup must not be closed again'),
      },
    },
    async () => {
      flushes += 1;
    },
  );

  assert.equal(flushed, false);
  assert.equal(flushes, 0);
});
