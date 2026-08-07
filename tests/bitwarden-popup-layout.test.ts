import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isPointInsideBitwardenAnchor,
  positionBitwardenPopup,
} from '../electron/bitwarden-popup-layout.ts';

test('Bitwarden popup opens directly below a left-side toolbar icon', () => {
  assert.deepEqual(positionBitwardenPopup({ x: 124, y: 118, width: 28, height: 28 }, [1200, 720]), {
    x: 124,
    y: 150,
    width: 380,
    height: 560,
  });
});

test('Bitwarden popup stays within the right edge of the window', () => {
  assert.deepEqual(positionBitwardenPopup({ x: 990, y: 80, width: 28, height: 28 }, [1100, 700]), {
    x: 712,
    y: 112,
    width: 380,
    height: 560,
  });
});

test('Bitwarden popup uses the available space below the toolbar', () => {
  assert.deepEqual(positionBitwardenPopup({ x: 100, y: 110, width: 28, height: 28 }, [900, 620]), {
    x: 100,
    y: 142,
    width: 380,
    height: 470,
  });
});

test('the popup anchor click is left to the toolbar toggle', () => {
  const anchor = { x: 124, y: 118, width: 28, height: 28 };
  assert.equal(isPointInsideBitwardenAnchor({ x: 130, y: 125 }, anchor), true);
  assert.equal(isPointInsideBitwardenAnchor({ x: 123, y: 125 }, anchor), false);
  assert.equal(isPointInsideBitwardenAnchor({ x: 160, y: 125 }, anchor), false);
});
