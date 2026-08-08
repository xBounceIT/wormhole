import assert from 'node:assert/strict';
import test from 'node:test';
import {
  encodeTerminalClipboardText,
  isEncodedSshInput,
  normalizeTerminalPasteText as normalizeNativeTerminalPasteText,
} from '../electron/terminal-clipboard.ts';
import { writeClipboardText } from '../src/clipboard.ts';
import {
  normalizeTerminalPasteText,
  shouldAutoCopyTerminalSelection,
  shouldUseTerminalClipboardShortcut,
} from '../src/terminal-clipboard.ts';

const shortcut = (
  key: string,
  overrides: Partial<Parameters<typeof shouldUseTerminalClipboardShortcut>[0]> = {},
) => ({
  key,
  ctrlKey: true,
  metaKey: false,
  altKey: false,
  ...overrides,
});

test('paste shortcuts stay in Chromium instead of becoming SSH control input', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('v'), false), true);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('V'), false), true);
  assert.equal(
    shouldUseTerminalClipboardShortcut(shortcut('v', { ctrlKey: false, metaKey: true }), false),
    true,
  );
});

test('copy uses the clipboard only when terminal text is selected', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('c'), true), true);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('c'), false), false);
});

test('unrelated and alt-modified shortcuts remain terminal input', () => {
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('x'), true), false);
  assert.equal(shouldUseTerminalClipboardShortcut(shortcut('v', { altKey: true }), true), false);
});

test('auto-copy only handles selection gestures from the primary mouse button', () => {
  assert.equal(shouldAutoCopyTerminalSelection(true, 0), true);
  assert.equal(shouldAutoCopyTerminalSelection(true, 1), false);
  assert.equal(shouldAutoCopyTerminalSelection(true, 2), false);
  assert.equal(shouldAutoCopyTerminalSelection(false, 0), false);
});

test('right-click paste encodes Unicode text for the SSH wire protocol', () => {
  const text = 'printf "caffè ☕"\r\nprintf "done"\n';
  const normalized = 'printf "caffè ☕"\rprintf "done"\r';
  const encoded = encodeTerminalClipboardText(text);
  assert.equal(normalizeTerminalPasteText(text), normalized);
  assert.equal(normalizeNativeTerminalPasteText(text), normalized);
  assert.equal(encoded, Buffer.from(normalized, 'utf8').toString('base64'));
  assert.equal(isEncodedSshInput(encoded), true);
});

test('right-click paste ignores an empty clipboard and rejects oversized text', () => {
  assert.equal(encodeTerminalClipboardText(''), undefined);
  assert.doesNotThrow(() => encodeTerminalClipboardText('a'.repeat(1024 * 1024)));
  assert.throws(() => encodeTerminalClipboardText('a'.repeat(1024 * 1024 + 1)), /too large/i);
});

test('SSH input validation rejects malformed and oversized base64', () => {
  assert.equal(isEncodedSshInput('not base64'), false);
  assert.equal(isEncodedSshInput('YQ='), false);
  assert.equal(isEncodedSshInput(Buffer.alloc(1024 * 1024).toString('base64')), true);
  assert.equal(isEncodedSshInput(Buffer.alloc(1024 * 1024 + 1).toString('base64')), false);
});

test('clipboard writes fall back after the async API rejects', async () => {
  const calls: string[] = [];
  await writeClipboardText(
    'selected text',
    async () => {
      calls.push('async');
      throw new Error('permission denied');
    },
    () => {
      calls.push('fallback');
      return true;
    },
  );
  assert.deepEqual(calls, ['async', 'fallback']);
});

test('successful async clipboard writes do not invoke the fallback', async () => {
  let fallbackCalled = false;
  await writeClipboardText(
    'selected text',
    async () => undefined,
    () => {
      fallbackCalled = true;
      return true;
    },
  );
  assert.equal(fallbackCalled, false);
});

test('clipboard writes fail when neither implementation is available', async () => {
  await assert.rejects(
    writeClipboardText('selected text', undefined, () => false),
    /unavailable/i,
  );
});
