import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
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
import { terminalVisibleScrollback } from '../src/terminal-frame.ts';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const require = createRequire(import.meta.url);
const electronExecutable = require('electron') as string;
const execFileAsync = promisify(execFile);

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

test('normal terminal frames expose their retained scrollback', () => {
  const scrollback = [{ text: 'previous output' }];

  assert.equal(terminalVisibleScrollback({ alternateScreen: false, scrollback }), scrollback);
});

test('alternate-screen applications hide retained scrollback', () => {
  assert.equal(
    terminalVisibleScrollback({
      alternateScreen: true,
      scrollback: [{ text: 'previous output' }],
    }),
    undefined,
  );
});

test('styled runs remain inline and preserve spaces when Chromium copies a terminal row', () => {
  const terminalGridSource = appSource.slice(
    appSource.indexOf('const TerminalScrollback'),
    appSource.indexOf('function terminalCsiWithModifier'),
  );

  assert.equal(terminalGridSource.match(/inline-block overflow-hidden align-top/g)?.length, 2);
  assert.equal(
    terminalGridSource.match(/className="h-\[18px\] min-w-max whitespace-pre"/g)?.length,
    2,
  );
  assert.doesNotMatch(terminalGridSource, /className=(?:"|{`)[^"`]*block flex-none/);
});

test('Chromium keeps styled runs on one clipboard line and separates real terminal rows', async () => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'wormhole-terminal-clipboard-'));
  const harnessPath = join(temporaryDirectory, 'selection.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      String.raw`
const assert = require('node:assert/strict');
const { app, BrowserWindow } = require('electron');

const html = encodeURIComponent('<style>.row{display:block;white-space:pre}.run{display:inline-block;overflow:hidden;vertical-align:top}</style><div id="terminal"><div class="row"><span class="run" style="color:white">docker stack deploy -c </span><span class="run" style="color:red">portainer-agent-stack.yml </span><span class="run" style="color:red">portainer</span></div><div class="row"><span class="run">printf done</span></div></div>');

app.whenReady().then(async () => {
  const window = new BrowserWindow({ show: false });
  try {
    await window.loadURL('data:text/html;charset=utf-8,' + html);
    const selectedText = await window.webContents.executeJavaScript(
      "const range=document.createRange();range.selectNodeContents(document.getElementById('terminal'));const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);selection.toString()",
    );
    assert.equal(
      selectedText,
      'docker stack deploy -c portainer-agent-stack.yml portainer\nprintf done',
    );
  } finally {
    window.destroy();
  }
  app.quit();
}).catch((error) => {
  console.error(error);
  app.exit(1);
});
`,
      'utf8',
    );

    const needsVirtualDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const executable = needsVirtualDisplay ? 'xvfb-run' : electronExecutable;
    const arguments_ = needsVirtualDisplay
      ? [
          '--auto-servernum',
          electronExecutable,
          '--no-sandbox', // Safe for this local data-URL test; npm's binary has no SUID helper.
          harnessPath,
        ]
      : [harnessPath];

    await execFileAsync(executable, arguments_, {
      env: environment,
      timeout: 30_000,
      windowsHide: true,
    });
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});
