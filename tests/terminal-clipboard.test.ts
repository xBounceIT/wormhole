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
  copyAndClearTerminalSelection,
  normalizeTerminalPasteText,
  shouldAutoCopyTerminalSelection,
  shouldUseTerminalClipboardShortcut,
} from '../src/terminal-clipboard.ts';
import {
  nextTerminalViewportResetSequence,
  terminalScrollEventKeepsBottomPin,
  terminalVisibleScrollback,
} from '../src/terminal-frame.ts';

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

test('copying terminal text writes plain text and clears the selection', () => {
  const calls: string[] = [];
  const clipboardData = {
    setData(format: string, text: string) {
      calls.push(`${format}:${text}`);
    },
  };

  assert.equal(
    copyAndClearTerminalSelection('selected command', clipboardData, () => calls.push('clear')),
    true,
  );
  assert.deepEqual(calls, ['text/plain:selected command', 'clear']);

  calls.length = 0;
  assert.equal(
    copyAndClearTerminalSelection('', clipboardData, () => calls.push('clear')),
    false,
  );
  assert.deepEqual(calls, []);
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

test('terminal viewport reset survives later frames that React can batch into one render', () => {
  assert.equal(
    nextTerminalViewportResetSequence(undefined, {
      sequence: 11,
      viewportReset: false,
    }),
    undefined,
  );
  const resetSequence = nextTerminalViewportResetSequence(undefined, {
    sequence: 12,
    viewportReset: true,
  });

  assert.equal(
    nextTerminalViewportResetSequence(resetSequence, {
      sequence: 13,
      viewportReset: false,
    }),
    12,
  );
  assert.equal(
    nextTerminalViewportResetSequence(resetSequence, {
      sequence: 14,
      viewportReset: true,
    }),
    14,
  );
});

test('terminal output stays pinned after content grows ahead of an automatic scroll event', () => {
  assert.equal(terminalScrollEventKeepsBottomPin(360, false, 360), true);
  assert.equal(terminalScrollEventKeepsBottomPin(360.5, false, 360), true);
});

test('terminal scroll events still release the bottom pin after manual scrolling', () => {
  assert.equal(terminalScrollEventKeepsBottomPin(180, false, 360), false);
  assert.equal(terminalScrollEventKeepsBottomPin(180, false, undefined), false);
  assert.equal(terminalScrollEventKeepsBottomPin(360, true, undefined), true);
});

test('live terminal wires automatic scroll tracking into frame and user scroll handling', () => {
  const frameApplicationSource = appSource.slice(
    appSource.indexOf('function applySshTerminalFrame'),
    appSource.indexOf('const navItems'),
  );
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );

  assert.match(
    frameApplicationSource,
    /viewportResetSequence: nextTerminalViewportResetSequence\(\s*previous\?\.viewportResetSequence,\s*incoming,/,
  );
  assert.match(
    terminalSurfaceSource,
    /useLayoutEffect\(\(\) => \{[\s\S]*stickToBottomRef\.current = true;[\s\S]*automaticScrollTopRef\.current = undefined;[\s\S]*handledViewportResetSequenceRef\.current = undefined;[\s\S]*session\.backendSessionId, session\.status/,
  );
  assert.match(
    terminalSurfaceSource,
    /viewportResetSequence !== handledViewportResetSequenceRef\.current[\s\S]*stickToBottomRef\.current = true;[\s\S]*handledViewportResetSequenceRef\.current = viewportResetSequence;/,
  );
  assert.match(
    terminalSurfaceSource,
    /const bottom = Math\.max\(0, surface\.scrollHeight - surface\.clientHeight\);\s*automaticScrollTopRef\.current = bottom;\s*surface\.scrollTop = bottom;/,
  );
  assert.match(
    terminalSurfaceSource,
    /onScroll=\{\(event\) => \{[\s\S]*terminalScrollEventKeepsBottomPin\([\s\S]*automaticScrollTopRef\.current,[\s\S]*automaticScrollTopRef\.current = undefined;/,
  );
  assert.match(
    terminalSurfaceSource,
    /automaticScrollTopRef\.current = undefined;\s*surface\.scrollLeft = nextScrollLeft;\s*surface\.scrollTop = nextScrollTop;/,
  );
});

test('live terminal clears its DOM selection after a copy event', () => {
  const terminalSurfaceSource = appSource.slice(
    appSource.indexOf('function SshTerminalSurface'),
    appSource.indexOf("type SftpPaneKind = 'local' | 'remote'"),
  );
  const copyHandlerSource = terminalSurfaceSource.slice(
    terminalSurfaceSource.indexOf('onCopy='),
    terminalSurfaceSource.indexOf('onPaste='),
  );

  assert.match(
    copyHandlerSource,
    /copyAndClearTerminalSelection\([\s\S]*terminalSelectionText\(event\.currentTarget\),[\s\S]*event\.clipboardData,[\s\S]*removeAllRanges\(\)[\s\S]*event\.preventDefault\(\);/,
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
    const result = await window.webContents.executeJavaScript(
      "const terminal=document.getElementById('terminal');terminal.addEventListener('copy',(event)=>{const selection=window.getSelection();const text=selection.toString();if(!text)return;event.clipboardData.setData('text/plain',text);selection.removeAllRanges();event.preventDefault()});const range=document.createRange();range.selectNodeContents(terminal);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);const selectedText=selection.toString();const clipboardData=new DataTransfer();const copyEvent=new ClipboardEvent('copy',{bubbles:true,cancelable:true,clipboardData});terminal.dispatchEvent(copyEvent);({clipboardText:clipboardData.getData('text/plain'),defaultPrevented:copyEvent.defaultPrevented,selectedText,remainingText:selection.toString()})",
    );
    const expectedText = 'docker stack deploy -c portainer-agent-stack.yml portainer\nprintf done';
    assert.deepEqual(result, {
      clipboardText: expectedText,
      defaultPrevented: true,
      selectedText: expectedText,
      remainingText: '',
    });
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
