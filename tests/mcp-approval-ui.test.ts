import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';

const require = createRequire(import.meta.url);

test('MCP selector and queued approval popups work in the Electron renderer', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const extract = (start: string, end: string) => {
    const startIndex = source.indexOf(start);
    const endIndex = source.indexOf(end, startIndex);
    assert.ok(startIndex >= 0 && endIndex > startIndex);
    return source.slice(startIndex, endIndex);
  };
  const selectorIndex = source.indexOf('<Label htmlFor="settings-mcp-approval-mode">');
  const selector = source.slice(
    source.lastIndexOf('<div', selectorIndex),
    source.indexOf('<div className="grid max-w-52 gap-2">', selectorIndex),
  );
  const approvalSource = readFileSync(
    new URL('../src/components/McpApprovalDialog.tsx', import.meta.url),
    'utf8',
  );
  const selectSource = readFileSync(
    new URL('../src/components/ui/select.tsx', import.meta.url),
    'utf8',
  );
  const approvalDialog = extract('<McpApprovalDialog', '\n      <div');
  const transformed = await transformWithOxc(
    `
    ${selectSource.slice(selectSource.indexOf('function Select('), selectSource.lastIndexOf('export {'))}
    ${approvalSource.slice(approvalSource.indexOf('export function McpApprovalDialog')).replace('export function', 'function')}
    ${extract('function matchesMcpOpenConnectionApproval(', 'function containsTreeNode(')}
    function Harness() {
      const [mcpState, setMcpState] = useState({ approvalMode: 'first-access' });
      const [mcpBusy, setMcpBusy] = useState(false);
      const [mcpError, setMcpError] = useState('');
      const [mcpApprovals, setMcpApprovals] = useState([]);
      const setMcpMessage = () => {};
      const tree = [];
      window.setApprovals = setMcpApprovals;
      ${extract('async function handleMcpApprovalMode(', 'async function revealMcpToken(')}
      ${extract('async function resolveMcpApproval(', 'const openAuthorizedMcpConnection =')}
      return <>${selector}${approvalDialog}<p role="alert">{mcpError}</p></>;
    }
  `,
    'mcp-approval-ui.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderer = `(async () => { try {
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { Select: S, Dialog: D } = require(${JSON.stringify(require.resolve('radix-ui'))});
    const { useState, useLayoutEffect, useRef, act } = React;
    const SelectPrimitive = S;
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const cn = (...values) => twMerge(clsx(values));
    const ChevronDownIcon = 'span', CheckIcon = 'span', ChevronUpIcon = 'span';
    const Dialog = D.Root, DialogTitle = D.Title, DialogDescription = D.Description;
    const DialogContent = ({ overlayClassName, ...props }) => React.createElement(D.Portal, null,
      React.createElement(D.Overlay), React.createElement(D.Content, props));
    const DialogHeader = 'div', DialogFooter = 'div', AlertCircle = 'span', Button = 'button', Label = 'label';
    const authSettingsErrorMessage = error => error.message;
    const findTreeNode = () => undefined, openConnection = () => {};
    const decisions = [];
    let failSave = false;
    window.wormhole = {
      setMcpApprovalMode: async approvalMode => {
        if (failSave) throw Error('Cannot save approval mode');
        return { approvalMode };
      },
      respondMcpApproval: async (id, approved) => decisions.push([id, approved]),
    };
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
    const root = createRoot(document.getElementById('root'));
    await act(async () => root.render(React.createElement(Harness)));
    const trigger = () => document.getElementById('settings-mcp-approval-mode');
    assert.equal(trigger().getAttribute('role'), 'combobox');
    assert.match(document.body.textContent, /Approve access once per SSH session/);
    async function waitFor(predicate, description) {
      const deadline = performance.now() + 5000;
      while (!predicate()) {
        assert.ok(performance.now() < deadline, description);
        await act(async () => new Promise(resolve => setTimeout(resolve, 10)));
      }
    }
    async function choose(label) {
      await act(async () => {
        trigger().focus();
        trigger().dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
      });
      // Portal/layout work can finish after act when Chromium is running alongside other UI tests.
      await waitFor(() => document.querySelectorAll('[role="option"]').length > 0, 'MCP options did not render');
      const options = Array.from(document.querySelectorAll('[role="option"]'));
      assert.deepEqual(options.map(option => option.textContent), ['Full access', 'Always ask', 'Ask on first access']);
      await act(async () => options.find(option => option.textContent === label).click());
      await waitFor(() => trigger().getAttribute('aria-expanded') === 'false' && !trigger().disabled, 'MCP selection did not settle');
    }
    await choose('Full access');
    assert.match(trigger().textContent, /Full access/);
    assert.match(document.body.textContent, /without approval popups/);
    await choose('Always ask');
    assert.match(trigger().textContent, /Always ask/);
    assert.match(document.body.textContent, /Every MCP action requires approval/);
    failSave = true;
    await choose('Ask on first access');
    assert.match(trigger().textContent, /Always ask/);
    assert.match(document.querySelector('[role="alert"]').textContent, /Cannot save/);
    const action = { type: 'mcp.approval', approvalMode: 'always-ask', approvalKind: 'tool',
      tool: 'list_sessions', requestId: 'one', title: 'Wormhole workspace', host: '', port: 0, username: '' };
    await act(async () => window.setApprovals([action, { ...action, requestId: 'two', tool: 'list_connections' }]));
    let popup = document.querySelector('[role="dialog"]');
    assert.match(popup.textContent, /Allow this AI agent action/);
    assert.match(popup.textContent, /only to this action/);
    assert.doesNotMatch(popup.textContent, /@:0|session's lifetime/);
    await act(async () => Array.from(popup.querySelectorAll('button')).find(button => button.textContent.trim() === 'Deny').click());
    popup = document.querySelector('[role="dialog"]');
    assert.match(popup.textContent, /list_connections/);
    await act(async () => Array.from(popup.querySelectorAll('button')).find(button => button.textContent.trim() === 'Allow').click());
    assert.deepEqual(decisions, [['one', false], ['two', true]]);
    assert.equal(document.querySelector('[role="dialog"]'), null);
    await act(async () => window.setApprovals([{ ...action, requestId: 'session', approvalKind: 'session_control', approvalMode: 'first-access',
      title: 'Shell', host: 'host.example', port: 22, username: 'user', tool: 'read_terminal' }]));
    popup = document.querySelector('[role="dialog"]');
    assert.match(popup.textContent, /session's lifetime/);
    assert.match(popup.textContent, /user@host.example:22/);
    await act(async () => root.unmount());
    return { ok: true };
  } catch (error) { return { error: error.stack ?? String(error) }; } })()`;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-mcp-ui-'));
  const harness = join(directory, 'test.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } });
        try {
          await window.loadURL('data:text/html,<div id="root"></div>');
          const result = await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          if (!result.ok) throw Error(result.error);
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: environment, timeout: 30_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
