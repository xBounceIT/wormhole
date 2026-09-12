import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import tailwindcss from '@tailwindcss/vite';
import { build, transformWithOxc } from 'vite';

const require = createRequire(import.meta.url);

// Process entrypoints and TSX are excluded from loaded-module coverage by
// scripts/test-coverage.ts. Exercise their actual parser and mounted dialog here.
test('MCP parser validates bounded execution previews and forwards only display fields', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const extract = (start: string, end: string) => {
    const index = main.indexOf(start);
    assert.ok(index >= 0 && main.indexOf(end, index) > index);
    return main.slice(index, main.indexOf(end, index));
  };
  const parse = runInNewContext(
    stripTypeScriptTypes(
      [
        'const sshMaxSessionIdLength = 128;',
        extract('function isRecord(', '\n}') + '\n}',
        extract('function isSshSessionId(', 'function isUuid('),
        extract('function isMcpRequestId(', 'type TunnelBrowserEvent'),
        'parseMcpBackendMessage;',
      ].join('\n'),
    ),
  ) as (line: string) => { executionPreview?: unknown; approvalKind: string } | undefined;
  const event = {
    type: 'mcp.approval',
    request_id: 'request',
    session_id: 'session',
    host: 'example.test',
    port: 22,
    username: 'user',
    title: 'SSH',
    tool: 'run_command',
  };
  for (const truncated of [true, false]) {
    for (const redacted of [true, false]) {
      const preview = { content: '{"command":"printf hello"}', truncated, redacted };
      const parsed = parse(
        JSON.stringify({ ...event, execution_preview: { ...preview, ignored: 'extra' } }),
      );
      assert.deepEqual(JSON.parse(JSON.stringify(parsed?.executionPreview)), preview);
    }
  }
  for (const content of ['', 'x'.repeat(64 * 1024), 'printf hello\r\n\x03']) {
    assert.ok(
      parse(
        JSON.stringify({
          ...event,
          execution_preview: { content, truncated: false, redacted: false },
        }),
      ),
    );
  }
  for (const preview of [
    null,
    [],
    'text',
    {},
    { content: 7, truncated: false, redacted: false },
    { content: 'x'.repeat(64 * 1024 + 1), truncated: false, redacted: false },
    { content: 'command', redacted: false },
    { content: 'command', truncated: 'false', redacted: false },
    { content: 'command', truncated: false },
    { content: 'command', truncated: false, redacted: 1 },
  ]) {
    assert.equal(parse(JSON.stringify({ ...event, execution_preview: preview })), undefined);
  }
  assert.equal(parse(JSON.stringify(event))?.executionPreview, undefined);
  const opened = parse(
    JSON.stringify({
      ...event,
      approval_kind: 'open_connection',
      tool: 'open_connection',
      connection_id: event.session_id,
      protocol: 'ssh',
      execution_preview: {
        content: '{"connectionId":"session"}',
        truncated: false,
        redacted: false,
      },
    }),
  );
  assert.equal(opened?.approvalKind, 'open_connection');
  assert.ok(opened?.executionPreview);
});

test('MCP dialog renders request contents as selectable text with bounded scrolling', async () => {
  const approval = readFileSync(
    new URL('../src/components/McpApprovalDialog.tsx', import.meta.url),
    'utf8',
  );
  const start = approval.indexOf('export function McpApprovalDialog');
  assert.ok(start >= 0);
  const dialog = readFileSync(new URL('../src/components/ui/dialog.tsx', import.meta.url), 'utf8');
  const lifecycle = readFileSync(new URL('../src/dialog-lifecycle.ts', import.meta.url), 'utf8');
  const fixture = readFileSync(new URL('./fixtures/mcp-approval.tsx', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(
    lifecycle.replace(/^export /gm, '') +
      dialog.slice(dialog.indexOf('const DialogOpenContext'), dialog.lastIndexOf('export {')) +
      approval.slice(start).replace('export function', 'function') +
      fixture,
    'mcp-approval.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    plugins: [tailwindcss()],
    build: {
      write: false,
      rolldownOptions: { input: fileURLToPath(new URL('../src/index.css', import.meta.url)) },
    },
  });
  const assets = (Array.isArray(output) ? output : [output]).flatMap((result) => result.output);
  const css = assets
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { useLayoutEffect, useRef } = React;
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const DialogPrimitive = require(${JSON.stringify(require.resolve('radix-ui'))}).Dialog;
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const cn = (...values) => twMerge(clsx(values));
    const Button = ({ variant, size, ...props }) => React.createElement('button', props);
    const AlertCircle = 'i', XIcon = 'i';
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.append(style);
    ${transformed.code}
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-mcp-approval-'));
  const harnessPath = join(directory, 'mcp-approval.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, Menu } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        Menu.setApplicationMenu(null);
        const window = new BrowserWindow({ show: false, width: 900, height: 700, webPreferences: {
          nodeIntegration: true, contextIsolation: false,
        } });
        try {
          await window.loadURL('data:text/html,<html class="dark"><div id="root"></div></html>');
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        } finally { window.destroy(); }
        app.quit();
      }).catch((error) => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
