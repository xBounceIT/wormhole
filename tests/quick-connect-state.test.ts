import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import {
  connectionProtocolSupportsTunnel,
  connectionTypeForProtocol,
  connectionProtocolForType,
  connectionProtocolForAddress,
  quickConnectStartsImmediately,
  quickConnectTunnelId,
  type QuickConnectProtocol,
} from '../src/quick-connect-state.ts';

test('Browser is one connection type and preserves existing HTTP and HTTPS configurations', () => {
  assert.equal(connectionProtocolForType('browser', 'ssh', 'http://device.test/'), 'http');
  for (const protocol of ['http', 'https'] as const) {
    assert.equal(connectionTypeForProtocol(protocol), 'browser');
    assert.equal(connectionProtocolForType('browser', protocol), protocol);
  }
  for (const protocol of ['ssh', 'rdp', 'vnc', 'serial'] as const) {
    assert.equal(connectionTypeForProtocol(protocol), protocol);
    assert.equal(connectionProtocolForType(protocol, 'https'), protocol);
    assert.equal(connectionProtocolForType('browser', protocol), 'https');
    assert.equal(connectionProtocolForAddress(protocol, 'http://site.test/'), protocol);
  }
});

test('Browser selects the transport from its home page and defaults to HTTPS', () => {
  for (const protocol of ['http', 'https'] as const) {
    for (const address of ['http://site.test/', '  HTTP://site.test:8080/admin'])
      assert.equal(connectionProtocolForAddress(protocol, address), 'http');
    for (const address of ['', 'site.test/', 'https://site.test/', 'HTTPS://site.test/'])
      assert.equal(connectionProtocolForAddress(protocol, address), 'https');
  }
});

test('connection editor exposes VPN only for supported network protocols', () => {
  const supported: QuickConnectProtocol[] = ['ssh', 'sftp', 'rdp', 'http', 'https', 'vnc'];
  const unsupported: QuickConnectProtocol[] = ['serial'];

  for (const protocol of supported) assert.equal(connectionProtocolSupportsTunnel(protocol), true);
  for (const protocol of unsupported)
    assert.equal(connectionProtocolSupportsTunnel(protocol), false);
});

test('Quick Connect only marks SSH as connecting when credentials are immediately usable', () => {
  assert.equal(quickConnectStartsImmediately('ssh', true, undefined), false);
  assert.equal(quickConnectStartsImmediately('ssh', true, 'credential-id'), true);
  assert.equal(quickConnectStartsImmediately('ssh', false, undefined), true);
  assert.equal(quickConnectStartsImmediately('sftp', true, undefined), false);
  assert.equal(quickConnectStartsImmediately('sftp', true, 'credential-id'), true);
  assert.equal(quickConnectStartsImmediately('sftp', false, undefined), true);
  assert.equal(quickConnectStartsImmediately('rdp', true, 'credential-id'), false);
  assert.equal(quickConnectStartsImmediately('https', true, undefined), true);
});

test('Quick Connect maps the selected tunnel only when routing is supported and enabled', () => {
  const tunnelID = '11111111-2222-3333-4444-555555555555';

  assert.equal(quickConnectTunnelId('https', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('https', 'off'), undefined);
  assert.equal(quickConnectTunnelId('ssh', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('serial', tunnelID), undefined);
});

test('shared connection fields show Browser and Home page in create, edit and Quick Connect', async (context) => {
  const require = createRequire(import.meta.url);
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8').replaceAll(
    '\r',
    '',
  );
  const label = source.indexOf('<Label htmlFor="connection-protocol">');
  const start = source.lastIndexOf('<div className="grid gap-2">', label);
  const end = source.indexOf("{newConnectionForm.protocol !== 'serial' ? (", label);
  const tabsStart = source.lastIndexOf('<Tabs\n', label);
  const tabsKey = source
    .slice(tabsStart, source.indexOf('>', tabsStart))
    .match(/key=\{([^}]+)\}/)?.[1];
  assert.ok(start >= 0 && end > start && tabsKey, 'Missing shared production connection fields');
  const helpers = ['quick-connect-state', 'web-address']
    .map((name) =>
      readFileSync(new URL(`../src/${name}.ts`, import.meta.url), 'utf8').replace(/^export /gm, ''),
    )
    .join('\n');
  const protocolLabel = source.slice(
    source.indexOf('function protocolLabel('),
    source.indexOf('function ProtocolIcon('),
  );
  const transformed = await transformWithOxc(
    `
    ${helpers}
    ${protocolLabel}
    let state;
    const Select = ({ value, onValueChange, children }) => <select value={value} onChange={event => onValueChange(event.target.value)}>{children}</select>;
    const SelectTrigger = () => null, SelectValue = () => null;
    const SelectContent = ({ children }) => <>{children}</>;
    const SelectItem = ({ value, children }) => <option value={value}>{children}</option>;
    const Label = 'label', Input = 'input';
    function Harness({ mode, initial }) {
      const connectionEditorMode = mode;
      const [newConnectionForm, setNewConnectionForm] = useState({ protocol: 'ssh', host: '', port: '22', credential: 'existing', ...initial });
      state = newConnectionForm;
      return <div key={${tabsKey}}>${source.slice(start, end)}</div>;
    }
  `,
    'connection-browser-fields.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderer = `
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { useState } = React;
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const assert = require('node:assert/strict');
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
    (async () => {
      const root = createRoot(document.getElementById('root'));
      let key = 0;
      const mount = async (mode, initial = {}) => React.act(async () => root.render(React.createElement(Harness, { mode, initial, key: ++key })));
      const choose = async value => React.act(async () => {
        const select = document.querySelector('select'); select.value = value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
      });
      const address = async value => React.act(async () => {
        const input = document.getElementById('connection-host');
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      });
      assert.equal(protocolLabel('http'), 'Browser');
      assert.equal(protocolLabel('https'), 'Browser');
      for (const mode of ['quick', 'saved']) {
        await mount(mode);
        await choose('browser');
        assert.equal(state.protocol, 'https');
        assert.equal(state.credential, mode === 'quick' ? 'none' : 'inherit');
        const options = [...document.querySelectorAll('option')];
        assert.equal(options.filter(item => item.textContent === 'Browser').length, 1);
        assert.equal(options.some(item => ['HTTP', 'HTTPS'].includes(item.textContent)), false);
        assert.equal(document.querySelector('label[for="connection-host"]').textContent, 'Home page');
        const input = document.getElementById('connection-host'); input.focus();
        await address('http://device.test/admin?tab=network#routes');
        assert.equal(state.protocol, 'http');
        assert.equal(document.getElementById('connection-host'), input, 'changing the URL scheme must retain the input');
        assert.equal(document.activeElement, input);
        assert.equal(document.querySelector('select').value, 'browser');
        await address('https://device.test/admin');
        assert.equal(state.protocol, 'https');
        await choose('ssh');
        assert.equal(state.host, 'device.test');
        assert.equal(document.querySelector('label[for="connection-host"]').textContent, 'Host or address');
        await choose('serial');
        assert.equal(document.querySelector('label[for="connection-host"]').textContent, 'Serial line');
        assert.equal(document.getElementById('connection-host').placeholder, 'COM1');
      }
      await mount('quick', { host: 'http://pasted.test/start' });
      await choose('browser');
      assert.equal(state.protocol, 'http', 'an address pasted before choosing Browser preserves its scheme');
      await mount('saved', { protocol: 'http', host: browserHomePageForEditor('http', 'legacy.test', '/admin?q=one#tab'), port: '8080' });
      assert.equal(document.querySelector('select').value, 'browser');
      assert.equal(document.getElementById('connection-host').value, 'http://legacy.test/admin?q=one#tab');
      await choose('browser');
      assert.equal(state.protocol, 'http');
      assert.equal(state.port, '8080');
      assert.equal(state.credential, 'existing');
      await React.act(async () => root.unmount());
    })();
    //# sourceURL=wormhole-browser-fields.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-browser-fields-'));
  try {
    const harness = join(directory, 'fields.cjs');
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const owner = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false } });
        try {
          await owner.loadURL('data:text/html,<div id="root"></div>');
          const debuggerApi = owner.webContents.debugger; debuggerApi.attach('1.3');
          await debuggerApi.sendCommand('Profiler.enable');
          await debuggerApi.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await owner.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const report = await debuggerApi.sendCommand('Profiler.takePreciseCoverage');
          const script = report.result.find(item => item.url === 'wormhole-browser-fields.js');
          const parent = script.functions.find(item => item.functionName === 'Harness');
          const scope = parent.ranges[0];
          const ranges = script.functions.filter(item => item.ranges[0].startOffset >= scope.startOffset && item.ranges[0].endOffset <= scope.endOffset).flatMap(item => item.ranges);
          const percent = 100 * ranges.filter(item => item.count > 0).length / ranges.length;
          console.log('Shared connection fields: V8 block coverage ' + percent.toFixed(2) + '%');
          if (percent < ${coverageThreshold}) throw new Error('Shared connection fields coverage below threshold');
        } finally { owner.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...environment } = process.env;
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const result = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
    context.diagnostic(result.stdout.trim());
    if (result.stderr.trim()) process.stderr.write(result.stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
