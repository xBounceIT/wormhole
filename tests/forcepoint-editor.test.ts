import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { build, transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);
const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('Forcepoint aligns paired controls and displays certificate confirmation over its tester', async (context) => {
  const app = read('../src/App.tsx');
  const section = (source: string, from: string, to: string) => {
    const start = source.indexOf(from);
    const end = source.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `Missing production section: ${from}`);
    return source.slice(start, end);
  };
  const mounted = section(app, '            {value.kind === 7 ? (', '            ) : null}');
  const confirmationFixture = JSON.parse(read('fixtures/forcepoint-certificate-prompt.json'));
  const promptOpen = app.indexOf('        open={tunnelPrompts.length > 0}');
  const promptStart = app.lastIndexOf('      <Dialog', promptOpen);
  const promptEnd = app.indexOf('      </Dialog>', promptOpen) + '      </Dialog>'.length;
  assert.ok(promptStart > 0 && promptEnd > promptStart);
  const promptHandlerStart = app.indexOf("      if (event.type === 'tunnel.prompt-closed'");
  const promptHandlerEnd = app.indexOf('\n    });', promptHandlerStart);
  assert.ok(promptHandlerStart > 0 && promptHandlerEnd > promptHandlerStart);
  const controls = ['input', 'label', 'collapsible', 'button', 'dialog']
    .map((name) =>
      read(`../src/components/ui/${name}.tsx`)
        .replace(/^import .*;\r?\n/gm, '')
        .replace(/^export\s*\{[\s\S]*?\};\r?\n?/gm, '')
        .replace(/^export .*;\r?\n/gm, ''),
    )
    .join('\n');
  const transformed = await transformWithOxc(
    `
    ${read('../src/dialog-lifecycle.ts').replace(/^export /gm, '')}
    ${controls}
    ${section(app, 'function tunnelEditorFields(', 'function tunnelDefaultSettings(')}
    ${section(app, 'function tunnelSettingText(', '// Provider-specific tunnel fields')}
    const PasswordInput = (props) => <Input {...props} type="password" />;
    function ForcepointEditorHarness() {
      const value = { kind: 7, settings: { Host: 'vpn.example.test', Port: 443, Mtu: 1390 } };
      const [advancedOpen, setAdvancedOpen] = React.useState(true);
      const fields = tunnelEditorFields(value.kind);
      const rows = section => fields.filter(field => field.section === section).map(field =>
        <TunnelFieldRow key={field.key} field={field} value={value.settings} onChange={() => {}} />);
      return <div className="grid gap-6" style={{ maxWidth: 760, margin: 16, padding: 16 }}>
        ${mounted}
            ) : null}
      </div>;
    }
    let certificateControls;
    function ForcepointCertificateHarness() {
      const [tunnelPrompts, setTunnelPrompts] = React.useState([]);
      const [tunnelPromptValue, setTunnelPromptValue] = React.useState('');
      const TunnelPromptInput = tunnelPrompts[0]?.secret ? PasswordInput : Input;
      ${section(app, '  async function resolveTunnelPrompt(', '  async function resolveTunnelRoute(')}
      function dispatchTunnelPromptEvent(event) {
        ${app.slice(promptHandlerStart, promptHandlerEnd)}
      }
      certificateControls = { emit: dispatchTunnelPromptEvent, count: tunnelPrompts.length };
      return <>
        <Dialog open>
          <DialogContent>
            <DialogHeader><DialogTitle>Test VPN tunnel</DialogTitle><DialogDescription>Authenticating with the VPN gateway</DialogDescription></DialogHeader>
            <Button>Cancel test</Button>
          </DialogContent>
        </Dialog>
        ${app.slice(promptStart, promptEnd)}
      </>;
    }
    async function runForcepointCertificateTests(root) {
      const responses = [];
      window.wormhole = { respondTunnelPrompt: async response => { responses.push(response); } };
      await React.act(async () => { root.render(<ForcepointCertificateHarness />); });
      const wire = ${JSON.stringify(confirmationFixture)};
      assert.equal(Object.hasOwn(wire, 'secret'), false, 'fixture must reproduce the Go omitempty wire format');
      for (const secret of [null, 'false', 0, {}, []]) {
        await React.act(async () => { certificateControls.emit({ ...wire, secret }); });
        assert.equal(certificateControls.count, 0, 'invalid secret flag was accepted');
      }
      for (const variant of [{}, { secret: false }]) {
        await React.act(async () => { certificateControls.emit({ ...wire, ...variant }); });
        assert.equal(certificateControls.count, 1, 'serialized certificate confirmation was dropped');
        await React.act(async () => { certificateControls.emit({ ...wire, ...variant }); });
        assert.equal(certificateControls.count, 1, 'duplicate prompt was enqueued');
        const dialogs = [...document.querySelectorAll('[role="dialog"]')];
        const confirmation = dialogs.find(dialog => dialog.textContent.includes(wire.title));
        assert.ok(confirmation, 'certificate confirmation did not render over the tester');
        assert.ok(confirmation.textContent.includes(wire.message));
        assert.equal(confirmation.querySelector('input'), null, 'certificate consent became a credential input');
        const accept = confirmation.querySelector('button[type="submit"]');
        assert.equal(accept.textContent, wire.acceptLabel);
        const rect = accept.getBoundingClientRect();
        assert.equal(document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2)?.closest('button'), accept,
          'certificate confirmation is covered by the tester');
        assert.equal(document.activeElement.closest('[role="dialog"]'), confirmation, 'tester retained focus over certificate consent');
        if (Object.hasOwn(variant, 'secret')) {
          const cancel = [...confirmation.querySelectorAll('button')].find(button => button.textContent === 'Cancel');
          await React.act(async () => { cancel.click(); });
          assert.deepEqual(responses.at(-1), { leaseId: wire.sessionId, promptId: wire.promptId, value: '', cancelled: true });
        } else {
          await React.act(async () => { accept.click(); });
          assert.deepEqual(responses.at(-1), { leaseId: wire.sessionId, promptId: wire.promptId, value: 'accept', cancelled: false });
        }
        assert.equal(certificateControls.count, 0, 'answered certificate prompt remained pending');
      }
      for (const [variant, type] of [[{ secret: true }, 'password'], [{ secret: false }, 'text'], [{}, 'text']]) {
        await React.act(async () => { certificateControls.emit({ ...wire, ...variant, confirmation: false }); });
        assert.equal(document.querySelector('input')?.type, type, 'VPN prompt masking did not match the serialized secret flag');
        await React.act(async () => { certificateControls.emit({ type: 'tunnel.prompt-closed', promptId: wire.promptId }); });
        assert.equal(certificateControls.count, 0, 'backend cancellation did not close the prompt');
      }
    }
    async function runForcepointEditorTests() {
      const root = createRoot(document.getElementById('root'));
      await React.act(async () => { root.render(<ForcepointEditorHarness />); });
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      await runForcepointCertificateTests(root);
      await React.act(async () => { root.render(<ForcepointEditorHarness />); });
      for (const [left, right] of [['Host', 'Port'], ['ServerCertSha256Pin', 'Mtu']]) {
        const leftInput = document.getElementById('tunnel-' + left).getBoundingClientRect();
        const rightInput = document.getElementById('tunnel-' + right).getBoundingClientRect();
        const leftLabel = document.querySelector('label[for="tunnel-' + left + '"]').getBoundingClientRect();
        const rightLabel = document.querySelector('label[for="tunnel-' + right + '"]').getBoundingClientRect();
        if (innerWidth >= 768) {
          assert.ok(Math.abs(leftInput.top - rightInput.top) < 1, left + '/' + right + ' input tops differ');
          assert.ok(Math.abs(leftLabel.top - rightLabel.top) < 1, left + '/' + right + ' label tops differ');
          assert.ok(rightInput.left > leftInput.right, 'paired controls did not render in separate columns');
        } else {
          assert.ok(rightLabel.top > leftInput.bottom, 'narrow layout did not stack paired fields');
          assert.ok(Math.abs(leftInput.left - rightInput.left) < 1, 'stacked fields do not share their inset');
        }
      }
      assert.ok(document.body.textContent.includes('SSL VPN with username and password.'));
      assert.ok(document.body.textContent.includes('verify the gateway certificate'));
      const trigger = document.querySelector('[data-slot="collapsible-trigger"]');
      await React.act(async () => { trigger.click(); });
      assert.equal(trigger.getAttribute('aria-expanded'), 'false');
      assert.equal(document.getElementById('tunnel-Mtu'), null);
      await React.act(async () => { trigger.click(); });
      assert.equal(trigger.getAttribute('aria-expanded'), 'true');
      assert.ok(document.getElementById('tunnel-Mtu'));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    }
    runForcepointEditorTests();
  `,
    'forcepoint-editor.tsx',
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
  const css = (Array.isArray(output) ? output : [output])
    .flatMap((result) => result.output)
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { Label: LabelPrimitive, Collapsible: CollapsiblePrimitive, Dialog: DialogPrimitive, Slot } = require(${JSON.stringify(require.resolve('radix-ui'))});
    const { ChevronDown, XIcon } = require(${JSON.stringify(require.resolve('lucide-react'))});
    const { cva } = require(${JSON.stringify(require.resolve('class-variance-authority'))});
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const cn = (...inputs) => twMerge(clsx(inputs));
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css + '\n*{animation:none!important;transition:none!important}')};
    document.head.append(style);
    ${transformed.code}
    //# sourceURL=wormhole-forcepoint-editor.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-forcepoint-editor-'));
  const harnessPath = join(directory, 'editor.cjs');
  const artifactDirectory = process.env.WORMHOLE_TEST_ARTIFACT_DIR;
  if (artifactDirectory) mkdirSync(artifactDirectory, { recursive: true });
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow } = require('electron');
      const { writeFileSync } = require('node:fs');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.on('window-all-closed', () => {});
      app.whenReady().then(async () => {
        for (const [width, height] of [[1024,768],[800,800],[600,800]]) {
          const window = new BrowserWindow({ show: false, width, height, useContentSize: true,
            webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } });
          try {
            await window.loadURL('data:text/html,<html class="dark"><div id="root"></div></html>');
            window.webContents.debugger.attach('1.3');
            await window.webContents.debugger.sendCommand('Profiler.enable');
            await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
            await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
            const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
            const script = coverage.result.find(item => item.url === 'wormhole-forcepoint-editor.js');
            const parent = script?.functions.find(item => item.functionName === 'TunnelAdvanced');
            if (!parent) throw new Error('Missing modified TunnelAdvanced coverage.');
            const range = parent.ranges[0];
            const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
            const percent = 100 * ranges.filter(item => item.count > 0).length / ranges.length;
            if (percent < ${coverageThreshold}) throw new Error('TunnelAdvanced coverage below project threshold.');
            const handler = script.functions.find(item => item.functionName === 'dispatchTunnelPromptEvent');
            if (!handler) throw new Error('Missing production tunnel event handler coverage.');
            const handlerRange = handler.ranges[0];
            const handlerBlocks = script.functions.filter(item => item.ranges[0].startOffset >= handlerRange.startOffset && item.ranges[0].endOffset <= handlerRange.endOffset).flatMap(item => item.ranges);
            const handlerPercent = 100 * handlerBlocks.filter(item => item.count > 0).length / handlerBlocks.length;
            if (handlerPercent < ${coverageThreshold}) throw new Error('Tunnel prompt handler coverage below project threshold: ' + handlerPercent.toFixed(2));
            console.log(width + 'x' + height + ': paired labels and inputs aligned; TunnelAdvanced coverage ' + percent.toFixed(2) + '%');
            console.log(width + 'x' + height + ': Go certificate event shown over tester; prompt handler coverage ' + handlerPercent.toFixed(2) + '%');
            const target = ${JSON.stringify(artifactDirectory ?? '')};
            if (target) writeFileSync(require('node:path').join(target, 'forcepoint-editor-' + width + '.png'), (await window.webContents.capturePage()).toPNG());
          } finally { window.destroy(); }
        }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    if (stderr.trim()) process.stderr.write(stderr);
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
