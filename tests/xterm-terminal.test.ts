import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import rendererConfig from '../vite.config.ts';

const require = createRequire(import.meta.url);

test('xterm SSH presentation works in Chromium with WebGL and software fallback', async (context) => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const component = app.slice(
    app.indexOf('function SshXtermSurface('),
    app.indexOf('function SshTerminalSurface('),
  );
  assert.ok(component.length > 0);
  const result = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': '"development"' },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    plugins: [
      ...rendererConfig.plugins,
      {
        name: 'terminal-component-harness',
        resolveId(id) {
          if (id === 'virtual:ssh-surface') return '\0ssh-surface';
        },
        load(id) {
          if (id !== '\0ssh-surface') return;
          return `import { useRef, useEffect, useState } from 'react';
        import ${JSON.stringify(fileURLToPath(new URL('../src/index.css', import.meta.url)).replaceAll('\\', '/'))};
        import { TerminalLinkDialog } from ${JSON.stringify(fileURLToPath(new URL('../src/components/TerminalLinkDialog.tsx', import.meta.url)).replaceAll('\\', '/'))};
        import { sshTerminal } from ${JSON.stringify(fileURLToPath(new URL('../src/xterm-terminal.ts', import.meta.url)).replaceAll('\\', '/'))};
        const copyTextToClipboard = async text => window.copyTerminalTest(text);
        const SshTerminalConnectionState = ({session}) => <div>state {session.status}</div>;
        export ${component}`;
        },
        transform(code, id) {
          if (id === '\0ssh-surface')
            return import('vite').then(({ transformWithOxc }) =>
              transformWithOxc(code, 'ssh-surface.tsx'),
            );
        },
      },
    ],
    build: {
      write: false,
      minify: false,
      rolldownOptions: {
        input: fileURLToPath(new URL('./fixtures/xterm-terminal.ts', import.meta.url)),
        external: ['node:assert/strict'],
        output: { format: 'iife', globals: { 'node:assert/strict': 'terminalAssert' } },
      },
    },
  });
  const assets = (Array.isArray(result) ? result : [result]).flatMap((output) => output.output);
  const js = assets
    .filter((asset) => asset.type === 'chunk')
    .map((asset) => asset.code)
    .join('\n');
  const css = assets
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => String(asset.source))
    .join('\n');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-xterm-'));
  const harness = join(directory, 'test.cjs');
  const renderer = `(async () => { const terminalAssert = require('node:assert/strict');
    const style = document.createElement('style'); style.textContent = ${JSON.stringify(css)}; document.head.append(style);
    ${js}
    const { webFrame } = require('electron');
    // Hold atlas warmups until the next DPR. Disposing an xterm atlas does not
    // cancel its queued work, so callbacks from both scales can overlap.
    const originalTimer = globalThis.setTimeout;
    const pendingWarmups = [];
    let replayWarmups = false, replayedWarmups = 0;
    globalThis.setTimeout = (callback, delay, ...args) => {
      if (typeof callback === 'function' && callback.toString().includes('_createDeadline')) {
        if (replayWarmups) {
          const previous = pendingWarmups.splice(0);
          replayedWarmups += previous.length;
          for (const pending of previous) pending();
        }
        pendingWarmups.push(callback);
        return -1;
      }
      return originalTimer(callback, delay, ...args);
    };
    try {
      for (const zoom of [1, 2]) {
        replayWarmups = zoom === 2;
        webFrame.setZoomFactor(zoom);
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        await window.runTerminalFontTests();
      }
      terminalAssert.ok(replayedWarmups > 0, 'delayed atlas warmups were not exercised');
    } finally {
      globalThis.setTimeout = originalTimer;
      for (const pending of pendingWarmups.splice(0)) pending();
      webFrame.setZoomFactor(1);
    }
    await window.runTerminalTests().catch(error => { console.error(error.stack); throw error; }); })();
    //# sourceURL=wormhole-xterm.js`;
  writeFileSync(
    harness,
    `
    const { app, BrowserWindow } = require('electron');
    // Exercise real WebGL through SwiftShader even on GPU-less CI runners.
    // These switches apply only to this trusted, local test harness.
    app.commandLine.appendSwitch('use-gl', 'angle');
    app.commandLine.appendSwitch('use-angle', 'swiftshader');
    app.commandLine.appendSwitch('enable-unsafe-swiftshader');
    app.setPath('userData', ${JSON.stringify(directory)}); app.setPath('sessionData', ${JSON.stringify(directory)});
    app.whenReady().then(async () => {
      const window = new BrowserWindow({show:false,width:1000,height:700,webPreferences:{nodeIntegration:true,contextIsolation:false,backgroundThrottling:false,offscreen:true}});
      window.webContents.on('console-message', event => console.log(event.message));
      try {
        await window.loadURL('data:text/html,<body style="margin:0"></body>');
        window.webContents.debugger.attach('1.3');
        await window.webContents.debugger.sendCommand('Profiler.enable');
        await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', {callCount:true,detailed:true});
        await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
        const script = coverage.result.find(item => item.url === 'wormhole-xterm.js');
        const source = ${JSON.stringify(renderer)};
        const moduleStart = source.indexOf('function sshTerminal('), moduleEnd = source.indexOf('async function run()', moduleStart);
        const names = ['sshTerminal', 'setSshTerminalTheme', 'retainSshTerminals', 'XtermSession', 'setTheme', 'configure', 'attach', 'detach', 'fit', 'focus', 'receive', 'acknowledge', 'drain', 'copy', 'paste', 'key', 'dispose', 'SshXtermSurface'];
        let covered = 0, total = 0;
        for (const name of names) {
          const parent = script.functions.find(item => item.functionName === name && item.ranges[0].startOffset >= moduleStart && item.ranges[0].endOffset <= moduleEnd);
          if (!parent) throw new Error('Missing coverage: ' + name);
          const range = parent.ranges[0];
          const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
          covered += ranges.filter(item => item.count > 0).length; total += ranges.length;
        }
        console.log('XtermSession V8 block coverage: ' + covered + '/' + total + ' (' + (100*covered/total).toFixed(2) + '%)');
        if (100*covered/total < 80) throw new Error('XtermSession coverage below 80%');
        for (const name of ['webglContext', 'assertPainted', 'assertWebglFonts', 'TerminalLinkDialog', 'useNativeSurfaceOverlay', 'useSshTerminalTheme', 'SshThemeSettings', 'SshThemePreview']) {
          const parent = script.functions.find(item => item.functionName === name);
          if (!parent) throw new Error('Missing coverage: ' + name);
          const range = parent.ranges[0];
          const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
          const hits = ranges.filter(item => item.count > 0).length;
          console.log(name + ' V8 block coverage: ' + hits + '/' + ranges.length + ' (' + (100*hits/ranges.length).toFixed(2) + '%)');
          if (100*hits/ranges.length < 80) throw new Error(name + ' coverage below 80%');
        }
      } finally {window.destroy()}
      app.quit();
    }).catch(error => { console.error(error); app.exit(1); });
  `,
  );
  const { ELECTRON_RUN_AS_NODE: _ignored, ...env } = process.env;
  const electron = require('electron') as string;
  const needsDisplay = process.platform === 'linux' && !env.DISPLAY;
  try {
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 60_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) context.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
