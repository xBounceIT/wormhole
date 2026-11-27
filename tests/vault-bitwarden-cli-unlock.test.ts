import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { setImmediate as tick } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import {
  maxBitwardenCLIPassword,
  parseVaultBitwardenCLIUnlockBinding,
  parseVaultBitwardenCLIUnlockContext,
  parseVaultBitwardenCLIPassword,
  parseVaultBitwardenCLISession,
} from '../electron/vault-bitwarden-cli-unlock.ts';
import { VaultBitwardenCLIUnlockController } from '../electron/vault-bitwarden-cli-unlock-controller.ts';
import { runVaultBitwardenExchange } from '../electron/vault-ssh-bitwarden.ts';
import { sealBitwardenCLIPassword } from '../src/vault-bitwarden-cli-unlock-sender.ts';

const base64 = (size: number, byte = 1) => Buffer.alloc(size, byte).toString('base64');
const binding = {
  workspaceId: '11111111-1111-4111-8111-111111111111',
  requestId: '22222222-2222-4222-8222-222222222222',
  configuration: 'af'.repeat(32),
  vaultKey: base64(32),
  expiresAt: Date.now() + 240_000,
};
const publicKey = base64(32, 2);
const password = {
  formatVersion: 1 as const,
  suiteId: 2 as const,
  enc: base64(32),
  ciphertext: base64(17),
};
const session = { ...password, ciphertext: base64(60) };

test('unlock contracts reject substitutions, malformed and oversized envelopes', async () => {
  const context = { binding, publicKey };
  assert.deepEqual(parseVaultBitwardenCLIUnlockContext(context), context);
  for (const invalid of [
    null,
    { ...context, extra: true },
    { ...context, publicKey: 32 },
    { ...context, publicKey: 'x' },
    { ...context, publicKey: binding.vaultKey },
  ])
    assert.equal(parseVaultBitwardenCLIUnlockContext(invalid), undefined);
  for (const invalid of [
    null,
    { ...binding, extra: true },
    { ...binding, workspaceId: '?' },
    { ...binding, requestId: '?' },
    { ...binding, configuration: 0 },
    { ...binding, configuration: binding.configuration.toUpperCase() },
    { ...binding, vaultKey: true },
    { ...binding, vaultKey: 'x' },
    { ...binding, expiresAt: '1' },
    { ...binding, expiresAt: 1.5 },
    { ...binding, expiresAt: 0 },
  ])
    assert.equal(parseVaultBitwardenCLIUnlockBinding(invalid), undefined);
  for (const invalid of [
    null,
    { ...password, extra: true },
    { ...password, formatVersion: 2 },
    { ...password, suiteId: 1 },
    { ...password, enc: 1 },
    { ...password, enc: 'x' },
    { ...password, ciphertext: 1 },
    { ...password, ciphertext: 'AAA' },
    { ...password, ciphertext: base64(16) },
    { ...password, ciphertext: base64(90_000) },
    { ...password, ciphertext: base64(17).replace(/^./, '-') },
  ]) {
    assert.equal(parseVaultBitwardenCLIPassword(invalid), undefined);
    assert.equal(parseVaultBitwardenCLISession(invalid), undefined);
  }
  assert.deepEqual(parseVaultBitwardenCLIPassword(password), password);
  assert.deepEqual(parseVaultBitwardenCLISession(session), session);
  for (const input of [
    new Uint8Array(0),
    new Uint8Array([1, 0]),
    new Uint8Array([10]),
    new Uint8Array([13]),
    new Uint8Array(maxBitwardenCLIPassword + 1),
  ]) {
    await assert.rejects(sealBitwardenCLIPassword(context, input, new AbortController().signal));
    assert.ok(input.every((v) => !v));
  }
  const aborted = new Uint8Array([97]);
  await assert.rejects(sealBitwardenCLIPassword(context, aborted, AbortSignal.abort()));
  assert.equal(aborted[0], 0);
});

test('controller starts one exchange and commits only while its owner is authorized', async () => {
  for (const mode of ['success', 'bad-password', 'prompt', 'lock', 'owner', 'commit-rejected']) {
    const abort = new AbortController();
    let accepted = true;
    let commit = 0;
    let cancel = 0;
    let finish: (() => void) | undefined;
    const controller = new VaultBitwardenCLIUnlockController({
      executable: () => 'wormhole',
      databasePath: () => 'workspace.db',
      host: {
        beginBitwardenCLIUnlock: async (current) => {
          assert.equal(current(), true);
          return {
            binding,
            commit: async (value) => {
              assert.deepEqual(value, session);
              commit++;
              if (mode === 'commit-rejected') throw Error('stale');
            },
            cancel: async () => {
              cancel++;
            },
          };
        },
      },
      exchange: async (request) => {
        assert.equal(request.mode, 'unlock');
        assert.equal(request.otherRecipient, binding.vaultKey);
        assert.deepEqual(await request.prepare(publicKey, request.signal), { binding, password });
        if (mode === 'lock' || mode === 'owner')
          await new Promise<void>((resolve) => {
            finish = resolve;
          });
        return request.parse(session)!;
      },
    });
    const request = {
      accepted: () => accepted,
      signal: abort.signal,
      prompt: async (context: unknown) => {
        assert.deepEqual(context, { binding, publicKey });
        if (mode === 'prompt') throw Error('cancelled');
        return mode === 'bad-password' ? {} : password;
      },
    };
    const result = controller.unlock(request);
    const observed = mode === 'success' ? result : assert.rejects(result);
    await assert.rejects(controller.unlock(request));
    if (mode === 'lock' || mode === 'owner') {
      await tick();
      assert.ok(finish);
      let stopped = false;
      if (mode === 'owner') {
        accepted = false;
        abort.abort();
      }
      const stopping = controller.stop().then(() => {
        stopped = true;
      });
      await tick();
      assert.equal(stopped, false);
      finish();
      await stopping;
    }
    const value = await observed;
    if (mode === 'success') assert.deepEqual(value, { unlocked: true });
    assert.equal(commit, ['success', 'commit-rejected'].includes(mode) ? 1 : 0, mode);
    assert.equal(cancel, mode === 'success' ? 0 : 1, mode);
  }
});

test(
  'native relay confirms accepted worker exit and cancels before accepting pending input',
  { timeout: 10000 },
  async () => {
    for (const mode of ['success', 'lock', 'extra', 'early-close']) {
      const abort = new AbortController();
      let child: ReturnType<typeof spawn> | undefined;
      const result = runVaultBitwardenExchange({
        executable: process.execPath,
        databasePath: 'workspace.db',
        signal: abort.signal,
        mode: 'unlock',
        otherRecipient: binding.vaultKey,
        start: (exe, args) => {
          assert.deepEqual(args, [
            '--operation',
            'serve',
            '--sealed-bitwarden-unlock',
            '--database',
            'workspace.db',
          ]);
          const program = `
            process.stdout.write(${JSON.stringify(JSON.stringify({ publicKey }) + '\n')});
            if (${mode === 'early-close'}) setTimeout(() => process.exit(2), 25);
            else process.stdin.on('data', b => {
              if (JSON.parse(b).password.ciphertext !== ${JSON.stringify(password.ciphertext)}) process.exit(3);
              if (${mode === 'lock'}) { process.stderr.write('processing'); return; }
              process.stdout.write(${JSON.stringify(JSON.stringify(session) + '\n' + (mode === 'extra' ? '{}\n' : ''))}, () => process.exit(0));
            });
            process.stdin.on('end', () => process.exit(4));
         `;
          const launched = spawn(exe, ['-e', program], { stdio: 'pipe', windowsHide: true });
          child = launched;
          if (mode === 'lock') launched.stderr.once('data', () => abort.abort());
          return launched;
        },
        prepare: async (recipient, signal) => {
          assert.equal(recipient, publicKey);
          if (mode === 'early-close')
            await new Promise<void>((resolve) =>
              signal.addEventListener('abort', () => resolve(), { once: true }),
            );
          return { binding, password };
        },
        parse: parseVaultBitwardenCLISession,
      });
      if (mode === 'success') assert.deepEqual(await result, session);
      else await assert.rejects(result, /could not be unlocked/);
      assert.notEqual(child?.exitCode, null, mode);
    }
  },
);

async function browserEnvelope(
  directory: string,
  context: NonNullable<ReturnType<typeof parseVaultBitwardenCLIUnlockContext>>,
) {
  await build({
    configFile: false,
    logLevel: 'silent',
    base: './',
    publicDir: false,
    build: {
      outDir: join(directory, 'browser'),
      minify: false,
      rollupOptions: {
        input: fileURLToPath(new URL('../vault-bitwarden-cli-unlock.html', import.meta.url)),
      },
    },
  });
  const preload = stripTypeScriptTypes(
    await readFile(
      new URL('../electron/vault-bitwarden-cli-unlock-preload.cts', import.meta.url),
      'utf8',
    ),
  ).replace(
    "import { contextBridge, ipcRenderer } from 'electron';",
    "const { contextBridge, ipcRenderer } = require('electron');",
  );
  await writeFile(join(directory, 'protected-preload.cjs'), preload);
  const harness = join(directory, 'electron.cjs');
  const helpers = `
    const input = document.querySelector('input'), form = input.form;
    const submit = form.querySelector('button[type="submit"]'), status = form.querySelector('[role="status"]');
    const wait = async check => {
      for (let n = 0; n < 100 && !check(); n++) await new Promise(r => setTimeout(r, 10));
      if (!check()) throw Error('Password document did not respond');
    };
    const send = value => {
      input.value = value;
      form.dispatchEvent(new Event('submit', {cancelable: true}));
      if (input.value) throw Error('Password retained in DOM');
    };
  `;
  await writeFile(
    harness,
    `
    const {app, BrowserWindow, ipcMain} = require('electron');
    const assert = require('node:assert/strict');
    const {join} = require('node:path');
    app.setPath('userData', __dirname);
    app.setPath('sessionData', __dirname);
    app.disableHardwareAcceleration();
    const mark = message => process.stderr.write(message + '\\n');
    let context = ${JSON.stringify(context)}, submissions = 0, cancellations = 0, envelope;
    ipcMain.handle('vault-bitwarden-cli-unlock:context', () => context);
    ipcMain.handle('vault-bitwarden-cli-unlock:cancel', () => { cancellations++; });
    ipcMain.handle('vault-bitwarden-cli-unlock:submit', (_, value) => {
      if (++submissions === 1) return false;
      envelope = value;
      return true;
    });
    app.whenReady().then(async () => {
      mark('Electron ready');
      const window = new BrowserWindow({show:false, webPreferences:{
        preload:join(__dirname,'protected-preload.cjs'), sandbox:true,
        contextIsolation:true, nodeIntegration:false, offscreen:true, backgroundThrottling:false,
      }});
      window.webContents.on('preload-error', () => mark('Password preload failed'));
      window.webContents.on('render-process-gone', () => mark('Password renderer exited'));
      try {
        await window.loadURL('about:blank');
        mark('Initial document loaded');
        const debug = window.webContents.debugger;
        debug.attach('1.3');
        await debug.sendCommand('Profiler.enable');
        await debug.sendCommand('Profiler.startPreciseCoverage', {callCount:true,detailed:true});
        const load = () => window.loadFile(join(__dirname, 'browser', 'vault-bitwarden-cli-unlock.html'));
        const js = code => window.webContents.executeJavaScript('(async () => {' + ${JSON.stringify(helpers)} + code + '})()');
        await load();
        mark('Password document loaded');
        await js(${JSON.stringify(`
          if (typeof require !== 'undefined' || typeof wormhole !== 'undefined') throw Error('Unexpected bridge');
          await wait(() => !input.disabled);
          send('');
          send('é'.repeat(2049));
          if (!status.textContent.includes('4096')) throw Error('Size check unavailable');
          send('retry fixture');
          await wait(() => status.textContent.includes('could not be submitted'));
          if (input.disabled) throw Error('Retry unavailable');
          send('  synthetic rénewal 🔒  ');
        `)});
        for (let n = 0; n < 100 && !envelope; n++) await new Promise(r => setTimeout(r, 10));
        assert.equal(submissions, 2);
        assert.ok(envelope);
        mark('Password envelope submitted');
        await load();
        await js(${JSON.stringify(`
          await wait(() => !input.disabled);
          input.value = 'cancel fixture';
          form.querySelector('button[type="button"]').click();
          if (input.value || !input.disabled) throw Error('Cancel did not clear');
        `)});
        assert.equal(cancellations, 1);
        mark('Cancellation verified');
        await load();
        await js(${JSON.stringify(`
          await wait(() => !input.disabled);
          send('departure fixture');
          window.dispatchEvent(new Event('pagehide'));
          if (input.value || !submit.disabled) throw Error('Departure did not clear');
        `)});
        context = null;
        await load();
        await js(${JSON.stringify(`
          await wait(() => status.textContent.includes('unavailable'));
          if (!input.disabled) throw Error('Missing context enabled input');
        `)});
        assert.equal(submissions, 2);
        const coverage = await debug.sendCommand('Profiler.takePreciseCoverage');
        const measured = coverage.result.flatMap(s => s.functions)
          .filter(f => f.functionName === 'mountVaultBitwardenCLIUnlock');
        assert.ok(measured.length);
        const combined = new Map();
        for (const fn of measured) for (const r of fn.ranges) {
          const key = r.startOffset + ':' + r.endOffset;
          combined.set(key, combined.get(key) || r.count > 0);
        }
        assert.ok(100 * [...combined.values()].filter(Boolean).length / combined.size >= ${coverageThreshold});
        console.log(JSON.stringify(envelope));
      } finally {
        window.destroy();
      }
      app.quit();
    }).catch(error => { console.error(error); app.exit(1); });
  `,
  );
  const executable = createRequire(import.meta.url)('electron') as string;
  const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
  const headless = process.platform === 'linux' && !env.DISPLAY;
  const { stdout } = await promisify(execFile)(
    headless ? 'xvfb-run' : executable,
    headless ? ['--auto-servernum', executable, '--no-sandbox', harness] : [harness],
    { env, timeout: 25_000, windowsHide: true },
  );
  const result = parseVaultBitwardenCLIPassword(JSON.parse(stdout));
  assert.ok(result);
  return result;
}

test(
  'sandboxed password document interoperates with the Go vault and native CLI fixture',
  { timeout: 120000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-bitwarden-cli-unlock-'));
    try {
      const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
      const fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
      await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
        cwd,
        windowsHide: true,
        timeout: 70000,
      });
      const worker = spawn(
        fixture,
        ['-test.run=^TestVaultBitwardenCLIUnlockSenderInteropFixture$', '-test.timeout=45s'],
        {
          cwd,
          windowsHide: true,
          env: { ...process.env, WORMHOLE_TEST_BITWARDEN_UNLOCK_INTEROP: '1' },
        },
      );
      const exit = new Promise<number | null>((resolve, reject) => {
        worker.once('close', resolve);
        worker.once('error', reject);
      });
      void exit.catch(() => {});
      worker.stderr.resume();
      const reader = createInterface({ input: worker.stdout });
      const lines = reader[Symbol.asyncIterator]();
      const next = async () => {
        const line = await lines.next();
        assert.equal(line.done, false);
        return JSON.parse(line.value as string) as Record<string, unknown>;
      };
      try {
        const current = await next();
        const recipient = await next();
        const context = parseVaultBitwardenCLIUnlockContext({ binding: current, ...recipient });
        assert.ok(context);
        const input = new TextEncoder().encode('  synthetic rénewal 🔒  ');
        const sample = await sealBitwardenCLIPassword(context, input, new AbortController().signal);
        assert.ok(input.every((v) => v === 0));
        const password = await browserEnvelope(directory, context);
        assert.notEqual(password.enc, sample.enc);
        worker.stdin.write(JSON.stringify({ binding: current, password }) + '\n');
        const session = await next();
        assert.ok(parseVaultBitwardenCLISession(session));
        assert.doesNotMatch(JSON.stringify(session), /fixture-cli-interoperable/);
        assert.deepEqual(await next(), { unlocked: true });
        assert.equal(await exit, 0);
      } finally {
        reader.close();
        worker.stdin.destroy();
        if (worker.exitCode === null) worker.kill();
        await exit;
      }
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
    }
  },
);
