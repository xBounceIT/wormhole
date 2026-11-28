import { mainSyntax } from './fixtures/main-source.ts';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
import test from 'node:test';
test('actual native installation IPC accepts only the current main document and native picker path', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const registration = mainSyntax(source).program.body.find(
    (node: any) => node.type === 'FunctionDeclaration' && node.id?.name === 'registerIpcHandlers',
  ) as any;
  const loops = registration.body.body.filter((node: any) => {
    const right = node.right?.type === 'TSAsExpression' ? node.right.expression : node.right;
    return (
      node.type === 'ForOfStatement' &&
      node.left?.declarations?.[0]?.id?.name === 'action' &&
      right?.type === 'ArrayExpression' &&
      right.elements.map((item: any) => item.value).join(',') ===
        'read,install-folder,install-zip,cleanup'
    );
  });
  assert.equal(loops.length, 1, 'Expected exactly the native installation registration loop');
  const sample = source.slice(loops[0].start, loops[0].end);
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'vault-bitwarden-picker-ipc.js';
  let read: any,
    invokeCleanup: any,
    cleaning = false,
    invokeZip: any,
    archive = false;
  let invoke: any,
    trusted = true,
    present = true,
    destroyed = false,
    epoch = 1,
    workspace: string | undefined = 'workspace',
    selection: any = { canceled: false, filePaths: [resolve('extension')] };
  let during: (() => void) | undefined,
    calls = 0;
  const frame = {},
    parent = { isDestroyed: () => destroyed },
    event = { senderFrame: frame, sender: Object.assign(new EventEmitter(), { mainFrame: frame }) };
  runInNewContext(
    stripTypeScriptTypes(sample),
    {
      ipcMain: {
        handle: (name: string, fn: any) => {
          if (name === 'vault:bitwarden-read') read = fn;
          else if (name === 'vault:bitwarden-install-folder') invoke = fn;
          else if (name === 'vault:bitwarden-cleanup') invokeCleanup = fn;
          else invokeZip = fn;
        },
      },
      BrowserWindow: { fromWebContents: () => (present ? parent : null) },
      isTrustedVaultSender: () => trusted,
      authSession: {
        get authorizationEpoch() {
          return epoch;
        },
      },
      isAuthorizationEpochCurrent: (old: number) => old === epoch,
      showCoordinatedOpenDialog: async (owner: unknown, options: any) => {
        assert.equal(owner, parent);
        assert.equal(options.properties[0], archive ? 'openFile' : 'openDirectory');
        if (archive) assert.equal(options.filters[0].extensions[0], 'zip');
        during?.();
        return selection;
      },
      vaultBackend: {
        cleanupBitwardenInstallations: async (accepted: any, confirm: any) => {
          during?.();
          if (!accepted()) throw Error('expired');
          return confirm('bitwarden-cleanup', { vaultId: 'public' }, async () => 'cleaned');
        },
        get unlockedWorkspaceId() {
          return workspace;
        },
        bitwardenInstallationPlan: async (q: any, accepted: any) => {
          assert.equal(q.workspaceId, 'workspace');
          assert.equal(q.minimumRevision, '0');
          assert.ok(accepted());
          return { installation: null };
        },
        chooseBitwardenZip: async (pick: any, accepted: any, confirm: any) => {
          const path = await pick();
          if (!accepted()) throw Error('expired');
          if (path === null) return null;
          assert.equal(path, resolve('extension'));
          calls++;
          return confirm('bitwarden-install-zip', { vaultId: 'public' }, async () => 'installed');
        },
        chooseBitwardenFolder: async (pick: any, accepted: any, confirm: any) => {
          const path = await pick();
          if (!accepted()) throw Error('expired');
          if (path === null) return null;
          assert.equal(path, resolve('extension'));
          calls++;
          return confirm(
            'bitwarden-install-folder',
            { vaultId: 'public' },
            async () => 'installed',
          );
        },
      },
      vaultReauthenticationDialog: {
        open: async (owner: any, accepted: any, op: any, descriptor: any, submit: any) => {
          assert.equal(owner, parent);
          assert.ok(accepted());
          assert.equal(
            op,
            cleaning
              ? 'bitwarden-cleanup'
              : archive
                ? 'bitwarden-install-zip'
                : 'bitwarden-install-folder',
          );
          assert.equal(descriptor.vaultId, 'public');
          return submit();
        },
      },
    },
    { filename },
  );
  assert.equal((await read(event)).installation, null);
  workspace = undefined;
  await assert.rejects(read(event), /unavailable/);
  workspace = 'workspace';
  await assert.rejects(read(event, 'untrusted-workspace'), /unavailable/);
  assert.equal(await invoke(event), 'installed');
  await assert.rejects(invoke(event, '/renderer-path'), /unavailable/);
  trusted = false;
  await assert.rejects(invoke(event), /unavailable/);
  trusted = true;
  present = false;
  await assert.rejects(invoke(event), /unavailable/);
  present = true;
  destroyed = true;
  await assert.rejects(invoke(event), /unavailable/);
  destroyed = false;
  event.sender.mainFrame = {};
  await assert.rejects(invoke(event), /unavailable/);
  event.sender.mainFrame = frame;
  selection = { canceled: true, filePaths: [] };
  assert.equal(await invoke(event), null);
  selection = { canceled: false, filePaths: [] };
  await assert.rejects(invoke(event), /Invalid/);
  selection = { canceled: false, filePaths: [resolve('extension')] };
  during = () => {
    epoch++;
  };
  await assert.rejects(invoke(event), /expired/);
  assert.equal(calls, 1);
  during = () => event.sender.emit('did-start-navigation', {}, 'same-url', false, true);
  await assert.rejects(invoke(event), /expired/);
  during = () => event.sender.emit('render-process-gone');
  await assert.rejects(invoke(event), /expired/);
  during = () => event.sender.emit('destroyed');
  await assert.rejects(invoke(event), /expired/);
  during = () => {
    event.sender.emit('did-start-navigation', {}, 'child-url', false, false);
    event.sender.emit('did-start-navigation', {}, 'fragment', true, true);
  };
  assert.equal(await invoke(event), 'installed');
  assert.equal(event.sender.listenerCount('did-start-navigation'), 0);
  assert.equal(event.sender.listenerCount('render-process-gone'), 0);
  assert.equal(event.sender.listenerCount('destroyed'), 0);
  archive = true;
  during = undefined;
  assert.equal(await invokeZip(event), 'installed');
  await assert.rejects(invokeZip(event, '/renderer-path'), /unavailable/);
  during = () => event.sender.emit('did-start-navigation', {}, 'same-url', false, true);
  await assert.rejects(invokeZip(event), /expired/);
  cleaning = true;
  during = undefined;
  assert.equal(await invokeCleanup(event), 'cleaned');
  await assert.rejects(invokeCleanup(event, 'untrusted-id'), /unavailable/);
  during = () => event.sender.emit('did-start-navigation', {}, 'same-url', false, true);
  await assert.rejects(invokeCleanup(event), /expired/);
  assert.equal(event.sender.listenerCount('did-start-navigation'), 0);
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  const ranges = coverage.result
    .find((s) => s.url === filename)!
    .functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('Native installation IPC coverage ' + percent.toFixed(2) + '%');
  assert.ok(percent >= 80);
});
test('installation preload cannot forward a renderer-provided path', async () => {
  const source = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  for (const [method, channel] of [
    ['installVaultBitwardenFolder', 'vault:bitwarden-install-folder'],
    ['installVaultBitwardenZip', 'vault:bitwarden-install-zip'],
    ['readVaultBitwardenInstallation', 'vault:bitwarden-read'],
    ['cleanupVaultBitwardenInstallations', 'vault:bitwarden-cleanup'],
  ]) {
    const start = source.indexOf('  ' + method + ':');
    const end = source.indexOf('\n', start);
    assert.ok(start > 0 && end > start);
    const api = runInNewContext('({' + source.slice(start, end) + '})', {
      ipcRenderer: {
        invoke: (...args: unknown[]) => {
          assert.deepEqual(args, [channel]);
          return Promise.resolve(null);
        },
      },
    });
    assert.equal(await api[method]('/untrusted'), null);
  }
});
