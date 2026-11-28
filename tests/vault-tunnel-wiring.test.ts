import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');

test('Tunnel page routes vault actions by exact revision without calling legacy readers', async () => {
  const start = app.indexOf('function TunnelsPage('),
    source = app.slice(start);
  const snippets = [
    source.slice(
      source.indexOf('  function addTunnel('),
      source.indexOf('  function setTunnelEditorOpen('),
    ),
    source.slice(
      source.indexOf('  async function editTunnel('),
      source.indexOf('  function openTunnelTest('),
    ),
  ].join('\n');
  for (const mode of [
    'vault',
    'legacy',
    'missing',
    'error',
    'unavailable',
    'decline',
    'legacy-delete-failure',
  ]) {
    const calls: string[] = [],
      requests: unknown[] = [],
      errors: string[] = [];
    const api = {
      readTunnel: async (id: string) => {
        calls.push('read');
        return { id };
      },
      deleteTunnel: async () => {
        calls.push('delete');
        return { deleted: mode !== 'legacy-delete-failure' };
      },
    };
    const vault = mode === 'vault' || mode === 'missing' || mode === 'error';
    const callback = async (selection: unknown) => {
      requests.push(selection);
      if (mode === 'error') throw Error('Saved but refresh failed.');
    };
    const scope: any = {
      Error,
      window: {
        wormhole: mode === 'unavailable' ? undefined : api,
      },
      confirm: async () => mode !== 'decline',
      pendingTunnelEditRef: { current: null },
      dialogTriggerRef: { current: null },
      onVaultEdit: vault ? callback : undefined,
      onVaultDelete: vault ? callback : undefined,
      setActionError: (value: string) => errors.push(value),
      setEditorValue: () => calls.push('editor'),
      setEditorOpen: () => calls.push('open'),
      blankTunnelEditor: () => ({}),
      tunnelEditorFromDetails: (v: unknown) => v,
      summaryLoadAttemptRef: { current: 0 },
      onTunnelDeleted: () => calls.push('removed'),
    };
    runInNewContext(stripTypeScriptTypes(snippets), scope);
    const tunnel = {
      id: 'selected',
      name: 'Tunnel',
      rowVersion: mode === 'missing' ? undefined : '12',
    };
    const trigger = {};
    scope.addTunnel(trigger);
    await new Promise(setImmediate);
    await scope.editTunnel(tunnel, trigger);
    await scope.deleteTunnel(tunnel);
    if (vault) {
      assert.deepEqual(calls, []);
      assert.equal(requests[0], null);
      assert.equal(requests.length, mode === 'missing' ? 1 : 3);
      if (mode !== 'missing')
        for (const request of requests.slice(1))
          assert.equal(
            JSON.stringify(request),
            JSON.stringify({ id: 'selected', rowVersion: '12' }),
          );
    } else if (mode === 'legacy')
      assert.deepEqual(calls, ['editor', 'open', 'read', 'editor', 'open', 'delete', 'removed']);
    if (mode === 'missing') assert.ok(errors.some((e) => e.includes('Refresh the workspace')));
    if (mode === 'error') assert.ok(errors.includes('Saved but refresh failed.'));
    if (mode === 'legacy-delete-failure')
      assert.ok(errors.some((e) => e.includes('Could not delete')));
    if (mode === 'decline') assert.ok(!calls.includes('delete'));
    if (mode === 'unavailable') assert.ok(errors.some((e) => e.includes('unavailable')));
  }
  // A vault page uses the authenticated workspace snapshot instead of legacy summaries.
  const effect = source.slice(
    source.indexOf('  useEffect(() => {'),
    source.indexOf('  useEffect(() => {', source.indexOf('  useEffect(() => {') + 1),
  );
  assert.match(effect, /if \(onVaultEdit\) return;/);
  const bindings = app.slice(
    app.indexOf('<TunnelsPage'),
    app.indexOf('tunnels={tunnels}', app.indexOf('<TunnelsPage')),
  );
  assert.match(bindings, /onVaultEdit=\{\s*authState\?\.mode === 'vault'/);
  assert.match(bindings, /onVaultDelete=\{\s*authState\?\.mode === 'vault'/);
});

test('main tunnel entrypoint accepts only the trusted app document and forwards public selection', async () => {
  const begin = main.indexOf("  ipcMain.handle('vault:edit-tunnel'"),
    end = main.indexOf("  ipcMain.handle('vault:show-notes'", begin);
  let handler: any;
  let trusted = true,
    parent: any = { id: 'parent' },
    calls = 0;
  const scope = {
    ipcMain: { handle: (_name: string, value: any) => (handler = value) },
    isTrustedVaultSender: () => trusted,
    BrowserWindow: { fromWebContents: () => parent },
    vaultTunnelDialog: {
      open: async (owner: any, accepted: () => boolean, value: any) => {
        assert.equal(owner, parent);
        assert.equal(accepted(), true);
        calls++;
        return value;
      },
    },
  };
  runInNewContext(stripTypeScriptTypes(main.slice(begin, end)), scope);
  const event = { sender: {} };
  const selection = { id: 'public', rowVersion: '9' };
  assert.equal(await handler(event, selection), selection);
  assert.equal(calls, 1);
  await assert.rejects(handler(event));
  await assert.rejects(handler(event, selection, true));
  trusted = false;
  await assert.rejects(handler(event, selection));
  trusted = true;
  parent = null;
  await assert.rejects(handler(event, selection));
  assert.equal(calls, 1);
  for (const part of [
    main.slice(
      main.indexOf('async function lockApplication('),
      main.indexOf('function registerIpcHandlers('),
    ),
    main.slice(
      main.indexOf('function shutdownNativeResources()'),
      main.indexOf('function scheduleUnlockedBackgroundWork()'),
    ),
  ])
    assert.ok(part.includes('vaultTunnelDialog.cancel()'));
});

test('vault legacy-operation guard permits only the pre-database capability probe', async () => {
  const start = main.indexOf('async function runBackend<T>('),
    end = main.indexOf('// ---- update checks / downloads ----', start);
  const reached = Error('reached capability argument construction');
  let paths = 0;
  const scope: any = {
    backendTimeoutMs: 30000,
    vaultBackend: { isVaultWorkspace: true },
    wormholeDatabasePath: () => {
      paths++;
      throw reached;
    },
  };
  runInNewContext(stripTypeScriptTypes(main.slice(start, end)), scope);
  for (const operation of [
    'workspace',
    'tunnel-list',
    'tunnel-read',
    'tunnel-update',
    'tunnel-test',
    'migrate',
    'startup',
  ])
    await assert.rejects(scope.runBackend(operation), /not yet available/);
  assert.equal(paths, 0);
  await assert.rejects(scope.runBackend('tunnel-capabilities'), (error) => error === reached);
  assert.equal(paths, 1);
  await assert.rejects(
    scope.runBackend('tunnel-capabilities', undefined, 30000, { aborted: true }),
    /cancelled/,
  );
  assert.equal(paths, 1);
});

test('native profile picker offers only supported formats and never returns multiple selections', async () => {
  const begin = main.indexOf(
    '  pickImport: async (parent, format) => {',
    main.indexOf('const vaultTunnelDialog ='),
  );
  const end = main.indexOf('  capabilities:', begin);
  const source =
    main.slice(
      main.indexOf('function runCoordinatedFileDialog'),
      main.indexOf('function enqueueTunnelBrowserAuth'),
    ) +
    '\nglobalThis.pickImport = ' +
    main
      .slice(begin, end)
      .trim()
      .replace(/^pickImport: /, '')
      .replace(/,$/, '') +
    ';';
  const picked: any[] = [];
  let result = { canceled: false, filePaths: ['/native/selection'] };
  let pendingApproval = false;
  const owner = { id: 'protected-editor' };
  const scope: any = {
    mcpApprovalWindowCoordinator: {
      get hasPendingApprovals() {
        return pendingApproval;
      },
      runNativeDialog: (open: () => Promise<unknown>) => open(),
    },
    dialog: {
      showOpenDialog: async (parent: any, options: any) => {
        assert.equal(parent, owner);
        picked.push(options);
        return result;
      },
    },
  };
  runInNewContext(stripTypeScriptTypes(source), scope);
  for (const [format, extensions] of [
    ['openvpn', ['ovpn', 'conf']],
    ['watchguard', ['wgssl', 'zip']],
    ['azure', ['xml']],
    ['cisco', ['xml']],
  ]) {
    assert.equal(await scope.pickImport(owner, format), '/native/selection');
    const options = picked.at(-1);
    assert.equal(JSON.stringify(options.filters[0].extensions), JSON.stringify(extensions));
    assert.equal(
      JSON.stringify(options.properties),
      JSON.stringify(['openFile', 'dontAddToRecent']),
    );
  }
  pendingApproval = true;
  const count = picked.length;
  assert.equal(await scope.pickImport(owner, 'openvpn'), null);
  assert.equal(picked.length, count);
  pendingApproval = false;
  for (const value of [
    { canceled: true, filePaths: ['/native/selection'] },
    { canceled: false, filePaths: [] },
    { canceled: false, filePaths: ['first', 'second'] },
  ]) {
    result = value;
    assert.equal(await scope.pickImport(owner, 'openvpn'), null);
  }
});
