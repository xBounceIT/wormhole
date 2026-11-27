import { prepareVaultCredentialSelections } from '../electron/vault-credential-selection.ts';
import { transformWithOxc } from 'vite';
import {
  connectionInlinePasswordAction,
  effectiveSshAutoSudoMode,
} from '../src/credential-state.ts';
import { connectionProtocolSupportsTunnel } from '../src/quick-connect-state.ts';
import {
  connectionEditRequiresReconnect,
  connectionEditCanRestartSession,
} from '../src/connection-edit-state.ts';
import { connectionInput, connectionNodeId } from './fixtures/vault-connection.ts';
import { consumeVaultConnectionInput } from '../electron/vault-connection.ts';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { Session } from 'node:inspector/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { preferences } from './fixtures/vault-preferences.ts';
import { canonicalizeConnectionTreeNodeIds } from '../src/tree-shortcuts.ts';
import { findParentFolderId } from '../src/tree-parent.ts';
import { parseVaultFolder } from '../electron/vault-folder.ts';
import { tunnelModeFor, tunnelValueFor } from '../src/tunnel-state.ts';
import { vaultDeleteSelection } from '../src/vault-delete-selection.ts';
import { ipcRegistration } from './fixtures/main-source.ts';

const renderer = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
function cut(source: string, start: string, end: string) {
  const first = source.indexOf(start),
    last = source.indexOf(end, first);
  assert.ok(first >= 0 && last > first, start);
  return source.slice(first, last);
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
async function measure(t: any, filename: string) {
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE)
    return async () => {};
  const profiler = new Session();
  profiler.connect();
  t.after(() => profiler.disconnect());
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  return async () => {
    const result = await profiler.post('Profiler.takePreciseCoverage');
    const blocks = new Map<string, number>();
    for (const script of result.result.filter((s) => s.url === filename))
      for (const fn of script.functions)
        for (const r of fn.ranges) {
          const key = `${r.startOffset}:${r.endOffset}`;
          blocks.set(key, (blocks.get(key) ?? 0) + r.count);
        }
    assert.ok(blocks.size);
    const percent = (100 * [...blocks.values()].filter((n) => n > 0).length) / blocks.size;
    t.diagnostic(`${filename}: ${percent.toFixed(2)}% V8 blocks`);
    assert.ok(percent >= coverageThreshold);
  };
}
const workspace = {
  tree: [],
  credentials: [],
  credentialOptions: { ssh: [], rdp: [], vnc: [] },
  tunnels: [],
};
const native = {
  auth: { mode: 'vault', configured: true },
  workspace,
  settings: preferences(),
  themeMigration: { handled: false },
};
const descriptor = { vaultId: '11111111-1111-4111-8111-111111111111', slots: [] };

test('actual main registration binds both recovery prompts to native isolation and current parent trust', async (t) => {
  const filename = 'wormhole-vault-resume-main.js',
    verify = await measure(t, filename);
  const source = stripTypeScriptTypes(
    cut(main, '  const vaultResumeOptions = {', "  ipcMain.handle('vault:create'"),
  );
  let migration: any,
    osMigration: any,
    upgrade: any,
    rotation: any,
    parent: any = {},
    remembered = 0,
    activated = 0,
    retired = 0;
  const host = {},
    prompt = {};
  const context: any = {
    ipcMain: {},
    vaultUpgradeSetupDialog: {},
    registerVaultUpgradeIpc: (options: any) => {
      upgrade = options;
    },
    registerVaultOSMigrationIpc: (options: any) => {
      osMigration = options;
    },
    vaultProtectionOptions: { fatal: () => {} },
    vaultBackend: host,
    vaultReauthenticationDialog: prompt,
    BrowserWindow: { fromWebContents: () => parent },
    trusted: true,
    isQuitting: false,
    authLockRequested: false,
    isTrustedVaultSender: () => context.trusted,
    vaultMigrationBoot: {},
    lockApplication: async () => {
      retired++;
    },
    rememberAuthState: () => {
      remembered++;
    },
    vaultAuthState: () => ({ mode: 'vault' }),
    authSession: {
      markUnlocked: () => {
        assert.equal(remembered, 1);
        activated++;
      },
    },
    registerVaultMigrationIpc: (options: any) => {
      migration = options;
    },
    registerVaultRootRotationIpc: (options: any) => {
      rotation = options;
    },
  };
  runInNewContext(source, context, { filename });
  assert.equal(rotation, migration);
  assert.equal(rotation.host, host);
  assert.equal(rotation.dialog, prompt);
  assert.equal(osMigration.host, host);
  assert.equal(osMigration.activate, rotation.activate);
  assert.equal(osMigration.quiesced, rotation.quiesced);
  assert.equal(osMigration.trusted, rotation.trusted);
  assert.equal(osMigration.fatal, context.vaultProtectionOptions.fatal);
  assert.equal(upgrade.dialog, context.vaultUpgradeSetupDialog);
  context.authSession.holdLock = () => 'held';
  assert.equal(upgrade.hold(), 'held');
  const exits: number[] = [];
  context.process = { argv: ['exe', 'app'] };
  context.app = {
    relaunch: (options: any) => assert.deepEqual(Array.from(options.args), ['app']),
    exit: (code: number) => exits.push(code),
  };
  context.dialog = { showErrorBox: () => {} };
  upgrade.restart();
  upgrade.fatal();
  assert.deepEqual(exits, [0, 1]);
  assert.equal(rotation.parent({ sender: {} }), parent);
  parent = null;
  assert.equal(rotation.parent({ sender: {} }), undefined);
  assert.equal(rotation.trusted({}), true);
  for (const field of ['trusted', 'isQuitting', 'authLockRequested']) {
    context[field] = field !== 'trusted';
    assert.equal(rotation.trusted({}), false);
    context[field] = field === 'trusted';
  }
  assert.equal(rotation.quiesced(), false);
  context.vaultMigrationBoot.migrationSessionData = 'native-isolated';
  assert.equal(rotation.quiesced(), true);
  rotation.activate();
  assert.equal(activated, 1);
  await rotation.retire();
  assert.equal(retired, 1);
  await verify();
});

test('actual connection submit uses the native bridge and ignores stale dialogs and duplicate submits', async () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = stripTypeScriptTypes(
    cut(app, 'function autoSudoModeFor(', 'function matchesMcpOpenConnectionApproval(') +
      cut(app, 'function credentialSettingsFor(', 'function backendErrorMessage(') +
      cut(app, '  async function submitNewConnection(', '  async function refreshSavedFolder()') +
      ';submitNewConnection;',
  );
  for (const edit of [false, true])
    for (const scenario of [
      'native',
      'legacy',
      'reopened',
      'reopened-error',
      'error',
      'raw-error',
      'refresh-error',
      'double',
      'pending',
      'busy',
      'not-ready',
      'invalid-credential',
      'invalid-port',
      'no-api',
      'not-updated',
      'reconnect',
    ]) {
      let calls = 0,
        closed = false,
        error = '',
        selected = '',
        release!: () => void,
        request: any;
      const metadata = connectionInput().metadata;
      const form = {
        name: 'Edited connection',
        host: 'host.example',
        port: '22',
        protocol: 'ssh',
        folder: '',
        username: 'alice',
        inlinePassword: '',
        removeInlinePassword: false,
        notes: '',
        useSavedCredentials: false,
        credential: 'none',
        sshAutoSudo: 'inherit',
        tunnel: 'inherit',
        httpIgnoreCertErrors: false,
        serial: { baudRate: 115200, dataBits: 8, stopBits: 1, parity: 0, flowControl: 0 },
        rdp: {},
      };
      const env: any = {
        Error,
        TextEncoder,
        Set,
        connectionInlinePasswordAction,
        effectiveSshAutoSudoMode,
        connectionProtocolSupportsTunnel,
        connectionEditRequiresReconnect,
        connectionEditCanRestartSession,
        tunnelValueFor,
        editorBusy: scenario === 'busy',
        connectionNotesReady: scenario !== 'not-ready',
        connectionSavePending: { current: scenario === 'pending' },
        connectionEditorGeneration: { current: 1 },
        connectionEditorCredentialSelectionComplete: scenario !== 'invalid-credential',
        connectionAuthenticationSelectionError: 'credential missing',
        newConnectionForm: form,
        editingConnectionId: edit ? connectionNodeId : null,
        editingConnectionVersion: { current: '7' },
        nativeSavedConnection: scenario !== 'legacy',
        tree: [
          {
            ...metadata,
            id: connectionNodeId,
            kind: 'connection',
            rowVersion: '8',
            hasInlineCredential: true,
          },
        ],
        canConfigureConnectionSshAutoSudo: true,
        nativeConnectionPassword: { current: { value: 'typed-password' } },
        nativeConnectionNotes: { current: { value: 'typed-notes' } },
        removeNativeNotes: false,
        clearSecretInput: (input: any) => {
          if (input) input.value = '';
        },
        initialConnectionEditForm: {
          current: { ...form, host: scenario === 'reconnect' ? 'old.example' : form.host },
        },
        sessionsRef: { current: [] },
        setEditorBusy: () => {},
        setEditorError: (value: string) => {
          error = value;
        },
        setTreeMoveError: () => {},
        setSessions: (fn: any) => fn([]),
        setSelectedNodeId: (value: string) => {
          selected = value;
        },
        setExpanded: (fn: any) => fn(new Set()),
        setEditingConnectionId: () => {},
        setNewConnectionForm: (fn: any) => {
          env.newConnectionForm = fn(env.newConnectionForm);
        },
        setNewConnectionOpen: (value: boolean) => {
          closed = !value;
        },
        refreshWorkspace: async () => {
          if (scenario === 'refresh-error') throw Error('refresh failed');
        },
      };
      if (scenario === 'invalid-port') form.port = '70000';
      const save = async (route: string, input: any) => {
        assert.equal(route, scenario === 'legacy' ? 'legacy' : 'native');
        calls++;
        request = input;
        if (route === 'native') {
          const owned = consumeVaultConnectionInput(input);
          assert.equal(new TextDecoder().decode(owned.password), 'typed-password');
          assert.equal(new TextDecoder().decode(owned.notes), 'typed-notes');
          owned.password.fill(0);
          owned.notes.fill(0);
        }
        if (scenario.startsWith('reopened')) env.connectionEditorGeneration.current++;
        if (scenario === 'error' || scenario === 'reopened-error') throw Error('write failed');
        if (scenario === 'raw-error') throw null;
        if (scenario === 'double')
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        return {
          nodeId: connectionNodeId,
          rowVersion: edit ? '8' : '1',
          updated: scenario !== 'not-updated',
        };
      };
      env.window = {
        wormhole:
          scenario === 'no-api'
            ? undefined
            : {
                saveVaultConnection: (input: any) => save('native', input),
                createWorkspaceNode: (input: any) => save('legacy', input),
                updateWorkspaceNode: (input: any) => save('legacy', input),
              },
      };
      const submit = runInNewContext(source, env),
        pending = submit({ preventDefault() {} });
      if (scenario === 'double') {
        await submit({ preventDefault() {} });
        assert.equal(calls, 1);
        release();
      }
      await pending;
      const skipped = [
        'pending',
        'busy',
        'not-ready',
        'invalid-credential',
        'invalid-port',
        'no-api',
      ].includes(scenario);
      assert.equal(calls, skipped ? 0 : 1, `${scenario}/${edit}: ${error}`);
      if (skipped) continue;
      if (scenario !== 'legacy') {
        assert.equal(request.rowVersion, edit ? '7' : '0');
        assert.equal(env.newConnectionForm.inlinePassword, '');
        assert.equal(env.newConnectionForm.notes, '');
      }
      if (
        ['error', 'raw-error', 'reopened-error'].includes(scenario) ||
        (edit && scenario === 'not-updated')
      ) {
        assert.equal(closed, false);
        assert.equal(Boolean(error), scenario !== 'reopened-error');
      } else {
        assert.equal(closed, scenario !== 'reopened');
        if (!edit && scenario === 'reopened') assert.equal(selected, '');
      }
      assert.equal(env.connectionSavePending.current, false);
    }
});

test('actual connection save helpers consume DOM bytes and preserve empty fields and original revisions', async (t) => {
  const filename = 'wormhole-vault-connection-save.js',
    verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = stripTypeScriptTypes(
    cut(
      app,
      '      const saveNativeConnection = async () => {',
      '      const reconnectEditedSession =',
    ) + ';({ saveNativeConnection, refreshSavedConnection })',
  );
  for (const scenario of [
    'create',
    'edit',
    'empty',
    'clear',
    'missing-dom',
    'saved-credentials',
    'write-error',
    'refresh-error',
    'refresh-raw-error',
    'legacy-refresh-error',
  ]) {
    const fixture = connectionInput();
    let submitted: any,
      capturedPassword = '',
      capturedNotes = '',
      error = '';
    const password = { value: 'entered-password' },
      notes = { value: 'entered-notes' };
    const empty = ['empty', 'missing-dom', 'clear', 'saved-credentials'].includes(scenario);
    if (empty) {
      password.value = '';
      notes.value = '';
    }
    const env = {
      Error,
      TextEncoder,
      editingId: scenario === 'edit' ? connectionNodeId : null,
      editingConnectionVersion: { current: '7' },
      nativeSavedConnection: scenario !== 'legacy-refresh-error',
      nativeConnectionPassword: { current: scenario === 'missing-dom' ? null : password },
      nativeConnectionNotes: { current: scenario === 'missing-dom' ? null : notes },
      removeNativeNotes: scenario === 'clear',
      inlinePasswordAction: empty ? 'clear' : 'set',
      nodeWrite: {
        ...fixture.metadata,
        inlinePasswordAction: empty ? 'clear' : 'set',
        rdp: undefined,
      },
      clearSecretInput: (input: any) => {
        if (input) input.value = '';
      },
      window: {
        wormhole: {
          saveVaultConnection: async (input: any) => {
            submitted = input;
            capturedPassword = new TextDecoder().decode(input.password);
            capturedNotes = new TextDecoder().decode(input.notes);
            const owned = consumeVaultConnectionInput(input);
            owned.password.fill(0);
            owned.notes.fill(0);
            if (scenario === 'write-error') throw Error('write failed');
            return {
              nodeId: connectionNodeId,
              rowVersion: scenario === 'edit' ? '8' : '1',
              updated: true,
            };
          },
        },
      },
      refreshWorkspace: async () => {
        if (scenario === 'refresh-raw-error') throw null;
        if (scenario.includes('refresh-error')) throw Error('refresh failed');
      },
      setTreeMoveError: (value: string) => {
        error = value;
      },
    };
    const api = runInNewContext(source, env, { filename });
    if (scenario === 'write-error')
      await assert.rejects(api.saveNativeConnection(), /write failed/);
    else await api.saveNativeConnection();
    assert.equal(submitted.rowVersion, scenario === 'edit' ? '7' : '0');
    assert.equal(submitted.metadata.id, scenario === 'edit' ? connectionNodeId : '');
    assert.equal(
      submitted.notesAction,
      scenario === 'clear' ? 'clear' : empty ? 'preserve' : 'set',
    );
    assert.equal(capturedPassword, empty ? '' : 'entered-password');
    assert.equal(capturedNotes, empty ? '' : 'entered-notes');
    assert.equal(password.value, '');
    assert.equal(notes.value, '');
    assert.ok(
      submitted.password.every((v: number) => v === 0) &&
        submitted.notes.every((v: number) => v === 0),
    );
    assert.equal('notes' in submitted.metadata, false);
    assert.equal('password' in submitted.metadata, false);
    if (scenario === 'legacy-refresh-error')
      await assert.rejects(api.refreshSavedConnection(), /refresh failed/);
    else {
      await api.refreshSavedConnection();
      assert.equal(Boolean(error), scenario.startsWith('refresh-'));
    }
  }
  await verify();
});

test('actual folder editors use native metadata and the opening revision, preserving legacy and retry behavior', async (t) => {
  const filename = 'wormhole-vault-folder-editors.js',
    verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = stripTypeScriptTypes(
    cut(app, 'function autoSudoModeFor(', 'function matchesMcpOpenConnectionApproval(') +
      cut(app, 'function credentialSelectionFor(', 'function backendErrorMessage(') +
      cut(app, '  function openEditFolder(', '  function openEditNode(') +
      cut(app, '  async function refreshSavedFolder()', '  const draggedNodeIdSet') +
      ';({ openEditFolder, submitFolderDetails, submitNewFolder })',
  );
  const id = '11111111-1111-4111-8111-111111111111',
    parent = '22222222-2222-4222-8222-222222222222';
  for (const action of ['edit', 'create'])
    for (const scenario of [
      'native',
      'legacy',
      'root',
      'busy',
      'pending',
      'empty',
      'missing',
      'no-id',
      'no-api',
      'no-version',
      'error',
      'raw-error',
      'not-updated',
      'refresh-error',
      'legacy-refresh-error',
      'reopened',
      'reopened-error',
      'double',
    ]) {
      const nativeMode = !scenario.startsWith('legacy');
      let requests: any[] = [],
        refreshes = 0,
        error = '',
        treeError = '',
        closed = false,
        selected = '',
        expanded = new Set<string>();
      let release!: () => void;
      const folder = {
        id,
        name: 'Original',
        kind: 'folder',
        rowVersion: '7',
        credentialMode: 0,
        sshAutoSudo: null,
        tunnelEnabled: null,
      };
      const env: any = {
        Error,
        Set,
        tunnelModeFor,
        tunnelValueFor,
        findParentFolderId,
        authState: { mode: nativeMode ? 'vault' : 'password' },
        tree:
          scenario === 'root'
            ? [{ ...folder, rowVersion: '8' }]
            : [{ id: parent, kind: 'folder', children: [{ ...folder, rowVersion: '8' }] }],
        editingFolderId: { current: null },
        editingFolderVersion: { current: undefined },
        editingFolderGeneration: { current: 0 },
        newFolderParentId: { current: scenario === 'root' ? null : parent },
        newFolderGeneration: { current: 1 },
        folderSavePending: { current: scenario === 'pending' },
        editorBusy: scenario === 'busy',
        setSelectedNodeId: (value: string) => {
          selected = value;
        },
        setEditorError: (value: string) => {
          error = value;
        },
        setTreeMoveError: (value: string) => {
          treeError = value;
        },
        setFolderDetailsForm: (value: any) => {
          env.folderDetailsForm = value;
        },
        setFolderDetailsOpen: (value: boolean) => {
          closed = !value;
        },
        setNewFolderOpen: (value: boolean) => {
          closed = !value;
        },
        setEditorBusy: () => {},
        setExpanded: (fn: any) => {
          expanded = fn(expanded);
        },
        refreshWorkspace: async () => {
          refreshes++;
          if (scenario.includes('refresh-error')) throw Error('refresh unavailable');
        },
      };
      const save = async (route: string, input: any) => {
        assert.equal(route, nativeMode ? 'native' : action);
        if (route === 'native') assert.ok(parseVaultFolder(input), 'invalid native metadata');
        requests.push(JSON.parse(JSON.stringify(input)));
        if (scenario.startsWith('reopened')) {
          env.editingFolderGeneration.current++;
          env.newFolderGeneration.current++;
        }
        if (scenario === 'error' || scenario === 'reopened-error') throw Error('write failed');
        if (scenario === 'raw-error') throw null;
        if (scenario === 'double')
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        return {
          nodeId: id,
          rowVersion: action === 'edit' ? '8' : '1',
          updated: scenario !== 'not-updated',
        };
      };
      env.window = {
        wormhole:
          scenario === 'no-api'
            ? undefined
            : {
                saveVaultFolder: (input: any) => save('native', input),
                updateWorkspaceNode: (input: any) => save('edit', input),
                createWorkspaceNode: (input: any) => save('create', input),
              },
      };
      const api = runInNewContext(source, env, { filename });
      api.openEditFolder({ kind: 'connection' });
      assert.equal(env.editingFolderId.current, null);
      api.openEditFolder(folder);
      assert.equal(env.editingFolderVersion.current, '7');
      env.folderDetailsForm.name = scenario === 'empty' ? '  ' : ' Renamed ';
      env.newFolderForm = { ...env.folderDetailsForm };
      if (scenario === 'missing') env.tree = [];
      if (scenario === 'no-id') env.editingFolderId.current = null;
      if (scenario === 'no-version') env.editingFolderVersion.current = undefined;
      const submit = action === 'edit' ? api.submitFolderDetails : api.submitNewFolder;
      const pending = submit({ preventDefault() {} });
      if (scenario === 'double') {
        await submit({ preventDefault() {} });
        assert.equal(requests.length, 1, `${action}/${scenario}: ${error}`);
        release();
      }
      await pending;
      const skipped =
        ['busy', 'pending', 'empty'].includes(scenario) ||
        (action === 'edit' && ['missing', 'no-id'].includes(scenario));
      if (skipped || scenario === 'no-api' || (action === 'edit' && scenario === 'no-version')) {
        assert.equal(requests.length, 0);
        continue;
      }
      assert.equal(requests.length, 1, `${action}/${scenario}: ${error}`);
      assert.equal(requests[0].name, 'Renamed');
      if (nativeMode) {
        assert.equal(requests[0].rowVersion, action === 'edit' ? '7' : '0');
        assert.deepEqual(
          Object.keys(requests[0]).sort(),
          [
            'id',
            'rowVersion',
            'parentId',
            'name',
            'sshAutoSudo',
            'tunnelEnabled',
            'tunnelConfigId',
            'credentialMode',
            'credentialId',
          ].sort(),
        );
      }
      if (
        ['error', 'raw-error', 'reopened-error'].includes(scenario) ||
        (scenario === 'not-updated' && action === 'edit')
      ) {
        assert.equal(refreshes, 0);
        assert.equal(closed, false);
        assert.equal(Boolean(error), scenario !== 'reopened-error');
      } else if (scenario === 'legacy-refresh-error') {
        assert.equal(closed, false);
        assert.equal(error, 'refresh unavailable');
      } else {
        assert.equal(refreshes, 1);
        assert.equal(closed, scenario !== 'reopened');
        assert.equal(Boolean(treeError), scenario === 'refresh-error');
        assert.equal(error, '');
        if (action === 'create') {
          assert.ok(expanded.has(id));
          if (scenario !== 'reopened') assert.equal(selected, id);
        }
      }
      assert.equal(env.folderSavePending.current, false);
    }
  await verify();
});

test('actual tree deletion routes vault selections with confirmation revisions and preserves legacy/local paths', async (t) => {
  const filename = 'wormhole-vault-tree-deletion.js',
    verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const helpers = stripTypeScriptTypes(
    cut(app, 'function findTreeNode(', 'function matchesMcpOpenConnectionApproval(') +
      cut(app, 'function collectTreeNodeIds(', 'function insertIntoTreeFolder('),
  );
  const source = stripTypeScriptTypes(
    cut(app, '  async function confirmDeleteNodes()', '  function duplicateConnection(') +
      ';confirmDeleteNodes',
  );
  for (const mode of [
    'vault',
    'legacy',
    'local',
    'missing',
    'empty',
    'busy',
    'no-api',
    'declined',
    'failure',
    'refresh-failure',
  ]) {
    const old = {
      id: descriptor.vaultId,
      kind: 'folder',
      persisted: mode !== 'local',
      rowVersion: '7',
      children: [
        { id: '22222222-2222-4222-8222-222222222222', kind: 'connection', persisted: false },
      ],
    };
    const treeRef = { current: mode === 'missing' ? [] : [{ ...old, rowVersion: '8' }] };
    const calls: string[] = [],
      errors: string[] = [];
    const api = {
      deleteVaultNodes: async (request: any) => {
        calls.push('vault');
        assert.equal(request.nodes[0].rowVersion, '7');
        if (mode === 'failure') throw Error('stale revision');
        return { deleted: mode !== 'declined' };
      },
      deleteWorkspaceNodes: async (request: any) => {
        calls.push('legacy');
        assert.equal(request.nodeIds[0], old.id);
        return { deleted: true };
      },
    };
    const environment: any = {
      pendingDeleteNodes: mode === 'empty' ? [] : [old],
      deleteNodeBusy: mode === 'busy',
      authState: { mode: mode === 'legacy' ? 'password' : 'vault' },
      treeRef,
      window: { wormhole: mode === 'no-api' ? undefined : api },
      canonicalizeConnectionTreeNodeIds,
      vaultDeleteSelection,
      setDeleteNodeBusy: () => {},
      setDeleteNodeError: (error: string) => errors.push(error),
      setPendingDeleteNodes: () => calls.push('dismiss'),
      workspaceRefresh: { invalidate: () => calls.push('invalidate') },
      closeSessionsForNodeIds: async (ids: Set<string>) => {
        assert.ok(ids.has(old.id));
        calls.push('sessions');
      },
      applyDeletedTreeState: (next: any[]) => {
        treeRef.current = next;
        calls.push('remove');
      },
      refreshWorkspace: async () => {
        calls.push('refresh');
        if (mode === 'refresh-failure') throw Error('refresh failed');
      },
    };
    Object.assign(
      environment,
      runInNewContext(helpers + ';({findTreeNode,collectTreeNodeIds,extractTreeNodes})'),
    );
    await runInNewContext(source, environment, { filename })();
    if (['empty', 'busy'].includes(mode)) assert.deepEqual(calls, []);
    else if (['missing', 'no-api', 'declined', 'failure'].includes(mode)) {
      assert.ok(errors.at(-1));
      assert.ok(!calls.includes('remove'));
    } else {
      assert.equal(treeRef.current.length, 0);
      assert.ok(calls.includes('sessions') && calls.includes('dismiss'));
      assert.equal(calls.includes('legacy'), mode === 'legacy');
      assert.equal(calls.includes('vault'), mode !== 'legacy' && mode !== 'local');
    }
  }
  await verify();
});

test('main creation requires a current trusted new-workspace request and OS lock also closes pending creation', async (t) => {
  const filename = 'wormhole-vault-creation-main.js';
  const verify = await measure(t, filename);
  const handlerSource = ipcRegistration(main, 'vault:create');
  for (const mode of [
    'new',
    'existing',
    'legacy',
    'untrusted',
    'late-untrusted',
    'extra',
    'missing-parent',
  ]) {
    let handler: any,
      reads = 0,
      opens = 0,
      trusted = mode !== 'untrusted';
    runInNewContext(
      stripTypeScriptTypes(handlerSource),
      {
        ipcMain: { handle: (_name: string, fn: any) => (handler = fn) },
        isTrustedVaultSender: () => trusted,
        vaultBackend: {
          startup: async () => {
            reads++;
            if (mode === 'late-untrusted') trusted = false;
            return {
              slots: mode === 'existing' ? descriptor : null,
              newWorkspace: mode !== 'legacy',
            };
          },
        },
        BrowserWindow: { fromWebContents: () => (mode === 'missing-parent' ? null : 'parent') },
        vaultCreateDialog: {
          open: async (parent: any, accepted: any) => {
            assert.equal(parent, 'parent');
            assert.equal(accepted(), true);
            opens++;
            return true;
          },
        },
      },
      { filename },
    );
    if (mode === 'new') assert.equal(await handler({ sender: {} }), true);
    else await assert.rejects(handler({ sender: {} }, ...(mode === 'extra' ? [1] : [])));
    assert.equal(opens, mode === 'new' ? 1 : 0);
    assert.equal(reads, mode === 'untrusted' || mode === 'extra' ? 0 : 1);
  }
  let locks = 0;
  const state = { isVaultWorkspace: false },
    dialog = { active: false },
    migrationDialog = { active: false },
    osMigrationDialog = { active: false },
    sharedSetup = { active: false };
  const power = runInNewContext(
    stripTypeScriptTypes(
      cut(main, 'function hasAutomaticVaultLockTarget()', 'function beginLinuxVaultSleep()') +
        '; requestAutomaticVaultLock',
    ),
    {
      vaultBackend: state,
      vaultCreateDialog: dialog,
      vaultMigrationSetupDialog: migrationDialog,
      vaultOSMigrationDialog: osMigrationDialog,
      vaultSharedSetupDialog: sharedSetup,
      lockApplication: async () => {
        locks++;
      },
      console: { warn: () => {} },
    },
    { filename },
  );
  power();
  assert.equal(locks, 0);
  dialog.active = true;
  power();
  assert.equal(locks, 1);
  dialog.active = false;
  state.isVaultWorkspace = true;
  power();
  assert.equal(locks, 2);
  state.isVaultWorkspace = false;
  migrationDialog.active = true;
  power();
  assert.equal(locks, 3);
  migrationDialog.active = false;
  osMigrationDialog.active = true;
  power();
  assert.equal(locks, 4);
  osMigrationDialog.active = false;
  sharedSetup.active = true;
  power();
  assert.equal(locks, 5);
  await verify();
});

test('real renderer bootstrap probes public metadata first and cannot mount after a vault lock', async (t) => {
  const filename = 'wormhole-native-startup-renderer.js';
  const verify = await measure(t, filename);
  const code =
    stripTypeScriptTypes(`let startupRequest; let startupGeneration = 0; let disposeWorkspace; let disposeVaultUnlock;
    ${cut(renderer, 'function showVaultLock()', 'window.wormhole?.onVaultLocked')}
    ${cut(renderer, 'function showVaultUnlock(', 'void bootstrap();')}
    ({bootstrap, showVaultLock, showVaultUnlock});`);
  for (const scenario of [
    'native',
    'migration',
    'os-migration',
    'legacy-choice',
    'shared-join',
    'rotation',
    'upgrade',
    'unprotected',
    'new-unprotected',
    'new-created',
    'new-cancelled',
    'new-cancelled-committed',
    'new-failed',
    'new-load-retry',
    'new-lock',
    'new-join-success',
    'new-join-cancelled',
    'new-join-failed',
    'new-join-stale',
    'new-join-double',
    'new-join-metadata-error',
    'legacy',
    'legacy-locked',
    'legacy-missing',
    'no-bridge',
    'metadata-error',
    'metadata-string-error',
    'legacy-error',
    'wrong-mode',
    'no-workspace',
    'module-error',
    'lock-during-metadata',
    'lock-during-legacy',
    'lock-during-error',
    'lock-during-module',
    'retry-load',
  ]) {
    const calls: string[] = [],
      errors: string[] = [],
      buttons: any[] = [];
    const metadata = deferred<any>(),
      loading = deferred<any>(),
      module = deferred<any>();
    let unlocked!: () => Promise<void>;
    let failLoad = scenario === 'retry-load' || scenario === 'new-load-retry';
    const mountModule = {
      mountWorkspaceApp: (_root: unknown, props: any) => {
        assert.equal(props.initialAuthState.mode, 'vault');
        calls.push('mount');
        return () => calls.push('unmount');
      },
    };
    const api = {
      markStartupReady: () => calls.push('ready'),
      authenticateSharedVault: async (...args: unknown[]) => {
        assert.deepEqual(args, ['join-initial']);
        calls.push('join-request');
        if (scenario === 'new-join-failed') throw Error('lost join reply');
        if (scenario === 'new-join-stale' || scenario === 'new-join-double') return loading.promise;
        if (scenario === 'new-join-cancelled') return null;
        return { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' };
      },
      lockAuthentication: async () => {
        calls.push('lock-auth');
      },
      createVault: async () => {
        calls.push('create');
        if (scenario === 'new-lock') return loading.promise;
        if (scenario === 'new-failed') throw Error('private create failure');
        return !scenario.startsWith('new-cancelled');
      },
      loadVaultStartup: async () => {
        if (
          scenario.startsWith('new-join-') &&
          calls.includes('join-request') &&
          scenario !== 'new-join-cancelled'
        ) {
          if (scenario === 'new-join-metadata-error')
            throw Error('completed selection unavailable');
          return {
            slots: descriptor,
            cosmetics: { theme: 'dark' },
            newWorkspace: false,
            ...(scenario === 'new-join-failed'
              ? { sharedJoin: { lastLoginName: 'alice', serverDisplayName: 'Team' } }
              : { shared: { lastLoginName: 'alice', serverDisplayName: 'Team' } }),
          };
        }
        if (scenario === 'shared-join')
          return {
            slots: { ...descriptor, encrypted: true },
            cosmetics: { theme: 'dark' },
            newWorkspace: false,
            sharedJoin: { lastLoginName: 'alice', serverDisplayName: 'Team' },
          };
        if (scenario === 'legacy-choice')
          return {
            slots: null,
            cosmetics: { theme: 'dark' },
            newWorkspace: false,
            legacy: { unprotectedAllowed: true },
          };
        if (scenario === 'os-migration')
          return {
            slots: null,
            cosmetics: { theme: 'dark' },
            newWorkspace: false,
            osMigration: { vaultId: descriptor.vaultId },
          };
        if (scenario === 'unprotected')
          return {
            slots: null,
            cosmetics: { theme: 'dark' },
            newWorkspace: false,
            unprotected: { vaultId: descriptor.vaultId },
          };
        calls.push('metadata');
        if (scenario.startsWith('metadata-'))
          throw scenario.endsWith('string-error')
            ? 'private diagnostic'
            : Error('metadata unavailable');
        if (scenario === 'lock-during-metadata' || scenario === 'lock-during-error')
          return metadata.promise;
        if (scenario === 'new-cancelled-committed' && calls.includes('create'))
          return { slots: descriptor, cosmetics: { theme: 'dark' }, newWorkspace: false };
        return {
          slots:
            scenario.startsWith('legacy') ||
            scenario.startsWith('new-') ||
            scenario === 'lock-during-legacy'
              ? null
              : descriptor,
          cosmetics: { theme: 'dark' },
          newWorkspace: scenario.startsWith('new-'),
          ...(scenario === 'new-unprotected' ? { unprotectedAllowed: true } : {}),
          ...(scenario === 'migration' ? { migration: { pending: true } } : {}),
          ...(scenario === 'rotation' ? { rotation: { pending: true } } : {}),
          ...(scenario === 'upgrade'
            ? { slots: null, upgrade: { vaultId: descriptor.vaultId } }
            : {}),
        };
      },
      createUnprotectedVault: async () => {
        calls.push('create-unprotected');
        return true;
      },
      loadStartup: async () => {
        calls.push('data');
        if (scenario === 'legacy-error' || failLoad) throw Error('load unavailable');
        if (scenario === 'lock-during-legacy') return loading.promise;
        if (scenario.startsWith('legacy'))
          return {
            ...native,
            auth: { configured: scenario === 'legacy-locked' },
            workspace: scenario === 'legacy-missing' ? undefined : workspace,
            themeMigration: { handled: true },
          };
        if (scenario === 'wrong-mode') return { ...native, auth: { mode: 'password' } };
        if (scenario === 'no-workspace') return { ...native, workspace: undefined };
        return native;
      },
    };
    const ui = runInNewContext(
      code,
      {
        window: {
          wormhole: scenario === 'no-bridge' ? undefined : api,
          setTimeout: (fn: () => void) => {
            fn();
            return 1;
          },
        },
        root: {},
        legacyTheme: undefined,
        applyTheme: () => {},
        clearLegacyTheme: () => calls.push('clear-theme'),
        renderLoading: () => calls.push('loading'),
        renderCard: () => ({ append: () => {} }),
        document: {
          createElement: () => {
            const button: any = {
              setAttribute: () => {},
              addEventListener: (_: string, fn: () => void) => {
                button.click = fn;
              },
            };
            buttons.push(button);
            return button;
          },
        },
        showError: (message: string) => errors.push(message),
        showUnlock: () => calls.push('legacy-unlock'),
        mountWorkspace: async () => calls.push('legacy-mount'),
        loadWorkspaceModule: async () => {
          if (scenario === 'module-error') throw Error('module unavailable');
          if (scenario === 'lock-during-module') return module.promise;
          return mountModule;
        },
        mountVaultMigrationStartup: (
          _card: unknown,
          bridge: unknown,
          callback: typeof unlocked,
        ) => {
          assert.equal(bridge, api);
          unlocked = callback;
          calls.push('migration-screen');
          return () => calls.push('dispose-migration');
        },
        mountVaultOSMigrationStartup: (
          _card: unknown,
          bridge: unknown,
          callback: typeof unlocked,
        ) => {
          assert.equal(bridge, api);
          unlocked = callback;
          calls.push('os-migration-screen');
          return () => calls.push('dispose-os-migration');
        },
        mountVaultRootRotationStartup: (
          _card: unknown,
          bridge: unknown,
          callback: typeof unlocked,
        ) => {
          assert.equal(bridge, api);
          unlocked = callback;
          calls.push('rotation-screen');
          return () => calls.push('dispose-rotation');
        },
        mountVaultUpgradeStartup: (_card: unknown, bridge: unknown) => {
          assert.equal(bridge, api);
          calls.push('upgrade-screen');
          return () => calls.push('dispose-upgrade');
        },
        mountVaultLegacyStartup: (_card: unknown, bridge: unknown, allowed: boolean) => {
          assert.equal(bridge, api);
          assert.equal(allowed, true);
          calls.push('legacy-choice-screen');
          return () => calls.push('dispose-legacy-choice');
        },
        mountSharedStartup: (
          _card: unknown,
          metadata: any,
          bridge: unknown,
          _sessions: unknown,
          initial?: any,
        ) => {
          assert.equal(bridge, api);
          assert.ok(metadata.sharedJoin || metadata.shared);
          if (scenario.startsWith('new-join-') && scenario !== 'new-join-failed') {
            assert.equal(initial?.admitted, true);
            assert.equal(initial.orgEscrow, true);
            assert.equal(initial.tls, 'off');
          } else assert.equal(initial, undefined);
          calls.push('shared-join-screen');
          return () => calls.push('dispose-shared-join');
        },
        mountUnprotectedStartup: (_card: unknown, bridge: unknown, callback: typeof unlocked) => {
          assert.equal(bridge, api);
          unlocked = callback;
          calls.push('unprotected-screen');
          return () => calls.push('dispose-unprotected');
        },
        mountVaultUnlockScreen: (
          _card: unknown,
          value: unknown,
          bridge: unknown,
          callback: typeof unlocked,
        ) => {
          assert.equal(value, descriptor);
          assert.equal(bridge, api);
          unlocked = callback;
          calls.push('unlock-screen');
          return () => calls.push('dispose-unlock');
        },
      },
      { filename },
    );
    const pending = ui.bootstrap();
    if (scenario.startsWith('new-join-')) {
      await pending;
      const button = buttons.find((b) => b.textContent === 'Join a shared workspace');
      assert.ok(button);
      const join = button.click();
      if (scenario === 'new-join-stale' || scenario === 'new-join-double') {
        await new Promise(setImmediate);
        assert.equal(button.disabled, true);
        if (scenario === 'new-join-stale') ui.showVaultLock();
        else {
          await button.click();
          await buttons.find((b) => b.textContent === 'Use on this computer').click();
        }
        loading.resolve({ admitted: true, lockedMemory: true, orgEscrow: true, tls: 'off' });
      }
      await join;
      assert.equal(calls.filter((c) => c === 'join-request').length, 1);
      assert.equal(
        calls.includes('create') || calls.includes('create-unprotected') || calls.includes('data'),
        false,
      );
      if (scenario === 'new-join-metadata-error') {
        assert.equal(calls.includes('lock-auth'), true);
        assert.equal(errors.length, 1);
      } else if (scenario !== 'new-join-cancelled' && scenario !== 'new-join-stale')
        assert.equal(calls.includes('shared-join-screen'), true);
      continue;
    }
    if (scenario === 'lock-during-metadata' || scenario === 'lock-during-error') {
      ui.showVaultLock();
      if (scenario === 'lock-during-error') metadata.reject(Error('late metadata'));
      else
        metadata.resolve({ slots: descriptor, cosmetics: { theme: 'dark' }, newWorkspace: false });
    }
    if (scenario === 'lock-during-legacy') {
      await new Promise(setImmediate);
      ui.showVaultLock();
      loading.resolve(native);
    }
    await pending;
    if (
      [
        'native',
        'wrong-mode',
        'no-workspace',
        'module-error',
        'lock-during-module',
        'retry-load',
      ].includes(scenario)
    ) {
      assert.equal(calls.includes('data'), false, 'workspace read before unlock');
      if (scenario === 'retry-load') {
        await assert.rejects(unlocked(), /load unavailable/);
        failLoad = false;
      }
      const mounted = unlocked();
      if (scenario === 'lock-during-module') {
        await new Promise(setImmediate);
        ui.showVaultLock();
        module.resolve(mountModule);
      }
      if (['wrong-mode', 'no-workspace', 'module-error'].includes(scenario))
        await assert.rejects(mounted);
      else await mounted;
      if (scenario === 'native' || scenario === 'retry-load') {
        assert.equal(calls.filter((c) => c === 'mount').length, 1);
        ui.showVaultLock();
        assert.ok(calls.includes('unmount'));
        buttons.at(-1).click();
        await new Promise(setImmediate);
        assert.equal(calls.filter((c) => c === 'unlock-screen').length, 2);
      } else assert.equal(calls.includes('mount'), false);
    } else if (scenario === 'migration' || scenario === 'rotation' || scenario === 'os-migration') {
      assert.equal(calls.includes(`${scenario}-screen`), true);
      assert.equal(calls.includes('data'), false);
      assert.equal(calls.includes('unlock-screen'), false);
      await unlocked();
      assert.equal(calls.includes('mount'), true);
    } else if (scenario === 'shared-join') {
      assert.ok(calls.includes('shared-join-screen'));
      for (const forbidden of ['data', 'mount', 'legacy-mount', 'unlock-screen'])
        assert.equal(calls.includes(forbidden), false);
    } else if (scenario === 'legacy-choice') {
      assert.ok(calls.includes('legacy-choice-screen'));
      for (const forbidden of ['data', 'mount', 'legacy-mount', 'unlock-screen', 'legacy-load'])
        assert.equal(calls.includes(forbidden), false);
    } else if (scenario === 'upgrade') {
      assert.ok(calls.includes('upgrade-screen'));
      for (const forbidden of ['data', 'mount', 'legacy-mount', 'unlock-screen'])
        assert.equal(calls.includes(forbidden), false);
    } else if (scenario === 'unprotected') {
      assert.ok(calls.includes('unprotected-screen'));
      assert.equal(calls.includes('data'), false);
      await unlocked();
      assert.ok(calls.includes('mount'));
    } else if (scenario === 'new-unprotected') {
      const skip = buttons.find((b) => b.textContent === 'Skip for now (Unprotected)');
      assert.ok(skip);
      const opening = skip.click();
      await skip.click();
      await opening;
      assert.equal(calls.filter((c) => c === 'create-unprotected').length, 1);
      assert.equal(calls.includes('create'), false);
      assert.ok(calls.includes('mount'));
    } else if (scenario.startsWith('new-')) {
      assert.equal(calls.includes('data'), false);
      const button = buttons.find((b) => b.textContent === 'Use on this computer');
      assert.ok(button);
      const click = button.click();
      const duplicate = button.click();
      await duplicate;
      if (scenario === 'new-lock') {
        ui.showVaultLock();
        loading.resolve(true);
      }
      await click;
      if (scenario === 'new-load-retry') {
        failLoad = false;
        assert.equal(button.textContent, 'Open workspace');
        await button.click();
      }
      assert.equal(calls.filter((c) => c === 'create').length, 1);
      if (scenario === 'new-cancelled-committed') assert.ok(calls.includes('unlock-screen'));
      assert.equal(
        calls.includes('mount'),
        scenario === 'new-created' || scenario === 'new-load-retry',
      );
    } else if (scenario === 'legacy') assert.ok(calls.includes('legacy-mount'));
    else if (scenario === 'legacy-locked') assert.ok(calls.includes('legacy-unlock'));
    else if (scenario.startsWith('lock-during-')) {
      assert.equal(calls.includes('legacy-mount'), false);
      assert.equal(errors.length, 0);
    } else assert.equal(errors.length, 1, scenario);
  }
  await verify();
});

test('main startup routes encrypted workspaces through the unlocked owner and preserves legacy startup', async (t) => {
  const filename = 'wormhole-native-startup-main.js';
  const verify = await measure(t, filename);
  const code = stripTypeScriptTypes(`let confirmOnWindowClose;
    ${cut(main, 'function vaultAuthState()', 'function refreshAuthSession()')}
    ${cut(main, "  ipcMain.handle('startup:load'", "  ipcMain.handle('startup:unlock'")}
    ${cut(main, "  ipcMain.handle('workspace:load'", "  ipcMain.handle('workspace:node-notes'")}`);
  for (const scenario of [
    'native',
    'locked',
    'untrusted',
    'navigate',
    'metadata-error',
    'preferences-error',
    'workspace-error',
    'legacy',
    'legacy-locked-data',
    'legacy-migration-error',
    'legacy-migrated',
  ]) {
    const handlers = new Map<string, any>(),
      calls: string[] = [];
    let trusted = scenario !== 'untrusted';
    const isVaultWorkspace = !scenario.startsWith('legacy');
    const api = {
      isVaultWorkspace,
      unlockedWorkspaceId: scenario === 'locked' ? undefined : descriptor.vaultId,
      startup: async () => {
        calls.push('metadata');
        if (scenario === 'metadata-error') throw Error('metadata');
      },
      preferences: async () => {
        calls.push('preferences');
        if (scenario === 'preferences-error') throw Error('preferences');
        return preferences();
      },
      workspace: async () => {
        calls.push('workspace');
        if (scenario === 'workspace-error') throw Error('workspace');
        if (scenario === 'navigate') trusted = false;
        return workspace;
      },
    };
    runInNewContext(
      code,
      {
        ipcMain: { handle: (channel: string, callback: any) => handlers.set(channel, callback) },
        vaultBackend: api,
        parseThemeStartupRequest: () => ({}),
        serializeAuthOperation: (fn: any) => fn(),
        runAuthorizedOperation: (fn: any) => fn(),
        isTrustedVaultSender: () => trusted,
        runBackend: async (op: string) => {
          assert.equal(isVaultWorkspace, false, 'native startup invoked legacy SQL');
          calls.push(`legacy:${op}`);
          if (op === 'workspace') return workspace;
          return {
            ...native,
            auth: { configured: scenario === 'legacy-locked-data' },
            migrationFailed: scenario === 'legacy-migration-error',
            migration: {
              status: scenario === 'legacy-migrated' ? 'completed' : 'already-completed',
              migrated: 0,
              missing: 0,
            },
          };
        },
        rememberAuthState: () => calls.push('remember'),
        normalizeWindowCloseConfirmation: (value: boolean) => value,
        scheduleStartupUpdateCheck: () => calls.push('updates'),
        recordDiagnostic() {},
        console: { info: () => {}, error: () => {} },
      },
      { filename },
    );
    const pending = handlers.get('startup:load')({}, undefined);
    if (
      scenario === 'native' ||
      (scenario.startsWith('legacy') && scenario !== 'legacy-locked-data')
    ) {
      const result = await pending;
      assert.equal(result.workspace, workspace);
      if (scenario === 'native') {
        assert.equal(result.auth.mode, 'vault');
        assert.equal(result.auth.configured, true);
        assert.equal(result.migration.status, 'vault');
        assert.deepEqual(calls, ['metadata', 'preferences', 'workspace']);
      }
    } else await assert.rejects(pending);
    trusted = scenario !== 'untrusted';
    const refresh = handlers.get('workspace:load')({});
    if (['untrusted', 'navigate', 'workspace-error'].includes(scenario))
      await assert.rejects(refresh);
    else assert.equal(await refresh, workspace);
  }
  await verify();
});

test('native vault actions never open the legacy secret prompt and security UI offers native lock', async (t) => {
  const filename = 'wormhole-native-auth-actions.js';
  const verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const code = stripTypeScriptTypes(
    cut(app, '  const requestAuthentication = useCallback(', '  function handleAuthPromptResult(') +
      '\nrequestAuthentication;',
  );
  for (const mode of [
    'vault',
    'password',
    'disabled',
    'none',
    'unconfigured',
    'locked',
    'pending',
  ]) {
    let prompt: any;
    const resolver = { current: mode === 'pending' ? () => {} : (undefined as any) };
    const request = runInNewContext(
      code,
      {
        useCallback: (fn: any) => fn,
        authGate: mode === 'locked' ? 'locked' : 'unlocked',
        authState: mode === 'none' ? null : { mode, configured: mode !== 'unconfigured' },
        authPromptResolver: resolver,
        setAuthPrompt: (value: any) => {
          prompt = value;
        },
      },
      { filename },
    );
    const response = request('Sensitive operation');
    if (mode === 'password') {
      assert.equal(prompt.reason, 'Sensitive operation');
      resolver.current(true);
      assert.equal(await response, true);
    } else {
      assert.equal(prompt, undefined);
      assert.equal(await response, ['disabled', 'none', 'unconfigured'].includes(mode));
    }
  }
  await verify();
  const { transformWithOxc } = await import('vite');
  const jsx = cut(
    app,
    '        <SettingsTabPanel value="security">',
    '        <SettingsTabPanel value="extensions">',
  ).trim();
  const transformed = await transformWithOxc(
    `const panel = (${jsx}); panel;`,
    'native-vault-security.tsx',
  );
  let locks = 0;
  let exported = 0,
    exportSaved = false,
    exportBusy = false,
    exportError = '';
  const bridge = {
    lockAuthentication: async () => {
      locks++;
    },
    exportLocalVaultBackup: async () => {
      exported++;
      return true;
    },
  };
  const view = runInNewContext(transformed.code, {
    require: () => ({
      jsx: (type: any, props: any) => ({ type, props }),
      jsxs: (type: any, props: any) => ({ type, props }),
    }),
    authState: { mode: 'vault' },
    checkingDatabaseEncryption: true,
    databaseEncryptionAvailable: false,
    localVaultBackupAvailable: true,
    localVaultBackupSaved: false,
    setLocalVaultBackupSaved: (value: boolean) => {
      exportSaved = value;
    },
    setSecurityBusy: (value: boolean) => {
      exportBusy = value;
    },
    setSecurityError: (message: string) => {
      exportError = message;
    },
    securityBusy: false,
    securityError: 'Vault protection could not be prepared.',
    sharedWorkspaceRestartPending: false,
    window: { wormhole: bridge },
    SettingsTabPanel: 'panel',
    SettingsSection: 'section',
    VaultPresenceSettings: 'presence-settings',
    VaultSecurityProfile: 'security-profile',
    Button: 'button',
  });
  assert.equal(view.props.value, 'security');
  const vaultSection = view.props.children.find(
    (child: any) => child?.props?.title === 'Encrypted vault',
  );
  assert.ok(vaultSection);
  const children = vaultSection.props.children;
  assert.equal(
    children.find((child: any) => child?.type === 'security-profile')?.props.api,
    bridge,
  );
  const button = children.find((child: any) => child?.props?.children === 'Lock vault');
  const alert = children.find((child: any) => child?.props?.role === 'alert');
  assert.equal(alert.props.children, 'Vault protection could not be prepared.');
  assert.equal(button.type, 'button');
  assert.equal(button.props.children, 'Lock vault');
  button.props.onClick();
  assert.equal(locks, 1);
  bridge.lockAuthentication = async () => {
    throw Error('shutdown unconfirmed');
  };
  button.props.onClick();
  await new Promise(setImmediate);
  const exportButton = children.find(
    (child: any) => child?.props?.children === 'Export encrypted vault backup…',
  );
  assert.ok(exportButton);
  exportButton.props.onClick();
  assert.equal(exportBusy, true);
  await new Promise(setImmediate);
  assert.equal(exported, 1);
  assert.equal(exportSaved, true);
  assert.equal(exportBusy, false);
  assert.equal(exportError, '');
  bridge.exportLocalVaultBackup = async () => {
    throw Error('internal detail');
  };
  exportButton.props.onClick();
  await new Promise(setImmediate);
  assert.equal(exportSaved, false);
  assert.equal(exportBusy, false);
  assert.equal(exportError, 'Could not save the encrypted vault backup.');
});

test('shared workspace creation binds restart selection to the current local owner', async (t) => {
  const filename = 'wormhole-shared-creation-main.js';
  const verify = await measure(t, filename);
  const source = stripTypeScriptTypes(
    cut(
      main,
      "  ipcMain.handle('vault:create-shared-workspace'",
      '  registerSharedAdminRecoveryIpc(',
    ),
  );
  let create!: (...args: unknown[]) => Promise<unknown>;
  let selected: string | undefined = 'local-owner';
  let shared = false;
  let trusted = true;
  let fresh = false;
  let remembered = 0;
  let unlocked = 0;
  let switchRequested: boolean | undefined;
  let whileJoining = () => {};
  const restart = { switchOnRestart: true };
  const admission = { admitted: true, tls: 'verified' };
  const context = {
    ipcMain: { handle: (_name: string, handler: typeof create) => (create = handler) },
    authLocksInProgress: 0,
    isTrustedVaultSender: () => trusted,
    isSharedInitialStartup: () => fresh,
    vaultBackend: {
      startup: async () => ({}),
      get unlockedWorkspaceId() {
        return selected;
      },
      get isSharedWorkspace() {
        return shared;
      },
      get isVaultWorkspace() {
        return selected !== undefined;
      },
    },
    BrowserWindow: { fromWebContents: (sender: unknown) => sender },
    vaultSharedSetupDialog: {
      async open(
        _parent: unknown,
        accepted: () => boolean,
        join: () => boolean,
        restartMode: boolean,
      ) {
        assert.equal(accepted(), true);
        switchRequested = restartMode;
        whileJoining();
        return join() ? (restartMode ? restart : admission) : undefined;
      },
    },
    vaultAuthState: () => ({}),
    rememberAuthState: () => {
      remembered++;
    },
    authSession: {
      markUnlocked: () => {
        unlocked++;
      },
    },
  };
  runInNewContext(source, context, { filename });
  const event = { sender: {} };
  assert.equal(await create(event), restart);
  assert.equal(switchRequested, true);
  assert.equal(remembered + unlocked, 0);
  whileJoining = () => {
    selected = 'other-local-owner';
  };
  assert.equal(await create(event), undefined);
  whileJoining = () => {};
  selected = undefined;
  await assert.rejects(create(event), /unavailable/);
  await assert.rejects(create({}), /unavailable/);
  await assert.rejects(create(event, 'extra'), /Invalid/);
  fresh = true;
  assert.equal(await create(event), admission);
  assert.equal(switchRequested, false);
  assert.equal(remembered, 1);
  assert.equal(unlocked, 1);
  shared = true;
  await assert.rejects(create(event), /unavailable/);
  shared = false;
  trusted = false;
  await assert.rejects(create(event), /Invalid/);
  trusted = true;
  context.authLocksInProgress = 1;
  await assert.rejects(create(event), /Invalid/);
  await verify();
});

test('fresh workspace restore opens a modal without changing startup selection', async () => {
  const source = stripTypeScriptTypes(
    cut(renderer, 'function showNewWorkspace(', 'async function bootstrap('),
  );
  const children: Array<{
    textContent: string;
    disabled: boolean;
    onclick: (() => Promise<void>) | undefined;
  }> = [];
  let openCount = 0;
  let localCount = 0;
  let result = deferred<void>();
  let localResult = deferred<boolean>();
  const context = {
    startupGeneration: 1,
    window: {
      wormhole: {
        markStartupReady: () => {},
        prepareSharedWorkspaceRestore: () => {
          openCount++;
          return result.promise;
        },
        restoreLocalVaultBackup: () => {
          localCount++;
          return localResult.promise;
        },
      },
    },
    document: {
      createElement: () => ({
        textContent: '',
        disabled: false,
        setAttribute() {},
        addEventListener() {},
      }),
    },
    renderCard: () => ({ append: (...elements: typeof children) => children.push(...elements) }),
    bootstrap: () => assert.fail('Restore preparation must not switch the selected workspace.'),
  };
  runInNewContext(source + '\nshowNewWorkspace(true);', context);
  const restore = children.find(({ textContent }) => textContent === 'Restore a shared workspace')!;
  assert.ok(restore.onclick);
  const opening = restore.onclick();
  assert.ok(children.slice(1).every(({ disabled }) => disabled));
  await restore.onclick();
  assert.equal(openCount, 1);
  result.resolve(undefined);
  await opening;
  assert.ok(children.every(({ disabled }) => !disabled));
  const local = children.find(
    ({ textContent }) => textContent === 'Restore an encrypted vault backup',
  )!;
  const canceled = local.onclick!();
  assert.ok(children.slice(1).every(({ disabled }) => disabled));
  await restore.onclick();
  assert.equal(openCount, 1);
  localResult.resolve(false);
  await canceled;
  assert.equal(localCount, 1);
  assert.ok(children.every(({ disabled }) => !disabled));
  for (const stale of [false, true]) {
    children[0].textContent = '';
    result = deferred<void>();
    const pending = restore.onclick();
    if (stale) context.startupGeneration++;
    result.reject(Error('internal detail'));
    await pending;
    assert.equal(
      children[0].textContent,
      stale ? '' : 'Could not open the workspace restore window.',
    );
  }
  context.startupGeneration = 1;
  localResult = deferred<boolean>();
  const restarting = local.onclick!();
  localResult.resolve(true);
  await restarting;
  assert.match(children[0].textContent, /Restarting to open your restored vault/);
  assert.ok(children.slice(1).every(({ disabled }) => disabled));
});

test('native selection closes app authorization and only the trusted unlock callback restores it', async () => {
  const { AuthSession } = await import('../electron/auth-session.ts');
  const auth = new AuthSession();
  auth.remember({ configured: false }, true);
  let selected!: () => void, unlocked!: () => void;
  const initialization = cut(
    main,
    'const vaultBackend = new VaultBackendHost(',
    'const vaultCreateDialog =',
  );
  const register = cut(
    main,
    '  registerVaultIpc(',
    "  ipcMain.on('lifecycle:close-confirmation-ready'",
  );
  const activate = cut(
    main,
    '  const activateVaultSession = () => {',
    '  registerVaultPresenceIpc(',
  );
  let fresh: any, prepare: any;
  const nativeKeys = new WeakMap(),
    nativeCertificates = new WeakMap();
  const checkedEpochs: number[] = [];
  let trusted = true;
  let parent: object | undefined = {};
  let captured: any[] | undefined;
  const event = { sender: {} };
  const api = { unlockedWorkspaceId: undefined as string | undefined };
  runInNewContext(stripTypeScriptTypes(initialization + activate + register), {
    vaultMigrationBoot: { legacyMigrationRequired: true },
    VaultBackendHost: class {
      constructor(_create: any, _can: any, _activate: any, select: () => void, legacy: boolean) {
        assert.equal(legacy, true);
        selected = select;
        return api;
      }
    },
    authSession: auth,
    vaultLockMonitor: {},
    rememberAuthState: (state: any, assume: boolean) => auth.remember(state, assume),
    vaultAuthState: () => ({ configured: true }),
    registerVaultIpc: (
      _ipc: any,
      _host: any,
      _trust: any,
      complete: () => void,
      confirm: any,
      prepareCredential: any,
    ) => {
      unlocked = complete;
      fresh = confirm;
      prepare = prepareCredential;
    },
    ipcMain: {},
    isTrustedVaultSender: (candidate: any) => trusted && candidate === event,
    BrowserWindow: {
      fromWebContents: (sender: any) => (sender === event.sender ? parent : undefined),
    },
    prepareVaultCredentialSelections,
    sshPrivateKeySelections: nativeKeys,
    sshCertificateSelections: nativeCertificates,
    requireAuthorizationEpoch: (epoch: number) => checkedEpochs.push(epoch),
    vaultReauthenticationDialog: {
      open: async (...args: any[]) => {
        captured = args;
        return 'confirmed';
      },
    },
  });
  selected();
  const keyId = '11111111-1111-4111-8111-111111111111';
  nativeKeys.set(event.sender, { id: keyId, path: 'main-owned-path', authorizationEpoch: 7 });
  const credential = prepare(event, {
    metadata: { privateKeySelectionId: keyId, certificateSelectionId: '' },
    password: new Uint8Array(),
    passphrase: new Uint8Array(),
    rowVersion: '0',
  });
  assert.equal(credential.metadata.privateKeyPath, 'main-owned-path');
  assert.deepEqual(checkedEpochs, [7]);
  assert.equal(nativeKeys.has(event.sender), false);
  assert.equal(auth.isAccessAllowed, false);
  assert.throws(unlocked, /locked/);
  api.unlockedWorkspaceId = descriptor.vaultId;
  unlocked();
  assert.equal(auth.isAccessAllowed, true);
  const release = auth.holdLock();
  assert.throws(unlocked, /locked during verification/);
  release();
  const submit = async () => ({ saved: true });
  assert.equal(await fresh(event)('folder-save', descriptor, submit), 'confirmed');
  assert.equal(captured![0], parent);
  assert.equal(captured![2], 'folder-save');
  assert.equal(captured![3], descriptor);
  assert.equal(captured![4], submit);
  const accepted = captured![1];
  assert.equal(accepted(), true);
  trusted = false;
  assert.equal(accepted(), false);
  await assert.rejects(fresh(event)('folder-save', descriptor, submit), /unavailable/);
  trusted = true;
  api.unlockedWorkspaceId = undefined;
  assert.equal(accepted(), false);
  parent = undefined;
  await assert.rejects(fresh(event)('folder-save', descriptor, submit), /unavailable/);
});

test('legacy background maintenance stays dormant across native selection including an already queued timer', () => {
  const code = stripTypeScriptTypes(
    cut(main, 'function scheduleUnlockedBackgroundWork()', 'authSession.onUnlocked(') +
      '\nscheduleUnlockedBackgroundWork;',
  );
  let timer: (() => void) | undefined;
  let work = 0;
  const vault = { isVaultWorkspace: true, requiresLegacyMigration: false };
  const window = { isDestroyed: () => false };
  const environment = {
    vaultBackend: vault,
    BrowserWindow: { getAllWindows: () => [window] },
    startupReadyWindows: new Set([window]),
    authSession: { isAccessAllowed: true, authorizationEpoch: 1 },
    isQuitting: false,
    startupBackgroundTimer: undefined,
    startupBackgroundDelayMs: 1,
    setTimeout: (fn: () => void) => {
      timer = fn;
      return 1;
    },
    startBitwardenBackgroundMaintenance: () => {
      work++;
    },
    showBitwardenOnboardingNoticeIfNeeded: async () => {},
    sshBackend: { syncMcpAfterUnlock: async () => {} },
    console,
  };
  const schedule = runInNewContext(code, environment);
  schedule();
  assert.equal(timer, undefined);
  vault.isVaultWorkspace = false;
  schedule();
  assert.ok(timer);
  vault.isVaultWorkspace = true;
  timer();
  assert.equal(work, 0);
  vault.isVaultWorkspace = false;
  schedule();
  timer!();
  assert.equal(work, 1);
  timer = undefined;
  vault.requiresLegacyMigration = true;
  schedule();
  assert.equal(timer, undefined);
  vault.requiresLegacyMigration = false;
  schedule();
  vault.requiresLegacyMigration = true;
  timer!();
  assert.equal(work, 1);
});

test('main notes IPC opens only a trusted main-owned destination and returns no content', async (t) => {
  const filename = 'wormhole-notes-main.js';
  const verify = await measure(t, filename);
  const source = cut(
    main,
    "  ipcMain.handle('vault:show-notes'",
    "  ipcMain.handle('vault:show-credentials'",
  );
  let handler: any,
    trusted = true,
    parent: any = {},
    opened: any;
  runInNewContext(
    stripTypeScriptTypes(source),
    {
      ipcMain: {
        handle: (name: string, fn: any) => {
          assert.equal(name, 'vault:show-notes');
          handler = fn;
        },
      },
      isTrustedVaultSender: () => trusted,
      BrowserWindow: { fromWebContents: () => parent },
      vaultNotesDialog: {
        open: async (p: any, accepted: any, value: any) => {
          opened = { p, accepted, value };
          return 'not forwarded';
        },
      },
    },
    { filename },
  );
  const selection = { nodeId: connectionNodeId, rowVersion: '1' };
  await assert.rejects(handler({}));
  await assert.rejects(handler({}, selection, 1));
  trusted = false;
  await assert.rejects(handler({}, selection));
  trusted = true;
  parent = undefined;
  await assert.rejects(handler({}, selection));
  parent = {};
  assert.equal(await handler({}, selection), undefined);
  assert.equal(opened.p, parent);
  assert.deepEqual(opened.value, selection);
  assert.equal(opened.accepted(), true);
  trusted = false;
  assert.equal(opened.accepted(), false);
  assert.match(
    cut(main, 'async function lockApplication(', 'function registerIpcHandlers('),
    /vaultNotesDialog.cancel\(\)/,
  );
  await verify();
});

test('actual editor migration callbacks share the mutation guard and advance only the current editor revision', async (t) => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const first = app.indexOf('<VaultMigrationChoices'),
    last = app.indexOf('/>', first) + 2;
  assert.ok(first > 0 && last > first);
  const compiled = await transformWithOxc(app.slice(first, last), 'migration-parent.tsx', {
    jsx: { runtime: 'classic' },
  });
  const filename = 'wormhole-migration-parent.js',
    verify = await measure(t, filename);
  const pending = { current: false },
    generation = { current: 2 },
    revision = { current: '2' },
    busy: boolean[] = [],
    errors: string[] = [];
  let failRefresh = false,
    refreshes = 0;
  const environment: any = {
    React: { createElement: (_type: any, props: any) => props },
    VaultMigrationChoices: () => {},
    editingConnectionId: connectionNodeId,
    editingConnectionVersion: revision,
    connectionSavePending: pending,
    connectionEditorGeneration: generation,
    migrationEditorGeneration: 2,
    editorBusy: false,
    setEditorBusy: (v: boolean) => busy.push(v),
    refreshWorkspace: async () => {
      refreshes++;
      if (failRefresh) throw Error('private');
    },
    setTreeMoveError: (v: string) => errors.push(v),
  };
  const props = runInNewContext(compiled.code.replace(/;\s*$/, ''), environment, { filename });
  assert.equal(props.nodeId, connectionNodeId);
  assert.equal(props.rowVersion, '2');
  assert.equal(props.beginChange(), true);
  assert.equal(props.beginChange(), false);
  props.endChange();
  environment.editorBusy = true;
  assert.equal(props.beginChange(), false);
  assert.deepEqual(busy, [true, false]);
  props.onCommitted('3');
  assert.equal(revision.current, '3');
  assert.equal(refreshes, 1);
  failRefresh = true;
  props.onCommitted('4');
  await new Promise(setImmediate);
  assert.equal(errors.length, 1);
  assert.ok(!errors[0].includes('private'));
  assert.equal(revision.current, '4');
  failRefresh = false;
  await props.refreshAfterFailure();
  assert.equal(refreshes, 3);
  generation.current++;
  props.onCommitted('5');
  assert.equal(revision.current, '4');
  assert.equal(refreshes, 3);
  await props.refreshAfterFailure();
  assert.equal(refreshes, 3);
  await verify();
});

test('native credential completion refreshes committed metadata and preserves the originating connection editor', async (t) => {
  const filename = 'wormhole-native-credential-completion.js',
    verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const code = stripTypeScriptTypes(
    cut(app, '  async function saveVaultCredential(', '  async function createCredential(') +
      '\nsaveVaultCredential;',
  );
  for (const mode of [
    'success',
    'standalone',
    'no-editor',
    'stale-editor',
    'stale-updater',
    'refresh-error',
    'save-error',
    'legacy',
    'missing',
  ]) {
    let writes = 0,
      refreshes = 0,
      message = '',
      selected: any;
    const editor = mode === 'no-editor' ? null : { fromConnection: mode !== 'standalone' },
      ref = { current: editor };
    const request = { password: new Uint8Array([1]) };
    const save = runInNewContext(
      code,
      {
        window: {
          wormhole:
            mode === 'missing'
              ? undefined
              : {
                  editVaultCredential: async (value: any) => {
                    assert.equal(value, request);
                    writes++;
                    if (mode === 'save-error') throw Error('native rejected');
                    if (mode === 'stale-editor') ref.current = null;
                    return { id: 'saved' };
                  },
                },
        },
        authState: { mode: mode === 'legacy' ? 'password' : 'vault' },
        sshKeyEditor: editor,
        sshKeyEditorRef: ref,
        refreshWorkspace: async () => {
          refreshes++;
          if (mode === 'refresh-error') throw Error('refresh');
        },
        setTreeMoveError: (value: string) => (message = value),
        setNewConnectionForm: (fn: any) => {
          if (mode === 'stale-updater') ref.current = null;
          selected = fn({ host: 'keep', inlinePassword: 'before' });
        },
      },
      { filename },
    );
    if (['save-error', 'legacy', 'missing'].includes(mode)) {
      await assert.rejects(save(request));
      assert.equal(refreshes, 0);
    } else {
      assert.equal(await save(request), mode !== 'refresh-error');
      assert.equal(writes, 1);
      assert.equal(refreshes, 1);
      if (mode === 'success') {
        assert.equal(selected.credential, 'saved');
        assert.equal(selected.host, 'keep');
        assert.equal(selected.inlinePassword, '');
      } else if (mode === 'stale-updater') assert.equal(selected.inlinePassword, 'before');
      else assert.equal(selected, undefined);
      assert.equal(Boolean(message), mode === 'refresh-error');
    }
  }
  await verify();
});

test('credential removal sends the revision captured when confirmation opened, even after refresh', async (t) => {
  const filename = 'wormhole-native-credential-removal.js',
    verify = await measure(t, filename);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const code = stripTypeScriptTypes(
    cut(
      app,
      '  async function deleteSavedCredential(',
      '  async function refreshWorkspaceCredentials(',
    ) + '\ndeleteSavedCredential;',
  );
  for (const mode of [
    'native',
    'legacy',
    'no-version',
    'missing',
    'refused',
    'refused-reason',
    'refresh-error',
  ]) {
    const sent: any[] = [];
    let records = [{ id: 'target' }, { id: 'other' }],
      options = { ssh: records, rdp: records, vnc: records, smb: records };
    const remove = runInNewContext(
      code,
      {
        window: {
          wormhole:
            mode === 'missing'
              ? undefined
              : {
                  deleteVaultCredential: async (value: any) => {
                    sent.push(value);
                    return { deleted: true };
                  },
                  deleteCredential: async (value: any) => {
                    sent.push(value);
                    return mode.startsWith('refused')
                      ? {
                          deleted: false,
                          ...(mode === 'refused-reason' ? { error: 'denied' } : {}),
                        }
                      : { deleted: true };
                  },
                },
        },
        authState: { mode: mode === 'native' || mode === 'no-version' ? 'vault' : 'password' },
        setCredentials: (fn: any) => (records = fn(records)),
        setCredentialOptions: (fn: any) => (options = fn(options)),
        refreshWorkspaceCredentials: async () => {
          if (mode === 'refresh-error') throw Error('refresh');
        },
      },
      { filename },
    );
    if (mode === 'missing' || mode.startsWith('refused')) {
      await assert.rejects(remove('target', '7'));
      assert.equal(records.length, 2);
    } else {
      await remove('target', mode === 'no-version' ? undefined : '7');
      await new Promise(setImmediate);
      assert.equal(records.length, 1);
      assert.equal(options.ssh[0].id, 'other');
      assert.equal(options.rdp.length, 1);
      assert.equal(options.vnc.length, 1);
      assert.equal(options.smb.length, 1);
      assert.equal(sent[0].id, 'target');
      if (mode === 'native') assert.equal(sent[0].rowVersion, '7');
      if (mode === 'no-version') assert.equal(sent[0].rowVersion, '');
    }
  }
  const revisions = { current: new Map() },
    byId = new Map([
      ['target', { rowVersion: '7' }],
      ['no-version', {}],
    ]);
  let pending: any;
  const capture = runInNewContext(
    stripTypeScriptTypes(
      cut(app, '  function requestCredentialDeletion(', '  async function submitCredential(') +
        '\nrequestCredentialDeletion;',
    ),
    {
      deletionVersions: revisions,
      credentialById: byId,
      setPendingDeletion: (value: any) => (pending = value),
    },
    { filename },
  );
  capture(['target', 'no-version', 'missing']);
  byId.set('target', { rowVersion: '8' });
  assert.equal(revisions.current.get('target'), '7');
  assert.equal(revisions.current.get('missing'), undefined);
  assert.equal(pending.length, 3);
  await verify();
});
