import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import {
  connectionEditRequiresReconnect,
  type ConnectionEditForm,
} from '../src/connection-edit-state.ts';
import { sessionRuntimeRetryKeys } from '../src/session-lifecycle.ts';
import {
  connectionInlinePasswordAction,
  connectionUsesSavedCredentials,
} from '../src/credential-state.ts';
import { connectionProtocolSupportsTunnel } from '../src/quick-connect-state.ts';
import { savedConnectionAddressForEditor } from '../src/web-address.ts';
import { tunnelValueFor } from '../src/tunnel-state.ts';

const original: ConnectionEditForm = {
  name: 'Server',
  notes: '',
  protocol: 'ssh',
  host: 'server.example',
  port: '22',
  folder: '',
  username: 'alice',
  inlinePassword: '',
  removeInlinePassword: false,
  sshAutoSudo: 'inherit',
  httpIgnoreCertErrors: false,
  tunnel: 'inherit',
  useSavedCredentials: true,
  credential: 'inherit',
  serial: { baudRate: 9600, dataBits: 8, stopBits: 1, parity: 0, flowControl: 0 },
  rdp: { domain: '', redirectClipboard: true },
};

test('renaming, editing notes, or saving unchanged defaults preserves the session', () => {
  assert.equal(connectionEditRequiresReconnect(original, { ...original }), false);
  assert.equal(
    connectionEditRequiresReconnect(original, { ...original, name: 'Renamed', notes: 'Updated' }),
    false,
  );
  assert.equal(
    connectionEditRequiresReconnect(original, {
      ...original,
      serial: { ...(original.serial as object) },
      rdp: { redirectClipboard: true, domain: '' },
    }),
    false,
  );
});

test('connection settings, password actions, and nested protocol options require reconnection', () => {
  for (const [field, value] of Object.entries(original)) {
    if (field === 'name' || field === 'notes') continue;
    const changed =
      typeof value === 'object'
        ? { ...value, [Object.keys(value)[0]]: 'changed' }
        : typeof value === 'boolean'
          ? !value
          : `${value}-changed`;
    assert.equal(
      connectionEditRequiresReconnect(original, { ...original, [field]: changed }),
      true,
      field,
    );
  }
  assert.equal(connectionEditRequiresReconnect(null, original), true);
  assert.equal(connectionEditRequiresReconnect(original, { ...original, rdp: {} }), true);
  assert.equal(connectionEditRequiresReconnect(original, { ...original, rdp: 'changed' }), true);
});

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const rdpDefaultsStart = app.indexOf('const defaultRdpSettings:');
const rdpDefaultsEnd = app.indexOf('\nconst rootFolderSelectionValue', rdpDefaultsStart);
assert.ok(rdpDefaultsStart >= 0 && rdpDefaultsEnd > rdpDefaultsStart);
const defaultRdpSettings = runInNewContext(
  `${stripTypeScriptTypes(app.slice(rdpDefaultsStart, rdpDefaultsEnd))}\ndefaultRdpSettings;`,
);
function handlerSource(name: string, next: string): string {
  const start = app.indexOf(`  ${name}`);
  const end = app.indexOf(`\n  ${next}`, start);
  assert.ok(start >= 0 && end > start);
  return stripTypeScriptTypes(app.slice(start, end));
}
const saveSource = handlerSource(
  'async function submitNewConnection(',
  'async function submitFolderDetails(',
);
const editSource = handlerSource('function openEditConnection(', 'function openEditFolder(');

function editorHarness(
  protocol: string,
  options: { updated?: boolean; saveError?: boolean; refreshError?: boolean } = {},
) {
  const node = {
    id: 'connection',
    name: 'Server',
    kind: 'connection',
    protocol,
    host: protocol === 'serial' ? 'COM1' : 'server.example',
    port: protocol === 'serial' ? undefined : 22,
  };
  const session = {
    id: 'session-connection',
    nodeId: node.id,
    title: node.name,
    protocol,
    status: 'connected',
    backendSessionId: 'native-original',
    mcpAccessible: true,
    terminalFrame: { text: 'existing scrollback' },
    sftp: { path: '/home/alice' },
    rdpStatus: 'connected',
    vncConnectionGeneration: 7,
    webUrl: 'https://server.example/current',
  };
  let sessions = [session, { ...session, id: 'unrelated', nodeId: 'other' }];
  const writes: Record<string, unknown>[] = [];
  const effects: string[] = [];
  let error = '';
  let busy = false;
  let open = true;
  const context: Record<string, any> = {
    Error,
    tree: [node],
    sessions,
    editingConnectionId: null,
    newConnectionForm: original,
    initialConnectionEditForm: { current: null },
    connectionNotesReady: true,
    connectionEditorCredentialSelectionComplete: true,
    editorBusy: false,
    canConfigureConnectionSshAutoSudo: false,
    defaultRdpSettings,
    window: {
      wormhole: {
        updateWorkspaceNode: async (write: Record<string, unknown>) => {
          writes.push(write);
          if (options.saveError) throw new Error('Save failed');
          return { updated: options.updated ?? true };
        },
      },
      setTimeout: (callback: () => void) => callback(),
    },
    setConnectionNotesReady: () => {},
    setConnectionEditorMode: () => {},
    setSelectedNodeId: () => {},
    setEditingConnectionId: (id: string | null) => {
      context.editingConnectionId = id;
    },
    setEditorError: (value: string) => {
      error = value;
    },
    setEditorBusy: (value: boolean) => {
      busy = value;
    },
    setNewConnectionOpen: (value: boolean) => {
      open = value;
    },
    setNewConnectionForm: (value: any) => {
      context.newConnectionForm =
        typeof value === 'function' ? value(context.newConnectionForm) : value;
    },
    setSessions: (update: (current: typeof sessions) => typeof sessions) => {
      sessions = update(sessions);
    },
    setExpanded: () => {},
    findTreeNode: () => node,
    findParentFolderId: () => '',
    savedConnectionAddressForEditor,
    autoSudoModeFor: () => 'inherit',
    tunnelModeFor: () => 'inherit',
    connectionUsesSavedCredentials,
    credentialSelectionFor: () => 'inherit',
    serialSettingsFromNode: () => original.serial,
    effectiveSshAutoSudoMode: () => 'inherit',
    connectionProtocolSupportsTunnel,
    tunnelValueFor,
    credentialSettingsFor: () => ({ mode: 0, credentialId: '' }),
    connectionInlinePasswordAction,
    autoSudoValueFor: () => null,
    connectionEditRequiresReconnect,
    sessionRuntimeRetryKeys,
    runtimeBitwardenRetries: { remove: () => effects.push('remove retry'), isEmpty: false },
    rdpSavedCredentialAttempts: { current: { delete: () => effects.push('clear credentials') } },
    rdpCredentialPrompt: null,
    sshCredentialPrompt: null,
    sshKeyPassphrasePrompt: null,
    bitwardenUnlockPrompt: null,
    releaseSessionResources: async () => {
      effects.push('release');
    },
    sessionResourceReleaseGate: { current: { reset: () => effects.push('reset release gate') } },
    clearSftpCancelRequestsForBrowser: () => effects.push('clear sftp'),
    sftpCancelRequests: { current: {} },
    newSessionToken: () => 'native-restarted',
    refreshWorkspace: async () => {
      effects.push('refresh');
      if (options.refreshError) throw new Error('Refresh failed');
    },
    startSshSession: () => effects.push('start ssh'),
    savedSerialNodeId: (id: string) => id,
    startSerialSession: () => effects.push('start serial'),
    refreshRdpSystemClientCapability: () => effects.push('refresh rdp'),
    requestRdpCredentials: () => effects.push('start rdp'),
    startWebSession: () => effects.push('start web'),
  };
  const edit = runInNewContext(`${editSource}\nopenEditConnection;`, context);
  const save = runInNewContext(`${saveSource}\nsubmitNewConnection;`, context);
  edit(node);
  return {
    context,
    session,
    writes,
    effects,
    save: () => save({ preventDefault() {} }),
    get sessions() {
      return sessions;
    },
    get error() {
      return error;
    },
    get busy() {
      return busy;
    },
    get open() {
      return open;
    },
  };
}

for (const protocol of ['ssh', 'rdp', 'vnc', 'serial', 'http', 'https']) {
  test(`${protocol}: the real editor save updates the title without releasing or restarting the session`, async () => {
    const harness = editorHarness(protocol);
    const unrelated = harness.sessions[1];
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      name: ' Renamed ',
      notes: 'Notes',
    };
    await harness.save();
    assert.equal(harness.writes.length, 1);
    assert.equal(harness.writes[0].name, 'Renamed');
    assert.equal(harness.writes[0].notes, 'Notes');
    assert.equal(harness.writes[0].inlinePasswordAction, 'clear');
    assert.deepEqual({ ...harness.sessions[0] }, { ...harness.session, title: 'Renamed' });
    assert.equal(harness.sessions[1], unrelated);
    assert.deepEqual(harness.effects, ['refresh']);
    assert.equal(harness.error, '');
    assert.equal(harness.busy, false);
    assert.equal(harness.open, false);
  });

  test(`${protocol}: changing the host still releases and restarts the session`, async () => {
    const harness = editorHarness(protocol);
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      name: 'Renamed',
      host: protocol === 'serial' ? 'COM2' : 'new.example',
    };
    await harness.save();
    assert.equal(harness.error, '');
    assert.ok(harness.effects.includes('release'));
    assert.equal(harness.sessions[0].host, protocol === 'serial' ? 'COM2' : 'new.example');
    assert.equal(harness.sessions[0].title, 'Renamed');
    if (protocol === 'vnc') assert.equal(harness.sessions[0].vncConnectionGeneration, 8);
    else
      assert.ok(
        harness.effects.includes(
          `start ${protocol === 'http' || protocol === 'https' ? 'web' : protocol}`,
        ),
      );
  });
}

test('failed rename saves leave the active session and editor intact', async () => {
  for (const options of [{ updated: false }, { saveError: true }]) {
    const harness = editorHarness('ssh', options);
    harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
    await harness.save();
    assert.equal(harness.sessions[0], harness.session);
    assert.deepEqual(harness.effects, []);
    assert.ok(harness.error);
    assert.equal(harness.busy, false);
    assert.equal(harness.open, true);
  }
});

test('a refresh failure after saving the rename still preserves runtime resources', async () => {
  const harness = editorHarness('ssh', { refreshError: true });
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
  await harness.save();
  assert.deepEqual({ ...harness.sessions[0] }, { ...harness.session, title: 'Renamed' });
  assert.deepEqual(harness.effects, ['refresh']);
  assert.equal(harness.error, 'Refresh failed');
  assert.equal(harness.busy, false);
});

test('renaming an inactive session preserves its status instead of reconnecting', async () => {
  for (const status of ['connecting', 'closed', 'failed']) {
    const harness = editorHarness('ssh');
    const inactive = { ...harness.session, status };
    harness.context.setSessions(() => [inactive]);
    harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
    await harness.save();
    assert.deepEqual({ ...harness.sessions[0] }, { ...inactive, title: 'Renamed' });
    assert.deepEqual(harness.effects, ['refresh']);
  }
});

test('saving a rename preserves session events received while persistence is pending', async () => {
  const harness = editorHarness('ssh');
  const pending = Promise.withResolvers<{ updated: boolean }>();
  harness.context.window.wormhole.updateWorkspaceNode = () => pending.promise;
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
  const saving = harness.save();
  const live = {
    ...harness.session,
    status: 'closed',
    mcpAccessible: false,
    terminalFrame: { text: 'output received during save' },
    sftp: { path: '/new/path' },
  };
  harness.context.setSessions(() => [live]);
  pending.resolve({ updated: true });
  await saving;
  assert.deepEqual({ ...harness.sessions[0] }, { ...live, title: 'Renamed' });
  assert.equal(harness.sessions[0].terminalFrame, live.terminalFrame);
  assert.equal(harness.sessions[0].sftp, live.sftp);
  assert.deepEqual(harness.effects, ['refresh']);
});

test('a session closed during a pending rename is not recreated', async () => {
  const harness = editorHarness('ssh');
  const pending = Promise.withResolvers<{ updated: boolean }>();
  harness.context.window.wormhole.updateWorkspaceNode = () => pending.promise;
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
  const saving = harness.save();
  const unrelated = harness.sessions[1];
  harness.context.setSessions(() => [unrelated]);
  pending.resolve({ updated: true });
  await saving;
  assert.equal(harness.sessions.length, 1);
  assert.equal(harness.sessions[0], unrelated);
  assert.deepEqual(harness.effects, ['refresh']);
});

test('renaming a connection without an open session only saves and refreshes the workspace', async () => {
  const harness = editorHarness('ssh');
  harness.context.setSessions(() => []);
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
  await harness.save();
  assert.equal(harness.writes.length, 1);
  assert.equal(harness.sessions.length, 0);
  assert.deepEqual(harness.effects, ['refresh']);
});
