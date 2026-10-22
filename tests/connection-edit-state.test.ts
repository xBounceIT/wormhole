import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import {
  connectionEditCanRestartSession,
  connectionEditRequiresReconnect,
  type ConnectionEditForm,
} from '../src/connection-edit-state.ts';
import {
  canDisconnectRemoteDesktopSession,
  canOpenRdpSystemClient,
  disconnectedRemoteDesktopState,
  SessionCloseGate,
  SessionResourceReleaseGate,
  sessionRuntimeRetryKeys,
} from '../src/session-lifecycle.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import {
  connectionInlinePasswordAction,
  connectionUsesSavedCredentials,
} from '../src/credential-state.ts';
import { connectionProtocolSupportsTunnel } from '../src/quick-connect-state.ts';
import { savedConnectionAddressForEditor } from '../src/web-address.ts';
import { tunnelValueFor } from '../src/tunnel-state.ts';
import { parseWorkspaceRdpSettings } from '../electron/workspace-rdp-contract.ts';

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

test('only live RDP sessions restart after editing; other protocols keep their existing behavior', () => {
  assert.equal(connectionEditCanRestartSession(undefined), false);
  for (const rdpStatus of [undefined, 'idle', 'disconnected', 'failed']) {
    assert.equal(connectionEditCanRestartSession({ protocol: 'rdp', rdpStatus }), false);
  }
  for (const rdpStatus of ['starting', 'connected']) {
    assert.equal(connectionEditCanRestartSession({ protocol: 'rdp', rdpStatus }), true);
  }
  for (const protocol of ['ssh', 'vnc', 'serial', 'http', 'https']) {
    assert.equal(connectionEditCanRestartSession({ protocol }), true);
  }
});

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
  options: {
    updated?: boolean;
    saveError?: boolean;
    refreshError?: boolean;
    screenSize?: string;
    rdpStatus?: string;
  } = {},
) {
  const node = {
    id: 'connection',
    name: 'Server',
    kind: 'connection',
    protocol,
    host: protocol === 'serial' ? 'COM1' : 'server.example',
    port: protocol === 'serial' ? undefined : 22,
    rdp: options.screenSize === undefined ? undefined : { screenSize: options.screenSize },
  };
  const session = {
    id: 'session-connection',
    nodeId: node.id,
    title: node.name,
    protocol,
    status: protocol === 'rdp' ? 'placeholder' : 'connected',
    backendSessionId: protocol === 'ssh' || protocol === 'serial' ? 'native-original' : undefined,
    mcpAccessible: true,
    terminalFrame: { text: 'existing scrollback' },
    sftp: { path: '/home/alice' },
    rdpStatus: options.rdpStatus ?? 'connected',
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
    sessionsRef: { current: sessions },
    rdpEditAttempts: { current: new WebSessionAttemptTracker() },
    sessionCloseGate: { current: { activeSessionIds: () => new Set() } },
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
          if (write.protocol === 'rdp') parseWorkspaceRdpSettings(write.rdp);
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
      context.sessionsRef.current = sessions;
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
    connectionEditCanRestartSession,
    sessionRuntimeRetryKeys,
    runtimeBitwardenRetries: { remove: () => effects.push('remove retry'), isEmpty: false },
    rdpSavedCredentialAttempts: { current: { delete: () => effects.push('clear credentials') } },
    rdpCredentialPrompt: null,
    sshCredentialPrompt: null,
    sshKeyPassphrasePrompt: null,
    setSshCredentialPrompt: () => {},
    setSshCredentialForm: () => {},
    setSshKeyPassphrasePrompt: () => {},
    sshKeyPassphraseInput: { current: null },
    clearSecretInput: () => {},
    bitwardenUnlockPrompt: null,
    releaseSessionResources: async () => {
      context.rdpEditAttempts.current.cancel(session.id);
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
    requestRdpCredentials: () => {
      if (!sessions.some((current) => current.id === session.id)) return;
      context.rdpEditAttempts.current.cancel(session.id);
      effects.push('start rdp');
    },
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

for (const rdpStatus of ['idle', 'disconnected', 'failed', 'starting', 'connected']) {
  test(`RDP ${rdpStatus}: saving credentials with a legacy screen size only restarts a live session`, async () => {
    const harness = editorHarness('rdp', { rdpStatus, screenSize: 'FitToWindow' });
    const unrelated = harness.sessions[1];
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      useSavedCredentials: false,
      username: 'updated-user',
      inlinePassword: 'test-password',
    };
    await harness.save();
    assert.equal(harness.error, '');
    assert.equal(harness.open, false);
    assert.equal(harness.writes.length, 1);
    assert.equal(harness.writes[0].username, 'updated-user');
    assert.equal(harness.writes[0].inlinePasswordAction, 'set');
    assert.equal(harness.writes[0].inlinePassword, 'test-password');
    assert.equal((harness.writes[0].rdp as { screenSize: string }).screenSize, 'FitToWindow');
    const live = rdpStatus === 'starting' || rdpStatus === 'connected';
    assert.ok(harness.effects.includes('release'));
    assert.ok(harness.effects.includes('reset release gate'));
    assert.equal(harness.effects.includes('start rdp'), live);
    assert.equal(harness.effects.includes('refresh rdp'), true);
    assert.equal(harness.sessions[0].rdpStatus, live ? 'idle' : rdpStatus);
    assert.equal(harness.sessions[1], unrelated);
  });
}

test('updating RDP credentials without an open tab does not start a connection', async () => {
  const harness = editorHarness('rdp');
  harness.context.setSessions(() => []);
  harness.context.newConnectionForm = {
    ...harness.context.newConnectionForm,
    credential: 'new-credential',
  };
  await harness.save();
  assert.equal(harness.error, '');
  assert.equal(harness.writes.length, 1);
  assert.equal(harness.sessions.length, 0);
  assert.ok(!harness.effects.includes('start rdp'));
});

test('RDP disconnecting or closing while credentials are being saved is not restarted', async () => {
  for (const closeTab of [false, true]) {
    const harness = editorHarness('rdp');
    const pending = Promise.withResolvers<{ updated: boolean }>();
    harness.context.window.wormhole.updateWorkspaceNode = () => pending.promise;
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      username: 'updated-user',
    };
    const saving = harness.save();
    harness.context.setSessions(() =>
      closeTab ? [] : [{ ...harness.session, rdpStatus: 'disconnected' }],
    );
    pending.resolve({ updated: true });
    await saving;
    assert.equal(harness.error, '');
    assert.ok(!harness.effects.includes('start rdp'));
    assert.equal(harness.sessions.length, closeTab ? 0 : 1);
    if (!closeTab) assert.equal(harness.sessions[0].rdpStatus, 'disconnected');
  }
});

test('failed RDP credential saves preserve the disconnected session without starting it', async () => {
  for (const options of [{ updated: false }, { saveError: true }]) {
    const harness = editorHarness('rdp', { ...options, rdpStatus: 'disconnected' });
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      username: 'updated-user',
    };
    await harness.save();
    assert.equal(harness.sessions[0], harness.session);
    assert.deepEqual(harness.effects, []);
    assert.ok(harness.error);
    assert.equal(harness.open, true);
  }
});

test('new RDP lifecycle actions during resource release supersede the editor restart', async () => {
  for (const action of ['disconnect', 'reopen', 'connect']) {
    const harness = editorHarness('rdp');
    const pending = Promise.withResolvers<void>();
    const entered = Promise.withResolvers<void>();
    harness.context.releaseSessionResources = () => {
      harness.context.rdpEditAttempts.current.cancel(harness.session.id);
      entered.resolve();
      return pending.promise;
    };
    harness.context.newConnectionForm = { ...harness.context.newConnectionForm, username: 'new' };
    const saving = harness.save();
    await entered.promise;
    harness.context.rdpEditAttempts.current.cancel(harness.session.id);
    const replacement = {
      ...harness.session,
      rdpStatus: action === 'disconnect' ? 'disconnected' : 'starting',
      rdpProfile: { name: 'new lifecycle' },
    };
    harness.context.setSessions(() => [replacement]);
    pending.resolve();
    await saving;
    assert.equal(harness.error, '');
    assert.equal(harness.sessions[0], replacement, action);
    assert.ok(!harness.effects.includes('start rdp'), action);
    assert.ok(!harness.effects.includes('reset release gate'), action);
  }
});

test('a newly opened RDP session during persistence is not claimed by the old edit', async () => {
  for (const hadTab of [false, true]) {
    const harness = editorHarness('rdp');
    if (!hadTab) harness.context.setSessions(() => []);
    const pending = Promise.withResolvers<{ updated: boolean }>();
    harness.context.window.wormhole.updateWorkspaceNode = () => pending.promise;
    harness.context.newConnectionForm = { ...harness.context.newConnectionForm, username: 'new' };
    const saving = harness.save();
    harness.context.rdpEditAttempts.current.cancel(harness.session.id);
    const replacement = { ...harness.session, rdpStatus: 'starting' };
    harness.context.setSessions(() => [replacement]);
    pending.resolve({ updated: true });
    await saving;
    assert.equal(harness.error, '');
    assert.equal(harness.sessions[0], replacement);
    assert.deepEqual(harness.effects, ['refresh']);
  }
});

test('a deferred editor restart cannot reconnect a session after another lifecycle action', async () => {
  const harness = editorHarness('rdp');
  const timers: (() => void)[] = [];
  harness.context.window.setTimeout = (callback: () => void) => timers.push(callback);
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, username: 'new' };
  await harness.save();
  assert.equal(timers.length, 1);
  harness.context.rdpEditAttempts.current.cancel(harness.session.id);
  harness.context.setSessions(() => [{ ...harness.session, rdpStatus: 'disconnected' }]);
  timers.forEach((callback) => callback());
  assert.ok(!harness.effects.includes('start rdp'));
});

test('workspace refresh failure after persistence does not leave an edited RDP tab stale', async () => {
  const harness = editorHarness('rdp', { refreshError: true, rdpStatus: 'disconnected' });
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, host: 'new.example' };
  await harness.save();
  assert.equal(harness.writes.length, 1);
  assert.equal(harness.sessions[0].host, 'new.example');
  assert.equal(harness.sessions[0].rdpStatus, 'disconnected');
  assert.ok(!harness.effects.includes('start rdp'));
  assert.equal(harness.error, 'Refresh failed');
});

test('an RDP tab already closing cannot be reclaimed by a save', async () => {
  const harness = editorHarness('rdp');
  const closing = new Set([harness.session.id]);
  harness.context.sessionCloseGate.current.activeSessionIds = () => closing;
  harness.context.releaseSessionResources = async () => {
    closing.clear();
  };
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, username: 'new' };
  await harness.save();
  assert.equal(harness.error, '');
  assert.equal(harness.sessions[0], harness.session);
  assert.ok(!harness.effects.includes('start rdp'));
  assert.ok(!harness.effects.includes('reset release gate'));
});

test('RDP lifecycle entry points invalidate pending editor work before awaiting native I/O', async () => {
  const source = {
    id: 'rdp-tab',
    nodeId: 'saved',
    protocol: 'rdp',
    status: 'placeholder',
    rdpStatus: 'connected',
    rdpSystemClientSupported: true,
  };
  const tracker = new WebSessionAttemptTracker();
  const context: Record<string, any> = {
    sessionsRef: { current: [source] },
    rdpEditAttempts: { current: tracker },
    rdpSessionAttempts: { current: new WebSessionAttemptTracker() },
    rdpSavedCredentialAttempts: { current: new Set() },
    sessionDisconnectGate: { current: new SessionCloseGate() },
    sessionResourceReleaseGate: { current: new SessionResourceReleaseGate() },
    rdpCredentialPrompt: null,
    setSessions: () => {},
    defaultRdpProfile: () => ({}),
    waitForRdpSurfaceBounds: () => new Promise(() => {}),
    canDisconnectRemoteDesktopSession,
    canOpenRdpSystemClient,
    disconnectedRemoteDesktopState,
    sessionRuntimeRetryKeys,
    runtimeBitwardenRetries: { remove() {} },
    window: {
      wormhole: {
        commandRdpSession: async () => ({}),
        openRdpInSystemClient: async () => ({ ok: true }),
      },
    },
  };
  const cases: [string, string, unknown[]][] = [
    [
      'function startRdpSession(',
      'function retryRdpSession(',
      [source.id, { username: '', domain: '', password: '' }, false],
    ],
    [
      'async function disconnectRemoteDesktopSession(',
      'async function openRdpInSystemClient(',
      [source.id],
    ],
    ['async function openRdpInSystemClient(', 'async function submitRdpCredentials(', [source.id]],
    [
      'async function releaseSessionResources(',
      'function handleConfirmOnTabCloseChange(',
      [source],
    ],
  ];
  for (const [start, end, args] of cases) {
    const name = start.replace('async ', '').replace('function ', '').replace('(', '');
    const action = runInNewContext(`${handlerSource(start, end)}\n${name};`, context);
    const generation = tracker.begin(source.id);
    const result = action(...args);
    assert.equal(tracker.isCurrent(source.id, generation), false, name);
    await result;
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
