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
  connectionEditorCredentialSelectionIsComplete,
  connectionInlinePasswordAction,
  connectionUsesSavedCredentials,
} from '../src/credential-state.ts';
import { connectionProtocolSupportsTunnel } from '../src/quick-connect-state.ts';
import { browserHomePageForEditor, savedConnectionAddressForEditor } from '../src/web-address.ts';
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
  rdp: {
    domain: '',
    gatewayCredentialId: '',
    gatewayUseSameCreds: false,
    gatewayHostname: '',
    redirectClipboard: true,
  },
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
      rdp: { ...(original.rdp as object) },
    }),
    false,
  );
});

test('connection settings and non-authentication protocol options still require reconnection', () => {
  for (const [field, value] of Object.entries(original)) {
    if (
      [
        'name',
        'notes',
        'username',
        'inlinePassword',
        'removeInlinePassword',
        'useSavedCredentials',
        'credential',
      ].includes(field)
    )
      continue;
    const changed =
      typeof value === 'object'
        ? { ...value, [field === 'rdp' ? 'redirectClipboard' : Object.keys(value)[0]]: 'changed' }
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

test('authentication changes take effect on the next connection without restarting the current one', () => {
  for (const change of [
    { username: 'bob' },
    { inlinePassword: 'test-password' },
    { removeInlinePassword: true },
    { useSavedCredentials: false },
    { credential: 'saved-credential' },
    { credential: 'none' },
    { rdp: { ...(original.rdp as object), domain: 'EXAMPLE' } },
    { rdp: { ...(original.rdp as object), gatewayCredentialId: 'gateway-credential' } },
    { rdp: { ...(original.rdp as object), gatewayUseSameCreds: true } },
  ]) {
    assert.equal(connectionEditRequiresReconnect(original, { ...original, ...change }), false);
    assert.equal(
      connectionEditRequiresReconnect(original, { ...original, ...change, host: 'other.example' }),
      true,
    );
  }
  const rdp = { redirectClipboard: true, gatewayHostname: '' };
  assert.equal(connectionEditRequiresReconnect(original, { ...original, rdp }), false);
  assert.equal(connectionEditRequiresReconnect({ ...original, rdp }, original), false);
  assert.equal(
    connectionEditRequiresReconnect(original, {
      ...original,
      rdp: { ...rdp, domain: 'EXAMPLE', gatewayHostname: 'gateway.example' },
    }),
    true,
  );
  assert.equal(
    connectionEditRequiresReconnect(original, { ...original, rdp: { ...rdp, newOption: true } }),
    true,
  );
});

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const rdpDefaultsStart = app.indexOf('const defaultRdpSettings:');
const rdpDefaultsEnd = app.indexOf('\nconst rootFolderSelectionValue', rdpDefaultsStart);
assert.ok(rdpDefaultsStart >= 0 && rdpDefaultsEnd > rdpDefaultsStart);
const defaultRdpSettings = runInNewContext(
  `${stripTypeScriptTypes(app.slice(rdpDefaultsStart, rdpDefaultsEnd))}\ndefaultRdpSettings;`,
);
function handlerSource(name: string, next: string, indent = '  '): string {
  const start = app.indexOf(`${indent}${name}`);
  const end = app.indexOf(`\n${indent}${next}`, start);
  assert.ok(start >= 0 && end > start);
  return stripTypeScriptTypes(app.slice(start, end));
}
const saveSource = handlerSource(
  'async function submitNewConnection(',
  'async function submitFolderDetails(',
);
const editSource = handlerSource('function openEditConnection(', 'function openEditFolder(');
const credentialSelectionFor = runInNewContext(
  `${handlerSource('function credentialSelectionFor(', 'function credentialSettingsFor(', '')}\ncredentialSelectionFor;`,
);
const credentialSettingsFor = runInNewContext(
  `${handlerSource('function credentialSettingsFor(', 'function backendErrorMessage(', '')}\ncredentialSettingsFor;`,
);

test('only authentication options are exempt from the complete RDP settings comparison', () => {
  const initial = { ...original, rdp: defaultRdpSettings };
  for (const [key, value] of Object.entries(defaultRdpSettings)) {
    const changed =
      typeof value === 'boolean'
        ? !value
        : typeof value === 'number'
          ? value + 1
          : `${value}-changed`;
    assert.equal(
      connectionEditRequiresReconnect(initial, {
        ...initial,
        rdp: { ...defaultRdpSettings, [key]: changed },
      }),
      !['domain', 'gatewayCredentialId', 'gatewayUseSameCreds'].includes(key),
      key,
    );
  }
});

function editorHarness(
  protocol: string,
  options: {
    updated?: boolean;
    saveError?: boolean;
    refreshError?: boolean;
    screenSize?: string;
    rdpStatus?: string;
    node?: {
      host?: string;
      httpPath?: string;
      credentialMode?: number;
      credentialId?: string;
      hasInlineCredential?: boolean;
      username?: string;
    };
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
    ...options.node,
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
    get connectionEditorCredentialSelectionComplete() {
      const form = context.newConnectionForm;
      return connectionEditorCredentialSelectionIsComplete(
        'saved',
        ['ssh', 'rdp', 'vnc'].includes(form.protocol),
        form.useSavedCredentials,
        form.credential,
      );
    },
    connectionCredentialSelectionError: 'Choose saved credentials.',
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
    browserHomePageForEditor,
    autoSudoModeFor: () => 'inherit',
    tunnelModeFor: () => 'inherit',
    connectionUsesSavedCredentials,
    credentialSelectionFor,
    serialSettingsFromNode: () => original.serial,
    effectiveSshAutoSudoMode: () => 'inherit',
    connectionProtocolSupportsTunnel,
    tunnelValueFor,
    credentialSettingsFor,
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

for (const protocol of ['ssh', 'rdp', 'vnc']) {
  test(`${protocol}: invalid saved credential selections cannot persist or restart sessions`, async () => {
    for (const credential of ['', ' ', 'none']) {
      const harness = editorHarness(protocol);
      harness.context.newConnectionForm = { ...harness.context.newConnectionForm, credential };
      await harness.save();
      assert.equal(harness.writes.length, 0);
      assert.equal(harness.sessions[0], harness.session);
      assert.deepEqual(harness.effects, []);
      assert.ok(harness.error);
      assert.equal(harness.open, true);
      assert.equal(harness.busy, false);
    }
  });

  test(`${protocol}: credential saves preserve concurrent session events and never recreate a closed tab`, async () => {
    for (const status of ['connected', 'connecting', 'closed', 'failed', 'removed']) {
      const harness = editorHarness(protocol);
      const pending = Promise.withResolvers<{ updated: boolean }>();
      harness.context.window.wormhole.updateWorkspaceNode = () => pending.promise;
      harness.context.newConnectionForm = {
        ...harness.context.newConnectionForm,
        credential: 'new-credential',
      };
      const saving = harness.save();
      const live = {
        ...harness.session,
        status,
        rdpStatus:
          status === 'closed' ? 'disconnected' : status === 'connecting' ? 'starting' : status,
        terminalFrame: { text: 'output received during save' },
        sftp: { path: '/new/path' },
      };
      const duplicate = { ...harness.session, id: 'duplicate-session' };
      const unrelated = harness.sessions[1];
      const current = status === 'removed' ? [duplicate, unrelated] : [live, duplicate, unrelated];
      harness.context.setSessions(() => current);
      pending.resolve({ updated: true });
      await saving;
      assert.deepEqual(
        Array.from(harness.sessions, (session) => ({ ...session })),
        current,
      );
      assert.equal(harness.sessions.at(-1), unrelated);
      assert.deepEqual(harness.effects, ['refresh']);
      assert.equal(harness.error, '');
      if (status !== 'removed') {
        assert.equal(harness.sessions[0].terminalFrame, live.terminalFrame);
        assert.equal(harness.sessions[0].sftp, live.sftp);
      }
    }
  });

  test(`${protocol}: saving credential changes preserves the active session and persists authentication`, async () => {
    for (const { change, expectedMode, expectedId } of [
      {
        change: { useSavedCredentials: true, credential: 'saved-credential' },
        expectedMode: 2,
        expectedId: 'saved-credential',
      },
      {
        change: { useSavedCredentials: true, credential: 'inherit' },
        expectedMode: 0,
        expectedId: '',
      },
      { change: { useSavedCredentials: false }, expectedMode: 1, expectedId: '' },
      ...(protocol === 'vnc'
        ? []
        : [
            {
              change: {
                useSavedCredentials: false,
                username: 'bob',
                inlinePassword: 'test-password',
              },
              expectedMode: 1,
              expectedId: '',
            },
            {
              change: { useSavedCredentials: false, removeInlinePassword: true },
              expectedMode: 1,
              expectedId: '',
            },
          ]),
    ]) {
      const harness = editorHarness(protocol, {
        node: { credentialMode: 2, credentialId: 'previous-credential' },
      });
      const unrelated = harness.sessions[1];
      harness.context.newConnectionForm = { ...harness.context.newConnectionForm, ...change };
      await harness.save();
      assert.equal(harness.writes.length, 1);
      const write = harness.writes[0];
      assert.equal(write.credentialMode, expectedMode);
      assert.equal(write.credentialId, expectedId);
      assert.equal(write.username, protocol !== 'vnc' ? (change.username ?? '') : '');
      assert.equal(write.inlinePasswordAction, change.inlinePassword ? 'set' : 'clear');
      assert.equal(write.inlinePassword, change.inlinePassword ?? '');
      assert.deepEqual({ ...harness.sessions[0] }, harness.session);
      assert.equal(harness.sessions[0].terminalFrame, harness.session.terminalFrame);
      assert.equal(harness.sessions[0].sftp, harness.session.sftp);
      assert.equal(harness.sessions[1], unrelated);
      assert.deepEqual(harness.effects, ['refresh']);
      assert.equal(harness.error, '');
      assert.equal(harness.open, false);
      assert.equal(harness.busy, false);
    }
  });
}

for (const protocol of ['ssh', 'rdp']) {
  test(`${protocol}: editing inline credentials preserves the running session and the correct secret action`, async () => {
    for (const { change, action, password } of [
      { change: { username: 'bob' }, action: 'preserve', password: '' },
      {
        change: { inlinePassword: 'replacement-password' },
        action: 'set',
        password: 'replacement-password',
      },
      { change: { removeInlinePassword: true }, action: 'clear', password: '' },
    ]) {
      const harness = editorHarness(protocol, {
        node: { credentialMode: 1, hasInlineCredential: true, username: 'alice' },
      });
      assert.equal(harness.context.newConnectionForm.useSavedCredentials, false);
      harness.context.newConnectionForm = { ...harness.context.newConnectionForm, ...change };
      await harness.save();
      assert.equal(harness.writes.length, 1);
      assert.equal(harness.writes[0].username, change.username ?? 'alice');
      assert.equal(harness.writes[0].inlinePasswordAction, action);
      assert.equal(harness.writes[0].inlinePassword, password);
      assert.equal(harness.writes[0].credentialMode, 1);
      assert.equal(harness.writes[0].credentialId, '');
      assert.deepEqual({ ...harness.sessions[0] }, harness.session);
      assert.deepEqual(harness.effects, ['refresh']);
      assert.equal(harness.error, '');
    }
  });
}

test('RDP domain and gateway credential changes are saved without disconnecting', async () => {
  const harness = editorHarness('rdp');
  const rdp = {
    ...harness.context.newConnectionForm.rdp,
    domain: 'EXAMPLE',
    gatewayCredentialId: '12345678-1234-1234-1234-123456789abc',
    gatewayUseSameCreds: true,
  };
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, rdp };
  await harness.save();
  assert.equal(harness.error, '');
  assert.deepEqual(harness.writes[0].rdp, rdp);
  assert.deepEqual({ ...harness.sessions[0] }, harness.session);
  assert.deepEqual(harness.effects, ['refresh']);
  assert.equal(harness.error, '');
});

test('credential save and refresh failures do not release active sessions', async () => {
  for (const options of [{ updated: false }, { saveError: true }, { refreshError: true }]) {
    const harness = editorHarness('ssh', options);
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      credential: 'new-credential',
    };
    await harness.save();
    assert.deepEqual({ ...harness.sessions[0] }, harness.session);
    assert.deepEqual(harness.effects, options.refreshError ? ['refresh'] : []);
    assert.ok(harness.error);
    assert.equal(harness.open, true);
    assert.equal(harness.busy, false);
  }
});

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
  for (const changeHost of [false, true]) {
    test(`RDP ${rdpStatus}: credentials with a legacy screen size and host change ${changeHost}`, async () => {
      const harness = editorHarness('rdp', { rdpStatus, screenSize: 'FitToWindow' });
      const unrelated = harness.sessions[1];
      harness.context.newConnectionForm = {
        ...harness.context.newConnectionForm,
        useSavedCredentials: false,
        username: 'updated-user',
        inlinePassword: 'test-password',
        ...(changeHost ? { host: 'updated.example' } : {}),
      };
      await harness.save();
      assert.equal(harness.error, '');
      assert.equal(harness.open, false);
      assert.equal(harness.writes.length, 1);
      assert.equal(harness.writes[0].username, 'updated-user');
      assert.equal(harness.writes[0].inlinePasswordAction, 'set');
      assert.equal(harness.writes[0].inlinePassword, 'test-password');
      assert.equal((harness.writes[0].rdp as { screenSize: string }).screenSize, 'FitToWindow');
      const live = changeHost && (rdpStatus === 'starting' || rdpStatus === 'connected');
      assert.equal(harness.effects.includes('release'), changeHost);
      assert.equal(harness.effects.includes('reset release gate'), changeHost);
      assert.equal(harness.effects.includes('start rdp'), live);
      assert.equal(harness.effects.includes('refresh rdp'), changeHost);
      assert.equal(harness.sessions[0].rdpStatus, live ? 'idle' : rdpStatus);
      assert.equal(harness.sessions[1], unrelated);
    });
  }
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
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      host: 'updated.example',
    };
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
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      host: 'updated.example',
    };
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
  harness.context.newConnectionForm = {
    ...harness.context.newConnectionForm,
    host: 'updated.example',
  };
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
  harness.context.newConnectionForm = {
    ...harness.context.newConnectionForm,
    host: 'updated.example',
  };
  await harness.save();
  assert.equal(harness.error, '');
  assert.equal(harness.sessions[0], harness.session);
  assert.ok(!harness.effects.includes('start rdp'));
  assert.ok(!harness.effects.includes('reset release gate'));
});

function rdpLifecycleHarness() {
  const source = {
    id: 'rdp-tab',
    nodeId: 'saved',
    protocol: 'rdp',
    status: 'placeholder',
    rdpStatus: 'connected',
    rdpSystemClientSupported: true,
  };
  const tracker = new WebSessionAttemptTracker();
  const effects: string[] = [];
  const context: Record<string, any> = {
    sessionsRef: { current: [source] },
    rdpEditAttempts: { current: tracker },
    rdpSessionAttempts: { current: new WebSessionAttemptTracker() },
    rdpSavedCredentialAttempts: { current: new Set() },
    sessionDisconnectGate: { current: new SessionCloseGate() },
    sessionCloseGate: { current: new SessionCloseGate() },
    sessionResourceReleaseGate: { current: new SessionResourceReleaseGate() },
    rdpCredentialPrompt: null,
    setSessions: () => {},
    defaultRdpProfile: () => ({}),
    waitForRdpSurfaceBounds: async () => ({ x: 0, y: 0, width: 1024, height: 768 }),
    canDisconnectRemoteDesktopSession,
    canOpenRdpSystemClient,
    disconnectedRemoteDesktopState,
    sessionRuntimeRetryKeys,
    runtimeBitwardenRetries: { remove() {} },
    window: {
      wormhole: {
        commandRdpSession: async () => {
          effects.push('disconnect');
        },
        startRdpSession: async () => {
          effects.push('embedded');
        },
        openRdpInSystemClient: async () => {
          effects.push('system');
          return { ok: true };
        },
      },
    },
  };
  const action = (start: string, end: string) => {
    const name = start.replace('async ', '').replace('function ', '').replace('(', '');
    return runInNewContext(`${handlerSource(start, end)}\n${name};`, context);
  };
  return { source, tracker, context, effects, action };
}

test('RDP lifecycle entry points invalidate pending editor work before awaiting native I/O', async () => {
  const { source, tracker, action } = rdpLifecycleHarness();
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
    const generation = tracker.begin(source.id);
    const result = action(start, end)(...args);
    assert.equal(tracker.isCurrent(source.id, generation), false, start);
    await result;
  }
});

for (const client of ['embedded', 'system']) {
  for (const releaseState of ['none', 'scheduled', 'pending', 'completed']) {
    test(`${client} RDP start renews cleanup after a ${releaseState} editor release`, async () => {
      const { source, context, effects, action } = rdpLifecycleHarness();
      const pending = Promise.withResolvers<void>();
      context.window.wormhole.commandRdpSession = async () => {
        effects.push('disconnect');
        await pending.promise;
      };
      const release = action(
        'async function releaseSessionResources(',
        'function handleConfirmOnTabCloseChange(',
      );
      const releasing = releaseState === 'none' ? Promise.resolve() : release(source);
      if (releaseState === 'pending') await new Promise(setImmediate);
      if (releaseState === 'completed') {
        pending.resolve();
        await releasing;
      }
      const start =
        client === 'embedded'
          ? action('function startRdpSession(', 'function retryRdpSession(')
          : action('async function openRdpInSystemClient(', 'async function submitRdpCredentials(');
      const starting = start(source.id, { username: '', domain: '', password: '' }, false);
      await new Promise(setImmediate);
      if (releaseState === 'scheduled' || releaseState === 'pending') {
        assert.deepEqual(effects, ['disconnect'], 'replacement waits for old native resources');
      }
      pending.resolve();
      await Promise.all([releasing, starting]);
      await new Promise(setImmediate);
      assert.equal(effects.filter((effect) => effect === client).length, 1);
      await release(source);
      assert.deepEqual(
        effects,
        releaseState === 'none' ? [client, 'disconnect'] : ['disconnect', client, 'disconnect'],
      );
      await release(source);
      assert.equal(
        effects.filter((effect) => effect === 'disconnect').length,
        releaseState === 'none' ? 1 : 2,
      );
    });
  }

  for (const cancellation of ['close', 'remove', 'closing']) {
    test(`${client} RDP start cannot resume after ${cancellation} while cleanup is pending`, async () => {
      const { source, context, effects, action } = rdpLifecycleHarness();
      const pending = Promise.withResolvers<void>();
      context.window.wormhole.commandRdpSession = () => pending.promise;
      const release = action(
        'async function releaseSessionResources(',
        'function handleConfirmOnTabCloseChange(',
      );
      const releasing = release(source);
      const start =
        client === 'embedded'
          ? action('function startRdpSession(', 'function retryRdpSession(')
          : action('async function openRdpInSystemClient(', 'async function submitRdpCredentials(');
      const starting = start(source.id, { username: '', domain: '', password: '' }, false);
      await new Promise(setImmediate);
      let closing;
      if (cancellation === 'close') closing = release(source);
      if (cancellation === 'remove') context.sessionsRef.current = [];
      if (cancellation === 'closing') {
        context.sessionCloseGate.current.activeSessionIds = () => new Set([source.id]);
      }
      pending.resolve();
      await Promise.all([releasing, starting, closing]);
      await new Promise(setImmediate);
      assert.deepEqual(effects, []);
    });
  }
}

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

for (const protocol of ['http', 'https']) {
  test(`${protocol}: Browser home page saves preserve the current tab URL`, async () => {
    const harness = editorHarness(protocol, {
      node: {
        host: 'server.example',
        httpPath: '/start?section=network#tab',
      },
    });
    const homePage = `${protocol}://server.example/start?section=network#tab`;
    assert.equal(harness.context.newConnectionForm.host, homePage);
    harness.context.newConnectionForm = {
      ...harness.context.newConnectionForm,
      name: 'Browser connection',
    };
    await harness.save();
    assert.equal(harness.writes[0].protocol, protocol);
    assert.equal(harness.writes[0].host, homePage);
    assert.equal(harness.sessions[0].webUrl, 'https://server.example/current');
    assert.deepEqual(harness.effects, ['refresh']);
  });
}

test('renaming a connection without an open session only saves and refreshes the workspace', async () => {
  const harness = editorHarness('ssh');
  harness.context.setSessions(() => []);
  harness.context.newConnectionForm = { ...harness.context.newConnectionForm, name: 'Renamed' };
  await harness.save();
  assert.equal(harness.writes.length, 1);
  assert.equal(harness.sessions.length, 0);
  assert.deepEqual(harness.effects, ['refresh']);
});
