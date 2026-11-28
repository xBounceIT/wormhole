import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { transformWithOxc } from 'vite';
import { mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import { sshConnectRequest, vaultSshQuickTarget } from '../src/ssh-connect.ts';
import { parseVaultSshOpen } from '../electron/vault-ssh-open.ts';
import { fileSessionMode, isFileBrowserProtocol } from '../src/file-protocol.ts';
import { savedConnectionAddressForEditor } from '../src/web-address.ts';
import { quickConnectStartsImmediately, quickConnectTunnelId } from '../src/quick-connect-state.ts';

const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const names = [
  'startSshSession',
  'submitQuickConnect',
  'openConnection',
  'duplicateSession',
  'restartSession',
  'reconnectSession',
  'requestSshCredentials',
  'startQuickSshSession',
];
const selected: string[] = [];
visitSyntax(mainSyntax(source, true), (node) => {
  if (node.type === 'FunctionDeclaration' && names.includes(node.id?.name))
    selected.push(source.slice(node.start, node.end));
});
assert.equal(selected.length, names.length);
const tick = () => new Promise(setImmediate);

test('actual failed SSH/SFTP surfaces offer only protected temporary and passphrase actions in vault mode', async () => {
  const selected: string[] = [];
  visitSyntax(mainSyntax(source, true), (node) => {
    if (
      node.type === 'FunctionDeclaration' &&
      [
        'SessionSurface',
        'SessionSurfaceContent',
        'SshXtermSurface',
        'SshTerminalConnectionState',
      ].includes(node.id?.name)
    )
      selected.push(source.slice(node.start, node.end));
  });
  assert.equal(selected.length, 4);
  const { code } = await transformWithOxc(
    selected.join('\n') + '\nSessionSurface;',
    'ssh-actions.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const component = runInNewContext(code, {
    React: {
      createElement: (type: any, props: any, ...children: any[]) =>
        typeof type === 'function' ? type({ ...props, children }) : { type, props, children },
    },
    useRef: () => ({ current: null }),
    useState: () => [null, () => {}],
    useEffect() {},
    useLayoutEffect() {},
    ConnectionLoading: 'loading',
    useContext: () => undefined,
    SshCertificateEditorContext: {},
    ConnectionTransition: ({ pending, children }: any) => pending ?? children[0],
    isFileBrowserProtocol,
    protocolLabel: (p: string) => p.toUpperCase(),
    requiresSshCertificateReplacement: () => false,
    Button: 'button',
    LoaderCircle: 'loader',
    AlertCircle: 'alert',
    Terminal: 'terminal',
    RefreshCcw: 'refresh',
  });
  const buttons = (node: any): any[] =>
    !node || typeof node !== 'object'
      ? []
      : [
          ...(node.type === 'button' ? [node] : []),
          ...(node.children ?? []).flatMap((child: any) =>
            Array.isArray(child) ? child.flatMap(buttons) : buttons(child),
          ),
        ];
  for (const protocol of ['ssh', 'sftp'])
    for (const vault of [false, true])
      for (const status of ['failed', 'closed', 'connecting']) {
        const id = randomUUID(),
          calls: any[] = [];
        const tree = component({
          session: { id, protocol, status, host: 'ssh.example' },
          vault,
          onReconnectSession: (...args: any[]) => calls.push(args),
        });
        const actions = buttons(tree).filter(
          (b) =>
            JSON.stringify(b.children).includes('Temporary credentials') ||
            JSON.stringify(b.children).includes('Key passphrase'),
        );
        assert.equal(actions.length, vault && status !== 'connecting' ? 2 : 0);
        for (const action of actions) action.props.onClick();
        if (actions.length)
          assert.deepEqual(calls, [
            [id, 'account'],
            [id, 'passphrase'],
          ]);
      }
});
function fixture(protocol = 'ssh', mode = 'vault') {
  const requests: any[] = [],
    errors: string[] = [],
    prompts: string[] = [];
  const form: any = {
    protocol,
    host: 'ssh.example',
    port: '',
    name: 'Quick SSH',
    useSavedCredentials: true,
    credential: randomUUID(),
    tunnel: randomUUID(),
    sshAutoSudo: 'on',
  };
  for (const key of ['username', 'inlinePassword'])
    Object.defineProperty(form, key, {
      get() {
        throw Error('ordinary credentials read');
      },
    });
  const scope: any = {
    Error,
    Promise,
    window: {
      wormhole: {
        openSshSession: (q: any) => {
          requests.push(q);
          return Promise.resolve({});
        },
        closeSshSession: async () => {},
        prepareSftpEditClose: async () => true,
      },
    },
    sessions: [],
    sessionsRef: { current: [] },
    treeRef: { current: [] },
    authState: { mode },
    newConnectionForm: form,
    quickConnectSubmitInFlight: { current: false },
    connectionAuthenticationSelectionComplete: true,
    connectionAuthenticationSelectionError: 'choose',
    canConfigureConnectionSshAutoSudo: true,
    effectiveSshAutoSudoMode: () => 'on',
    fileSessionMode,
    isFileBrowserProtocol,
    savedConnectionAddressForEditor,
    quickConnectStartsImmediately,
    quickConnectTunnelId,
    sshConnectRequest,
    vaultSshQuickTarget,
    newSessionToken: randomUUID,
    sessionCloseGate: { current: { reopenAfterClose: () => false } },
    sessionResourceReleaseGate: { current: { reset() {} } },
    webSessionOpenInFlight: { current: new Map() },
    clearSftpCancelRequestsForBrowser() {},
    sftpCancelRequests: { current: new Map() },
    sftpReconnectPending: { current: new Set() },
    sshCredentialSubmitInFlight: { current: false },
    setSessions(update: any) {
      scope.sessions = update(scope.sessions);
    }, // refs intentionally lag React's state update
    setEditorError: (value: string) => errors.push(value),
    setSelectedSessionId() {},
    setActivePage() {},
    setNewConnectionForm() {},
    setNewConnectionOpen() {},
    isSshHostKeyMismatchError: (message: string) => message === 'mismatch',
    requiresSshKeyPassphrasePrompt: (message: string) => message === 'passphrase',
    isBitwardenUnlockError: (message: string) => message === 'unlock',
    requestRuntimeBitwardenUnlock: (key: string) => prompts.push(key),
    sshCredentialPromptTarget: (_q: any, message: string) =>
      message === 'saved' || message === 'quick' ? message : undefined,
    findTreeNode: () => undefined,
    clearSecretInput() {},
    sshKeyPassphraseInput: { current: null },
    setSshKeyPassphrasePrompt: () => prompts.push('passphrase'),
    setSshCredentialForm() {},
    setSshCredentialSelection() {},
    setSshCredentialSave() {},
    manualCredentialSelectionValue: 'manual',
    setSshCredentialPrompt: (value: any) => prompts.push(value.kind),
  };
  const api = runInNewContext(
    stripTypeScriptTypes(selected.join('\n') + '\n({' + names.join(',') + '})'),
    scope,
    { filename: 'wormhole-app-ssh.js' },
  );
  return {
    ...api,
    scope,
    requests,
    errors,
    prompts,
    form,
    render() {
      scope.sessionsRef.current = scope.sessions;
    },
  };
}

test('actual Quick SSH/SFTP manual intent opens protected entry without reading ordinary credentials', async () => {
  for (const protocol of ['ssh', 'sftp']) {
    const h = fixture(protocol);
    h.form.useSavedCredentials = false;
    h.form.credential = 'none';
    h.submitQuickConnect({ preventDefault() {} });
    assert.deepEqual(h.errors, []);
    assert.equal(h.requests.length, 1);
    assert.ok(parseVaultSshOpen(h.requests[0]));
    assert.equal(h.requests[0].manualCredentials, true);
    assert.equal(h.requests[0].quickTarget.credentialId, '');
    assert.equal(h.scope.sessions[0].sshManualCredentials, true);
    h.render();
    h.restartSession(h.scope.sessions[0].id, true);
    assert.equal(h.requests[1].manualCredentials, true);
    h.render();
    h.duplicateSession(h.scope.sessions[0].id);
    assert.equal(h.requests[2].manualCredentials, true);
    assert.notEqual(h.requests[1].sessionId, h.requests[2].sessionId);
    assert.deepEqual(h.prompts, []);
  }
});

test('actual SSH/SFTP credential actions preserve manual mode and consume only public references on reconnect', async (t) => {
  const inspector = new Session();
  inspector.connect();
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(() => inspector.disconnect());
  for (const protocol of ['ssh', 'sftp']) {
    const h = fixture(protocol);
    h.submitQuickConnect({ preventDefault() {} });
    h.render();
    const quick = h.scope.sessions[0];
    await h.reconnectSession(quick.id, 'passphrase');
    assert.equal(h.requests.at(-1).manualKeyPassphrase, true);
    assert.equal(h.requests.at(-1).manualCredentials, undefined);
    assert.equal(h.requests.at(-1).quickTarget.credentialId, h.form.credential);
    h.render();
    await h.reconnectSession(quick.id, 'account');
    assert.equal(h.requests.at(-1).manualCredentials, true);
    assert.equal(h.requests.at(-1).quickTarget.credentialId, '');
    assert.equal(h.scope.sessions[0].credentialId, undefined);
    h.render();
    h.requestSshCredentials(quick.id);
    assert.equal(h.requests.at(-1).manualCredentials, true);
    assert.deepEqual(h.prompts, []);
    const protectedInput = Object.defineProperties(
      {},
      {
        username: {
          get() {
            throw Error('ordinary username read');
          },
        },
        password: {
          get() {
            throw Error('ordinary password read');
          },
        },
      },
    );
    h.render();
    h.startQuickSshSession(quick.id, protectedInput);
    assert.equal(h.requests.at(-1).manualCredentials, true);
    const before = h.requests.length;
    h.requestSshCredentials('missing');
    h.startQuickSshSession('missing', protectedInput);
    assert.equal(h.requests.length, before);
    const node = {
      id: randomUUID(),
      kind: 'connection',
      protocol,
      name: 'Saved',
      host: 'saved.example',
      persisted: true,
    };
    h.openConnection(node);
    h.render();
    await h.reconnectSession(node.id, 'passphrase');
    assert.ok(parseVaultSshOpen(h.requests.at(-1)));
    assert.equal(h.requests.at(-1).manualKeyPassphrase, true);
    assert.equal(h.requests.at(-1).nodeId, node.id);
    h.render();
    await h.reconnectSession(node.id, 'account');
    assert.equal(h.requests.at(-1).manualCredentials, true);
    assert.equal('credentialId' in h.requests.at(-1), false);
    const savedCount = h.requests.length;
    h.requestSshCredentials(node.id);
    h.startQuickSshSession(node.id, protectedInput);
    assert.equal(h.requests.length, savedCount);
    h.scope.sessions = [{ id: 'desktop', protocol: 'rdp' }];
    h.render();
    h.requestSshCredentials('desktop');
    h.startQuickSshSession('desktop', protectedInput);
  }
  const h = fixture('ssh', 'local');
  h.scope.sessions = [{ id: 'legacy', protocol: 'ssh', host: 'legacy.example' }];
  h.render();
  h.requestSshCredentials('legacy');
  assert.deepEqual(h.prompts, ['quick']);
  h.startQuickSshSession('legacy', { username: 'user', password: 'fixture-only-password' });
  assert.equal(h.requests[0].username, 'user');
  assert.equal(h.requests[0].password, 'fixture-only-password');
  const report = await inspector.post('Profiler.takePreciseCoverage');
  for (const name of ['startQuickSshSession', 'requestSshCredentials']) {
    const ranges = report.result
      .filter((s) => s.url === 'wormhole-app-ssh.js')
      .flatMap((s) => s.functions.filter((f) => f.functionName === name).flatMap((f) => f.ranges));
    assert.ok(ranges.length);
    const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
    t.diagnostic(`App ${name} ${percent.toFixed(2)}% V8 blocks`);
    assert.ok(percent >= 80);
  }
});

test('actual App builds exact protected SSH/SFTP requests before React renders Quick tabs, and retains targets on restart/duplicate', async (t) => {
  const inspector = new Session();
  inspector.connect();
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(async () => {
    try {
      const report = await inspector.post('Profiler.takePreciseCoverage');
      const ranges = report.result
        .filter((s) => s.url === 'wormhole-app-ssh.js')
        .flatMap((s) =>
          s.functions.filter((f) => f.functionName === 'startSshSession').flatMap((f) => f.ranges),
        );
      assert.ok(ranges.length);
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(`App SSH start V8 block coverage ${percent.toFixed(2)}%`);
      assert.ok(percent >= 80);
    } finally {
      inspector.disconnect();
    }
  });
  for (const protocol of ['ssh', 'sftp']) {
    const h = fixture(protocol);
    h.submitQuickConnect({ preventDefault() {} });
    assert.deepEqual(h.errors, []);
    assert.equal(h.requests.length, 1, 'reserve IPC synchronously');
    const quick = h.scope.sessions[0];
    assert.equal(h.scope.sessionsRef.current.length, 0, 'test must preserve the real render gap');
    assert.equal(h.requests[0].quickTarget.host, h.form.host);
    assert.equal(h.requests[0].quickTarget.tunnelId, h.form.tunnel);
    assert.equal(h.requests[0].quickTarget.credentialId, h.form.credential);
    assert.equal(h.requests[0].quickTarget.sshAutoSudo, true);
    assert.ok(parseVaultSshOpen(h.requests[0]));
    assert.equal('host' in h.requests[0], false);
    h.render();
    h.restartSession(quick.id, true);
    assert.ok(parseVaultSshOpen(h.requests[1]));
    assert.notEqual(h.requests[1].sessionId, h.requests[0].sessionId);
    h.render();
    h.duplicateSession(quick.id);
    assert.ok(parseVaultSshOpen(h.requests[2]));
    assert.deepEqual(h.requests[2].quickTarget, h.requests[0].quickTarget);
    const node = {
      id: randomUUID(),
      kind: 'connection',
      protocol,
      name: 'Saved',
      host: 'saved.example',
      persisted: true,
    };
    h.openConnection(node);
    assert.ok(parseVaultSshOpen(h.requests[3]));
    assert.equal(h.requests[3].nodeId, node.id);
    h.render();
    h.restartSession(node.id, true);
    assert.ok(parseVaultSshOpen(h.requests[4]));
    const backendId = h.scope.sessions[0].backendSessionId,
      override = randomUUID();
    h.render();
    h.startSshSession({
      sessionId: backendId,
      frontendSessionId: quick.id,
      credentialId: override,
    });
    assert.equal(h.requests.at(-1).quickTarget.credentialId, override);
    assert.equal(h.scope.sessions[0].quickTarget.credentialId, override);
    const last = h.scope.sessions.at(-1),
      service = h.scope.window.wormhole;
    h.scope.window.wormhole = undefined;
    h.startSshSession({ sessionId: last.backendSessionId, nodeId: node.id });
    assert.match(h.scope.sessions.at(-1).error, /unavailable/);
    h.scope.window.wormhole = service;
    h.startSshSession({ sessionId: last.backendSessionId, nodeId: node.id, password: 'forbidden' });
    await tick();
    assert.match(h.scope.sessions.at(-1).error, /protected credential/);
    h.scope.window.wormhole.openSshSession = () => {
      throw Error('sync IPC error');
    };
    h.startSshSession({ sessionId: last.backendSessionId, nodeId: node.id });
    await tick();
    assert.equal(h.scope.sessions.at(-1).error, 'sync IPC error');
  }
  const h = fixture('ssh', 'local'),
    id = randomUUID();
  h.scope.sessions = [{ id: 'tab', backendSessionId: id, protocol: 'ssh', nodeId: randomUUID() }];
  h.render();
  for (const message of ['mismatch', 'passphrase', 'unlock', 'saved', 'quick', 'other']) {
    h.scope.window.wormhole.openSshSession = async () => {
      throw Error(message);
    };
    h.startSshSession({ sessionId: id, nodeId: h.scope.sessions[0].nodeId });
    await tick();
  }
  assert.deepEqual(h.prompts, ['passphrase', 'ssh:' + id, 'saved', 'quick']);
  h.scope.authState.mode = 'vault';
  h.scope.window.wormhole.openSshSession = async () => {
    throw Error('passphrase');
  };
  h.startSshSession({ sessionId: id, nodeId: h.scope.sessions[0].nodeId });
  await tick();
  assert.equal(
    h.prompts.filter((p) => p === 'passphrase').length,
    1,
    'vault cannot open legacy secret entry',
  );
});
