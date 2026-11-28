import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { randomUUID } from 'node:crypto';
import { Session } from 'node:inspector/promises';
import { mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import { vaultWebQuickTarget, webConnectRequest } from '../src/web-connect.ts';
import { quickConnectStartsImmediately, quickConnectTunnelId } from '../src/quick-connect-state.ts';
import { savedConnectionAddressForEditor } from '../src/web-address.ts';
import { parseVaultWebRequest } from '../electron/vault-web-open.ts';
const tick = () => new Promise(setImmediate);
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const functions: string[] = [];
visitSyntax(mainSyntax(app, true), (node) => {
  if (
    node.type === 'FunctionDeclaration' &&
    [
      'startWebSession',
      'closeWebSession',
      'submitQuickConnect',
      'openConnection',
      'duplicateSession',
    ].includes(node.id?.name)
  )
    functions.push(app.slice(node.start, node.end));
});
assert.equal(functions.length, 5);

test('actual App opens, duplicates and closes saved/Quick browsers through the protected public request', async (t) => {
  const inspector = new Session();
  inspector.connect();
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(async () => {
    try {
      const report = await inspector.post('Profiler.takePreciseCoverage');
      const scripts = report.result.filter((s) => s.url === 'wormhole-app-web.js');
      assert.ok(scripts.length);
      const directory = process.env.WORMHOLE_TEST_WEB_APP_COVERAGE;
      if (directory) {
        mkdirSync(directory, { recursive: true });
        writeFileSync(directory + '/app.json', JSON.stringify(scripts));
      }
      const ranges = scripts.flatMap((s) =>
        s.functions
          .filter(
            (f) => f.functionName === 'startWebSession' || f.functionName === 'closeWebSession',
          )
          .flatMap((f) => f.ranges),
      );
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(`App browser start/close V8 block coverage ${percent.toFixed(2)}%`);
      assert.ok(percent >= 80);
    } finally {
      inspector.disconnect();
    }
  });
  for (const mode of ['vault', 'local'])
    for (const protocol of ['http', 'https']) {
      const requests: any[] = [],
        errors: string[] = [];
      let reject = false,
        delayed: ((target: any) => void) | undefined,
        hold = false;
      const tunnel = randomUUID();
      const form: any = {
        name: 'Quick browser',
        host: 'HTTPS://[::1]:8443/path%2Fpart?q=a#page',
        protocol,
        port: '',
        useSavedCredentials: false,
        credential: 'none',
        tunnel,
        sshAutoSudo: 'off',
        rdp: {},
        httpIgnoreCertErrors: protocol === 'https',
      };
      for (const key of ['username', 'inlinePassword'])
        Object.defineProperty(form, key, {
          get() {
            throw Error('ordinary credentials accessed');
          },
        });
      const scope: any = {
        Error,
        Promise,
        authState: { mode },
        newConnectionForm: form,
        sessions: [],
        sessionsRef: { current: [] },
        treeRef: { current: [] },
        quickConnectSubmitInFlight: { current: false },
        connectionAuthenticationSelectionComplete: true,
        connectionAuthenticationSelectionError: 'choose',
        canConfigureConnectionSshAutoSudo: false,
        effectiveSshAutoSudoMode: () => 'off',
        isFileBrowserProtocol: () => false,
        quickConnectStartsImmediately,
        quickConnectTunnelId,
        vaultWebQuickTarget,
        webConnectRequest,
        savedConnectionAddressForEditor,
        newSessionToken: randomUUID,
        sessionCloseGate: { current: { reopenAfterClose: () => false } },
        sessionResourceReleaseGate: { current: { reset() {} } },
        webSessionOpenInFlight: { current: new Map() },
        webSessionReconnectAttempts: { current: { cancel() {} } },
        webSessionAttempts: { current: new WebSessionAttemptTracker() },
        setSessions: (update: any) => {
          scope.sessions = update(scope.sessions);
          scope.sessionsRef.current = scope.sessions;
        },
        setEditorError: (v: string) => errors.push(v),
        setSelectedSessionId() {},
        setActivePage() {},
        setNewConnectionForm() {},
        setNewConnectionOpen() {},
        window: {
          wormhole: {
            openWebSession: (q: any) => {
              requests.push(q);
              if (reject) return Promise.reject(Error('native failure'));
              if (hold)
                return new Promise((r) => {
                  delayed = r;
                });
              return Promise.resolve({
                url: 'https://[::1]:8443/path%2Fpart?q=a#page',
                ignoreCertErrors: protocol === 'https',
              });
            },
            closeWebSession: async () => {},
          },
        },
      };
      const invoke = runInNewContext(
        stripTypeScriptTypes(
          functions.join('\n') +
            '\n({submitQuickConnect,openConnection,duplicateSession,startWebSession,closeWebSession})',
        ),
        scope,
        { filename: 'wormhole-app-web.js' },
      );
      invoke.submitQuickConnect({ preventDefault() {} });
      assert.deepEqual(errors, []);
      assert.equal(requests.length, 1, 'IPC must start synchronously before a possible close');
      const quick = scope.sessions[0];
      if (mode === 'vault') {
        assert.ok(parseVaultWebRequest(requests[0]));
        assert.equal(quick.id.startsWith('session-'), false);
        assert.equal(requests[0].quickTarget.host, form.host);
        assert.equal(requests[0].quickTarget.tunnelId, tunnel);
        assert.equal(requests[0].quickTarget.ignoreCertificateErrors, protocol === 'https');
        assert.equal('address' in requests[0], false);
      } else assert.equal(requests[0].address, form.host);
      invoke.startWebSession(quick);
      assert.equal(requests.length, 1);
      await tick();
      assert.equal(scope.sessions[0].webUrl, 'https://[::1]:8443/path%2Fpart?q=a#page');
      invoke.duplicateSession(quick.id);
      await tick();
      const duplicate = scope.sessions[1];
      assert.notEqual(duplicate.id, quick.id);
      if (mode === 'vault') assert.ok(parseVaultWebRequest(requests[1]));
      const nodeId = randomUUID();
      invoke.openConnection({
        kind: 'connection',
        id: nodeId,
        name: 'Saved',
        protocol,
        host: 'saved.example',
        httpPath: '/path',
        persisted: true,
      });
      await tick();
      assert.equal(requests[2].nodeId, nodeId);
      if (mode === 'vault') assert.equal(requests[2].sessionId, nodeId);
      else assert.equal(requests[2].sessionId, 'session-' + nodeId);
      invoke.openConnection({ kind: 'connection', id: nodeId, protocol });
      assert.equal(requests.length, 3);
      reject = true;
      invoke.startWebSession(quick);
      await tick();
      assert.equal(scope.sessions[0].error, 'native failure');
      reject = false;
      hold = true;
      invoke.startWebSession(quick);
      await invoke.closeWebSession(quick.id);
      delayed!({ url: 'https://stale.example' });
      await tick();
      assert.notEqual(scope.sessions[0].webUrl, 'https://stale.example');
      hold = false;
      const api = scope.window.wormhole;
      scope.window.wormhole = undefined;
      invoke.startWebSession(quick);
      assert.match(scope.sessions[0].error, /unavailable/);
      scope.window.wormhole = api;
      if (mode === 'vault') {
        scope.quickConnectSubmitInFlight.current = false;
        form.host = 'https://user:password@host/';
        invoke.submitQuickConnect({ preventDefault() {} });
        assert.equal(scope.sessions.length, 3);
        assert.equal(errors.length, 1);
        invoke.startWebSession({ ...quick, quickTarget: undefined });
        await tick();
        assert.match(scope.sessions[0].error, /invalid/);
      }
      scope.startSshSession = () => {};
      scope.fileSessionMode = () => 'ssh';
      const sshNode = randomUUID();
      invoke.openConnection({
        kind: 'connection',
        id: sshNode,
        name: 'Editable SSH',
        protocol: 'ssh',
        host: 'ssh.example',
        persisted: true,
      });
      const sshSession = scope.sessions.find((s: any) => s.nodeId === sshNode);
      invoke.duplicateSession(sshSession.id);
      for (const edited of scope.sessions.filter((s: any) => s.nodeId === sshNode)) {
        const request = webConnectRequest(
          { ...edited, protocol: 'https', webTargetNodeId: sshNode },
          1,
          mode === 'vault',
        );
        if (mode === 'vault')
          assert.ok(
            parseVaultWebRequest(request),
            'SSH-to-web edits retain a canonical tab identity',
          );
      }
    }
});
