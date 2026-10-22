import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

test('middle-click closes tabs without waiting for native teardown or restoring removed selections', async (context) => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8').replaceAll('\r', '');
  const slice = (from: string, to: string) => {
    const start = app.indexOf(from);
    const end = app.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `Missing production section: ${from}`);
    return app.slice(start, end);
  };
  const modules = ['session-layout', 'session-lifecycle', 'session-tab-state']
    .map((name) => readFileSync(new URL(`../src/${name}.ts`, import.meta.url), 'utf8'))
    .join('\n')
    .replaceAll('export ', '');
  const source = `
    ${modules}
    ${readFileSync(new URL('../electron/web-session-attempt.ts', import.meta.url), 'utf8').replaceAll('export ', '')}
    ${slice('function SessionsPage(', 'function SessionSurface({')}
    const IconButton = ({ label, children, ...props }) => <button aria-label={label} {...props}>{children}</button>;
    const SessionTabContextMenu = ({ children }) => children;
    const SessionSurface = ({ session, isActive }) => <output data-surface={session.id} data-active={isActive}>{session.title}</output>;
    const PanelLeft = 'span', Zap = 'span', Bot = 'span', ProtocolIcon = 'span';
    const ArrowRightLeft = 'span', X = 'span', Button = 'button';
    const pendingReleases = [], releaseCalls = [], openedWeb = [], openedSsh = [];
    let windowCloseListener;
    const nativeRelease = id => {
      releaseCalls.push(id);
      return new Promise((resolve, reject) => pendingReleases.push({ id, resolve, reject }));
    };
    window.wormhole = {
      closeSshSession: nativeRelease, closeSerialSession: nativeRelease,
      closeWebSession: nativeRelease,
      openWebSession: async request => { openedWeb.push(request.sessionId); return { url: 'https://localhost' }; },
      commandRdpSession: ({ sessionId }) => nativeRelease(sessionId),
      sendVncCommand: ({ sessionId }) => nativeRelease(sessionId),
      onBitwardenPopupState: () => () => {},
      onWindowCloseRequested: listener => { windowCloseListener = listener; return () => { windowCloseListener = undefined; }; },
    };
    let controls;
    function Harness({ initial, confirm = false, prompts = false }) {
      const [authGate, setAuthGate] = useState('unlocked');
      const [sessions, setSessions] = useState(initial);
      const sessionsRef = useRef(sessions);
      useLayoutEffect(() => { sessionsRef.current = sessions; }, [sessions]);
      const [selectedSessionId, setSelectedSessionId] = useState(initial[0]?.id ?? '');
      const [pendingSessionClose, setPendingSessionClose] = useState(null);
      const [sessionCloseBusy, setSessionCloseBusy] = useState(false);
      const sessionCloseGate = useRef(new SessionCloseGate());
      const sessionResourceReleaseGate = useRef(new SessionResourceReleaseGate());
      const [rdpCredentialPrompt, setRdpCredentialPrompt] = useState(prompts ? initial[0].id : null);
      const [sshCredentialPrompt, setSshCredentialPrompt] = useState(prompts ? {
        sessionId: initial[0].id, backendSessionId: initial[0].backendSessionId,
      } : null);
      const [sshKeyPassphrasePrompt, setSshKeyPassphrasePrompt] = useState(prompts ? {
        sessionId: initial[0].backendSessionId,
      } : null);
      const confirmOnTabClose = confirm;
      const runtimeBitwardenRetries = { remove() {}, isEmpty: prompts };
      const bitwardenUnlockPrompt = prompts;
      const dismissRuntimeBitwardenUnlock = () => {};
      const rdpSavedCredentialAttempts = useRef(new Set());
      const sftpRequestIds = useRef(new Set()), sftpCancelRequests = useRef(new Map());
      const sshKeyPassphraseInput = useRef(null);
      const setSshCredentialForm = () => {}, clearSecretInput = () => {};
      const clearSftpCancelRequestsForBrowser = () => {};
      const rdpSessionAttempts = useRef({ cancel() {} });
      const rdpEditAttempts = useRef(new WebSessionAttemptTracker());
      const webSessionAttempts = useRef(new WebSessionAttemptTracker());
      const webSessionReconnectAttempts = useRef(new WebSessionAttemptTracker());
      const webSessionOpenInFlight = useRef(new Map());
      const treeRef = useRef([{ id: 'saved', kind: 'connection', protocol: 'ssh', name: 'Saved', host: 'localhost' }]);
      const findTreeNode = (tree, id) => tree.find(node => node.id === id);
      const savedConnectionAddressForEditor = (_protocol, host) => host;
      const newSessionToken = () => 'reopened-native';
      const setActivePage = () => {}, startSshSession = request => openedSsh.push(request);
      const setRoutePrompts = () => {};
      const sidebarWriter = useMemo(() => ({ flush: async () => {} }), []);
      const connectionTreeExpansionWriter = sidebarWriter;
      ${slice('function openConnection(', 'async function releaseSessionResources(')}
      ${slice('function startWebSession(', 'async function closeWebSession(')}
      ${slice('async function closeWebSession(', 'async function requestRdpCredentials(')}
      ${slice('async function releaseSessionResources(', 'function handleConfirmOnTabCloseChange(')}
      ${slice('async function performSessionClose(', 'async function closeSessionsForNodeIds(')}
      ${slice('async function closeSessionsForNodeIds(', 'const releaseSessionResourcesRef =')}
      ${slice('const releaseSessionResourcesRef =', '  useEffect(() => {\n    return window.wormhole?.onWindowCloseConfirmationRequested').replaceAll('\r', '')}
      ${slice('function reconnectSession(', 'function duplicateSession(')}
      controls = { closeSession, confirmSessionClose, performSessionClose, setSelectedSessionId, openConnection, treeRef, reconnectSession, setAuthGate, closeSessionsForNodeIds, webSessionAttempts,
        pendingSessionClose, sessionCloseBusy, selectedSessionId, sessions, sessionsRef,
        append: session => setSessions(current => [...current, session]),
        cancel: () => setPendingSessionClose(null),
      };
      return <>
        {pendingSessionClose ? <button id="confirm" disabled={sessionCloseBusy} onClick={confirmSessionClose}>Confirm</button> : null}
        <SessionsPage sessions={sessions} selectedSession={sessions.find(session => session.id === selectedSessionId)}
          onCloseSession={closeSession} onSelectSession={setSelectedSessionId} />
      </>;
    }
  `;
  const transformed = await transformWithOxc(source, 'session-close.tsx', {
    jsx: { runtime: 'classic' },
  });
  const fixture = `
    const root = createRoot(document.getElementById('root'));
    const session = (id, protocol = 'ssh', status = 'connected') => ({
      id, title: id, protocol, status, rdpStatus: 'connected',
      backendSessionId: protocol === 'ssh' || protocol === 'serial' ? 'native-' + id : undefined,
    });
    let key = 0;
    const mount = async (initial, options = {}) => {
      await React.act(async () => root.render(React.createElement(React.StrictMode, null,
        React.createElement(Harness, { initial, ...options, key: ++key }))));
    };
    const tab = id => document.querySelector('[data-session-tab-id="' + id + '"]');
    const ids = () => controls.sessions.map(item => item.id);
    const selected = id => {
      assert.equal(controls.selectedSessionId, id);
      assert.ok(tab(id));
      assert.equal(tab(id).getAttribute('aria-selected'), 'true');
      assert.equal(document.querySelector('[data-surface="' + id + '"]').dataset.active, 'true');
    };
    const aux = (target, button = 1) => {
      const event = new MouseEvent('auxclick', { button, bubbles: true, cancelable: true });
      target.dispatchEvent(event);
      return event;
    };
    const nativeClick = async (target, button) => {
      const rect = target.getBoundingClientRect();
      assert.ok(rect.width > 0 && rect.height > 0);
      await React.act(async () => {
        const type = button === 'left' ? 'click' : 'auxclick';
        const delivered = new Promise((resolve, reject) => {
          const timeout = setTimeout(() => reject(new Error('No ' + type + ' for ' + target.outerHTML + '; hit: ' + document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2)?.outerHTML)), 3000);
          document.addEventListener(type, () => { clearTimeout(timeout); resolve(); }, { once: true, capture: true });
        });
        await require('electron').ipcRenderer.invoke('test:mouse', button,
          Math.floor(rect.x + rect.width / 2), Math.floor(rect.y + rect.height / 2));
        await delivered;
      });
    };
    // Native middle down must neither focus the inactive tab nor start autoscroll.
    await mount([session('a'), session('b'), session('c')]);
    await React.act(async () => tab('a').focus());
    let prevented = false;
    const observeDown = event => { prevented = event.defaultPrevented; };
    document.addEventListener('mousedown', observeDown);
    await nativeClick(tab('b'), 'middle');
    document.removeEventListener('mousedown', observeDown);
    assert.equal(prevented, true);
    assert.deepEqual(ids(), ['a', 'c']);
    selected('a');
    assert.equal(document.activeElement, tab('a'));
    assert.ok(pendingReleases.some(item => item.id === 'native-b'));

    // Close the selected tab while the first disconnect remains unresolved.
    await nativeClick(tab('a'), 'middle');
    selected('c');
    assert.deepEqual(ids(), ['c']);
    // Closing over the icon follows the same path, including the last tab.
    await nativeClick(document.querySelector('[aria-label="Close c"]'), 'middle');
    assert.deepEqual(ids(), []);
    assert.equal(controls.selectedSessionId, '');
    assert.match(document.body.textContent, /No active sessions/);

    // Stale callbacks and batched closes must not resurrect already removed tabs.
    await mount([session('a'), session('b'), session('c')], { prompts: true });
    const staleClose = controls.closeSession;
    await React.act(async () => {
      await staleClose('b');
      await staleClose('a', 'b');
    });
    selected('c');
    assert.deepEqual(ids(), ['c']);
    const count = releaseCalls.length;
    await React.act(async () => { await staleClose('a'); await controls.performSessionClose('missing'); });
    assert.equal(releaseCalls.length, count);
    await React.act(async () => controls.append(session('new')));
    await React.act(async () => controls.setSelectedSessionId('new'));
    // Late native failures/completions cannot change the current selection.
    await React.act(async () => {
      pendingReleases.splice(0).forEach((item, index) => index % 2 ? item.reject(new Error('disconnect failed')) : item.resolve());
    });
    selected('new');

    // Confirmation cancels without native calls and accepts without waiting for cleanup.
    await mount([session('a'), session('b')], { confirm: true });
    await nativeClick(tab('a'), 'middle');
    assert.deepEqual(ids(), ['a', 'b']);
    assert.ok(document.getElementById('confirm'));
    await React.act(async () => controls.cancel());
    await React.act(async () => controls.confirmSessionClose());
    assert.deepEqual(ids(), ['a', 'b']);
    await nativeClick(tab('a'), 'middle');
    await nativeClick(document.getElementById('confirm'), 'left');
    selected('b');
    assert.equal(document.getElementById('confirm'), null);
    assert.equal(controls.sessionCloseBusy, false);
    await nativeClick(tab('b'), 'middle');
    await nativeClick(document.getElementById('confirm'), 'left');
    assert.deepEqual(ids(), []);

    // Left click selects, right auxclick does not close, and left-click X still closes.
    await mount([session('a'), session('b')]);
    await nativeClick(tab('b'), 'left');
    selected('b');
    await React.act(async () => assert.equal(aux(tab('b'), 2).defaultPrevented, false));
    assert.deepEqual(ids(), ['a', 'b']);
    await nativeClick(document.querySelector('[aria-label="Close b"]'), 'left');
    selected('a');

    // All protocol teardowns may be delayed; none may leave an empty tab behind.
    for (const protocol of ['ssh', 'serial', 'rdp', 'vnc', 'http', 'https']) {
      await mount([session(protocol, protocol), session('survivor')]);
      await nativeClick(tab(protocol), 'middle');
      selected('survivor');
      assert.equal(tab(protocol), null);
    }
    await mount([session('closed', 'ssh', 'closed')], { confirm: true });
    await nativeClick(tab('closed'), 'middle');
    assert.deepEqual(ids(), []);
    assert.equal(document.getElementById('confirm'), null);

    // Closing a split pane selects the survivor and collapses the empty pane.
    await mount([session('a'), session('b'), session('c')]);
    await React.act(async () => tab('b').dispatchEvent(new KeyboardEvent('keydown', {
      key: 'ArrowRight', altKey: true, shiftKey: true, bubbles: true, cancelable: true,
    })));
    assert.equal(document.querySelectorAll('[role="tablist"]').length, 2);
    await nativeClick(tab('b'), 'middle');
    assert.equal(document.querySelectorAll('[role="tablist"]').length, 1);
    assert.ok(ids().includes(controls.selectedSessionId));
    selected(controls.selectedSessionId);
    await React.act(async () => {
      const a = tab('a'), c = tab('c');
      assert.equal(aux(a).defaultPrevented, true);
      assert.equal(aux(c).defaultPrevented, true);
    });
    assert.deepEqual(ids(), []);
    assert.equal(controls.selectedSessionId, '');
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));

    // A reconnect already waiting for web teardown must not start after its tab closes.
    await mount([session('web', 'https')]);
    await React.act(async () => controls.reconnectSession('web'));
    await nativeClick(tab('web'), 'middle');
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
    assert.deepEqual(openedWeb, [], 'a closed tab must not leave a headless web reconnect');
    await mount([session('web', 'https')]);
    await React.act(async () => controls.reconnectSession('web'));
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
    assert.deepEqual(openedWeb.splice(0), ['web'], 'a live tab still reconnects');
    await React.act(async () => controls.reconnectSession('web'));
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.reject(new Error('already disconnected'))));
    assert.deepEqual(openedWeb.splice(0), ['web'], 'a failed close reply retains the existing reconnect policy');
    await React.act(async () => { controls.reconnectSession('web'); controls.reconnectSession('web'); });
    await React.act(async () => pendingReleases.splice(0).reverse().forEach(item => item.resolve()));
    assert.deepEqual(openedWeb.splice(0), ['web'], 'only the latest reconnect may start');
    await React.act(async () => controls.reconnectSession('web'));
    const activeAttempt = controls.webSessionAttempts.current.begin('unrelated-live-web');
    await React.act(async () => controls.setAuthGate('locked'));
    await React.act(async () => controls.setAuthGate('unlocked'));
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
    assert.deepEqual(openedWeb, [], 'locking must cancel queued reconnects');
    assert.equal(controls.webSessionAttempts.current.isCurrent('unrelated-live-web', activeAttempt), true);

    // Reopening a saved connection waits for the old native surface to finish closing.
    for (const deleted of [false, true]) {
      await mount([session('session-saved'), session('other')]);
      const reopen = controls.openConnection;
      const node = controls.treeRef.current[0];
      await nativeClick(tab('session-saved'), 'middle');
      await React.act(async () => { reopen(node); reopen(node); });
      assert.deepEqual(ids(), ['other']);
      if (deleted) controls.treeRef.current = [];
      await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
      if (deleted) {
        assert.deepEqual(ids(), ['other'], 'deleted connections must not reopen after teardown');
      } else {
        selected('session-saved');
        assert.deepEqual(ids(), ['other', 'session-saved']);
        await nativeClick(tab('session-saved'), 'middle');
        selected('other');
        assert.ok(pendingReleases.some(item => item.id === 'reopened-native'));
        await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
      }
    }
    await mount([session('session-saved')]);
    await nativeClick(tab('session-saved'), 'middle');
    await React.act(async () => controls.openConnection(controls.treeRef.current[0]));
    const opensBeforeShutdown = openedSsh.length;
    await React.act(async () => windowCloseListener());
    await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
    assert.equal(openedSsh.length, opensBeforeShutdown, 'window teardown must cancel deferred opens');
    for (const boundary of ['lock', 'delete', 'unmount']) {
      await mount([session('session-saved')]);
      await nativeClick(tab('session-saved'), 'middle');
      await React.act(async () => controls.openConnection(controls.treeRef.current[0]));
      const before = openedSsh.length;
      if (boundary === 'lock') {
        await React.act(async () => controls.setAuthGate('locked'));
        await React.act(async () => controls.setAuthGate('unlocked'));
      } else if (boundary === 'delete') {
        // The closed tab is already absent; deletion must still cancel its queued reopen.
        await React.act(async () => controls.closeSessionsForNodeIds(new Set(['saved'])));
      } else {
        await mount([]);
      }
      await React.act(async () => pendingReleases.splice(0).forEach(item => item.resolve()));
      assert.equal(openedSsh.length, before, boundary + ' must cancel deferred opens');
    }
    await React.act(async () => root.unmount());
  `;
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { useState, useRef, useEffect, useLayoutEffect, useMemo } = React;
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
    (async () => { ${fixture} })();
    //# sourceURL=wormhole-session-close.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-session-close-'));
  const harnessPath = join(directory, 'session-close.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, width: 1200, height: 800, webPreferences: {
          nodeIntegration: true, contextIsolation: false, backgroundThrottling: false,
        } });
        ipcMain.handle('test:mouse', (_event, button, x, y) => {
          window.webContents.sendInputEvent({ type: 'mouseDown', button, x, y, clickCount: 1 });
          window.webContents.sendInputEvent({ type: 'mouseUp', button, x, y, clickCount: 1 });
        });
        try {
          await window.loadURL('data:text/html,<style>section { position:relative; height:600px; } [role=group] { position:absolute; } button { min-width:80px; min-height:30px; } [role=tablist], [data-session-tab-index] { display:flex; }</style><div id="root"></div>');
          window.webContents.debugger.attach('1.3');
          await window.webContents.debugger.sendCommand('Profiler.enable');
          await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-session-close.js');
          if (!script) throw new Error('Missing session close renderer coverage');
          for (const name of ['performSessionClose', 'closeSession', 'confirmSessionClose', 'closePaneSession', 'onAuxClick', 'onMouseDown']) {
            const parent = script.functions.find(item => item.functionName === name);
            if (!parent) throw new Error('Missing coverage for ' + name);
            const range = parent.ranges[0];
            const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
            const covered = ranges.filter(item => item.count > 0).length;
            const percent = 100 * covered / ranges.length;
            console.log(name + ': V8 block coverage ' + covered + '/' + ranges.length + ' (' + percent.toFixed(2) + '%)');
            if (percent < ${coverageThreshold}) throw new Error(name + ' coverage below ${coverageThreshold}%');
          }
          // Only the reopen guard changed in openConnection; measure its new branch
          // and nested completion callback, not the unrelated protocol launch paths.
          const reopen = script.functions.find(item => item.functionName === 'openConnection');
          const reopenRange = reopen.ranges[0];
          const guardStart = ${JSON.stringify(renderer.indexOf('sessionCloseGate.current.reopenAfterClose'))};
          const guardEnd = ${JSON.stringify(renderer.indexOf('if (webSessionOpenInFlight.current.has(sessionId))'))};
          const guardRanges = script.functions.flatMap(item => item.ranges).filter(range => range.startOffset >= guardStart && range.endOffset <= guardEnd);
          if (!(guardStart > reopenRange.startOffset && guardEnd < reopenRange.endOffset && guardRanges.length > 0)) throw new Error('Missing reopen guard coverage');
          const guardPercent = 100 * guardRanges.filter(range => range.count > 0).length / guardRanges.length;
          console.log('saved connection reopen guard: V8 block coverage ' + guardPercent.toFixed(2) + '%');
          if (guardPercent < ${coverageThreshold}) throw new Error('Reopen guard coverage below ${coverageThreshold}%');
          const continuationStart = ${JSON.stringify(renderer.indexOf('const closing = closeWebSession(source.id)'))};
          const continuationEnd = ${JSON.stringify(renderer.indexOf('clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, source.sftp)', renderer.indexOf('function reconnectSession(')))};
          const continuationRanges = script.functions.flatMap(item => item.ranges).filter(range => range.startOffset >= continuationStart && range.endOffset <= continuationEnd);
          if (!(continuationStart >= 0 && continuationEnd > continuationStart && continuationRanges.length > 0)) throw new Error('Missing web reconnect coverage');
          const continuationPercent = 100 * continuationRanges.filter(range => range.count > 0).length / continuationRanges.length;
          console.log('web reconnect continuation: V8 block coverage ' + continuationPercent.toFixed(2) + '%');
          if (continuationPercent < ${coverageThreshold}) throw new Error('Web reconnect coverage below ${coverageThreshold}%');
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
