import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

// JSX call sites are covered by these scoped contracts. The shared behavior and
// callbacks are exercised and measured in Chromium in auth-prompt.test.ts.
test('password forms use the shared visibility control across every editor and prompt', () => {
  for (const file of [
    'App.tsx',
    'components/VncSurface.tsx',
    'components/MRemoteImportDialog.tsx',
  ]) {
    const source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8');
    assert.match(source, /import \{ PasswordInput \} from '@\/components\/ui\/password-input'/);
    assert.doesNotMatch(source, /type="password"/, `${file} must use PasswordInput`);
  }
  const fields = [...appSource.matchAll(/<PasswordInput\b[\s\S]*?\/>/g)].map(([field]) => field);
  for (const id of [
    'auth-secret',
    'ssh-key-passphrase',
    'connection-inline-password',
    'credential-key-passphrase',
    'credential-password',
    'auth-new-secret',
    'auth-confirm-secret',
    'backup-export-password',
    'backup-export-confirmation',
    'backup-import-password',
  ]) {
    assert.ok(
      fields.some((field) => field.includes(`id="${id}"`)),
      `${id} needs visibility control`,
    );
  }
  assert.match(
    appSource,
    /const TunnelPromptInput = tunnelPrompts\[0\]\?\.secret \? PasswordInput : Input/,
  );
  assert.match(appSource, /<TunnelPromptInput[\s\S]*?key=\{tunnelPrompts\[0\]\?\.promptId\}/);
});
const vncSource = readFileSync(
  new URL('../src/components/VncSurface.tsx', import.meta.url),
  'utf8',
);
const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
const workspaceRootSource = readFileSync(
  new URL('../src/WorkspaceRoot.tsx', import.meta.url),
  'utf8',
);
const contextMenuSource = readFileSync(
  new URL('../src/components/ui/context-menu.tsx', import.meta.url),
  'utf8',
);
const rdpHostSource = readFileSync(
  new URL('../tools/wormhole-rdp-host/Program.cs', import.meta.url),
  'utf8',
);
const rdpHostFormSource = readFileSync(
  new URL('../tools/wormhole-rdp-host/Interop/Rdp/RdpHostForm.cs', import.meta.url),
  'utf8',
);

function sourceBetween(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  assert.ok(start >= 0, `missing source marker: ${startMarker}`);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(end > start, `missing source marker after ${startMarker}: ${endMarker}`);
  return source.slice(start, end);
}

test('stable VNC identity preserves the single App-owned disconnect lifecycle', () => {
  assert.match(vncSource, /return \(\) => \{/);
  assert.doesNotMatch(vncSource, /action: 'vnc\.disconnect'/);
  assert.match(appSource, /visibility: active \? 'visible' : 'hidden'/);
  const releaseSource = appSource.slice(
    appSource.indexOf('async function releaseSessionResources'),
    appSource.indexOf('function handleConfirmOnTabCloseChange'),
  );
  assert.match(releaseSource, /vnc\.disconnect/);
  assert.match(vncSource, /const connectAttempt = useRef\(0\)/);
  assert.match(vncSource, /expectedConnectAttempt[\s\S]*connectAttempt\.current/);
  assert.match(vncSource, /onStatusChangeRef\.current\?\.\(nextStatus\)/);
  assert.match(vncSource, /if \(!request\.isAuthorized\) return/);
  assert.match(
    vncSource,
    /const promptAllowed = unlockRequired && bitwardenUnlockRequestRef\.current\.isAuthorized/,
  );
  assert.match(vncSource, /isAuthorized && bitwardenUnlockRequired && bitwardenUnlockPending/);
  assert.match(vncSource, /const message = formatBitwardenAuthenticationError\(error, 'unlock'\)/);
  assert.match(vncSource, /setBitwardenUnlockRequired\(promptAllowed\)/);
  assert.match(vncSource, /if \(promptAllowed\) notifyBitwardenUnlockRequired\(message\)/);
  assert.match(appSource, /<VncSurface[\s\S]*isAuthorized=\{isAuthorized\}/);
  assert.match(
    appSource,
    /<SessionsPage[\s\S]*bitwardenUnlockPending=\{bitwardenUnlockPrompt !== null\}/,
  );
  const vncMountSource = appSource.slice(
    appSource.indexOf('<VncSurface'),
    appSource.indexOf('/>', appSource.indexOf('<VncSurface')),
  );
  assert.doesNotMatch(vncMountSource, /key=/);
  assert.match(vncMountSource, /bitwardenUnlockPending=\{bitwardenUnlockPending\}/);
  assert.match(
    vncSource,
    /if \(!disconnected\) void connect\(\);[\s\S]*connectAttempt\.current \+= 1/,
  );
});

test('MCP approval settles an active authentication confirmation before opening', () => {
  const mcpSubscription = sourceBetween(
    appSource,
    'const unsubscribeMcp',
    'const unsubscribeBackend',
  );
  const settlePrompt = mcpSubscription.indexOf('settleAuthConfirmation(false)');
  const enqueueApproval = mcpSubscription.indexOf('setMcpApprovals', settlePrompt);

  assert.ok(settlePrompt >= 0 && settlePrompt < enqueueApproval);
  assert.match(
    mcpSubscription,
    /event\.type === 'mcp\.approval-cancelled'[\s\S]*?filter\(\(approval\) => approval\.requestId !== event\.requestId\)/,
  );
  assert.match(
    appSource,
    /const settleAuthConfirmation = useCallback[\s\S]*?setAuthPrompt\(null\)/,
  );
  assert.match(appSource, /settleAuthConfirmation\(succeeded\)/);
});

test('RDP system-client capability refresh hides stale actions and rejects stale results', () => {
  const capabilitySource = appSource.slice(
    appSource.indexOf('const refreshRdpSystemClientCapability'),
    appSource.indexOf('async function disconnectRemoteDesktopSession'),
  );
  assert.match(capabilitySource, /rdpSystemClientSupported: false/);
  assert.match(capabilitySource, /rdpCapabilityAttempts\.current\.begin\(sessionId\)/);
  assert.match(capabilitySource, /rdpCapabilityAttempts\.current\.isCurrent\(sessionId, attempt\)/);
  assert.match(capabilitySource, /useLayoutEffect\(\(\) =>/);
});

test('replacement RDP credentials disconnect a non-terminal logon attempt before restart', () => {
  const submitSource = appSource.slice(
    appSource.indexOf('async function submitRdpCredentials'),
    appSource.indexOf('function requestSshCredentials'),
  );
  const cleanup = submitSource.indexOf('await disconnectRemoteDesktopSession(sessionId)');
  const restart = submitSource.indexOf('startRdpSession(');
  assert.ok(cleanup >= 0 && restart > cleanup);
  assert.match(submitSource, /!rdpCredentialSave && !selectedCredentialID/);
});

test('RDP overlays track owner-window moves in screen coordinates', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  assert.match(
    mainSource,
    /window\.on\('move', \(\) => scheduleRdpSurfacePlacementSync\(window\)\)/,
  );
  assert.match(mainSource, /placement\.rendererBounds/);
  assert.match(mainSource, /toScreenBounds\(owner, placement\.rendererBounds\)/);
  assert.match(mainSource, /rdpClient\.resize\(\{ sessionId, bounds \}, ownerWindow\)/);
});

test('RDP main lifecycle ignores request responses and stale process generations', () => {
  const lifecycleSource = mainSource.slice(
    mainSource.indexOf('rdpClient.onEvent'),
    mainSource.indexOf('function releaseRdpTunnel'),
  );
  assert.match(lifecycleSource, /if \(!isRdpLifecycleEvent\(event\)\) return/);
  assert.match(lifecycleSource, /event\.lifecycleGeneration[\s\S]*rdpSessionAttempts\.isCurrent/);
});

test('renderer reload settles RDP processes and every broker tunnel lease', () => {
  const reloadSource = sourceBetween(
    mainSource,
    "window.webContents.on('did-start-loading'",
    "window.webContents.on('preload-error'",
  );
  assert.match(reloadSource, /await shutdownNativeResources\(\)/);
  assert.match(reloadSource, /vncSessionAttempts\.cancelAll\(\)/);
  assert.match(reloadSource, /cancelPreparingRdpStarts\(\)/);
  const shutdownSource = sourceBetween(
    mainSource,
    'function shutdownNativeResources()',
    'authSession.onUnlocked',
  );
  assert.match(
    shutdownSource,
    /Promise\.allSettled\(\[sshBackend\.dispose\(\), rdpClient\?\.dispose\(\)\]\)/,
  );
  assert.match(shutdownSource, /await releaseAllRdpTunnels\(\)/);
  const rdpCleanup = shutdownSource.indexOf('releaseAllRdpTunnels()');
  const backendStop = shutdownSource.indexOf('backend?.stop(true)');
  assert.ok(rdpCleanup >= 0 && backendStop > rdpCleanup);
});

test('stale system RDP starts release their reserved lifecycle and VPN', () => {
  const systemSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:open-system'",
    "ipcMain.handle('rdp:resize'",
  );
  const systemStart = systemSource.indexOf('const result = await client.start');
  const systemCatch = systemSource.indexOf('} catch (error) {', systemStart);
  assert.ok(systemStart >= 0 && systemCatch > systemStart);
  assert.match(
    systemSource.slice(systemCatch),
    /settleTunnelCleanup\([\s\S]*client\.command\([\s\S]*lifecycleId[\s\S]*releaseRdpTunnel\(lifecycleId\)/,
  );
});

test('system RDP commits its replacement lifecycle only after safe profile resolution', () => {
  const systemSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:open-system'",
    "ipcMain.handle('rdp:resize'",
  );
  const profileResolution = systemSource.indexOf('await resolveNativeRdpSystemProfile');
  const lifecycleBegin = systemSource.indexOf('rdpSessionAttempts.begin(request.sessionId)');
  const disconnect = systemSource.indexOf('client.command(', lifecycleBegin);
  const lifecycleIdBegin = systemSource.indexOf(
    'lifecycleId = client.beginStart(request.sessionId)',
  );
  assert.ok(
    profileResolution >= 0 &&
      lifecycleBegin > profileResolution &&
      disconnect > lifecycleBegin &&
      lifecycleIdBegin > disconnect,
  );
  assert.match(systemSource, /rdpStartAttempts\.isCurrent\(request\.sessionId, requestAttempt\)/);
  assert.match(systemSource, /if \(!ownsLifecycle\) return/);
  assert.match(systemSource, /lifecycleCommitted: ownsLifecycle/);
  assert.match(systemSource, /rdpStartOperations\.runExclusive\(/);
  assert.match(
    systemSource,
    /catch \(error\) \{[\s\S]*client[\s\S]*\.command\([\s\S]*'disconnect'/,
  );
  const rendererSource = appSource.slice(
    appSource.indexOf('async function openRdpInSystemClient'),
    appSource.indexOf('function submitRdpCredentials'),
  );
  assert.doesNotMatch(rendererSource, /rdpStatus: 'starting'/);
  assert.match(rendererSource, /result\.lifecycleCommitted/);
});

test('RDP disconnect blocks new starts until the active start cleanup is idle', () => {
  const commandSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:command'",
    'function getRdpClient',
  );
  const suspend = commandSource.indexOf('rdpStartOperations.suspend(request.sessionId)');
  const cleanup = commandSource.indexOf('settleTunnelCleanup(');
  const idle = commandSource.indexOf('rdpStartOperations.waitForIdle(request.sessionId)');
  const resume = commandSource.indexOf('resumeStarts?.()');
  assert.ok(suspend >= 0 && cleanup > suspend && idle > cleanup && resume > idle);
});

test('native RDP prompts and dynamic resolution use the measured connection surface', () => {
  const startSource = rdpHostSource.slice(
    rdpHostSource.indexOf('private void Start(RdpHostCommand command)'),
    rdpHostSource.indexOf('private void ScheduleRemoteResolution'),
  );
  const positionIndex = startSource.indexOf('if (!form.SetHostBounds(');
  const configureIndex = startSource.indexOf('form.Configure(');
  assert.ok(positionIndex >= 0 && positionIndex < configureIndex);
  assert.match(startSource, /form\.Configure\([\s\S]*?\n\s*hwnd,/);
  assert.match(rdpHostFormSource, /ocx\.UIParentWindowHandle = ownerHwnd\.ToInt64\(\)/);
  assert.doesNotMatch(rdpHostFormSource, /adv\.UIParentWindowHandle/);
  assert.match(rdpHostSource, /ResolutionDebounceMs = 100/);
  assert.match(rdpHostSource, /if \(command\.Op == "resize"\)[\s\S]*QueueResize\(command\)/);
  assert.match(rdpHostSource, /_pendingResize = command/);
  assert.match(rdpHostSource, /private void FlushPendingResize\(\)/);
  assert.match(rdpHostSource, /form\.TryUpdateRemoteResolution/);
  assert.match(rdpHostFormSource, /MoveWindow\([\s\S]*bRepaint: false\)/);
  assert.match(rdpHostFormSource, /RequestHostTreeRedraw\(hostHwnd, immediate: false\)/);
  assert.match(rdpHostFormSource, /RDW_ALLCHILDREN/);
  assert.doesNotMatch(rdpHostFormSource, /PerformLayout\(\)/);
});

test('native RDP start resolves only after the ActiveX helper is initialized', () => {
  const goSource = readFileSync(
    new URL('../tools/wormhole-backend/rdp.go', import.meta.url),
    'utf8',
  );
  const goStart = goSource.slice(
    goSource.indexOf('func (c *rdpController) startNative'),
    goSource.indexOf('func (c *rdpController) startExternalRdp'),
  );
  assert.match(rdpHostSource, /RdpHostEvent\("ready", command\.RequestId\)/);
  assert.doesNotMatch(goStart, /Type: "started"/);
  assert.match(goSource, /unansweredStartRequestID/);
});

test('native RDP disconnect acknowledges only after ActiveX and Go resource cleanup', () => {
  const disconnectSource = rdpHostSource.slice(
    rdpHostSource.indexOf('case "disconnect":'),
    rdpHostSource.indexOf('default:', rdpHostSource.indexOf('case "disconnect":')),
  );
  const closeIndex = disconnectSource.indexOf('CloseHost();');
  const ackIndex = disconnectSource.indexOf('Write(new RdpHostEvent("ack"');
  assert.ok(closeIndex >= 0 && closeIndex < ackIndex);
  assert.match(mainSource, /settleTunnelCleanup\([\s\S]*command\(\)[\s\S]*releaseRdpTunnel/);
});

test('native overlays hide during drag or resize and return when resizing ends', () => {
  assert.match(
    appSource,
    /active && isWebSurfaceVisible && !activeDraggedSessionId && !resizingSplitId/,
  );
  const webSurface = sourceBetween(appSource, '<WebSurface', '/>');
  assert.match(webSurface, /isActive=\{isActive\}/);
  assert.match(webSurface, /isAuthorized=\{isAuthorized\}/);
  assert.match(webSurface, /isOccluded=\{!nativeSurfaceActive\}/);
  assert.match(appSource, /<RdpSurface[\s\S]*isActive=\{nativeSurfaceActive\}/);
  assert.match(appSource, /isFileBrowserProtocol\(session\.protocol\)/);
  assert.match(appSource, /return \(\s*<SftpBrowserSurface/);

  // The native view must leave the six-pixel split handle reachable before resizing starts.
  const surfaceStyle = sourceBetween(
    appSource,
    'function sessionSurfaceStyle',
    'function SessionPaneChrome',
  );
  assert.match(surfaceStyle, /left: `calc\(\$\{rect\.x\}% \+ 3px\)`/);
  assert.match(surfaceStyle, /width: `calc\(\$\{rect\.width\}% - 6px\)`/);

  const handleMount = sourceBetween(appSource, '<SessionSplitHandle', '/>');
  assert.match(handleMount, /onResizeStart=\{\(\) => setResizingSplitId\(divider\.splitId\)\}/);
  assert.match(handleMount, /onResizeEnd=\{\(\) => setResizingSplitId\(''\)\}/);
  const handle = sourceBetween(
    appSource,
    'function SessionSplitHandle',
    'function sessionSurfaceStyle',
  );
  assert.match(handle, /onPointerDown=\{[\s\S]*?onResizeStart\(\)/);
  assert.match(handle, /onPointerCancel=\{onResizeEnd\}/);
  assert.match(handle, /onPointerUp=\{[\s\S]*?onResizeEnd\(\)/);
});

test('renderer context menus occlude native session surfaces while their portal is open', () => {
  assert.match(workspaceRootSource, /<ContextMenuOverlayProvider>/);
  assert.match(contextMenuSource, /setOpenOverlayIds/);
  assert.match(contextMenuSource, /report\(overlayId, open\)/);
  assert.match(contextMenuSource, /if \(openRef\.current\) report\(overlayId, false\)/);
  assert.match(appSource, /const contextMenuOverlayOpen = useContextMenuOverlayOpen\(\)/);
  assert.match(
    appSource,
    /isWebSurfaceVisible=\{[\s\S]*?mcpApprovals\.length === 0 &&[\s\S]*?!contextMenuOverlayOpen/,
  );
});

test('active session close uses the themed confirmation dialog', () => {
  const closeSource = appSource.slice(
    appSource.indexOf('async function performSessionClose'),
    appSource.indexOf('async function closeSessionsForNodeIds'),
  );
  assert.doesNotMatch(closeSource, /window\.confirm\(/);
  assert.match(closeSource, /setPendingSessionClose/);
  assert.match(appSource, /<DialogTitle>Disconnect active connection\?<\/DialogTitle>/);
  assert.match(appSource, /role="alertdialog"/);
  assert.match(appSource, /Close and disconnect/);
});

test('session tab menu actions stay labeled and wired to the selected session', () => {
  const menu = sourceBetween(
    appSource,
    'function SessionTabContextMenu',
    'const nodeTooltipDelayMs',
  );
  const mount = sourceBetween(appSource, '<SessionTabContextMenu', '</SessionTabContextMenu>');
  assert.match(menu, /<ContextMenu>/);
  assert.match(menu, /<ContextMenuTrigger asChild>/);
  const items = [...menu.matchAll(/<ContextMenuItem\b([^>]*)>([\s\S]*?)<\/ContextMenuItem>/g)];
  for (const [action, handler] of [
    ['onDuplicate', 'onDuplicateSession'],
    ['onReconnect', 'onReconnectSession'],
    ['onRestoreFullView', 'restoreFullView'],
    ['onDisconnect', 'onDisconnectSession'],
    ['onOpenSystemRdp', 'onOpenSystemRdp'],
    ['onFileTransfer', 'onOpenFileTransfer'],
    ['onClose', 'closePaneSession'],
  ]) {
    const item = items.find(([, props]) => props.includes(`onSelect={${action}}`));
    assert.ok(item, `${action} must remain available in the session tab menu`);
    assert.match(item[2], /(?:^|>)\s*[^<>\s][^<>]*(?=<|$)/, `${action} requires a visible label`);
    const callback = mount.match(new RegExp(`${action}=\\{([^}]*)\\}`))?.[1];
    assert.ok(callback, `${action} must be wired on the mounted menu`);
    assert.match(callback, new RegExp(`\\b${handler}\\([^)]*\\bsession\\.id\\)`));
  }
});

test('session tab titles reserve action width with and without SFTP', () => {
  const mount = sourceBetween(appSource, '<SessionTabContextMenu', '</SessionTabContextMenu>');
  const titleButton = sourceBetween(mount, '<button', '</button>');
  const titleClasses = titleButton.match(/className="([^"]+)"/)?.[1].split(/\s+/) ?? [];
  for (const token of ['flex', 'min-w-0', 'flex-1', 'pr-2']) {
    assert.ok(titleClasses.includes(token), `title button needs ${token}`);
  }
  assert.match(titleButton, /<span className="truncate">\{session\.title\}<\/span>/);

  const actions = mount.slice(mount.indexOf('</button>') + '</button>'.length);
  const actionContainer = actions.match(/^\s*<div className="([^"]+)">([\s\S]*?)<\/div>/);
  assert.ok(actionContainer, 'actions must be siblings of the title button');
  const actionClasses = actionContainer[1].split(/\s+/);
  for (const token of ['flex', 'shrink-0']) {
    assert.ok(actionClasses.includes(token), `actions must reserve their width with ${token}`);
  }
  assert.ok(!actionClasses.includes('absolute') && !actionClasses.includes('fixed'));

  const sftpAction = sourceBetween(
    actionContainer[2],
    "{session.canTransfer && session.status === 'connected' ? (",
    ') : null}',
  );
  assert.match(sftpAction, /label=\{`Open file transfer in new tab for \$\{session\.title\}`\}/);
  assert.match(sftpAction, /onClick=\{\(\) => onOpenFileTransfer\(session\.id\)\}/);
  const alwaysVisibleActions = actionContainer[2].slice(actionContainer[2].indexOf(') : null}'));
  assert.match(alwaysVisibleActions, /label=\{`Close \$\{session\.title\}`\}/);
  assert.match(alwaysVisibleActions, /onClick=\{\(\) => closePaneSession\(pane, session\.id\)\}/);
});

test('new folders expose every inheritable default before creation', () => {
  assert.match(appSource, /id="new-folder-credential"/);
  assert.match(appSource, /id="new-folder-auto-sudo"/);
  assert.match(appSource, /id="new-folder-tunnel-route"/);
  assert.match(appSource, /credentialSettingsFor\(newFolderForm\.credential\)/);
  assert.match(appSource, /tunnelValueFor\(newFolderForm\.tunnel\)/);
});

test('folder writes retain their submitted target when a dialog is reopened mid-request', () => {
  const folderDetailsSource = sourceBetween(
    appSource,
    'async function submitFolderDetails',
    'async function submitNewFolder',
  );
  const newFolderSource = sourceBetween(
    appSource,
    'async function submitNewFolder',
    'const draggedNodeIdSet',
  );
  assert.match(folderDetailsSource, /const folderId = editingFolderId\.current/);
  assert.match(folderDetailsSource, /const dialogGeneration = editingFolderGeneration\.current/);
  assert.match(folderDetailsSource, /if \(editingFolderGeneration\.current === dialogGeneration\)/);
  assert.match(newFolderSource, /const parentFolderId = newFolderParentId\.current/);
  assert.match(newFolderSource, /const dialogGeneration = newFolderGeneration\.current/);
  assert.match(newFolderSource, /if \(newFolderGeneration\.current === dialogGeneration\)/);
  assert.doesNotMatch(newFolderSource, /parentId: newFolderParentId\.current/);
});

test('opening update settings does not remount and orphan active settings operations', () => {
  const settingsMount = sourceBetween(
    appSource,
    '<SettingsPage',
    'onWorkspaceCredentialsChanged={refreshWorkspaceCredentials}',
  );
  const settingsSource = sourceBetween(appSource, 'function SettingsPage', 'function UtilityPage');
  assert.doesNotMatch(settingsMount, /key=/);
  assert.match(
    settingsSource,
    /activeTabSelection\.request === settingsUpdatesRequest[\s\S]*activeTabSelection\.value[\s\S]*'updates'/,
  );
  assert.match(
    settingsSource,
    /if \(authGate === 'unlocked'\) return;[\s\S]*setMcpState\(null\);[\s\S]*setMcpToken\(''\);[\s\S]*setMcpTokenRevealed\(false\);/,
  );
  for (const operation of [
    'revealMcpToken',
    'copyMcpToken',
    'regenerateMcpToken',
    'copyMcpConfig',
  ]) {
    const operationSource = sourceBetween(
      settingsSource,
      `async function ${operation}`,
      operation === 'copyMcpConfig' ? 'async function openCurrentLogFile' : 'async function',
    );
    assert.match(operationSource, /authGateRef\.current !== 'unlocked'/);
  }
});

test('credential mutations do not remount and orphan an active batch operation', () => {
  const credentialsMount = appSource.match(/<CredentialsPage[\s\S]*?\/>/)?.[0] ?? '';

  assert.doesNotMatch(credentialsMount, /key=/);
  assert.match(credentialsMount, /isAuthorized=\{authGate === 'unlocked'\}/);
  assert.doesNotMatch(credentialsMount, /credentials\.map/);
  assert.match(appSource, /const validSelectedCredentials = useMemo\(/);
  assert.match(
    appSource,
    /new Set\(\[\.\.\.selectedCredentials\]\.filter\(\(id\) => credentialById\.has\(id\)\)\)/,
  );
});

test('new credential flow cannot create Bitwarden-backed profiles', () => {
  const emptyDraft = sourceBetween(
    appSource,
    'function emptyCredentialDraft',
    'function credentialSelectionFor',
  );
  const credentialsPage = sourceBetween(
    appSource,
    'function CredentialsPage(',
    'function tunnelKindLabel',
  );
  const providerSelector = sourceBetween(
    credentialsPage,
    "{credentialForm.kind === 'password' ? (",
    "{credentialForm.protocol !== 'vnc' ? (",
  );
  const createParser = sourceBetween(
    mainSource,
    'function parseCredentialCreateRequest',
    'function parseWorkspaceNodeWriteRequest',
  );
  const preloadCreate = sourceBetween(preloadSource, 'createCredential:', 'updateCredential:');

  assert.match(emptyDraft, /provider: 'Local'/);
  assert.match(providerSelector, /editingCredential \? \(/);
  assert.match(providerSelector, /<SelectItem value="Bitwarden">Bitwarden item<\/SelectItem>/);
  assert.match(providerSelector, /\) : null/);
  assert.match(credentialsPage, /!editingCredential && credentialForm\.provider !== 'Local'/);
  assert.match(createParser, /request\.provider !== 'Local'/);
  assert.match(preloadCreate, /provider: 'Local'/);
  assert.doesNotMatch(preloadCreate, /Bitwarden/);
});

test('VPN diagnostics expose target probing and cancellation across the bridge', () => {
  assert.match(appSource, /id="tunnel-test-target-host"/);
  assert.match(appSource, /id="tunnel-test-target-port"/);
  assert.match(appSource, /cancelTunnelTestRun/);
  assert.match(appSource, /status: 'cancelling'/);
  assert.match(
    preloadSource,
    /cancelTunnelTest: \(\) => ipcRenderer\.invoke\('tunnel:test-cancel'\)/,
  );
  assert.match(mainSource, /ipcMain\.handle\('tunnel:test-cancel'/);
  assert.match(preloadSource, /onTunnelTestProgress/);
  assert.match(mainSource, /routeTunnelTestProgress/);
  assert.match(mainSource, /'tunnel:test-progress'/);
  assert.match(appSource, /Diagnostic log/);
  assert.match(appSource, /attempt,/);
  assert.match(mainSource, /probeTunnelTarget\([\s\S]{0,180}request\.targetHost/);
  assert.match(mainSource, /return test\.leases\.release\('tunnel-test'/);
  assert.match(
    mainSource,
    /if \(test\.cancelled\)[\s\S]{0,180}test\.backend = backend[\s\S]{0,180}test\.leases\.claim\('tunnel-test'/,
  );
  assert.match(
    appSource,
    /function closeTunnelTest\(\)[\s\S]{0,180}void cancelTunnelTestRun\(\)[\s\S]{0,180}status === 'cancelling'\) return/,
  );
});

test('backup and mRemoteNG mutations expose cooperative progress and cancellation', () => {
  assert.match(preloadSource, /cancelBackupExport/);
  assert.match(preloadSource, /cancelBackupImport/);
  assert.match(preloadSource, /cancelMRemoteImportCommit/);
  assert.match(preloadSource, /onOperationProgress/);
  assert.match(mainSource, /operation\.cancel/);
  assert.match(mainSource, /routeNativeOperationProgress/);
  assert.match(mainSource, /runOwnedNativeOperation/);
  assert.doesNotMatch(
    mainSource.slice(
      mainSource.indexOf("ipcMain.handle('backup:export'"),
      mainSource.indexOf("ipcMain.handle('workspace:create-node'"),
    ),
    /runBackend<Backup(?:Export|Import)/,
  );
});

test('SSH host-key trust delegates the retained lifecycle retry to Go', () => {
  const startSource = sourceBetween(
    appSource,
    'function startSshSession',
    'function submitSshKeyPassphrase',
  );
  assert.match(startSource, /if \(isSshHostKeyMismatchError\(message\)\) return/);

  const trustSource = sourceBetween(
    appSource,
    'async function trustSshHostKey',
    'function openQuickConnect',
  );
  assert.match(trustSource, /sessionId: session\.backendSessionId/);
  assert.match(trustSource, /sshHostKeyTrustInFlight\.current\.has/);
  assert.match(trustSource, /sshHostKeyTrustInFlight\.current\.add/);
  assert.match(trustSource, /sshHostKeyTrustInFlight\.current\.delete/);
  assert.match(
    trustSource,
    /if \(!sshHostKeyTrustInFlight\.current\.has\(session\.backendSessionId\)\) return/,
  );
  assert.match(appSource, /settlesSshHostKeyTrustAttempt\(event\.type\)/);
  assert.doesNotMatch(trustSource, /startSshSession\(|reconnectSession\(/);

  const sshEvents = sourceBetween(mainSource, 'private handleLine', 'private broadcast');
  assert.match(
    sshEvents,
    /if \(event\.retainTunnelLease\) \{[\s\S]*?\} else \{[\s\S]*?releaseTunnel/,
  );
  assert.match(mainSource, /hostKeyExpected: hasHostKeyMismatch \? hostKeyExpected : undefined/);
  assert.match(mainSource, /hostKeyReceived: hasHostKeyMismatch \? hostKeyReceived : undefined/);
  assert.match(mainSource, /value\.retain_tunnel_lease === true && hasHostKeyMismatch/);
  assert.match(sshEvents, /this\.retainedMismatchSessions\.add\(event\.sessionId\)/);
  assert.match(sshEvents, /this\.retainedMismatchSessions\.delete\(event\.sessionId\)/);
  assert.match(mainSource, /drainSshBackendSessionIds\([\s\S]*?this\.retainedMismatchSessions/);

  const sshLock = sourceBetween(mainSource, 'prepareForLock(): void', 'async close(sessionId');
  assert.match(sshLock, /this\.write\(\{ type: 'app-lock-all' \}\)/);

  const sshTrust = sourceBetween(mainSource, 'async trustHostKey', 'private waitForConnection');
  assert.match(sshTrust, /type: 'host-key-trust'/);
  assert.match(sshTrust, /host_key_expected: request\.expected/);
  assert.match(sshTrust, /host_key_received: request\.received/);
  assert.match(
    mainSource,
    /this\.pendingConnections\.get\(request\.sessionId\) === generation[\s\S]*?this\.pendingConnections\.delete\(request\.sessionId\)/,
  );
});
