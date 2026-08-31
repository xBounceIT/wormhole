import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const vncSource = readFileSync(
  new URL('../src/components/VncSurface.tsx', import.meta.url),
  'utf8',
);
const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
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

test('live surfaces are keyed only by session identity in one stable workspace layer', () => {
  const surfaceLayer = appSource.slice(
    appSource.indexOf('{sessions.map((session) => {', appSource.indexOf('function SessionsPage')),
    appSource.indexOf('{dropPreview?.edge ?', appSource.indexOf('function SessionsPage')),
  );
  assert.match(surfaceLayer, /key=\{session\.id\}/);
  assert.match(surfaceLayer, /<SessionSurface/);
  assert.doesNotMatch(surfaceLayer, /key=\{`?\$?\{?pane/);
});

test('layout moves do not call protocol close or disconnect operations', () => {
  const layoutSource = readFileSync(new URL('../src/session-layout.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(layoutSource, /wormhole|disconnect|closeWebSession|closeRdpSession/);
  assert.match(appSource, /function closeSession\(id: string, preferredNextSessionId\?: string\)/);
});

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

test('authentication prompt keeps the active Windows Hello request through StrictMode replay', () => {
  const promptSource = appSource.slice(
    appSource.indexOf('function AuthPrompt'),
    appSource.indexOf('type WormholeAppProps'),
  );
  assert.match(promptSource, /const activeHelloRequest = useRef<string \| null>\(null\)/);
  assert.match(promptSource, /helloInFlight\.current === requestKey/);
  assert.match(promptSource, /activeHelloRequest\.current = helloRequestKey/);
  assert.match(
    promptSource,
    /if \(activeHelloRequest\.current === helloRequestKey\) activeHelloRequest\.current = null/,
  );
  assert.doesNotMatch(promptSource, /let cancelled = false/);
});

test('first-open RDP startup reads the committed session snapshot', () => {
  const requestSource = appSource.slice(
    appSource.indexOf('async function requestRdpCredentials'),
    appSource.indexOf('function retryRdpSession'),
  );
  assert.match(requestSource, /sessionsRef\.current\.find/);
  assert.doesNotMatch(requestSource, /const session = sessions\.find/);
  assert.match(
    requestSource,
    /rdpSessionAttempts\.current\.isCurrent\(sessionId, attempt\)[\s\S]*wormhole\.startRdpSession/,
  );
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

test('RDP retry cleans a possibly live failed process before starting again', () => {
  const retrySource = appSource.slice(
    appSource.indexOf('function retryRdpSession'),
    appSource.indexOf('const refreshRdpSystemClientCapability'),
  );
  const cleanupIndex = retrySource.indexOf('disconnectRemoteDesktopSession(sessionId)');
  const startIndex = retrySource.indexOf('requestRdpCredentials(sessionId)');
  assert.ok(cleanupIndex >= 0 && cleanupIndex < startIndex);
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

test('RDP bounds updates avoid renderer-frame latency and are deduplicated', () => {
  const rdpSource = readFileSync(
    new URL('../src/components/RdpSurface.tsx', import.meta.url),
    'utf8',
  );
  assert.match(rdpSource, /const observer = new ResizeObserver\(reportBounds\)/);
  assert.match(rdpSource, /window\.addEventListener\('resize', reportBounds\)/);
  assert.doesNotMatch(rdpSource, /requestAnimationFrame\(reportBounds\)/);
  assert.match(rdpSource, /signature === boundsSignature\.current/);
  assert.match(rdpSource, /data-rdp-session-id=\{sessionId\}/);
  assert.match(rdpSource, /const shouldShowNativeSurface = status === 'connected'/);
  assert.match(rdpSource, /void api\.resizeRdpSession\(\{ sessionId, bounds \}\)/);
  assert.match(
    rdpSource,
    /if \(!shouldShowNativeSurface \|\| nativeSurfaceVisible\.current\) return/,
  );
  assert.match(appSource, /waitForRdpSurfaceBounds\(sessionId\)[\s\S]*bounds,/);
});

test('RDP system-client controls stay outside native surface bounds', () => {
  const rdpSource = readFileSync(
    new URL('../src/components/RdpSurface.tsx', import.meta.url),
    'utf8',
  );
  const toolbarIndex = rdpSource.indexOf('data-rdp-system-client-toolbar');
  const nativeRegionIndex = rdpSource.indexOf('data-rdp-native-surface-region');
  assert.ok(toolbarIndex >= 0 && toolbarIndex < nativeRegionIndex);
  assert.match(rdpSource, /data-rdp-native-surface-region[\s\S]*?ref=\{surfaceRef\}/);
  assert.match(rdpSource, /status === 'connected' && !external/);
  assert.match(rdpSource, /System Remote Desktop is running/);
  assert.match(appSource, /external=\{session\.rdpExternal\}/);
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

test('RDP start rechecks lifecycle generation after the native acknowledgement', () => {
  const startSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:start'",
    "ipcMain.handle('rdp:system-client-capability'",
  );
  const startCall = startSource.indexOf('const response = await client.start');
  const postStartCheck = startSource.indexOf(
    '!rdpSessionAttempts.isCurrent(request.sessionId, generation)',
    startCall,
  );
  assert.ok(startCall >= 0 && postStartCheck > startCall);
  assert.match(startSource.slice(postStartCheck), /client\.command\([\s\S]*'disconnect'/);
});

test('stale RDP starts delegate process and tunnel cleanup to their failure boundary once', () => {
  const embeddedSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:start'",
    "ipcMain.handle('rdp:system-client-capability'",
  );
  const systemSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:open-system'",
    "ipcMain.handle('rdp:resize'",
  );
  const embeddedStart = embeddedSource.indexOf('const response = await client.start');
  const embeddedCatch = embeddedSource.indexOf('} catch (error) {', embeddedStart);
  const systemStart = systemSource.indexOf('const result = await client.start');
  const systemCatch = systemSource.indexOf('} catch (error) {', systemStart);
  assert.ok(embeddedStart >= 0 && embeddedCatch > embeddedStart);
  assert.match(
    embeddedSource.slice(embeddedCatch),
    /settleTunnelCleanup\([\s\S]*client\.command\([\s\S]*lifecycleId[\s\S]*releaseRdpTunnel\(lifecycleId\)/,
  );
  assert.ok(systemStart >= 0 && systemCatch > systemStart);
  assert.match(
    systemSource.slice(systemCatch),
    /settleTunnelCleanup\([\s\S]*client\.command\([\s\S]*lifecycleId[\s\S]*releaseRdpTunnel\(lifecycleId\)/,
  );
});

test('authorization loss disconnects an acknowledged RDP lifecycle after renderer invalidation', () => {
  const startSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:start'",
    "ipcMain.handle('rdp:system-client-capability'",
  );
  const authorizationCleanup = startSource.slice(startSource.indexOf('if (!ownsLifecycle) return'));
  assert.doesNotMatch(authorizationCleanup, /lifecycleId && !ownerWindow\.isDestroyed\(\)/);
  assert.match(authorizationCleanup, /settleTunnelCleanup\(/);
  assert.match(
    authorizationCleanup,
    /ownerWindowAvailable \? nativeWindowHandle\(ownerWindow\) : ''[\s\S]*ownerWindowAvailable \? toScreenBounds\(ownerWindow, request\.bounds\) : undefined[\s\S]*lifecycleId/,
  );
});

test('duplicate RDP starts preserve the accepted lifecycle and VPN lease', () => {
  const startSource = sourceBetween(
    mainSource,
    "ipcMain.handle('rdp:start'",
    "ipcMain.handle('rdp:system-client-capability'",
  );
  const profileResolution = startSource.indexOf('resolveNativeRdpProfile');
  const runningCheck = startSource.indexOf('client.hasSession(request.sessionId)');
  const lifecycleBegin = startSource.indexOf('rdpSessionAttempts.begin(request.sessionId)');
  const previousDisconnect = startSource.indexOf('.command(', lifecycleBegin);
  const tunnelRelease = startSource.indexOf('await releaseRdpTunnelsForSession(request.sessionId)');
  const lifecycleIdBegin = startSource.indexOf(
    'lifecycleId = client.beginStart(request.sessionId)',
  );
  const tunnelClaim = startSource.indexOf('rdpTunnelLeases.claim(lifecycleId, leaseId)');
  const exclusiveStart = startSource.indexOf('rdpStartOperations.runExclusive(');
  assert.ok(
    exclusiveStart >= 0 &&
      profileResolution > exclusiveStart &&
      runningCheck > profileResolution &&
      lifecycleBegin > runningCheck &&
      previousDisconnect > lifecycleBegin &&
      tunnelRelease > previousDisconnect &&
      lifecycleIdBegin > tunnelRelease &&
      tunnelClaim > lifecycleIdBegin,
  );
  assert.match(startSource, /rdpStartAttempts\.begin\(request\.sessionId\)/);
  assert.match(startSource, /if \(!ownsLifecycle\) return/);
  assert.match(
    startSource,
    /catch \(error\) \{[\s\S]*settleTunnelCleanup\([\s\S]*client\.command\([\s\S]*'disconnect'[\s\S]*releaseRdpTunnel/,
  );
});

test('RDP start honors only Go-authorized direct broker routes', () => {
  const startSource = mainSource.slice(
    mainSource.indexOf("ipcMain.handle('rdp:start'"),
    mainSource.indexOf("ipcMain.handle('rdp:system-client-capability'"),
  );
  assert.match(startSource, /acquireTunnelRoute\(/);
  assert.match(startSource, /canProceedWithRdpTunnelRoute\(resolvedProfile, route\)/);
  assert.doesNotMatch(startSource, /!socksEndpoint && resolvedProfile\.tunnelConfigId/);
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

test('system RDP launches only the verified Windows system executable', () => {
  const goSource = readFileSync(
    new URL('../tools/wormhole-backend/rdp.go', import.meta.url),
    'utf8',
  );
  const windowsAdapter = readFileSync(
    new URL('../tools/wormhole-backend/rdp_system_windows.go', import.meta.url),
    'utf8',
  );
  assert.match(windowsAdapter, /windows\.GetSystemDirectory\(\)/);
  assert.match(windowsAdapter, /filepath\.Join\(systemDirectory, "mstsc\.exe"\)/);
  assert.match(goSource, /newExternalRdpCommand\s+= exec\.Command/);
  assert.match(goSource, /newExternalRdpCommand\(executable, args\.\.\.\)/);
  assert.doesNotMatch(goSource, /exec\.Command\("mstsc\.exe"/);
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

test('editing an open RDP session releases and resets its native lifecycle', () => {
  const editorSource = appSource.slice(
    appSource.indexOf('const editedSessionId = `session-${editingId}`'),
    appSource.indexOf(
      '} else {',
      appSource.indexOf('const editedSessionId = `session-${editingId}`'),
    ),
  );
  assert.match(editorSource, /await releaseSessionResources\(editedSession\)/);
  assert.match(
    editorSource,
    /rdpStatus: newConnectionForm\.protocol === 'rdp' \? 'idle' : undefined/,
  );
  assert.match(editorSource, /requestRdpCredentials\(editedSessionId\)/);
});

test('native web and RDP overlays are hidden while a layout drag is active', () => {
  assert.match(
    appSource,
    /active && isWebSurfaceVisible && !activeDraggedSessionId && !resizingSplitId/,
  );
  assert.match(appSource, /<WebSurface[\s\S]*isActive=\{nativeSurfaceActive\}/);
  assert.match(appSource, /<RdpSurface[\s\S]*isActive=\{nativeSurfaceActive\}/);
  assert.match(appSource, /session\.sftp && isActive/);
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

test('session tab actions use the themed renderer context menu with dedicated icons', () => {
  const menuSource = appSource.slice(
    appSource.indexOf('function SessionTabContextMenu'),
    appSource.indexOf('const nodeTooltipDelayMs'),
  );
  assert.match(menuSource, /<ContextMenu>/);
  assert.match(menuSource, /<ContextMenuTrigger asChild>/);
  assert.match(menuSource, /<Copy \/>[\s\S]*Duplicate/);
  assert.match(menuSource, /<RefreshCcw \/>[\s\S]*Reconnect/);
  assert.match(menuSource, /<Maximize2 \/>[\s\S]*Restore full view/);
  assert.match(menuSource, /<Power \/>[\s\S]*Disconnect/);
  assert.match(menuSource, /<Monitor \/>[\s\S]*Open in System Remote Desktop/);
  assert.match(menuSource, /<FolderOpen \/>[\s\S]*SFTP browser/);
  assert.match(menuSource, /<X \/>[\s\S]*Close/);
  assert.doesNotMatch(appSource, /showSessionTabContextMenu/);
  assert.doesNotMatch(preloadSource, /session-tab:context-menu/);
  assert.doesNotMatch(mainSource, /session-tab:context-menu/);
});

test('surface bounds reserve a reachable gutter for split handles above native views', () => {
  assert.match(appSource, /left: `calc\(\$\{rect\.x\}% \+ 3px\)`/);
  assert.match(appSource, /width: `calc\(\$\{rect\.width\}% - 6px\)`/);
  assert.match(appSource, /className=\{`absolute z-30 touch-none/);
  assert.match(appSource, /onResizeStart=\{\(\) => setResizingSplitId\(divider\.splitId\)\}/);
  assert.match(appSource, /onPointerCancel=\{onResizeEnd\}/);
});

test('drag cancellation clears both the dragged tab and its visual target', () => {
  assert.match(
    appSource,
    /onDragEnd=\{\(\) => \{\s*setDraggedSessionId\(''\);\s*setDropPreview\(null\);/,
  );
  assert.match(
    appSource,
    /const dragIsValid = !draggedSessionId \|\| sessionIds\.includes\(draggedSessionId\)/,
  );
  assert.match(appSource, /const activeDropPreview = dragIsValid \? dropPreview : null/);
  assert.match(
    appSource,
    /if \(draggedSessionId && !sessionIds\.includes\(draggedSessionId\)\)[\s\S]*setDraggedSessionId\(''\);[\s\S]*setDropPreview\(null\);/,
  );
});

test('session reconciliation is persisted so reopened IDs cannot revive stale pane placement', () => {
  const sessionsSource = sourceBetween(
    appSource,
    'function SessionsPage',
    'function SessionSplitHandle',
  );

  assert.match(
    sessionsSource,
    /setLayout\(\(current\) =>[\s\S]*reconcileSessionLayout\(current, sessionIds, selectedSession\?\.id\)/,
  );
  assert.match(sessionsSource, /\}, \[draggedSessionId, selectedSession\?\.id, sessionIds\]\);/);
});

test('session pane chrome stays neutral and tab labels match connection tree typography', () => {
  const sessionsSource = appSource.slice(
    appSource.indexOf('function SessionsPage'),
    appSource.indexOf('function SessionPaneChrome'),
  );
  const paneChromeSource = appSource.slice(
    appSource.indexOf('function SessionPaneChrome'),
    appSource.indexOf('function SessionDropPreview'),
  );

  assert.match(sessionsSource, /cursor-grab truncate px-3 pr-12 text-left !text-xs font-medium/);
  assert.match(paneChromeSource, /absolute border border-border/);
  assert.doesNotMatch(paneChromeSource, /active \? 'border-primary/);
});

test('Quick Connect keeps its session name optional in the mounted form', () => {
  assert.match(appSource, /Session name \(optional\)/);
  assert.match(appSource, /required=\{connectionEditorMode === 'saved'\}/);
  assert.match(appSource, /connectionEditorMode === 'quick'[\s\S]{0,160}Defaults to target/);
});

test('Connect actions use text without a power icon', () => {
  const connectButtonSources = [...appSource.matchAll(/<Button\b[\s\S]*?<\/Button>/g)]
    .map((match) => match[0])
    .filter((source) => /\bConnect(?:ing)?\b/i.test(source));

  assert.ok(connectButtonSources.length > 0);
  for (const source of connectButtonSources) assert.doesNotMatch(source, /<Power\b/);
});

test('serial connections omit the VPN route from the mounted connection editor', () => {
  const editorSource = sourceBetween(
    appSource,
    'open={newConnectionOpen}',
    'open={folderDetailsOpen}',
  );
  const tunnelFieldIndex = editorSource.indexOf('id="connection-tunnel-route"');
  assert.ok(tunnelFieldIndex >= 0, 'missing connection VPN route field');
  const tunnelFieldSource = editorSource.slice(
    Math.max(0, tunnelFieldIndex - 300),
    tunnelFieldIndex + 500,
  );

  assert.match(
    tunnelFieldSource,
    /connectionProtocolSupportsTunnel\(newConnectionForm\.protocol\) \? \([\s\S]*<TunnelRouteField/,
  );
  assert.doesNotMatch(tunnelFieldSource, /disabled=/);
  assert.equal(editorSource.match(/id="connection-tunnel-route"/g)?.length, 1);
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
  assert.doesNotMatch(settingsMount, /key=\{`\$\{authGate\}:\$\{settingsUpdatesRequest\}`\}/);
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

test('header update action matches the compact app button typography', () => {
  const updateButtonSource = sourceBetween(
    appSource,
    '{updateBannerVisible ? (',
    '<ResizablePanelGroup',
  );
  assert.match(updateButtonSource, /className="[^"]*!text-xs[^"]*"/);
  assert.doesNotMatch(updateButtonSource, /text-\[10px\]/);
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

test('virtual card grids label the semantic list rather than a generic scroll container', () => {
  const virtualGridSource = readFileSync(
    new URL('../src/components/VirtualCardGrid.tsx', import.meta.url),
    'utf8',
  );
  const scrollArea = sourceBetween(virtualGridSource, '<ScrollArea', '<ul');
  const list = sourceBetween(virtualGridSource, '<ul', 'className="absolute');

  assert.doesNotMatch(scrollArea, /aria-label/);
  assert.match(list, /aria-label=\{ariaLabel\}/);
});

test('an asynchronous Bitwarden region refresh does not clear an open login form', () => {
  const dialogMount = sourceBetween(appSource, '<BitwardenCliDialog', 'onUnlock={(masterPassword)');

  assert.match(dialogMount, /key=\{bitwardenCliDialog\}/);
  assert.doesNotMatch(
    dialogMount,
    /key=\{`\$\{bitwardenCliDialog\}:\$\{bitwardenServerRegion\}`\}/,
  );
});

test('SFTP keyboard range selection replaces a stale anchor', () => {
  const keyboardSelection = sourceBetween(
    appSource,
    'function moveKeyboardSelection',
    'function beginRename',
  );

  assert.match(keyboardSelection, /validSelectedPaths\.size > 0/);
  assert.match(keyboardSelection, /nextSftpSelection\(/);
  assert.match(keyboardSelection, /selectionAnchorPath\.current = next\.anchorPath/);
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

test('VPN cards show searchable endpoint metadata instead of a managed-tunnel placeholder', () => {
  const tunnelsPage = sourceBetween(appSource, 'function TunnelsPage', 'function SettingsSection');

  assert.match(preloadSource, /listTunnels: \(\) => ipcRenderer\.invoke\('tunnel:list'\)/);
  assert.match(mainSource, /parseTunnelSummaryList\(await runBackend<unknown>\('tunnel-list'\)\)/);
  assert.match(
    mainSource,
    /parseTunnelDetailsResponse\(await runBackend<unknown>\('tunnel-create'/,
  );
  assert.match(tunnelsPage, /\.listTunnels\(\)/);
  assert.match(tunnelsPage, /attempt === summaryLoadAttemptRef\.current/);
  assert.match(tunnelsPage, /\+\+summaryLoadAttemptRef\.current/);
  assert.match(appSource, /current\.filter\(\(item\) => item\.id !== tunnel\.id\)/);
  assert.match(tunnelsPage, /tunnel\.endpoint \?\? ''/);
  assert.match(tunnelsPage, /tunnel\.endpoint \|\| 'Endpoint unavailable'/);
  assert.match(tunnelsPage, /title=\{tunnel\.endpoint \|\| undefined\}/);
  assert.match(tunnelsPage, /label=\{`Delete \$\{tunnel\.name\}`\}[\s\S]{0,160}<Trash2 \/>/);
  assert.doesNotMatch(tunnelsPage, /Managed VPN tunnel/i);
});

test('VPN editor keeps WatchGuard authentication and Stormshield OTP layout contracts explicit', () => {
  const fields = sourceBetween(
    appSource,
    'function tunnelEditorFields',
    'function tunnelDefaultSettings',
  );
  const watchguard = sourceBetween(fields, 'case 3:', 'case 4:');
  const stormshield = sourceBetween(fields, 'case 4:', 'case 5:');

  const server = watchguard.indexOf("key: 'Server'");
  const port = watchguard.indexOf("key: 'Port'");
  const authMode = watchguard.indexOf("key: 'AuthMode'");
  assert.ok(server >= 0 && server < port && port < authMode);
  assert.match(
    watchguard,
    /key: 'TrustServerCertificate'[\s\S]{0,180}label: 'Ignore certificate errors'[\s\S]{0,100}type: 'switch'/,
  );
  assert.match(watchguard, /key: 'AuthMode'[\s\S]{0,240}Username and password[\s\S]{0,120}SAML/);
  assert.match(watchguard, /key: 'VerifyX509Name'[\s\S]{0,240}fullWidth: true/);
  assert.doesNotMatch(watchguard, /UseSingleSignOn|Use SSO|label: 'Automatic'/);
  const watchguardRender = sourceBetween(
    appSource,
    '{value.kind === 3 ? (',
    '{value.kind === 4 ? (',
  );
  assert.match(
    watchguardRender,
    /title="Authentication"[\s\S]{0,180}useWatchguardSso[\s\S]{0,160}field\.key === 'Username'[\s\S]{0,120}field\.key === 'Password'/,
  );
  assert.match(
    watchguardRender,
    /grid-cols-\[minmax\(0,1fr\)_7rem\][\s\S]{0,180}rows\('Gateway'\)/,
  );
  assert.match(
    mainSource,
    /setCertificateVerifyProc[\s\S]{0,180}event\.ignoreCertificateErrors[\s\S]{0,100}fireboxHost/,
  );
  const fieldRow = sourceBetween(appSource, 'function TunnelFieldRow', 'function TunnelSection');
  assert.match(
    fieldRow,
    /field\.type === 'switch'[\s\S]{0,160}justify-between[\s\S]{0,160}<Label[\s\S]{0,120}<Switch/,
  );
  assert.match(fieldRow, /field\.type === 'checkbox'[\s\S]{0,120}<Checkbox/);

  const otp = stormshield.indexOf("key: 'UseOtp'");
  const username = stormshield.indexOf("key: 'Username'");
  const password = stormshield.indexOf("key: 'Password'");
  assert.ok(otp >= 0 && otp < username && username < password);
  assert.match(stormshield, /key: 'UseOtp'[\s\S]{0,180}fullWidth: true/);
  assert.doesNotMatch(stormshield, /UseSingleSignOn|Connect with single sign-on/i);
  assert.match(appSource, /field\.fullWidth\) && 'col-span-full'/);
});

test('OpenVPN profile import shares the field label row without rendering a duplicate label', () => {
  const fields = sourceBetween(
    appSource,
    'function tunnelEditorFields',
    'function tunnelDefaultSettings',
  );
  const openVpnFields = sourceBetween(fields, 'case 1:', 'case 2:');
  const fieldRow = sourceBetween(appSource, 'function TunnelFieldRow', 'function TunnelSection');
  const openVpnRender = sourceBetween(appSource, '{value.kind === 1 ? (', '{value.kind === 2 ? (');

  assert.equal(openVpnFields.match(/label: 'OpenVPN profile \(\.ovpn contents\)'/g)?.length, 1);
  assert.match(openVpnRender, /rows\('Profile', \{[\s\S]{0,120}labelAction:/);
  assert.match(openVpnRender, /disabled=\{busy\}/);
  assert.match(openVpnRender, /onClick=\{\(\) => void importOvpnProfile\(\)\}/);
  assert.match(openVpnRender, /type="button"/);
  assert.match(openVpnRender, /Import from file…/);
  assert.doesNotMatch(openVpnRender, /<Label[^>]*>OpenVPN profile/);
  assert.match(fieldRow, /labelAction \? \(/);
  assert.match(fieldRow, /flex flex-wrap items-center justify-between gap-2/);
  assert.match(fieldRow, /<Label htmlFor=\{`tunnel-\$\{field\.key\}`\}>\{field\.label\}<\/Label>/);
  assert.match(fieldRow, /\{labelAction\}/);
});

test('Fortinet SSO and certificate choices render as switches on dedicated rows', () => {
  const fields = sourceBetween(
    appSource,
    'function tunnelEditorFields',
    'function tunnelDefaultSettings',
  );
  const fortinet = sourceBetween(fields, 'case 2:', 'case 3:');
  const watchguard = sourceBetween(fields, 'case 3:', 'case 4:');
  const stormshield = sourceBetween(fields, 'case 4:', 'case 5:');
  const cisco = sourceBetween(fields, 'case 6:', 'default:');
  const fieldRow = sourceBetween(appSource, 'function TunnelFieldRow', 'function TunnelSection');

  assert.match(fortinet, /key: 'UseSingleSignOn'[\s\S]{0,180}type: 'switch'/);
  assert.match(fortinet, /key: 'UseExternalBrowser'[\s\S]{0,180}type: 'switch'/);
  assert.match(fortinet, /key: 'TrustServerCertificate'[\s\S]{0,180}type: 'switch'/);
  assert.match(fortinet, /key: 'TotpSecret'[\s\S]{0,240}fullWidth: true/);
  assert.match(fortinet, /key: 'TrustServerCertificate'[\s\S]{0,240}fullWidth: true/);
  assert.match(fortinet, /key: 'ServerCertSha256Pin'[\s\S]{0,240}fullWidth: true/);
  assert.match(fieldRow, /field\.type === 'switch'[\s\S]{0,500}<Switch/);
  assert.match(fieldRow, /<Switch[\s\S]{0,160}aria-label=\{field\.label\}/);
  assert.match(fieldRow, /field\.type === 'checkbox'[\s\S]{0,180}<Checkbox/);
  assert.match(watchguard, /key: 'TrustServerCertificate'[\s\S]{0,180}type: 'switch'/);
  assert.match(stormshield, /key: 'UseOtp'[\s\S]{0,180}type: 'checkbox'/);
  assert.match(stormshield, /key: 'TrustServerCertificate'[\s\S]{0,180}type: 'checkbox'/);
  assert.match(cisco, /key: 'TrustServerCertificate'[\s\S]{0,180}type: 'checkbox'/);
});

test('VPN editor keeps expanded provider fields inside its scrolling body', () => {
  const editor = sourceBetween(
    appSource,
    'function TunnelEditorDialog',
    '// Tunnel CRUD, test progress, and editor lifecycle form',
  );
  const dialogContent = sourceBetween(editor, '<DialogContent', '>');
  const form = sourceBetween(editor, '<form', '</form>');

  assert.match(dialogContent, /max-h-\[calc\(100dvh-2rem\)\]/);
  assert.match(dialogContent, /flex-col/);
  assert.match(dialogContent, /overflow-hidden/);
  assert.match(form, /className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto pr-3"/);
  assert.match(form, /id="tunnel-editor-form"/);
  assert.match(form, /Manual profile fallback & advanced/);
  assert.doesNotMatch(form, /role="alert"|<DialogFooter>/);
  assert.match(editor, /<Button[^>]*form="tunnel-editor-form" type="submit">/);
  const afterForm = editor.slice(editor.indexOf('</form>'));
  const alertPosition = afterForm.indexOf('role="alert"');
  const footerPosition = afterForm.indexOf('<DialogFooter>');
  assert.ok(alertPosition >= 0 && alertPosition < footerPosition);
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

test('failed initial web navigation diagnoses SOCKS targets and releases its VPN lease', () => {
  assert.match(mainSource, /finishInitialNavigationFailure/);
  assert.match(mainSource, /tunnelBackend: openingLeaseId \? openingTunnelBackend : undefined/);
  assert.match(
    mainSource,
    /await backend\.probeTunnelTarget\(leaseId, probeTarget\.host, probeTarget\.port\)/,
  );
  assert.doesNotMatch(mainSource, /getNativeBackend\(\)\.probeTunnelTarget/);
  assert.match(mainSource, /tunnelLeases\.isActive\(sessionId, leaseId\)/);
  assert.match(mainSource, /Could not release the failed web session VPN tunnel/);
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
  assert.doesNotMatch(trustSource, /startSshSession\(|reconnectSession\(/);

  const sshEvents = sourceBetween(mainSource, 'private handleLine', 'private broadcast');
  assert.match(sshEvents, /if \(!event\.retainTunnelLease\) \{[\s\S]*?releaseTunnel/);
  assert.match(mainSource, /hostKeyExpected: hasHostKeyMismatch \? hostKeyExpected : undefined/);
  assert.match(mainSource, /hostKeyReceived: hasHostKeyMismatch \? hostKeyReceived : undefined/);
  assert.match(mainSource, /value\.retain_tunnel_lease === true && hasHostKeyMismatch/);

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
