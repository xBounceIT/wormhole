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
  new URL('../Interop/Rdp/RdpHostForm.cs', import.meta.url),
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
  assert.match(vncSource, /if \(!disconnected\) return;[\s\S]*connectAttempt\.current \+= 1/);
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

test('manual RDP credentials disconnect a non-terminal logon attempt before restart', () => {
  const submitSource = appSource.slice(
    appSource.indexOf('async function submitRdpCredentials'),
    appSource.indexOf('function requestSshCredentials'),
  );
  const cleanup = submitSource.indexOf('await disconnectRemoteDesktopSession(sessionId)');
  const restart = submitSource.indexOf('startRdpSession(sessionId, credentials, true)');
  assert.ok(cleanup >= 0 && restart > cleanup);
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
  assert.match(goSource, /exec\.Command\(executable, args\.\.\.\)/);
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
  assert.match(appSource, /active && isWebSurfaceVisible && !draggedSessionId && !resizingSplitId/);
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
  assert.match(appSource, /!sessionIds\.includes\(draggedSessionId\)/);
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
