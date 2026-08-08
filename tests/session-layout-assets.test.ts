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
});

test('first-open RDP startup reads the committed session snapshot', () => {
  const requestSource = appSource.slice(
    appSource.indexOf('async function requestRdpCredentials'),
    appSource.indexOf('function retryRdpSession'),
  );
  assert.match(requestSource, /sessionsRef\.current\.find/);
  assert.doesNotMatch(requestSource, /const session = sessions\.find/);
});

test('RDP bounds updates are frame-coalesced and deduplicated', () => {
  const rdpSource = readFileSync(
    new URL('../src/components/RdpSurface.tsx', import.meta.url),
    'utf8',
  );
  assert.match(rdpSource, /requestAnimationFrame\(reportBounds\)/);
  assert.match(rdpSource, /signature === boundsSignature\.current/);
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
