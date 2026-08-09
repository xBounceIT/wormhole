import assert from 'node:assert/strict';
import test from 'node:test';
import { parseWorkspaceRdpSettings } from '../electron/workspace-rdp-contract.ts';
import {
  canProceedWithRdpTunnelRoute,
  isRdpSurfaceRectWithinNativeBounds,
  isRdpLifecycleEvent,
  rdpGatewayCredentialIdForResolution,
  rdpGatewayUsername,
  rdpTunnelEnabledForNative,
} from '../electron/rdp-contract.ts';

const validSettings = () => ({
  domain: 'CONTOSO',
  screenSize: '1600x900',
  fullScreen: false,
  colorDepth: 32,
  useAllMonitors: true,
  audioMode: 0,
  audioCaptureMode: 1,
  keyboardHookMode: 2,
  redirectClipboard: true,
  redirectPrinters: true,
  redirectSmartCards: true,
  redirectPorts: false,
  redirectDevices: false,
  redirectDrives: 'C, D',
  connectionSpeed: 7,
  desktopBackground: true,
  fontSmoothing: true,
  desktopComposition: true,
  windowDrag: true,
  menuAnimation: true,
  visualStyles: true,
  bitmapCaching: true,
  autoReconnect: true,
  serverAuthentication: 2,
  gatewayUsageMethod: 1,
  gatewayHostname: 'gateway.example',
  gatewayCredentialId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  gatewayBypassLocal: true,
  gatewayUseSameCreds: false,
  useExternalClient: false,
});

test('Quick Connect resolves a gateway credential only when it is actually selected for use', () => {
  const base = {
    host: 'server.example',
    gatewayUsageMethod: 1,
    gatewayCredentialId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  };
  assert.equal(rdpGatewayCredentialIdForResolution(base), base.gatewayCredentialId);
  assert.equal(rdpGatewayCredentialIdForResolution({ ...base, gatewayUsageMethod: 0 }), undefined);
  assert.equal(
    rdpGatewayCredentialIdForResolution({ ...base, gatewayUseSameCreds: true }),
    undefined,
  );
  assert.equal(rdpGatewayUsername('operator', 'CONTOSO'), 'CONTOSO\\operator');
  assert.equal(rdpGatewayUsername('CONTOSO\\operator', 'IGNORED'), 'CONTOSO\\operator');
});

test('a brokered RDP route cannot be disabled by renderer tunnel metadata', () => {
  assert.equal(
    rdpTunnelEnabledForNative(
      { tunnelConfigId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', tunnelEnabled: false },
      '127.0.0.1:1080',
    ),
    true,
  );
  assert.equal(rdpTunnelEnabledForNative({ nodeId: 'saved', tunnelEnabled: true }, ''), false);
  assert.equal(rdpTunnelEnabledForNative({ tunnelEnabled: true }, ''), true);
});

test('RDP broker routes allow only Go-authorized direct saved connections', () => {
  const saved = { nodeId: 'saved', tunnelConfigId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
  const quick = { tunnelConfigId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };

  assert.equal(canProceedWithRdpTunnelRoute(saved, { active: false, socksEndpoint: '' }), true);
  assert.equal(canProceedWithRdpTunnelRoute(quick, { active: false, socksEndpoint: '' }), false);
  assert.equal(
    canProceedWithRdpTunnelRoute(saved, { active: true, socksEndpoint: '127.0.0.1:1080' }),
    true,
  );
  assert.equal(canProceedWithRdpTunnelRoute(saved, { active: true, socksEndpoint: '' }), false);
  assert.equal(
    canProceedWithRdpTunnelRoute(saved, { active: false, socksEndpoint: '127.0.0.1:1080' }),
    false,
  );
});

test('request acknowledgements and errors are not renderer lifecycle events', () => {
  assert.equal(isRdpLifecycleEvent({}), true);
  assert.equal(isRdpLifecycleEvent({ requestId: 'request-1' }), false);
});

test('native RDP surface bounds reject unsafe coordinates before screen conversion', () => {
  assert.equal(
    isRdpSurfaceRectWithinNativeBounds({ x: -1_000_000, y: 1_000_000, width: 1, height: 16_384 }),
    true,
  );
  assert.equal(
    isRdpSurfaceRectWithinNativeBounds({ x: 1_000_001, y: 0, width: 800, height: 600 }),
    false,
  );
  assert.equal(
    isRdpSurfaceRectWithinNativeBounds({ x: 0, y: 0, width: 16_385, height: 600 }),
    false,
  );
});

test('workspace RDP IPC contract accepts the complete persisted profile', () => {
  assert.deepEqual(parseWorkspaceRdpSettings(validSettings()), validSettings());
});

test('workspace RDP IPC contract rejects malformed sizes, enums, and gateways', () => {
  for (const patch of [
    { screenSize: '639x480' },
    { screenSize: '16385x900' },
    { colorDepth: 8 },
    { connectionSpeed: 0 },
    { gatewayUsageMethod: 1, gatewayHostname: '' },
    { gatewayHostname: 'bad gateway' },
    { gatewayCredentialId: 'not-a-credential' },
  ]) {
    assert.throws(() => parseWorkspaceRdpSettings({ ...validSettings(), ...patch }));
  }
});

test('workspace RDP IPC contract rejects oversized and secret-shaped malformed text', () => {
  assert.throws(() =>
    parseWorkspaceRdpSettings({ ...validSettings(), gatewayHostname: 'g'.repeat(254) }),
  );
  assert.throws(() => parseWorkspaceRdpSettings({ ...validSettings(), domain: 'bad\nvalue' }));
  assert.throws(() =>
    parseWorkspaceRdpSettings({ ...validSettings(), redirectDrives: 'C'.repeat(129) }),
  );
});
