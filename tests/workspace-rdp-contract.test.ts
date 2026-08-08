import assert from 'node:assert/strict';
import test from 'node:test';
import { parseWorkspaceRdpSettings } from '../electron/workspace-rdp-contract.ts';

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
