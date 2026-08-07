import assert from 'node:assert/strict';
import test from 'node:test';
import {
  quickConnectSupportsTunnel,
  quickConnectTunnelId,
  type QuickConnectProtocol,
} from '../src/quick-connect-state.ts';

test('Quick Connect exposes VPN only for supported network surfaces', () => {
  const supported: QuickConnectProtocol[] = ['ssh', 'rdp', 'http', 'https', 'vnc'];
  const unsupported: QuickConnectProtocol[] = ['serial'];

  for (const protocol of supported) assert.equal(quickConnectSupportsTunnel(protocol), true);
  for (const protocol of unsupported) assert.equal(quickConnectSupportsTunnel(protocol), false);
});

test('Quick Connect maps the selected tunnel only when routing is supported and enabled', () => {
  const tunnelID = '11111111-2222-3333-4444-555555555555';

  assert.equal(quickConnectTunnelId('https', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('https', 'off'), undefined);
  assert.equal(quickConnectTunnelId('ssh', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('serial', tunnelID), undefined);
});
