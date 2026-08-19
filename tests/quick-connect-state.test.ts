import assert from 'node:assert/strict';
import test from 'node:test';
import {
  connectionProtocolSupportsTunnel,
  quickConnectStartsImmediately,
  quickConnectTunnelId,
  type QuickConnectProtocol,
} from '../src/quick-connect-state.ts';

test('connection editor exposes VPN only for supported network protocols', () => {
  const supported: QuickConnectProtocol[] = ['ssh', 'rdp', 'http', 'https', 'vnc'];
  const unsupported: QuickConnectProtocol[] = ['serial'];

  for (const protocol of supported) assert.equal(connectionProtocolSupportsTunnel(protocol), true);
  for (const protocol of unsupported)
    assert.equal(connectionProtocolSupportsTunnel(protocol), false);
});

test('Quick Connect only marks SSH as connecting when credentials are immediately usable', () => {
  assert.equal(quickConnectStartsImmediately('ssh', true, undefined), false);
  assert.equal(quickConnectStartsImmediately('ssh', true, 'credential-id'), true);
  assert.equal(quickConnectStartsImmediately('ssh', false, undefined), true);
  assert.equal(quickConnectStartsImmediately('rdp', true, 'credential-id'), false);
  assert.equal(quickConnectStartsImmediately('https', true, undefined), true);
});

test('Quick Connect maps the selected tunnel only when routing is supported and enabled', () => {
  const tunnelID = '11111111-2222-3333-4444-555555555555';

  assert.equal(quickConnectTunnelId('https', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('https', 'off'), undefined);
  assert.equal(quickConnectTunnelId('ssh', tunnelID), tunnelID);
  assert.equal(quickConnectTunnelId('serial', tunnelID), undefined);
});
