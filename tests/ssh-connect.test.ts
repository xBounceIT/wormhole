import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { sshConnectRequest, vaultSshQuickTarget } from '../src/ssh-connect.ts';
import { parseVaultSshOpen } from '../electron/vault-ssh-open.ts';

test('SSH public request reconstructs saved and Quick intent without legacy transport fields', () => {
  const sessionId = randomUUID(),
    nodeId = randomUUID(),
    credentialId = randomUUID();
  const legacy = {
    sessionId,
    nodeId,
    credentialId: undefined,
    mode: undefined,
    host: 'renderer.example',
    tunnelConfigId: randomUUID(),
    autoSudo: true,
    username: undefined,
    password: undefined,
    keyPassphrase: undefined,
  };
  assert.deepEqual(sshConnectRequest(legacy, undefined, true), {
    sessionId,
    nodeId,
    columns: 80,
    rows: 24,
    mode: 'terminal',
  });
  assert.equal(
    sshConnectRequest({ ...legacy, credentialId }, undefined, true).credentialId,
    credentialId,
  );
  for (const protocol of ['ssh', 'sftp']) {
    const target = vaultSshQuickTarget({
      protocol,
      host: '::1',
      port: 22,
      credentialId,
      tunnelId: randomUUID(),
      sshAutoSudo: true,
    });
    for (const explicit of [false, true]) {
      const q = sshConnectRequest(
        {
          sessionId,
          ...(explicit ? { quickTarget: target } : {}),
          frontendSessionId: randomUUID(),
        },
        { protocol, quickTarget: target },
        true,
      );
      assert.deepEqual(parseVaultSshOpen(q), q);
      assert.equal(q.quickTarget!.tunnelId, target.tunnelId);
      assert.equal(q.quickTarget!.sshAutoSudo, true);
      assert.equal(q.mode, protocol === 'sftp' ? 'sftp' : 'terminal');
      assert.equal('credentialId' in q, false);
      const changed = sshConnectRequest(
        { sessionId, quickTarget: target, mode: q.mode, credentialId: nodeId },
        undefined,
        true,
      );
      assert.equal(changed.quickTarget!.credentialId, nodeId);
      assert.equal(target.credentialId, credentialId);
      const manual = sshConnectRequest(
        { sessionId, quickTarget: target, mode: q.mode, manualCredentials: true },
        undefined,
        true,
      );
      assert.equal(manual.quickTarget!.credentialId, '');
      assert.equal(manual.manualCredentials, true);
      assert.equal(
        sshConnectRequest(
          { sessionId, quickTarget: target, mode: q.mode, manualKeyPassphrase: true },
          undefined,
          true,
        ).manualKeyPassphrase,
        true,
      );
    }
  }
  assert.equal(vaultSshQuickTarget({ protocol: 'ssh', host: 'example' }).port, 0);
  assert.equal(
    sshConnectRequest({ sessionId, nodeId, manualCredentials: true }, undefined, true)
      .manualCredentials,
    true,
  );
  assert.equal(
    'credentialId' in
      sshConnectRequest(
        { sessionId, nodeId, credentialId, manualCredentials: true },
        undefined,
        true,
      ),
    false,
  );
});

test('vault SSH cannot accept account bytes, ambiguous sources or invalid metadata; legacy remains compatible', () => {
  const request = { sessionId: randomUUID(), nodeId: randomUUID() };
  for (const key of ['username', 'password', 'keyPassphrase'])
    for (const value of ['', 'secret'])
      assert.throws(
        () => sshConnectRequest({ ...request, [key]: value }, undefined, true),
        /protected credential/,
      );
  const target = vaultSshQuickTarget({ protocol: 'ssh', host: 'example' });
  for (const q of [
    { ...request, quickTarget: target },
    { ...request, sessionId: 'bad' },
    { ...request, nodeId: undefined },
    { ...request, mode: 'smb' as const },
    { ...request, manualCredentials: true, manualKeyPassphrase: true },
  ])
    assert.throws(() => sshConnectRequest(q, undefined, true), /invalid/);
  for (const protocol of ['vnc', 'smb', 'unknown'])
    assert.throws(() => vaultSshQuickTarget({ protocol, host: 'example' }), /invalid/);
  assert.throws(() => vaultSshQuickTarget({ protocol: 'ssh', host: '' }), /invalid/);
  const legacy = {
    ...request,
    host: 'legacy',
    username: 'user',
    password: '',
    keyPassphrase: '',
    manualKeyPassphrase: true,
    frontendSessionId: 'tab',
  };
  const { frontendSessionId: _, ...expected } = legacy;
  assert.deepEqual(sshConnectRequest(legacy, undefined, false), {
    ...expected,
    mode: 'terminal',
    columns: 80,
    rows: 24,
  });
  assert.equal(sshConnectRequest(request, { protocol: 'smb' }, false).mode, 'smb');
  assert.equal(sshConnectRequest(request, { protocol: 'sftp' }, false).mode, 'sftp');
});
