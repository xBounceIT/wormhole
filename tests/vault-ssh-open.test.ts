import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { parseVaultSshOpen } from '../electron/vault-ssh-open.ts';
const target = (protocol = 'ssh') => ({
  protocol,
  host: 'ssh.example',
  port: 22,
  credentialId: '',
  tunnelId: '',
  sshAutoSudo: false,
  httpPath: '',
  ignoreCertificateErrors: false,
  rdp: null,
});
const request = () => ({ sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24 });

test('protected SSH intent admits saved references and owned Quick metadata with explicit file-only mode', () => {
  const q = request();
  for (const value of [
    q,
    { ...q, mode: 'terminal' },
    { ...q, mode: 'sftp' },
    { ...q, credentialId: randomUUID() },
    { ...q, manualCredentials: true },
    { ...q, credentialId: randomUUID(), manualKeyPassphrase: true },
  ])
    assert.deepEqual(parseVaultSshOpen(value), value);
  const { nodeId: _, ...base } = q;
  for (const protocol of ['ssh', 'sftp']) {
    const value = {
      ...base,
      mode: protocol === 'sftp' ? 'sftp' : 'terminal',
      quickTarget: target(protocol),
    };
    const parsed = parseVaultSshOpen(value)!;
    assert.deepEqual(parsed, value);
    parsed.quickTarget!.host = 'changed';
    assert.equal(value.quickTarget.host, 'ssh.example');
    assert.ok(parseVaultSshOpen({ ...value, manualCredentials: true }));
    assert.ok(
      parseVaultSshOpen({
        ...value,
        quickTarget: { ...value.quickTarget, credentialId: randomUUID() },
        manualKeyPassphrase: true,
      }),
    );
  }
  assert.ok(
    parseVaultSshOpen({ ...base, mode: 'sftp', quickTarget: target('ssh') }),
    'file tab on SSH keeps the source protocol',
  );
});

test('protected SSH intent rejects private fields, ambiguous sources, malformed bounds and mode fallback', () => {
  const q = request(),
    { nodeId: _, ...base } = q;
  const quick = { ...base, quickTarget: target() };
  for (const bad of [
    null,
    [],
    {},
    { ...q, sessionId: 'session-id' },
    { ...q, nodeId: 'bad' },
    ...[-1, 0, 501, 1.5, NaN].flatMap((n) => [
      { ...q, columns: n },
      { ...q, rows: n },
    ]),
    { ...q, mode: 'smb' },
    { ...q, mode: null },
    { ...q, manualCredentials: false },
    { ...q, manualKeyPassphrase: false },
    { ...q, manualCredentials: true, manualKeyPassphrase: true },
    { ...q, manualCredentials: true, credentialId: randomUUID() },
    { ...q, credentialId: 'bad' },
    ...[
      'username',
      'password',
      'privateKey',
      'keyPassphrase',
      'publicKey',
      'bundle',
      'host',
      'tunnelConfigId',
    ].map((key) => ({ ...q, [key]: 'forbidden' })),
    { ...quick, nodeId: q.nodeId },
    { ...quick, credentialId: randomUUID() },
    { ...quick, quickTarget: null },
    { ...quick, quickTarget: { ...target(), password: 'forbidden' } },
    { ...quick, quickTarget: target('vnc') },
    { ...quick, quickTarget: target('sftp') },
    { ...quick, quickTarget: { ...target(), credentialId: randomUUID() }, manualCredentials: true },
    { ...q, credentialId: undefined },
    { ...q, mode: undefined },
  ])
    assert.equal(parseVaultSshOpen(bad), undefined);
  for (const key of Object.keys(q)) {
    const value: any = { ...q };
    delete value[key];
    assert.equal(parseVaultSshOpen(value), undefined);
  }
});
