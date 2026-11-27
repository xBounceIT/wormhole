import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  canonicalBase64,
  parseVaultSshBundle,
  validVaultSshRequest,
} from '../electron/vault-ssh.ts';

import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';

test('SSH relay contracts bind every authority field and preserve only exact bounded ciphertext', () => {
  const q = sshRequest(),
    value = sshBundle(q);
  assert.equal(validVaultSshRequest(q), true);
  assert.deepEqual(parseVaultSshBundle(value, q), value);
  for (const field of [
    'workspaceId',
    'nodeId',
    'sessionId',
    'requestId',
    'epoch',
    'protocol',
    'host',
    'port',
    'tunnelConfigId',
    'useExternalClient',
  ]) {
    const changed = structuredClone(value) as any;
    changed.binding[field] =
      field === 'port'
        ? 0
        : field === 'host'
          ? 'bad host'
          : field === 'epoch'
            ? 2
            : field === 'useExternalClient'
              ? true
              : randomUUID();
    assert.equal(parseVaultSshBundle(changed, q), undefined, field);
  }
  for (const mutate of [
    (v: any) => {
      v.extra = 1;
    },
    (v: any) => {
      v.binding.extra = 1;
    },
    (v: any) => {
      v.bundle.extra = 1;
    },
    (v: any) => {
      v.bundle.suiteId = 3;
    },
    (v: any) => {
      v.bundle.formatVersion = 2;
    },
    (v: any) => {
      v.bundle.enc = 'bad';
    },
    (v: any) => {
      v.bundle.ciphertext = '';
    },
    (v: any) => {
      v.binding.host = '\ud800';
    },
    (v: any) => {
      v.binding.port = 65536;
    },
  ]) {
    const v = structuredClone(value);
    mutate(v);
    assert.equal(parseVaultSshBundle(v, q), undefined);
  }
  for (const v of [null, [], 1, '', {}]) assert.equal(parseVaultSshBundle(v, q), undefined);
  for (const mutate of [
    (q: any) => {
      q.epoch = 0;
    },
    (q: any) => {
      q.epoch = 2 ** 53;
    },
    (q: any) => {
      q.nodeId = 'bad';
    },
    (q: any) => {
      q.credentialOverride = 'bad';
    },
    (q: any) => {
      q.publicKey = '';
    },
  ]) {
    const bad = { ...q };
    mutate(bad);
    assert.equal(validVaultSshRequest(bad), false);
    assert.equal(parseVaultSshBundle(value, bad), undefined);
  }
  assert.ok(validVaultSshRequest({ ...q, credentialOverride: randomUUID() }));
  for (const v of [null, '!!!!', 'YQ==\n', 'YQ=', 'YR==', Buffer.alloc(33).toString('base64')])
    assert.equal(canonicalBase64(v, 32, 32), false);
  value.bundle.ciphertext = Buffer.alloc(4 * 1024 * 1024 + 16).toString('base64');
  assert.ok(parseVaultSshBundle(value, q));
  value.bundle.ciphertext = Buffer.alloc(4 * 1024 * 1024 + 17).toString('base64');
  assert.equal(parseVaultSshBundle(value, q), undefined);
});
test('direct SFTP ciphertext retains its native protocol', () => {
  const q = sshRequest(),
    value = sshBundle(q);
  value.binding.protocol = 'sftp';
  assert.deepEqual(parseVaultSshBundle(value, q), value);
});
test('file-only mode is explicit and cannot be stripped from direct ciphertext', () => {
  const q = { ...sshRequest(), sftpOnly: true as const },
    value = sshBundle(q);
  assert.deepEqual(parseVaultSshBundle(value, q), value);
  for (const sftpOnly of [undefined, false, null, 'true', 1]) {
    assert.equal(parseVaultSshBundle({ ...value, sftpOnly }, q), undefined);
    if (sftpOnly !== undefined)
      assert.equal(validVaultSshRequest({ ...q, sftpOnly } as any), false);
  }
  assert.equal(parseVaultSshBundle(value, { ...q, sftpOnly: undefined }), undefined);
});
