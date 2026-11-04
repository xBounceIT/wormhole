import assert from 'node:assert/strict';
import test from 'node:test';
import { confirmRdpCertificate } from '../electron/rdp-certificate.ts';

test('certificate trust is bounded, explicit, temporary and gated by current authorization', async () => {
  const notice = {
    sessionId: 'session',
    lifecycleId: 'attempt',
    certificate: { host: 'rdp.example', fingerprint: 'SHA256:example' },
  };
  const replies: boolean[] = [];
  let authorized = true;
  let prompts = 0;
  let mode: 'accept' | 'cancel' | 'lock' | 'fail' = 'accept';
  const hooks = {
    available: () => authorized,
    prompt: async (certificate: typeof notice.certificate) => {
      prompts++;
      assert.deepEqual(certificate, notice.certificate);
      if (mode === 'fail') throw new Error('window closed');
      if (mode === 'lock') authorized = false;
      return mode !== 'cancel';
    },
    reply: async (sessionId: string, lifecycleId: string, accepted: boolean) => {
      assert.equal(sessionId, 'session');
      assert.equal(lifecycleId, 'attempt');
      replies.push(accepted);
    },
  };
  await confirmRdpCertificate(notice, hooks);
  mode = 'cancel';
  await confirmRdpCertificate(notice, hooks);
  mode = 'fail';
  await confirmRdpCertificate(notice, hooks);
  mode = 'lock';
  await confirmRdpCertificate(notice, hooks);
  await confirmRdpCertificate(notice, hooks);
  assert.equal(prompts, 4);
  assert.deepEqual(replies, [true, false, false, false, false]);
  authorized = true;
  for (const certificate of [
    undefined,
    { host: '', fingerprint: 'x' },
    { host: 'x', fingerprint: '' },
    { host: 'x'.repeat(4097), fingerprint: 'x' },
    { host: 'x', fingerprint: 'x'.repeat(4097) },
  ]) {
    await confirmRdpCertificate({ ...notice, certificate }, hooks);
    assert.equal(replies.at(-1), false);
  }
  await confirmRdpCertificate({}, hooks);
  await confirmRdpCertificate({ sessionId: 'session' }, hooks);
  assert.equal(prompts, 4);
  await confirmRdpCertificate(notice, {
    ...hooks,
    available: () => false,
    reply: async () => {
      throw new Error('gone');
    },
  });
});
