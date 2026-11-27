import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { stopChildProcess } from '../electron/rdp.ts';

// Independent native-client fixture. The production sender/browser adapter is
// still pending; this checks Go's frozen wire AAD against another implementation.
const chunkBytes = 4 * 1024 * 1024;
type Context = {
  workspaceId: string;
  fileId: string;
  profileId: string;
  requestId: string;
  transferId: string;
  sessionId: string;
  challengeId: string;
  epoch: number;
  policySequence: string;
  sourceRevision: string;
  sourceDeleted: boolean;
  sourceDigest: string;
  bindingDigest: string;
  capturePublicKey: string;
  restorePublicKey: string;
};
type Manifest = { bytes: number; digest: string };
type Packet = {
  context: Context;
  direction: string;
  manifest: Manifest;
  index: number;
  bundle: { formatVersion: number; suiteId: number; enc: string; ciphertext: string };
};
const b64 = (raw: Uint8Array) => Buffer.from(raw).toString('base64');
function info(
  c: Context,
  direction: string,
  m: Manifest,
  index: number,
  prefix = 'wormhole/v1/vpn-sso-transfer',
) {
  const fields = [
    c.workspaceId,
    c.fileId,
    c.profileId,
    c.requestId,
    c.transferId,
    c.sessionId,
    c.challengeId,
    String(c.epoch),
    c.policySequence,
    c.sourceRevision,
    c.sourceDeleted ? '1' : '0',
    c.sourceDigest,
    c.bindingDigest,
    c.capturePublicKey,
    c.restorePublicKey,
    direction,
    String(m.bytes),
    m.digest,
    String(index),
  ];
  return Buffer.concat([
    Buffer.from(prefix),
    ...fields.flatMap((value) => {
      const bytes = Buffer.from(value),
        length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return [length, bytes];
    }),
  ]);
}
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
let directory: string, fixture: string;
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-vpn-transfer-'));
    fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['test', '-c', '-o', fixture, './internal/localvault'], {
      cwd,
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 150000 },
);
after(async () => {
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
for (const mode of ['ready', 'tamper', 'purpose', 'foreign'])
  test(
    'independent native HPKE exchanges an archive with Go custody (' + mode + ')',
    { timeout: 45000 },
    async () => {
      const child = spawn(
        fixture,
        ['-test.run=^TestVPNSSOTransferInteropFixture$', '-test.timeout=30s'],
        {
          cwd,
          windowsHide: true,
          stdio: 'pipe',
          env: { ...process.env, WORMHOLE_TEST_VPN_TRANSFER_INTEROP: mode },
        },
      );
      child.stderr.resume();
      child.stdin.on('error', () => {});
      const exited = new Promise<number | null>((yes, no) => {
        child.once('exit', yes);
        child.once('error', no);
      });
      void exited.catch(() => {});
      const reader = createInterface({ input: child.stdout }),
        lines = reader[Symbol.asyncIterator]();
      const next = async () => {
        const row = await lines.next();
        assert.equal(row.done, false);
        return JSON.parse(row.value);
      };
      try {
        const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
          'deriveBits',
        ])) as CryptoKeyPair;
        const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
        child.stdin.write(JSON.stringify({ publicKey }) + '\n');
        const offer = (await next()) as { context: Context; manifest: Manifest };
        const c = offer.context;
        assert.equal(c.restorePublicKey, publicKey);
        assert.equal(c.sourceRevision, '1');
        assert.equal(offer.manifest.bytes, chunkBytes + 3);
        const suite = new CipherSuite({
          kem: new DhkemX25519HkdfSha256(),
          kdf: new HkdfSha256(),
          aead: new Aes256Gcm(),
        });
        const restored: Uint8Array[] = [];
        for (let i = 0; i < 2; i++) {
          const packet = (await next()) as Packet;
          assert.equal(packet.index, i);
          assert.equal(packet.direction, 'restore');
          assert.deepEqual(packet.context, c);
          assert.deepEqual(packet.manifest, offer.manifest);
          const raw = new Uint8Array(
            await suite.open(
              {
                recipientKey: pair,
                enc: Buffer.from(packet.bundle.enc, 'base64'),
                info: info(c, 'restore', offer.manifest, i),
              },
              Buffer.from(packet.bundle.ciphertext, 'base64'),
            ),
          );
          assert.equal(raw.length, i === 0 ? chunkBytes : 3);
          assert.ok(raw.every((value) => value === 0x73));
          restored.push(raw);
        }
        assert.equal(
          createHash('sha256').update(restored[0]).update(restored[1]).digest('base64'),
          offer.manifest.digest,
        );
        for (const part of restored) part.fill(0);
        const raw = Buffer.alloc(chunkBytes + 7, 0xa9);
        const m: Manifest = {
          bytes: raw.length,
          digest: createHash('sha256').update(raw).digest('base64'),
        };
        child.stdin.write(JSON.stringify({ manifest: offer.manifest, chunks: 2 }) + '\n');
        const publicRecipient = await suite.kem.deserializePublicKey(
          Buffer.from(c.capturePublicKey, 'base64'),
        );
        const supplied = mode === 'foreign' ? { ...c, challengeId: randomUUID() } : c;
        for (let i = 0; i < 2; i++) {
          const sealed = await suite.seal(
            {
              recipientPublicKey: publicRecipient,
              info: info(
                supplied,
                'capture',
                m,
                i,
                mode === 'purpose' ? 'wormhole/v1/bitwarden-browser-transfer' : undefined,
              ),
            },
            raw.subarray(i * chunkBytes, Math.min(raw.length, (i + 1) * chunkBytes)),
          );
          const ciphertext = new Uint8Array(sealed.ct);
          if (mode === 'tamper' && i === 0) ciphertext[0] ^= 1;
          child.stdin.write(
            JSON.stringify({
              context: supplied,
              direction: 'capture',
              manifest: m,
              index: i,
              bundle: {
                formatVersion: 1,
                suiteId: 2,
                enc: b64(new Uint8Array(sealed.enc)),
                ciphertext: b64(ciphertext),
              },
            }) + '\n',
          );
          ciphertext.fill(0);
        }
        child.stdin.end();
        const result = await next();
        if (mode === 'ready') {
          assert.equal(result.verified, true);
          assert.equal(result.checkpoint.revision, '2');
          const header = Buffer.alloc(48);
          header.write('VSS1');
          Buffer.from(c.bindingDigest, 'base64').copy(header, 4);
          header.writeBigUInt64BE(2n, 36);
          header.writeUInt32BE(raw.length, 44);
          assert.deepEqual(result.checkpoint.digest, [
            ...createHash('sha256').update(header).update(raw).digest(),
          ]);
        } else assert.deepEqual(result, { rejected: true, preserved: mode === 'foreign' });
        raw.fill(0);
        assert.equal(await exited, 0);
      } finally {
        reader.close();
        child.stdout.resume();
        assert.equal(
          await stopChildProcess(child, { gracefulTimeoutMs: 1000, forceKillTimeoutMs: 1000 }),
          true,
        );
      }
    },
  );
