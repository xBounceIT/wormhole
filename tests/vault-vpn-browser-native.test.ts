import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import { VaultVPNBrowserRecipient } from '../electron/vault-vpn-browser.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { stopChildProcess } from '../electron/rdp.ts';
import type { VPNSSOBegin } from '../electron/vault-vpn-sso.ts';

const backend = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
let directory: string, executable: string;
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-vpn-browser-'));
    executable = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['test', '-c', '-o', executable, '.'], {
      cwd: backend,
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 150000 },
);
after(async () => {
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});
function launch(mode: string) {
  const child = spawn(
    executable,
    ['-test.run=^TestVPNBrowserInteropProcess$', '-test.timeout=60s'],
    {
      cwd: backend,
      windowsHide: true,
      stdio: 'pipe',
      env: {
        ...process.env,
        TEMP: directory,
        TMP: directory,
        TMPDIR: directory,
        WORMHOLE_TEST_VPN_BROWSER: mode,
      },
    },
  );
  child.stderr.resume();
  return child;
}
async function root() {
  const child = launch('vault'),
    reader = createInterface({ input: child.stdout });
  let info: any;
  try {
    info = await new Promise<any>((resolve, reject) => {
      reader.once('line', (line) => {
        try {
          resolve(JSON.parse(line));
        } catch (error) {
          reject(error);
        }
      });
      child.once('error', reject);
    });
  } finally {
    reader.close();
  }
  const client = new VaultBackendClient(
    { executable, databasePath: 'owned-native-fixture', heartbeatMs: 10000 },
    () => {
      queueMicrotask(() => {
        child.emit('spawn');
        child.stdout.resume();
      });
      return child;
    },
  );
  const request = {
    ...info.request,
    workspaceId: info.binding.workspaceId,
    epoch: Number(info.request.epoch),
  };
  return { child, client, request, binding: info.binding };
}
async function recipient(controller: AbortController, current: () => boolean) {
  let child: ReturnType<typeof launch> | undefined;
  const native = await VaultVPNBrowserRecipient.open(
    { executable, signal: controller.signal, current },
    (exe, args) => {
      assert.equal(exe, executable);
      assert.deepEqual(args, ['--operation', 'vault-vpn-browser']);
      child = launch('recipient');
      return child;
    },
  );
  return { native, child: child! };
}
function begin(r: Awaited<ReturnType<typeof root>>, native: VaultVPNBrowserRecipient): VPNSSOBegin {
  return {
    request: r.request,
    binding: r.binding,
    challengeId: randomUUID(),
    profileId: native.metadata.profileId,
    restorePublicKey: native.metadata.publicKey,
    startURL: 'https://vpn.test:443/remote/saml/start?realm=staff',
    ignoreCertificateErrors: false,
  };
}

test(
  'disposable Go CLI recipient exchanges two-chunk storage through the production native vault client',
  { timeout: 60000 },
  async () => {
    const r = await root(),
      first = await recipient(new AbortController(), () => true);
    let second: Awaited<ReturnType<typeof recipient>> | undefined;
    try {
      assert.deepEqual(Object.keys(first.native.metadata).sort(), [
        'lockedMemory',
        'profileId',
        'publicKey',
      ]);
      first.native.metadata.profileId = randomUUID();
      const offer = await r.client.beginVPNSSO(begin(r, first.native));
      assert.equal(
        (
          await first.native.restore(offer, (i) =>
            r.client.takeVPNSSO(offer.context, offer.manifest, i),
          )
        ).length,
        0,
      );
      await r.client.acknowledgeVPNSSO(offer.context, offer.manifest);
      const archive = Buffer.alloc(4 * 1024 * 1024 + 37, 0x79),
        expected = Buffer.from(archive);
      const manifest = await first.native.capture(archive, async (p) => {
        await r.client.pushVPNSSO(p);
      });
      assert.equal(manifest.bytes, expected.length);
      assert.ok(archive.every((n) => n === 0));
      assert.equal((await r.client.commitVPNSSO(offer.context)).revision, '1');
      await first.native.close();
      second = await recipient(new AbortController(), () => true);
      assert.notEqual(second.native.metadata.publicKey, first.native.metadata.publicKey);
      const restoredOffer = await r.client.beginVPNSSO(begin(r, second.native));
      const restored = await second.native.restore(restoredOffer, (i) =>
        r.client.takeVPNSSO(restoredOffer.context, restoredOffer.manifest, i),
      );
      assert.deepEqual(restored, expected);
      restored.fill(0);
      expected.fill(0);
      await r.client.acknowledgeVPNSSO(restoredOffer.context, restoredOffer.manifest);
      await r.client.cancelVPNSSO(restoredOffer.context);
      await second.native.close();
      await second.native.close();
    } finally {
      await first.native.close();
      await second?.native.close();
      await r.client.stop();
      assert.ok(
        await stopChildProcess(r.child, { gracefulTimeoutMs: 1000, forceKillTimeoutMs: 1000 }),
      );
    }
  },
);

test(
  'native recipient cancellation joins original child termination and wipes refused capture input',
  { timeout: 60000 },
  async () => {
    const r = await root(),
      controller = new AbortController();
    let current = true;
    const f = await recipient(controller, () => current);
    try {
      const offer = await r.client.beginVPNSSO(begin(r, f.native));
      await f.native.restore(offer, () => {
        throw Error('empty restore must not request a chunk');
      });
      await r.client.acknowledgeVPNSSO(offer.context, offer.manifest);
      current = false;
      controller.abort();
      const input = Buffer.from('private native capture fixture');
      await assert.rejects(
        f.native.capture(input, async () => assert.fail('revoked capture reached root')),
      );
      assert.ok(input.every((n) => n === 0));
      await f.native.close();
      assert.ok(f.child.exitCode !== null || f.child.signalCode !== null);
      await r.client.cancelVPNSSO(offer.context);
    } finally {
      await f.native.close();
      await r.client.stop();
    }
  },
);
