import assert from 'node:assert/strict';
import test from 'node:test';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import {
  createCredentialsRecipient,
  decodeCredentialDisplay,
} from '../src/vault-credentials-recipient.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
const context = {
  workspaceId: '11111111-1111-4111-8111-111111111111',
  nodeId: '22222222-2222-4222-8222-222222222222',
  requestId: '33333333-3333-4333-8333-333333333333',
  rowVersion: '7',
};
function payload(fields = ['alïce', 'CORP', '<secret>🪱'], flag = 0) {
  return Buffer.concat([
    Buffer.from([1, flag]),
    ...fields.flatMap((value) => {
      const bytes = Buffer.from(value),
        length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return [length, bytes];
    }),
  ]);
}
test('credential display decodes bounded binary fields without accepting ambiguous payloads', () => {
  for (const flag of [0, 1])
    assert.deepEqual(decodeCredentialDisplay(payload(undefined, flag)), {
      username: 'alïce',
      domain: 'CORP',
      secret: '<secret>🪱',
      label: flag ? 'Passphrase' : 'Password',
    });
  assert.equal(decodeCredentialDisplay(payload(['', '', ''])).secret, '');
  assert.equal(decodeCredentialDisplay(payload(['', '', '\ufeffsecret'])).secret, '\ufeffsecret');
  const invalid = payload();
  invalid[6] = 255;
  for (const raw of [
    new Uint8Array(),
    Buffer.alloc(20495),
    Buffer.from([0, ...payload().subarray(1)]),
    payload(undefined, 2),
    payload(['a'.repeat(2049), '', '']),
    payload(['', 'a'.repeat(2049), '']),
    payload(['', '', 'a'.repeat(16385)]),
    payload().subarray(0, 15),
    payload().subarray(0, -1),
    Buffer.concat([payload(), Buffer.from([0])]),
    invalid,
  ])
    assert.throws(() => decodeCredentialDisplay(raw));
  const offset = Buffer.concat([Buffer.from([9]), payload()]);
  assert.equal(decodeCredentialDisplay(offset.subarray(1)).username, 'alïce');
});
test('credential recipient is one-use and authenticates purpose and exact opening context', async () => {
  await assert.rejects(createCredentialsRecipient({} as any));
  for (const mode of ['valid', 'domain', 'context', 'tamper', 'disposed', 'late']) {
    const r = await createCredentialsRecipient(context),
      suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      });
    const publicKey = await suite.kem.deserializePublicKey(Buffer.from(r.publicKey, 'base64'));
    const info = Buffer.concat([
      Buffer.from(
        mode === 'domain' ? 'wormhole/v1/notes-display' : 'wormhole/v1/credential-display',
      ),
      ...[context.workspaceId, context.nodeId, context.requestId, context.rowVersion].flatMap(
        (value) => {
          const length = Buffer.alloc(4);
          length.writeUInt32BE(value.length);
          return [length, Buffer.from(value)];
        },
      ),
    ]);
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info });
    const value = {
      ...context,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.from(sender.enc).toString('base64'),
        ciphertext: Buffer.from(await sender.seal(payload())).toString('base64'),
      },
    };
    if (mode === 'context') value.nodeId = context.requestId;
    if (mode === 'tamper') value.bundle.ciphertext = Buffer.alloc(32).toString('base64');
    if (mode === 'disposed') r.dispose();
    const pending = r.open(value);
    if (mode === 'late') r.dispose();
    if (mode === 'valid') {
      const raw = await pending;
      try {
        assert.equal(decodeCredentialDisplay(raw).secret, '<secret>🪱');
      } finally {
        raw.fill(0);
      }
    } else await assert.rejects(pending);
    await assert.rejects(r.open(value));
    r.dispose();
  }
});
test('credential host binds Standard reauthentication and discards late display replies', async () => {
  let profile = 'standard',
    calls = 0,
    release: any,
    delay = false,
    received: any;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: profile }),
    describe: async () => ({
      vaultId: context.workspaceId,
      slots: [{ id: context.nodeId, kind: 'password' }],
    }),
    displayCredentials: async (q: any) => {
      calls++;
      received = q;
      if (delay) await new Promise((resolve) => (release = resolve));
      return { opaque: true };
    },
  };
  const host = new VaultBackendHost(
      () => client,
      () => true,
    ),
    request = { ...context, publicKey: Buffer.alloc(32, 1).toString('base64') };
  const factor = () => ({
    vaultId: context.workspaceId,
    slotId: context.nodeId,
    kind: 'password' as const,
    factor: new Uint8Array([7]),
  });
  await assert.rejects(host.displayCredentials(null), /Invalid/);
  await assert.rejects(host.displayCredentials(request), /locked/);
  assert.equal(calls, 0);
  await host.unlock(factor());
  await assert.rejects(
    host.displayCredentials({ ...request, workspaceId: context.nodeId }),
    /locked/,
  );
  await assert.rejects(host.displayCredentials(request), /Fresh authentication/);
  const input = { ...request },
    authentication = factor();
  assert.deepEqual(
    await host.displayCredentials(input, async (op, _descriptor, submit) => {
      assert.equal(op, 'credential-display');
      input.nodeId = context.requestId;
      return submit(authentication);
    }),
    { opaque: true },
  );
  assert.deepEqual(received, request);
  assert.ok(authentication.factor.every((x) => x === 0));
  let accepted = true;
  await assert.rejects(
    host.displayCredentials(
      request,
      async (_op, _descriptor, submit) => {
        accepted = false;
        return submit(factor());
      },
      () => accepted,
    ),
    /locked/,
  );
  assert.equal(calls, 1);
  profile = 'default';
  delay = true;
  const pending = host.displayCredentials(request);
  await new Promise(setImmediate);
  await host.stop();
  release();
  await assert.rejects(pending, /locked/);
});
test('actual Show credentials callback keeps protected secrets out of app state', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'),
    start = source.indexOf('  async function showConnectionCredentials('),
    end = source.indexOf('  function closeCredentialDialog', start);
  assert.ok(start > 0 && end > start);
  const script = stripTypeScriptTypes(source.slice(start, end)) + ';showConnectionCredentials';
  for (const mode of ['vault', 'legacy'])
    for (const outcome of ['ok', 'error', 'stale', 'stale-error', 'unknown-error']) {
      const calls: any[] = [],
        dialogs: any[] = [];
      const ctx = {
        window: {
          wormhole: {
            showVaultCredentials: async (q: any) => {
              calls.push(q);
              if (outcome.startsWith('stale')) ctx.credentialRevealRequest.current++;
              if (outcome === 'unknown-error') throw 'native failure';
              if (outcome.endsWith('error')) throw Error('safe failure');
            },
            showWorkspaceCredentials: async (q: any) => {
              calls.push(q);
              if (outcome.startsWith('stale')) ctx.credentialRevealRequest.current++;
              if (outcome === 'unknown-error') throw 'native failure';
              if (outcome.endsWith('error')) throw Error('safe failure');
              return { secret: 'legacy only' };
            },
          },
        },
        authState: { mode },
        credentialRevealBusy: { current: false },
        credentialRevealRequest: { current: 0 },
        setCopiedCredentialField: () => {},
        setCredentialDialog: (v: any) => dialogs.push(v),
        Error,
      };
      const callback = runInNewContext(script, ctx, { filename: 'vault-credentials-app.js' });
      await callback({ kind: 'folder' });
      ctx.credentialRevealBusy.current = true;
      await callback({ kind: 'connection' });
      ctx.credentialRevealBusy.current = false;
      assert.equal(calls.length, 0);
      await callback({
        kind: 'connection',
        id: context.nodeId,
        rowVersion: '7',
      });
      assert.deepEqual(JSON.parse(JSON.stringify(calls)), [
        mode === 'vault' ? { nodeId: context.nodeId, rowVersion: '7' } : { nodeId: context.nodeId },
      ]);
      if (outcome.startsWith('stale')) assert.equal(dialogs.length, 0);
      else if (outcome.endsWith('error')) {
        assert.equal(dialogs[0].kind, 'error');
        if (outcome === 'unknown-error')
          assert.equal(dialogs[0].message, 'Could not show the connection credentials.');
      } else if (mode === 'vault') assert.equal(dialogs.length, 0);
      else assert.equal(dialogs[0].result.secret, 'legacy only');
      assert.equal(ctx.credentialRevealBusy.current, false);
    }
});

test('actual main registration admits only the trusted selection and parents fresh authentication to its display', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const vaultCredentialsDialog ='),
    end = source.indexOf('\n});', start) + 4;
  assert.ok(start > 0 && end > start);
  let options: any,
    created = 0,
    opened: any;
  const env = {
    VaultCredentialsDialog: class {
      constructor(value: any) {
        options = value;
      }
    },
    vaultBackend: { unlockedWorkspaceId: context.workspaceId },
    vaultReauthenticationDialog: {
      open: async (...args: any[]) => {
        opened = args;
        return 'confirmed';
      },
    },
    ipcMain: {},
    createApplicationWindow: () => {
      created++;
    },
    vaultLinuxClipboard: { copy: () => {} },
    rendererUrl: 'http://localhost:5173',
    app: { isPackaged: false },
    URL,
    path: {
      join: (...parts: string[]) => parts.join('/'),
      resolve: (...parts: string[]) => parts.join('/'),
    },
    pathToFileURL: (value: string) => ({ href: 'file://' + value }),
    __dirname: '/app/electron',
  };
  runInNewContext(
    stripTypeScriptTypes(source.slice(start, end)),
    { ...env },
    { filename: 'vault-credentials-main.js' },
  );
  assert.equal(options.linuxClipboard, env.vaultLinuxClipboard);
  assert.equal(options.url, 'http://localhost:5173/vault-credentials.html');
  options.createWindow({});
  assert.equal(created, 1);
  const parent = {},
    submit = async () => true;
  let accepted = true;
  assert.equal(
    await options.authenticate(parent, () => accepted)(
      'credential-display',
      { vaultId: context.workspaceId },
      submit,
    ),
    'confirmed',
  );
  assert.equal(opened[0], parent);
  assert.equal(opened[2], 'credential-display');
  assert.equal(opened[4], submit);
  assert.equal(opened[1](), true);
  accepted = false;
  assert.equal(opened[1](), false);
  accepted = true;
  env.vaultBackend.unlockedWorkspaceId = context.nodeId;
  assert.equal(opened[1](), false);
  env.app.isPackaged = true;
  runInNewContext(
    stripTypeScriptTypes(source.slice(start, end)),
    { ...env },
    { filename: 'vault-credentials-main.js' },
  );
  assert.match(options.url, /vault-credentials.html$/);
  const begin = source.indexOf("  ipcMain.handle('vault:show-credentials'"),
    finish = source.indexOf(
      "  for (const action of ['read', 'install-folder', 'install-zip', 'cleanup']",
      begin,
    );
  assert.ok(begin > 0 && finish > begin);
  let trusted = false,
    parentPresent = true,
    handler: any,
    calls = 0;
  const main = {
    ipcMain: {
      handle: (name: string, fn: any) => {
        assert.equal(name, 'vault:show-credentials');
        handler = fn;
      },
    },
    isTrustedVaultSender: () => trusted,
    BrowserWindow: { fromWebContents: () => (parentPresent ? parent : undefined) },
    vaultCredentialsDialog: {
      open: async (p: any, valid: () => boolean, q: any) => {
        assert.equal(p, parent);
        assert.equal(valid(), true);
        assert.equal(q.nodeId, context.nodeId);
        calls++;
      },
    },
    Error,
  };
  runInNewContext(stripTypeScriptTypes(source.slice(begin, finish)), main, {
    filename: 'vault-credentials-ipc.js',
  });
  const selection = { nodeId: context.nodeId, rowVersion: '7' };
  await assert.rejects(handler({ sender: {} }, selection));
  trusted = true;
  await assert.rejects(handler({ sender: {} }, selection, {}));
  parentPresent = false;
  await assert.rejects(handler({ sender: {} }, selection));
  parentPresent = true;
  await handler({ sender: {} }, selection);
  assert.equal(calls, 1);
});
