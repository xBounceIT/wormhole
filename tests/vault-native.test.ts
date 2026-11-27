import { crc32 } from 'node:zlib';
import { LinuxVaultClipboard } from '../electron/vault-linux-clipboard.ts';
import {
  createClipboardRecipient,
  decodeClipboardRelease,
} from '../electron/vault-clipboard-release.ts';
import {
  createCredentialsRecipient,
  decodeCredentialDisplay,
} from '../src/vault-credentials-recipient.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { createTunnelImportRecipient } from '../src/vault-tunnel-import-recipient.ts';
import { consumeVaultTunnelProjection } from '../src/vault-tunnel-form.ts';
import { createTunnelEditorRecipient } from '../src/vault-tunnel-recipient.ts';
import { createHash, randomUUID } from 'node:crypto';
import { connectionInput } from './fixtures/vault-connection.ts';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { SealedRouteBroker } from '../electron/sealed-route.ts';
import { mkdtemp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { parseVaultCatalog, parseVaultResponse } from '../electron/vault-contract.ts';
import { parseVaultWorkspace } from '../electron/vault-workspace.ts';

// Small stored ZIP fixture: no external archiver or platform-specific shell.
function nativeExtensionZip(entries: [string, Buffer][]): Buffer {
  const local: Buffer[] = [],
    central: Buffer[] = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const filename = Buffer.from(name),
      header = Buffer.alloc(30),
      directory = Buffer.alloc(46);
    header.writeUInt32LE(0x04034b50);
    header.writeUInt16LE(20, 4);
    header.writeUInt32LE(crc32(data), 14);
    header.writeUInt32LE(data.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(filename.length, 26);
    directory.writeUInt32LE(0x02014b50);
    directory.writeUInt16LE(20, 4);
    directory.writeUInt16LE(20, 6);
    header.copy(directory, 16, 14, 26);
    directory.writeUInt16LE(filename.length, 28);
    directory.writeUInt32LE(offset, 42);
    local.push(header, filename, data);
    central.push(directory, filename);
    offset += header.length + filename.length + data.length;
  }
  const index = Buffer.concat(central),
    end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(index.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, index, end]);
}

test(
  'Electron interoperates with native vault metadata, password/recovery unlock and lock',
  { timeout: 180_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-client-'));
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    const databasePath = join(directory, 'workspace.db');
    const sidecarFixture = join(
      directory,
      process.platform === 'win32' ? 'route-fixture.exe' : 'route-fixture',
    );
    const clients: VaultBackendClient[] = [];
    let phase = 'setup';
    const unavailable: { owner: string; phase: string; reason: string }[] = [];
    const create = () => {
      const client = new VaultBackendClient({
        executable,
        databasePath,
        onUnavailable: (reason) => unavailable.push({ owner: 'metadata', phase, reason }),
      });
      clients.push(client);
      return client;
    };
    try {
      await promisify(execFile)('go', ['build', '-o', executable, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        windowsHide: true,
        timeout: 120_000,
      });
      // Compile immutable helpers before opening any live vault owner. Every slot
      // scenario has independent storage and reuses the same fixture executable.
      phase = 'compiling route fixture';
      await promisify(execFile)('go', ['test', '-c', '-o', sidecarFixture, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        windowsHide: true,
        timeout: 120000,
      });
      phase = 'native vault lifecycle';
      const framePath = join(directory, 'catalog-frame.json');
      const nativeDirectory = join(directory, 'native');
      await mkdir(nativeDirectory);
      const nativeDatabase = join(nativeDirectory, 'workspace.db');
      await writeFile(
        join(nativeDirectory, 'settings.json'),
        JSON.stringify({
          Theme: 1,
          AuthenticationMode: 0,
          IdleTimeoutMinutes: 0,
          Profile: 'private-settings-policy',
        }),
      );
      await promisify(execFile)(
        'go',
        ['test', '-count=1', '-run', '^TestVaultCatalogRequiresOwnerAndProjectsMetadata$', '.'],
        {
          cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
          env: {
            ...process.env,
            WORMHOLE_TEST_CATALOG_FRAME: framePath,
            WORMHOLE_TEST_CATALOG_DATABASE: nativeDatabase,
          },
          windowsHide: true,
          timeout: 120_000,
        },
      );
      const frame = await readFile(framePath, 'utf8');
      const catalog = parseVaultCatalog(parseVaultResponse(frame)?.result);
      assert.ok(catalog);
      assert.equal(catalog.credentials[0].name, 'Account <&> 日本語\u2028😀');
      assert.equal(catalog.nodes[0].sortOrder, '-9223372036854775808');
      assert.doesNotMatch(frame, /catalog-private-/);
      const workspaceFrame = await readFile(framePath + '.workspace', 'utf8');
      const workspace = parseVaultWorkspace(parseVaultResponse(workspaceFrame)?.result);
      assert.ok(workspace);
      assert.equal(workspace.tree[0].rdp?.screenSize, '\u0085fitToWindow\u0085');
      assert.equal(workspace.tree[0].rdp?.domain, 'domain 🧪');
      assert.doesNotMatch(workspaceFrame, /catalog-private-/);
      for (const kind of ['recovery', 'password', 'recovery-code'] as const) {
        phase = `native vault lifecycle (${kind})`;
        const createUnlocked = () => {
          const client = new VaultBackendClient({
            executable,
            databasePath: nativeDatabase,
            onUnavailable: (reason) => unavailable.push({ owner: kind, phase, reason }),
          });
          clients.push(client);
          return client;
        };
        let unlocked = createUnlocked();
        const descriptor = await unlocked.describe();
        assert.ok(descriptor);
        assert.deepEqual(await unlocked.startup(), {
          slots: descriptor,
          cosmetics: { theme: 'light' },
          newWorkspace: false,
        });
        const slot = descriptor.slots.find(
          (slot) => slot.kind === (kind === 'recovery-code' ? 'recovery' : kind),
        )!;
        const wrong = new Uint8Array(
          kind === 'recovery' ? 32 : kind === 'recovery-code' ? 76 : 8,
        ).fill(0x31);
        await assert.rejects(
          unlocked.unlock({ vaultId: descriptor.vaultId, slotId: slot.id, kind, factor: wrong }),
          { message: 'Vault operation failed.' },
        );
        assert.ok(wrong.every((byte) => byte === 0));
        assert.equal((await unlocked.status()).unlocked, false);
        await assert.rejects(unlocked.security(), { message: 'Vault operation failed.' });
        const factor =
          kind === 'recovery'
            ? new Uint8Array(32).fill(0x32)
            : new TextEncoder().encode(
                kind === 'recovery-code'
                  ? 'WHREC1-GIZDE-MRSGI-ZDEMR-SGIZD-EMRSG-IZDEM-RSGIZ-DEMRS-GIZDE-MRSGI-ZA7A2-6Z4'
                  : 'native-password-🧪',
              );
        assert.deepEqual(
          await unlocked.unlock({ vaultId: descriptor.vaultId, slotId: slot.id, kind, factor }),
          { unlocked: true, lockedMemory: true },
        );
        assert.ok(factor.every((byte) => byte === 0));
        assert.equal((await unlocked.status()).unlocked, true);
        assert.deepEqual(await unlocked.security(), {
          sequence: '3',
          workspace: 'default',
          user: 'default',
          os: 'default',
          effective: 'default',
          source: 'workspace',
          canTightenToStandard: true,
        });
        assert.deepEqual(await unlocked.startup(), {
          slots: descriptor,
          cosmetics: { theme: 'light' },
          newWorkspace: false,
        });
        assert.deepEqual(
          await unlocked.bitwardenInstallationPlan({
            workspaceId: descriptor.vaultId,
            minimumRevision: '0',
          }),
          { workspaceId: descriptor.vaultId, revision: '0', installation: null },
        );
        await assert.rejects(
          unlocked.bitwardenInstallationPlan({
            workspaceId: randomUUID(),
            minimumRevision: '0',
          }),
          { message: 'Vault operation failed.' },
        );
        assert.deepEqual(await unlocked.catalog(), catalog);
        assert.deepEqual(await unlocked.workspace(), workspace);
        // Exercise actual Go factor parsing and exact-action wrapping over stdin.
        if (kind === 'recovery-code') {
          const freshFolder = {
            id: '',
            rowVersion: '0',
            parentId: '',
            name: 'Fresh authenticated folder',
            sshAutoSudo: null,
            tunnelEnabled: null,
            tunnelConfigId: '',
            credentialMode: 0,
            credentialId: '',
          };
          const freshFactor = () => ({
            vaultId: descriptor.vaultId,
            slotId: slot.id,
            kind: 'recovery-code' as const,
            factor: new TextEncoder().encode(
              'WHREC1-GIZDE-MRSGI-ZDEMR-SGIZD-EMRSG-IZDEM-RSGIZ-DEMRS-GIZDE-MRSGI-ZA7A2-6Z4',
            ),
          });
          await assert.rejects(
            unlocked.saveFolder(freshFolder, {
              ...freshFactor(),
              kind: 'recovery',
              factor: new Uint8Array(32).fill(0x31),
            }),
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
          const credential = () => ({
            metadata: {
              id: '',
              name: 'Native edited credential',
              protocol: 'ssh',
              kind: 'password',
              username: 'alice',
              domain: '',
              provider: 'Local',
              bitwardenItemId: '',
              bitwardenItemName: '',
              privateKeyPath: '',
              certificatePath: '',
              clearPassphrase: false,
              clearCertificate: false,
            },
            rowVersion: '0',
            password: new TextEncoder().encode('native secret'),
            passphrase: new Uint8Array(),
          });
          await assert.rejects(
            unlocked.editCredential(credential(), {
              ...freshFactor(),
              kind: 'recovery',
              factor: new Uint8Array(32).fill(0x31),
            }),
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
          const createdCredential = await unlocked.editCredential(credential(), freshFactor());
          assert.equal(createdCredential.rowVersion, '1');
          const nativeCredential = (await unlocked.workspace()).credentials.find(
            (item) => item.id === createdCredential.id,
          )!;
          assert.equal(nativeCredential.rowVersion, '1');
          assert.equal(nativeCredential.name, 'Native edited credential');
          const edit = credential();
          edit.metadata.id = createdCredential.id;
          edit.rowVersion = '1';
          edit.password = new Uint8Array();
          edit.metadata.name = 'Updated native credential';
          assert.equal((await unlocked.editCredential(edit)).rowVersion, '2');
          await assert.rejects(unlocked.editCredential(edit), /operation failed/);
          await assert.rejects(
            unlocked.deleteCredential({ id: createdCredential.id, rowVersion: '1' }),
            /operation failed/,
          );
          assert.equal(
            (
              await unlocked.deleteCredential(
                { id: createdCredential.id, rowVersion: '2' },
                freshFactor(),
              )
            ).rowVersion,
            '3',
          );
          assert.deepEqual(await unlocked.workspace(), workspace);

          const ipsec = await unlocked.editTunnel(
            {
              metadata: { id: '', name: 'Native IPsec', kind: 9 },
              rowVersion: '0',
              forgetHostKey: false,
              patch: new TextEncoder().encode(
                JSON.stringify({
                  Host: 'ipsec.example',
                  UserAuth: 0,
                  PreSharedKey: 'native-ipsec-private-fixture',
                }),
              ),
            },
            freshFactor(),
          );
          assert.ok(
            (await unlocked.workspace()).tunnels.some(
              (t) => t.id === ipsec.id && t.kind === 'Fortinet IPsec',
            ),
          );
          const ipsecContext = {
            workspaceId: descriptor.vaultId,
            tunnelId: ipsec.id,
            requestId: randomUUID(),
            rowVersion: ipsec.rowVersion,
          };
          const ipsecRecipient = await createTunnelEditorRecipient(ipsecContext);
          const ipsecDisplay = await unlocked.displayTunnelEditor({
            ...ipsecContext,
            publicKey: ipsecRecipient.publicKey,
          });
          assert.doesNotMatch(
            JSON.stringify(ipsecDisplay),
            /native-ipsec-private-fixture|ipsec.example/,
          );
          const ipsecPlain = await ipsecRecipient.open(ipsecDisplay);
          ipsecRecipient.dispose();
          assert.deepEqual(consumeVaultTunnelProjection(ipsecPlain), {
            name: 'Native IPsec',
            kind: 9,
            settings: { Host: 'ipsec.example', UserAuth: 0 },
            present: ['PreSharedKey'],
          });
          await unlocked.deleteTunnel(
            { id: ipsec.id, rowVersion: ipsec.rowVersion },
            freshFactor(),
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
          const tunnelInput = () => ({
            metadata: { id: '', name: 'Native edited tunnel', kind: 1 },
            rowVersion: '0',
            forgetHostKey: false,
            patch: new TextEncoder().encode(
              JSON.stringify({
                ProfileOvpn: 'private-profile',
                Username: 'visible-user',
                Password: 'private-password',
              }),
            ),
          });
          const submittedTunnel = tunnelInput();
          const createdTunnel = await unlocked.editTunnel(submittedTunnel, freshFactor());
          assert.equal(createdTunnel.rowVersion, '1');
          assert.ok(submittedTunnel.patch.every((byte) => byte === 0));
          const routedInput = connectionInput();
          routedInput.metadata.tunnelEnabled = true;
          routedInput.metadata.tunnelConfigId = createdTunnel.id;
          const routedNode = await unlocked.saveConnection(routedInput, freshFactor());
          const routeKey = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
            'deriveBits',
          ])) as CryptoKeyPair;
          const routeRequest = {
            workspaceId: descriptor.vaultId,
            nodeId: routedNode.nodeId,
            credentialOverride: '',
            sessionId: randomUUID(),
            requestId: randomUUID(),
            epoch: 1,
            publicKey: Buffer.from(
              await crypto.subtle.exportKey('raw', routeKey.publicKey),
            ).toString('base64'),
          };
          const { publicKey: _routePublicKey, ...planRequest } = routeRequest;
          const plan = await unlocked.tunnelPlan(planRequest);
          const route = await unlocked.tunnelBundle(routeRequest);
          assert.deepEqual(plan, route.binding);
          assert.equal(route.binding.tunnelConfigId, createdTunnel.id);
          assert.equal(route.binding.rowVersion, '1');
          assert.doesNotMatch(JSON.stringify(route), /private-profile|private-password/);
          const integer = (value: number | bigint, size: number) => {
            const out = Buffer.alloc(size);
            if (size === 2) out.writeUInt16BE(Number(value));
            else out.writeBigUInt64BE(BigInt(value));
            return out;
          };
          const canonical = (domain: string, fields: Uint8Array[]) =>
            Buffer.concat([
              Buffer.from(domain),
              ...fields.flatMap((value) => {
                const length = Buffer.alloc(4);
                length.writeUInt32BE(value.length);
                return [length, value];
              }),
            ]);
          const tunnelInfo = (b: typeof route.binding) => {
            const base = canonical('wormhole/v1/protocol-bundle', [
              ...[b.workspaceId, b.sessionId, b.requestId, b.nodeId, b.protocol, b.host].map(
                (value) => Buffer.from(value),
              ),
              integer(b.port, 2),
              Buffer.from(b.tunnelConfigId),
              new Uint8Array([0]),
              integer(b.epoch, 8),
            ]);
            return canonical('wormhole/v1/tunnel-bundle', [
              base,
              Buffer.from(b.fileId),
              integer(b.kind, 2),
              integer(BigInt(b.rowVersion), 8),
              integer(BigInt(b.configurationVersion), 8),
            ]);
          };
          const info = tunnelInfo(route.binding);
          const routeSuite = new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
          });
          const routePlain = new Uint8Array(
            await routeSuite.open(
              { recipientKey: routeKey, enc: Buffer.from(route.bundle.enc, 'base64'), info },
              Buffer.from(route.bundle.ciphertext, 'base64'),
            ),
          );
          try {
            assert.deepEqual(JSON.parse(new TextDecoder().decode(routePlain)), {
              ProfileOvpn: 'private-profile',
              Password: 'private-password',
              Username: 'visible-user',
            });
          } finally {
            routePlain.fill(0);
          }
          phase = 'native fallback source handoff';
          const sslSettings = {
            Host: 'ssl.example',
            Username: 'ssl-user',
            Password: 'native-secondary-secret',
          };
          const ssl = await unlocked.editTunnel(
            {
              metadata: { id: '', name: 'Native fallback SSL', kind: 2 },
              rowVersion: '0',
              forgetHostKey: false,
              patch: new TextEncoder().encode(JSON.stringify(sslSettings)),
            },
            freshFactor(),
          );
          const primary = await unlocked.editTunnel(
            {
              metadata: { id: '', name: 'Native fallback IPsec', kind: 9 },
              rowVersion: '0',
              forgetHostKey: false,
              patch: new TextEncoder().encode(
                JSON.stringify({
                  Host: 'ipsec.example',
                  PreSharedKey: 'native-primary-secret',
                  UserAuth: 0,
                  FallbackTunnelId: ssl.id,
                }),
              ),
            },
            freshFactor(),
          );
          const fallbackInput = connectionInput();
          fallbackInput.metadata.tunnelEnabled = true;
          fallbackInput.metadata.tunnelConfigId = primary.id;
          const fallbackNode = await unlocked.saveConnection(fallbackInput, freshFactor());
          const sourceRequest = {
            ...planRequest,
            nodeId: fallbackNode.nodeId,
            requestId: randomUUID(),
          };
          const source = await unlocked.tunnelPlan(sourceRequest);
          const fallbackPlan = await unlocked.tunnelFallbackPlan({
            ...sourceRequest,
            primary: source,
            fallbackRequestId: randomUUID(),
          });
          assert.deepEqual(fallbackPlan.primary, source);
          assert.equal(fallbackPlan.fallback.tunnelConfigId, ssl.id);
          assert.equal(fallbackPlan.primary.kind, 9);
          assert.equal(fallbackPlan.fallback.kind, 2);
          const secondaryKey = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
            'deriveBits',
          ])) as CryptoKeyPair;
          const secondaryPublic = Buffer.from(
            await crypto.subtle.exportKey('raw', secondaryKey.publicKey),
          ).toString('base64');
          const fallbackPacket = await unlocked.tunnelFallbackBundle({
            ...sourceRequest,
            binding: fallbackPlan,
            publicKey: secondaryPublic,
          });
          assert.deepEqual(fallbackPacket.binding, fallbackPlan);
          assert.doesNotMatch(
            JSON.stringify(fallbackPacket),
            /native-primary-secret|native-secondary-secret|ssl-user/,
          );
          const secondaryPlain = new Uint8Array(
            await routeSuite.open(
              {
                recipientKey: secondaryKey,
                enc: Buffer.from(fallbackPacket.bundle.enc, 'base64'),
                info: canonical('wormhole/v1/tunnel-fallback', [
                  tunnelInfo(fallbackPlan.primary),
                  tunnelInfo(fallbackPlan.fallback),
                ]),
              },
              Buffer.from(fallbackPacket.bundle.ciphertext, 'base64'),
            ),
          );
          try {
            assert.deepEqual(JSON.parse(new TextDecoder().decode(secondaryPlain)), sslSettings);
          } finally {
            secondaryPlain.fill(0);
          }
          await assert.rejects(
            routeSuite.open(
              {
                recipientKey: secondaryKey,
                enc: Buffer.from(fallbackPacket.bundle.enc, 'base64'),
                info: tunnelInfo(fallbackPlan.fallback),
              },
              Buffer.from(fallbackPacket.bundle.ciphertext, 'base64'),
            ),
          );
          // A separately valid revision cannot replace the exact independently planned target.
          const replacement = structuredClone(fallbackPlan);
          replacement.fallback.rowVersion = '2';
          await assert.rejects(
            unlocked.tunnelFallbackBundle({
              ...sourceRequest,
              binding: replacement,
              publicKey: secondaryPublic,
            }),
            /unavailable/,
          );
          // Authentication mismatch retires the native owner. A fresh explicit
          // unlock is required; the failed client must never restart itself.
          await assert.rejects(
            unlocked.tunnelFallbackPlan({
              ...sourceRequest,
              primary: source,
              fallbackRequestId: randomUUID(),
            }),
            /unavailable/,
          );
          await unlocked.lock();
          unlocked = createUnlocked();
          await unlocked.unlock(freshFactor());
          await unlocked.deleteNodes(
            { nodes: [{ id: fallbackNode.nodeId, rowVersion: fallbackNode.rowVersion }] },
            freshFactor(),
          );
          await unlocked.deleteTunnel(
            { id: primary.id, rowVersion: primary.rowVersion },
            freshFactor(),
          );
          await unlocked.deleteTunnel({ id: ssl.id, rowVersion: ssl.rowVersion }, freshFactor());
          phase = 'native route leases';
          let routeAllowed = true,
            routeChildren = 0;
          const routes = new SealedRouteBroker(
            {
              executable: () => executable,
              workspaceId: () => descriptor.vaultId,
              authorized: (epoch) => routeAllowed && epoch === 1,
              plan: (q) => unlocked.tunnelPlan(q),
              bundle: (q) => unlocked.tunnelBundle(q),
            },
            (exe, args) => {
              routeChildren++;
              assert.deepEqual(args, ['--operation', 'tunnel-sealed']);
              return spawn(exe, args, {
                windowsHide: true,
                stdio: 'pipe',
                env: {
                  ...process.env,
                  WORMHOLE_OVPNPROXY_PATH: sidecarFixture,
                  WORMHOLE_CAPABILITY_TEST_HELPER: 'yes',
                },
              });
            },
          );
          try {
            const [firstRoute, secondRoute] = await Promise.all(
              [1, 2].map(() =>
                routes.acquire({ sessionId: randomUUID(), nodeId: routedNode.nodeId }, 1),
              ),
            );
            assert.equal(routeChildren, 1);
            assert.equal(firstRoute.endpoint, '127.0.0.1:32123');
            assert.equal(secondRoute.endpoint, firstRoute.endpoint);
            assert.ok(firstRoute.active && secondRoute.active);
            await firstRoute.release();
            await firstRoute.closed;
            assert.ok(secondRoute.active);
            routeAllowed = false;
            await routes.closeAll();
            await secondRoute.closed;
            assert.ok(!secondRoute.active);
          } finally {
            await routes.closeAll();
          }
          phase = 'after native route shutdown';
          await unlocked.deleteNodes(
            { nodes: [{ id: routedNode.nodeId, rowVersion: routedNode.rowVersion }] },
            freshFactor(),
          );
          const editorContext = {
            workspaceId: descriptor.vaultId,
            tunnelId: createdTunnel.id,
            requestId: randomUUID(),
            rowVersion: '1',
          };
          const recipient = await createTunnelEditorRecipient(editorContext);
          const publicKey = recipient.publicKey;
          const display = await unlocked.displayTunnelEditor({ ...editorContext, publicKey });
          assert.doesNotMatch(
            JSON.stringify(display),
            /private-profile|private-password|visible-user/,
          );
          const plain = await recipient.open(display);
          await assert.rejects(recipient.open(display), /closed/);
          recipient.dispose();
          try {
            assert.deepEqual(consumeVaultTunnelProjection(plain), {
              name: 'Native edited tunnel',
              kind: 1,
              settings: { Username: 'visible-user' },
              present: ['Password', 'ProfileOvpn'],
            });
          } finally {
            plain.fill(0);
          }
          const tunnelEdit = () => ({
            ...tunnelInput(),
            metadata: { id: createdTunnel.id, name: 'Renamed native tunnel', kind: 1 },
            rowVersion: '1',
            patch: new TextEncoder().encode('{}'),
          });
          assert.equal((await unlocked.editTunnel(tunnelEdit())).rowVersion, '2');
          await assert.rejects(unlocked.editTunnel(tunnelEdit()), /operation failed/);
          await assert.rejects(
            unlocked.displayTunnelEditor({ ...editorContext, publicKey }),
            /operation failed/,
          );
          await assert.rejects(
            unlocked.deleteTunnel({ id: createdTunnel.id, rowVersion: '1' }),
            /operation failed/,
          );
          assert.equal(
            (await unlocked.deleteTunnel({ id: createdTunnel.id, rowVersion: '2' }, freshFactor()))
              .rowVersion,
            '3',
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
          const importContext = {
            workspaceId: descriptor.vaultId,
            editorId: randomUUID(),
            importId: randomUUID(),
            kind: 1,
          };
          const importRecipient = await createTunnelImportRecipient(importContext);
          const importPath = join(directory, 'selected-profile.ovpn');
          await writeFile(
            importPath,
            'client\nremote private-import.example 1194\n<key>private-import-key</key>',
          );
          const importDisplay = await unlocked.stageTunnelImport({
            ...importContext,
            tunnelId: '',
            rowVersion: '0',
            format: 'openvpn',
            path: importPath,
            publicKey: importRecipient.publicKey,
          });
          assert.deepEqual(Object.keys(importDisplay).sort(), [
            'bundle',
            'editorId',
            'importId',
            'kind',
            'workspaceId',
          ]);
          assert.doesNotMatch(JSON.stringify(importDisplay), /private-import|selected-profile/);
          const importedPlain = await importRecipient.open(importDisplay);
          assert.deepEqual(consumeVaultTunnelProjection(importedPlain), {
            name: 'Imported tunnel',
            kind: 1,
            settings: {},
            present: ['ProfileOvpn'],
          });
          assert.ok(importedPlain.every((byte) => byte === 0));
          importRecipient.dispose();
          await rm(importPath); // Commit must use the staged snapshot, not re-open the selection.
          const importedTunnel = await unlocked.editTunnel(
            {
              metadata: { id: '', name: 'Imported', kind: 1 },
              rowVersion: '0',
              forgetHostKey: false,
              patch: new TextEncoder().encode('{}'),
              editorId: importContext.editorId,
              importId: importContext.importId,
            },
            freshFactor(),
          );
          assert.equal(importedTunnel.rowVersion, '1');
          assert.deepEqual(
            await unlocked.discardTunnelImport({
              workspaceId: descriptor.vaultId,
              editorId: importContext.editorId,
              importId: '',
            }),
            { discarded: true },
          );
          await unlocked.deleteTunnel({ id: importedTunnel.id, rowVersion: '1' }, freshFactor());
          assert.deepEqual(await unlocked.workspace(), workspace);
          // Real stdio installation: exact fresh action, native file copy/CAS,
          // and a subsequent authenticated content-verified public plan.
          const extensionSource = join(directory, 'extension-source');
          await mkdir(extensionSource);
          await writeFile(
            join(extensionSource, 'manifest.json'),
            JSON.stringify({
              manifest_version: 2,
              name: 'Native installation fixture',
              version: '1.0',
              browser_action: { default_popup: 'popup.html' },
              background: { scripts: ['background.js'], persistent: true },
            }),
          );
          await writeFile(join(extensionSource, 'popup.html'), '<p>Fixture</p>');
          await writeFile(join(extensionSource, 'background.js'), 'void 0;');
          const installRequest = {
            workspaceId: descriptor.vaultId,
            sourceDirectory: extensionSource,
            expectedRevision: '0',
          };
          const installFactor = freshFactor();
          assert.deepEqual(await unlocked.installBitwardenFolder(installRequest, installFactor), {
            workspaceId: descriptor.vaultId,
            revision: '1',
          });
          assert.ok(installFactor.factor.every((byte) => byte === 0));
          const installed = await unlocked.bitwardenInstallationPlan({
            workspaceId: descriptor.vaultId,
            minimumRevision: '1',
          });
          assert.equal(installed.revision, '1');
          assert.equal(installed.installation?.version, '1.0');
          assert.equal(installed.installation?.popup, 'popup.html');
          assert.match(installed.installation!.extensionId, /^[a-p]{32}$/);
          await assert.rejects(unlocked.installBitwardenFolder(installRequest, freshFactor()), {
            message: 'Vault operation failed.',
          });
          assert.deepEqual(
            await unlocked.bitwardenInstallationPlan({
              workspaceId: descriptor.vaultId,
              minimumRevision: '1',
            }),
            installed,
          );
          await writeFile(
            join(
              nativeDirectory,
              'vault-bitwarden-installations',
              'db-' + createHash('sha256').update('workspace.db').digest('hex'),
              installed.installation!.id,
              'popup.html',
            ),
            'corrupted fixture',
          );
          await assert.rejects(
            unlocked.bitwardenInstallationPlan({
              workspaceId: descriptor.vaultId,
              minimumRevision: '1',
            }),
            { message: 'Vault operation failed.' },
          );
          assert.deepEqual(
            await unlocked.bitwardenInstallationRevision({
              workspaceId: descriptor.vaultId,
              minimumRevision: '1',
            }),
            { workspaceId: descriptor.vaultId, revision: '1' },
          );
          await assert.rejects(
            unlocked.bitwardenInstallationRevision({
              workspaceId: descriptor.vaultId,
              minimumRevision: '2',
            }),
            { message: 'Vault operation failed.' },
          );
          const zipPath = join(directory, 'extension.zip');
          const zipEntries: [string, Buffer][] = [];
          for (const name of ['manifest.json', 'popup.html', 'background.js'])
            zipEntries.push([name, await readFile(join(extensionSource, name))]);
          await writeFile(zipPath, nativeExtensionZip(zipEntries));
          const zipFactor = freshFactor();
          assert.deepEqual(
            await unlocked.installBitwardenZip(
              { workspaceId: descriptor.vaultId, sourceFile: zipPath, expectedRevision: '1' },
              zipFactor,
            ),
            { workspaceId: descriptor.vaultId, revision: '2' },
          );
          assert.ok(zipFactor.factor.every((byte) => byte === 0));
          const zipPlan = await unlocked.bitwardenInstallationPlan({
            workspaceId: descriptor.vaultId,
            minimumRevision: '2',
          });
          assert.equal(zipPlan.installation?.version, '1.0');
          assert.notEqual(zipPlan.installation?.id, installed.installation?.id);
          const cleanupFactor = freshFactor();
          assert.deepEqual(
            await unlocked.cleanupBitwardenInstallations(
              { workspaceId: descriptor.vaultId, expectedRevision: '2' },
              cleanupFactor,
            ),
            { workspaceId: descriptor.vaultId, revision: '3' },
          );
          assert.ok(cleanupFactor.factor.every((byte) => byte === 0));
          await assert.rejects(
            readFile(
              join(
                nativeDirectory,
                'vault-bitwarden-installations',
                'db-' + createHash('sha256').update('workspace.db').digest('hex'),
                installed.installation!.id,
                'manifest.json',
              ),
            ),
            { code: 'ENOENT' },
          );
          assert.deepEqual(
            await unlocked.bitwardenInstallationPlan({
              workspaceId: descriptor.vaultId,
              minimumRevision: '3',
            }),
            { ...zipPlan, revision: '3' },
          );
          const confirmation = freshFactor();
          const freshResult = await unlocked.saveFolder(freshFolder, confirmation);
          assert.ok(confirmation.factor.every((byte) => byte === 0));
          await unlocked.deleteNodes(
            { nodes: [{ id: freshResult.nodeId, rowVersion: freshResult.rowVersion }] },
            freshFactor(),
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
        }
        if (kind === 'recovery-code') {
          const nodes = workspace.tree.map((node) => ({
            id: node.id,
            rowVersion: node.rowVersion!,
          }));
          assert.ok(
            nodes.length > 0 && nodes.every((node) => /^[1-9][0-9]*$/.test(node.rowVersion)),
          );
          await assert.rejects(
            unlocked.deleteNodes({
              nodes: nodes.map((node) => ({ ...node, rowVersion: '99999' })),
            }),
          );
          assert.deepEqual(await unlocked.workspace(), workspace);
          assert.equal((await unlocked.deleteNodes({ nodes })).deleted, true);
          assert.equal((await unlocked.workspace()).tree.length, 0);
          const newFolder = {
            id: '',
            rowVersion: '0',
            parentId: '',
            name: 'Native folder',
            sshAutoSudo: null,
            tunnelEnabled: null,
            tunnelConfigId: '',
            credentialMode: 0,
            credentialId: '',
          };
          const created = await unlocked.saveFolder(newFolder);
          assert.equal(created.rowVersion, '1');
          const updated = await unlocked.saveFolder({
            ...newFolder,
            id: created.nodeId,
            rowVersion: created.rowVersion,
            name: 'Renamed folder',
          });
          assert.equal(updated.rowVersion, '2');
          await assert.rejects(
            unlocked.saveFolder({ ...newFolder, id: created.nodeId, rowVersion: '1' }),
          );
          const editedWorkspace = await unlocked.workspace();
          assert.equal(editedWorkspace.tree.length, 1);
          assert.equal(editedWorkspace.tree[0].name, 'Renamed folder');
          assert.equal(editedWorkspace.tree[0].rowVersion, '2');
          const connection = await unlocked.saveConnection(connectionInput());
          assert.equal(connection.rowVersion, '1');
          const edit = connectionInput();
          edit.metadata.id = connection.nodeId;
          edit.metadata.name = 'Native saved connection';
          edit.metadata.inlinePasswordAction = 'preserve';
          edit.password = new Uint8Array();
          edit.notes = new Uint8Array();
          edit.notesAction = 'preserve';
          edit.rowVersion = '1';
          const edited = await unlocked.saveConnection(edit);
          assert.equal(edited.rowVersion, '2');
          const projected = (await unlocked.workspace()).tree.find(
            (node) => node.id === connection.nodeId,
          )!;
          assert.equal(projected.name, 'Native saved connection');
          assert.equal(projected.hasInlineCredential, true);
          assert.equal(projected.rowVersion, '2');
          const revealContext = {
            workspaceId: descriptor.vaultId,
            nodeId: connection.nodeId,
            rowVersion: '2',
            requestId: randomUUID(),
          };
          let copied = new Uint8Array(),
            marker = '',
            clipboardCleared = false;
          const linuxCopy = new LinuxVaultClipboard({
            host: {
              unlockedWorkspaceId: descriptor.vaultId,
              releaseClipboard: (q) => unlocked.releaseClipboard(q),
            },
            io: {
              write: async (value, ticket) => {
                copied = value;
                marker = ticket;
                assert.deepEqual(value, connectionInput().password);
              },
              has: async (ticket) => ticket === marker,
              clear: () => {
                clipboardCleared = true;
                marker = '';
              },
            },
          });
          assert.deepEqual(
            await linuxCopy.copy({
              workspaceId: descriptor.vaultId,
              nodeId: connection.nodeId,
              rowVersion: '2',
              field: 'secret',
            }),
            { expiresInSeconds: 30 },
          );
          assert.ok(copied.every((byte) => byte === 0));
          await linuxCopy.reset();
          assert.equal(clipboardCleared, true);
          const copyContext = {
            ...revealContext,
            requestId: randomUUID(),
            field: 'secret' as const,
          };
          const copyRecipient = await createClipboardRecipient(copyContext);
          const copyReply = await unlocked.releaseClipboard({
            ...copyContext,
            publicKey: copyRecipient.publicKey,
          });
          const copyBytes = await copyRecipient.open(copyReply);
          try {
            const copy = decodeClipboardRelease(copyBytes);
            assert.equal(copy.expiresInSeconds, 30);
            assert.deepEqual(copy.value, connectionInput().password);
          } finally {
            copyBytes.fill(0);
            copyRecipient.dispose();
          }
          await assert.rejects(copyRecipient.open(copyReply));
          await assert.rejects(
            unlocked.releaseClipboard({
              ...copyContext,
              rowVersion: '1',
              publicKey: copyRecipient.publicKey,
            }),
          );
          const revealRecipient = await createCredentialsRecipient(revealContext);
          const revealReply = await unlocked.displayCredentials({
            ...revealContext,
            publicKey: revealRecipient.publicKey,
          });
          const revealBytes = await revealRecipient.open(revealReply);
          try {
            const revealed = decodeCredentialDisplay(revealBytes);
            assert.equal(revealed.username, connectionInput().metadata.username);
            assert.equal(revealed.secret, new TextDecoder().decode(connectionInput().password));
            assert.equal(revealed.label, 'Password');
          } finally {
            revealBytes.fill(0);
            revealRecipient.dispose();
          }
          await assert.rejects(
            unlocked.displayCredentials({
              ...revealContext,
              rowVersion: '1',
              publicKey: revealRecipient.publicKey,
            }),
          );

          assert.equal('notes' in projected, false);
          assert.equal('password' in projected, false);
          edit.rowVersion = '1';
          await assert.rejects(unlocked.saveConnection(edit));
          const recover = () => ({
            vaultId: descriptor.vaultId,
            slotId: slot.id,
            kind: 'recovery' as const,
            factor: new Uint8Array(32).fill(0x32),
          });
          const before = await unlocked.security();
          phase = 'selecting Standard with the native recovery slot';
          assert.equal(await unlocked.tightenLocalProfile(before.sequence, recover()), true);
          phase = 'admitting a new native session after selecting Standard';
          await unlocked.lock();
          unlocked = createUnlocked();
          await unlocked.unlock(recover());
          const after = await unlocked.security();
          assert.equal(after.effective, 'standard');
          assert.equal(after.source, 'user');
          assert.equal(after.canTightenToStandard, undefined);
          assert.equal(BigInt(after.sequence), BigInt(before.sequence) + 1n);
        }
        await unlocked.lock();
      }
      const first = create();
      const status = await first.status();
      assert.deepEqual(status, {
        formatVersion: 1,
        stage: 'foundation',
        protectionAvailable: false,
        sharedWorkspaceAvailable: false,
        unlocked: false,
        lockedMemory: false,
      });
      assert.equal(await first.describe(), null);
      assert.deepEqual(await first.startup(), {
        slots: null,
        cosmetics: { theme: 'system' },
        newWorkspace: true,
        unprotectedAllowed: true,
      });
      const invalidInvitation = {
        invitation: 'WHINV2-invalid-checksum',
        code: new Uint8Array(16).fill(31),
        password: new TextEncoder().encode('native invitation password'),
        ask: new Uint8Array(32).fill(44),
        deviceName: 'Native test device',
        acknowledgeTLSOff: false,
      };
      await assert.rejects(first.sharedJoinInitial(invalidInvitation, '1.0.0'), {
        message: 'Vault operation failed.',
      });
      for (const factor of [
        invalidInvitation.code,
        invalidInvitation.password,
        invalidInvitation.ask,
      ])
        assert.ok(factor.every((byte) => byte === 0));
      assert.equal((await first.startup()).newWorkspace, true);
      await assert.rejects(readFile(databasePath), { code: 'ENOENT' });
      await assert.rejects(first.catalog(), { message: 'Vault operation failed.' });
      await assert.rejects(first.workspace(), { message: 'Vault operation failed.' });
      await assert.rejects(first.security(), { message: 'Vault operation failed.' });
      assert.deepEqual(await first.status(), status);
      phase = 'exclusive metadata ownership';
      // Prove native refusal on this exact held workspace separately from Node's
      // platform-dependent observation of process exit versus its request deadline.
      const denied = promisify(execFile)(
        executable,
        ['--operation', 'vault', '--database', databasePath],
        {
          windowsHide: true,
          timeout: 30_000,
          maxBuffer: 4096,
        },
      );
      denied.child.stdin!.end();
      await assert.rejects(denied, (error: unknown) => {
        const failure = error as Error & { code?: number; stdout?: string; stderr?: string };
        return (
          failure.code === 1 &&
          failure.stdout === '' &&
          failure.stderr?.trim() === 'vault_service_stopped'
        );
      });
      const competing = create();
      await assert.rejects(
        competing.status(),
        (error: unknown) =>
          error instanceof Error &&
          /^(Vault is unavailable\.|Vault did not respond in time\.)$/.test(error.message),
      );
      await competing.lock();
      assert.deepEqual(await first.status(), status);
      // The untrusted pre-unlock descriptor is parsed by Go; failure is fixed text.
      await writeFile(databasePath + '.slots', '{"password":"fixture-never-expose"}');
      await assert.rejects(first.describe(), { message: 'Vault operation failed.' });
      await assert.rejects(first.startup(), { message: 'Vault operation failed.' });
      assert.deepEqual(await first.status(), status);
      await first.lock();
      const replacement = create();
      assert.deepEqual(await replacement.status(), status);
      await replacement.lock();
      const files = await readdir(directory);
      assert.ok(files.includes('workspace.db.vault.lock'));
      assert.ok(!files.some((name) => name === 'workspace.db' || name.startsWith('workspace.db-')));
    } catch (error) {
      t.diagnostic(JSON.stringify({ phase, unavailable }));
      throw error;
    } finally {
      await Promise.all(clients.map((client) => client.lock()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'native migration decisions preserve pins until explicit choices and reject stale requests',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-migration-')),
      executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault'),
      databasePath = join(directory, 'workspace.db');
    const client = new VaultBackendClient({ executable, databasePath });
    try {
      const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
      await promisify(execFile)('go', ['build', '-o', executable, '.'], {
        cwd,
        windowsHide: true,
        timeout: 120000,
      });
      await promisify(execFile)(
        'go',
        ['test', '-count=1', '-run', '^TestVaultMigrationChoicesNativeFixture$', '.'],
        {
          cwd,
          env: { ...process.env, WORMHOLE_TEST_MIGRATION_DATABASE: databasePath },
          windowsHide: true,
          timeout: 120000,
        },
      );
      const expected = JSON.parse(await readFile(databasePath + '.migration-report.json', 'utf8'));
      const descriptor = await client.describe();
      assert.ok(descriptor);
      await client.unlock({
        vaultId: descriptor.vaultId,
        slotId: descriptor.slots[0].id,
        kind: 'recovery',
        factor: new Uint8Array(32).fill(0x32),
      });
      const selection = { nodeId: expected.nodeId, rowVersion: '2' };
      assert.deepEqual(await client.migrationReport(selection), expected);
      assert.doesNotMatch(JSON.stringify(expected), /private-(old|new|password)/);
      const choices = expected.entries.map((entry: any) => ({
        protocolPath: entry.protocolPath,
        choice: 'new',
      }));
      const request = { ...selection, fingerprint: expected.fingerprint, choices };
      const updated = await client.decideMigration(request);
      assert.equal(updated.rowVersion, '3');
      await assert.rejects(client.decideMigration(request));
      await assert.rejects(client.migrationReport(selection));
      const fresh = await client.migrationReport({ ...selection, rowVersion: '3' });
      assert.ok(fresh.entries.every((entry) => entry.choice === 'new'));
      const edit = connectionInput();
      edit.metadata.id = expected.nodeId;
      edit.rowVersion = '3';
      edit.password.fill(0);
      edit.password = new Uint8Array();
      edit.metadata.inlinePasswordAction = 'preserve';
      assert.equal((await client.saveConnection(edit)).rowVersion, '4');
    } finally {
      await client.lock();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
