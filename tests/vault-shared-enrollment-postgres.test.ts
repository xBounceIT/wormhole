import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import type { SharedVaultTransport } from '../electron/vault-shared-transport.ts';

function startInitialPostgresFixture(
  fixture: string,
  backend: string,
  scratch: string,
  tlsMode: SharedVaultTransport = 'off',
  options: {
    profile?: 'default' | 'standard';
    askRequired?: boolean;
    askUsed?: boolean;
    signedTLS?: boolean;
    tlsFailure?: string;
    largeTLS?: boolean;
  } = {},
) {
  const server = spawn(
    fixture,
    ['-test.run=^TestPostgresInitialApplicationFixture$', '-test.timeout=180s'],
    {
      cwd: backend,
      windowsHide: true,
      stdio: 'pipe',
      env: {
        ...process.env,
        WORMHOLE_TEST_INITIAL_APPLICATION: '1',
        WORMHOLE_TEST_INITIAL_TLS: tlsMode,
        WORMHOLE_TEST_INITIAL_PROFILE: options.profile ?? 'default',
        WORMHOLE_TEST_INITIAL_ASK: options.askRequired ? '1' : '0',
        WORMHOLE_TEST_INITIAL_ACCOUNT_ASK: (options.askUsed ?? options.askRequired) ? '1' : '0',
        WORMHOLE_TEST_INITIAL_SIGNED_TLS: options.signedTLS ? '1' : '0',
        WORMHOLE_TEST_INITIAL_TLS_FAILURE: options.tlsFailure ?? '',
        WORMHOLE_TEST_INITIAL_LARGE_TLS: options.largeTLS ? '1' : '0',
        WORMHOLE_TEST_POSTGRES_SCRATCH: scratch,
      },
    },
  );
  server.stderr.resume();
  const closed = new Promise<void>((yes, no) => {
    server.once('close', (code) =>
      code === 0 ? yes() : no(Error('PostgreSQL enrollment fixture failed.')),
    );
    server.once('error', no);
  });
  void closed.catch(() => undefined);
  const reader = createInterface({ input: server.stdout });
  const iterator = reader[Symbol.asyncIterator]();
  const diagnostics: string[] = [];
  const next = async () => {
    for (;;) {
      const line = await iterator.next();
      if (line.done) throw Error('PostgreSQL fixture stopped: ' + diagnostics.join(' | '));
      if (line.value.startsWith('{')) return JSON.parse(line.value);
      diagnostics.push(line.value.slice(0, 1024));
      if (diagnostics.length > 20) throw Error('Excess PostgreSQL fixture output.');
    }
  };
  return { server, closed, reader, next };
}

const legacyProfileCases = [
  ...(['off', 'encrypted', 'verified'] as const).flatMap((tlsMode) =>
    [false, true].map((askRequired) => ({
      tlsMode,
      profile: 'default' as const,
      askRequired,
      askUsed: askRequired,
    })),
  ),
  ...[false, true].map((askRequired) => ({
    tlsMode: 'verified' as const,
    profile: 'standard' as const,
    askRequired,
    askUsed: askRequired,
  })),
  ...(['default', 'standard'] as const).map((profile) => ({
    tlsMode: 'verified' as const,
    profile,
    askRequired: false,
    askUsed: true,
  })),
];
const profileCases = [
  ...legacyProfileCases.map((value) => ({ ...value, signedTLS: false, largeTLS: false })),
  ...legacyProfileCases
    .filter((value) => value.tlsMode === 'verified' && value.askRequired === value.askUsed)
    .map((value) => ({ ...value, signedTLS: true, largeTLS: false })),
  {
    tlsMode: 'verified' as const,
    profile: 'default' as const,
    askRequired: false,
    askUsed: false,
    signedTLS: true,
    largeTLS: true,
  },
];

for (const { tlsMode, profile, askRequired, askUsed, signedTLS, largeTLS } of profileCases)
  for (const continuation of largeTLS ? [false] : [false, true])
    for (const failure of [
      'none',
      ...(signedTLS && !largeTLS && profile === 'default' && !askUsed && !continuation
        ? ['revoked-peer', 'wrong-signer', 'stripped-proof']
        : []),
      ...(tlsMode === 'verified' && profile === 'default' && !askRequired && continuation
        ? ['untrusted-ca']
        : []),
      ...(tlsMode === 'verified' && askUsed
        ? continuation
          ? ['missing-ask', 'wrong-ask']
          : askRequired
            ? ['missing-ask']
            : []
        : []),
    ])
      test(
        (continuation
          ? 'protected continuation finishes a staged invitation on real PostgreSQL and reopens'
          : 'protected Join enrolls once on real PostgreSQL and reopens through ordinary device admission') +
          (tlsMode === 'verified'
            ? ' [verified TLS]'
            : tlsMode === 'encrypted'
              ? ' [TLS Encrypted]'
              : ' [TLS Off]') +
          (profile === 'standard' ? ' [Standard]' : '') +
          (askUsed ? (askRequired ? ' [ASK required]' : ' [ASK optional]') : '') +
          (signedTLS ? ' [org-signed TLS]' : '') +
          (largeTLS ? ' [large revocations]' : '') +
          (failure === 'none' ? '' : ` [${failure} refused]`),
        { timeout: 240_000, skip: !process.env.WORMHOLE_TEST_POSTGRES_BIN },
        async () => {
          const directory = await mkdtemp(join(tmpdir(), 'wormhole-initial-postgres-'));
          const root = fileURLToPath(new URL('../', import.meta.url));
          const backend = join(root, 'tools', 'wormhole-backend');
          const require = createRequire(import.meta.url);
          const suffix = process.platform === 'win32' ? '.exe' : '';
          let server: ReturnType<typeof spawn> | undefined;
          let closed: Promise<void> | undefined;
          try {
            const fixture = join(directory, 'server.test' + suffix);
            await promisify(execFile)('go', ['test', '-c', '-o', fixture, './internal/sharedpg'], {
              cwd: backend,
              windowsHide: true,
              timeout: 120_000,
            });
            const fixtureOwner = startInitialPostgresFixture(
              fixture,
              backend,
              join(root, 'artifacts', 'vault', basename(directory)),
              tlsMode,
              {
                profile,
                askRequired,
                askUsed,
                signedTLS,
                largeTLS,
                tlsFailure: failure === 'revoked-peer' || failure === 'wrong-signer' ? failure : '',
              },
            );
            server = fixtureOwner.server;
            closed = fixtureOwner.closed;
            const { next, reader } = fixtureOwner;
            const processOwner = server;
            const { invitation: originalInvitation } = await next();
            let invitation = originalInvitation;
            assert.ok(
              typeof invitation === 'string' &&
                invitation.startsWith(signedTLS ? 'WHINV3-' : 'WHINV2-'),
            );
            if (largeTLS) assert.ok(Buffer.byteLength(invitation) > 64 * 1024);
            if (failure === 'stripped-proof') {
              const forged = JSON.parse(
                Buffer.from(invitation.split('.')[0].slice(7), 'base64url').toString('utf8'),
              );
              const pem = forged.tlsIdentity.bundle.cas
                .map(
                  (der: string) =>
                    '-----BEGIN CERTIFICATE-----\n' +
                    der.match(/.{1,64}/g)!.join('\n') +
                    '\n-----END CERTIFICATE-----\n',
                )
                .join('');
              forged.formatVersion = 2;
              forged.caPem = Buffer.from(pem).toString('base64');
              delete forged.tlsIdentity;
              const payload = 'WHINV2-' + Buffer.from(JSON.stringify(forged)).toString('base64url');
              invitation = payload + '.' + createHash('sha256').update(payload).digest('hex');
            }
            const data = join(directory, 'data');
            await mkdir(data);
            if (continuation) {
              const application = join(directory, 'application.test' + suffix);
              const captureCoverage =
                signedTLS && profile === 'default' && !askUsed && failure === 'none';
              // Instrument only the case that writes a profile. On Windows,
              // compile in workspace scratch and keep the runtime temp separate.
              const buildTemp = join(root, 'artifacts', 'vault', basename(directory), 'go-build');
              if (captureCoverage) await mkdir(buildTemp, { recursive: true });
              await promisify(execFile)(
                'go',
                ['test', '-c', ...(captureCoverage ? ['-cover'] : []), '-o', application, '.'],
                {
                  cwd: backend,
                  ...(captureCoverage ? { env: { ...process.env, GOTMPDIR: buildTemp } } : {}),
                  windowsHide: true,
                  timeout: 120_000,
                },
              );
              await promisify(execFile)(
                application,
                [
                  '-test.run=^TestVaultSharedInitialPostgresFixture$',
                  '-test.timeout=35s',
                  ...(captureCoverage
                    ? [
                        '-test.coverprofile=' +
                          join(root, 'artifacts', 'vault', 'invite-tls-initial-native.cover'),
                      ]
                    : []),
                ],
                {
                  cwd: backend,
                  windowsHide: true,
                  timeout: 40_000,
                  env: {
                    ...process.env,
                    WORMHOLE_TEST_INITIAL_INVITATION: invitation,
                    WORMHOLE_TEST_INITIAL_RECOVERY_PREFIX: 'stage-only',
                    WORMHOLE_TEST_INITIAL_STAGE_DATABASE: join(data, 'workspace.db'),
                    WORMHOLE_TEST_INITIAL_ASK: askUsed ? '1' : '0',
                  },
                },
              );
            }
            if (failure === 'untrusted-ca') {
              processOwner.stdin!.write('rotate-untrusted-ca\n');
              assert.deepEqual(await next(), { rotated: true });
            }
            const checkpointPath = join(data, 'workspace.db.shared', 'device.trust.join-startup');
            const checkpoint =
              continuation && (failure === 'missing-ask' || failure === 'wrong-ask')
                ? await readFile(checkpointPath)
                : undefined;
            const moduleURL = (name: string) =>
              JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
            const document = join(directory, 'parent.html');
            await writeFile(document, '<!doctype html><html><body>Public parent</body></html>');
            const harness = join(directory, 'main.cjs');
            const ask = askUsed ? '2f'.repeat(32) : '';
            const enrollmentASK =
              failure === 'missing-ask' ? '' : failure === 'wrong-ask' ? '30'.repeat(32) : ask;
            const reopenForm = `document.querySelectorAll('input[type=password]')[0].value='real join password';document.querySelectorAll('input[type=password]')[1].value=${JSON.stringify(ask)};document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}))`;
            const enrollmentForm = continuation
              ? `const choice=document.querySelector('[name=continue-enrollment]');choice.checked=true;choice.dispatchEvent(new Event('change'));document.querySelectorAll('input[type=password]')[0].value='real join password';document.querySelectorAll('input[type=password]')[1].value=${JSON.stringify(enrollmentASK)};document.querySelector('[name=code]').value='1f'.repeat(16);document.querySelector('[name=acknowledge-tls-off]').checked=${tlsMode === 'off'};document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}))`
              : `for(const [name,value] of Object.entries(${JSON.stringify({ code: '1f'.repeat(16), password: 'real join password', 'password-confirm': 'real join password', 'device-name': 'PostgreSQL UI device', ask: enrollmentASK })}))document.querySelector('[name='+name+']').value=value;document.querySelector('[type=checkbox]').checked=${tlsMode === 'off'};document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}))`;
            await writeFile(
              harness,
              `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
app.setPath('userData',${JSON.stringify(data)});
app.whenReady().then(async()=>{
 const {VaultBackendClient}=await import(${moduleURL('vault-client')}),{VaultBackendHost}=await import(${moduleURL('vault-host')}),{VaultSharedAuthenticationDialog}=await import(${moduleURL('vault-shared-dialog')}),{registerSharedAuthenticationIpc}=await import(${moduleURL('vault-shared-ipc')});
 let policyActivations=0,appActivations=0,child;
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(join(root, 'dist-electron', `wormhole-backend-${process.arch}${suffix}`))},databasePath:${JSON.stringify(join(data, 'workspace.db'))},userDataPath:${JSON.stringify(data)}}),()=>true,security=>{assert.equal(security.effective,${JSON.stringify(profile)});policyActivations++});
 const parent=new BrowserWindow({show:false,webPreferences:{preload:${JSON.stringify(join(root, 'dist-electron', 'preload.cjs'))},sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
 const dialog=new VaultSharedAuthenticationDialog({host,ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-preload.cjs'))},appVersion:'1.2.3'});
 registerSharedAuthenticationIpc({host,dialog,ipc:ipcMain,trusted:event=>event.sender===parent.webContents&&event.senderFrame===parent.webContents.mainFrame&&event.senderFrame.url===${JSON.stringify(pathToFileURL(document).href)},parent:()=>parent,activate:()=>appActivations++});
 const wait=async check=>{for(let i=0;i<200;i++){if(await check())return;await new Promise(r=>setTimeout(r,25))}throw Error('Protected enrollment document did not become ready.')};
 try{
  await parent.loadFile(${JSON.stringify(document)});
  for(let attempt=0;attempt<${failure === 'none' ? 2 : 1};attempt++){
   const startup=await host.startup();assert.equal(startup.newWorkspace,attempt===0&&!${continuation});if(attempt)assert.ok(startup.shared&&!startup.sharedJoin);else if(${continuation})assert.equal(startup.sharedJoin.canContinue,true);
   child=undefined;const admission=parent.webContents.executeJavaScript(${JSON.stringify(continuation ? 'window.wormhole.authenticateSharedVault("recover-enrollment")' : 'window.wormhole.authenticateSharedVault("join-initial")')});void admission.catch(()=>{});
   await wait(async()=>child&&await child.webContents.executeJavaScript('!!document.querySelector("form")').catch(()=>false));
   if(!attempt&&!${continuation}){
    await wait(()=>child.webContents.executeJavaScript('!!document.querySelector("textarea")'));
    await child.webContents.executeJavaScript('const token=document.querySelector("textarea");token.value='+${JSON.stringify(JSON.stringify(invitation))}+';token.dispatchEvent(new Event("input"));document.querySelectorAll("button")[1].click()');
   }
   await wait(()=>child.webContents.executeJavaScript('!document.querySelector("[type=submit]").disabled'));
   if(!attempt&&!${continuation})assert.equal(await child.webContents.executeJavaScript('document.querySelector(".shared-invitation-off").hidden'),${tlsMode !== 'off'});
   if(attempt&&${askUsed})for(const badASK of ['', '30'.repeat(32)]){
    await child.webContents.executeJavaScript("document.querySelectorAll('input[type=password]')[0].value='real join password';document.querySelectorAll('input[type=password]')[1].value="+JSON.stringify(badASK)+";document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}))");
    await wait(()=>child.webContents.executeJavaScript('document.querySelector(".startup-status").textContent.includes("Could not sign in")&&!document.querySelector("[type=submit]").disabled'));
    assert.equal(host.unlockedWorkspaceId,undefined);assert.equal(policyActivations,1);assert.equal(appActivations,1);
    assert.equal(await child.webContents.executeJavaScript('[...document.querySelectorAll("input[type=password]")].every(input=>input.value==="")'),true);
    const retained=await host.startup();assert.equal(retained.sharedJoin,undefined);assert.ok(retained.shared);assert.equal(retained.slots.vaultId,startup.slots.vaultId);
   }
   await child.webContents.executeJavaScript(attempt?${JSON.stringify(reopenForm)}:${JSON.stringify(enrollmentForm)});
   if(${failure !== 'none'}){
    await wait(()=>child.webContents.executeJavaScript('document.querySelector(".startup-status").textContent.includes('+${JSON.stringify(JSON.stringify(continuation ? 'Could not sign in' : 'Could not join'))}+')&&!document.querySelector("[type=submit]").disabled'));
    assert.equal(host.unlockedWorkspaceId,undefined);assert.equal(policyActivations,0);assert.equal(appActivations,0);
    assert.equal(await child.webContents.executeJavaScript('[...document.querySelectorAll("input[type=password]")].every(input=>input.value==="")'),true);
    await dialog.cancel();assert.equal(await admission,null);
    const retained=await host.startup();assert.equal(retained.newWorkspace,!${continuation});assert.equal(retained.shared,undefined);if(${continuation}){assert.equal(retained.sharedJoin.canContinue,true);assert.equal(retained.slots.vaultId,startup.slots.vaultId)}else{assert.equal(retained.sharedJoin,undefined);assert.equal(retained.slots,null)};
    continue;
   }
   const result=await admission;assert.equal(result.admitted,true);assert.equal(typeof result.lockedMemory,'boolean');assert.equal(result.orgEscrow,true);assert.equal(result.tls,${JSON.stringify(tlsMode)});assert.deepEqual(Object.keys(result).sort(),['admitted','lockedMemory','orgEscrow','tls']);
   assert.equal(host.isSharedWorkspace,true);assert.equal(host.unlockedWorkspaceId,'12345678-1234-4234-8234-123456789abc');
   const completed=await host.startup();assert.ok(completed.shared&&!completed.sharedJoin);assert.equal(completed.newWorkspace,false);
   await host.stop();
  }
  assert.equal(policyActivations,${failure === 'none' ? 2 : 0});assert.equal(appActivations,${failure === 'none' ? 2 : 0});
 }finally{await dialog.cancel();await host.stop();if(child&&!child.isDestroyed())child.destroy();parent.destroy()}
 app.quit();
}).catch(error=>{console.error(error);app.exit(1)});
`,
            );
            const electron = require('electron') as string;
            const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
            const headless = process.platform === 'linux' && !env.DISPLAY;
            const { stdout, stderr } = await promisify(execFile)(
              headless ? 'xvfb-run' : electron,
              headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
              { env, windowsHide: true, timeout: 95_000, maxBuffer: 16384 },
            );
            assert.doesNotMatch(stdout + stderr, /real join password/);
            assert.ok(!ask || !(stdout + stderr).includes(ask));
            if (checkpoint) assert.deepEqual(await readFile(checkpointPath), checkpoint);
            if (!continuation && failure !== 'none')
              await assert.rejects(lstat(join(data, 'workspace.db.shared')), { code: 'ENOENT' });
            processOwner.stdin!.end(failure === 'none' ? 'verify\n' : 'verify-unused\n');
            assert.deepEqual(
              await next(),
              failure === 'none' ? { confirmed: true } : { unused: true },
            );
            await closed;
            reader.close();
          } finally {
            server?.stdin?.end();
            if (closed) await closed;
            assert.equal(resolve(directory, '..'), resolve(tmpdir()));
            await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
          }
        },
      );

test(
  'initial Join refuses an untrusted CA or host before staging on verified TLS',
  { timeout: 150_000, skip: !process.env.WORMHOLE_TEST_POSTGRES_BIN },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-tls-refusal-'));
    const root = fileURLToPath(new URL('../', import.meta.url)),
      backend = join(root, 'tools', 'wormhole-backend');
    const suffix = process.platform === 'win32' ? '.exe' : '',
      execute = promisify(execFile);
    try {
      const fixture = join(directory, 'server.test' + suffix),
        application = join(directory, 'application.test' + suffix);
      await execute('go', ['test', '-c', '-o', fixture, './internal/sharedpg'], {
        cwd: backend,
        windowsHide: true,
        timeout: 120_000,
      });
      await execute('go', ['test', '-c', '-o', application, '.'], {
        cwd: backend,
        windowsHide: true,
        timeout: 120_000,
      });
      for (const reject of ['ca', 'host'])
        await t.test(reject, async () => {
          const owner = startInitialPostgresFixture(
            fixture,
            backend,
            join(root, 'artifacts', 'vault', basename(directory), reject),
            'verified',
          );
          try {
            const { invitation } = await owner.next();
            const { stdout, stderr } = await execute(
              application,
              ['-test.run=^TestVaultSharedInitialPostgresFixture$', '-test.timeout=35s'],
              {
                cwd: backend,
                windowsHide: true,
                timeout: 40_000,
                maxBuffer: 16384,
                env: {
                  ...process.env,
                  WORMHOLE_TEST_INITIAL_INVITATION: invitation,
                  WORMHOLE_TEST_INITIAL_REJECT_TLS: reject,
                  WORMHOLE_TEST_INITIAL_RECOVERY_PREFIX: '',
                  WORMHOLE_TEST_INITIAL_STAGE_DATABASE: '',
                },
              },
            );
            assert.doesNotMatch(stdout + stderr, /real join password/);
            owner.server.stdin.end('verify-unused\n');
            assert.deepEqual(await owner.next(), { unused: true });
            await owner.closed;
          } finally {
            owner.server.stdin.end();
            await owner.closed;
            owner.reader.close();
          }
        });
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  },
);

test(
  'native recovery restores every interrupted staging prefix on real PostgreSQL without replaying Join',
  { timeout: 240_000, skip: !process.env.WORMHOLE_TEST_POSTGRES_BIN },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-recovery-postgres-'));
    const root = fileURLToPath(new URL('../', import.meta.url));
    const backend = join(root, 'tools', 'wormhole-backend');
    const suffix = process.platform === 'win32' ? '.exe' : '';
    const execute = promisify(execFile);
    try {
      const fixture = join(directory, 'server.test' + suffix);
      const application = join(directory, 'application.test' + suffix);
      const buildTemp = join(root, 'artifacts', 'vault', basename(directory) + '-build');
      await mkdir(buildTemp, { recursive: true });
      await execute('go', ['test', '-c', '-o', fixture, './internal/sharedpg'], {
        cwd: backend,
        windowsHide: true,
        timeout: 120_000,
      });
      await execute('go', ['test', '-c', '-cover', '-o', application, '.'], {
        cwd: backend,
        env: { ...process.env, GOTMPDIR: buildTemp },
        windowsHide: true,
        timeout: 120_000,
      });
      for (const prefix of ['snapshot', 'device', 'transport', 'complete', 'before-submit']) {
        await t.test(prefix, { timeout: 45_000 }, async () => {
          const owner = startInitialPostgresFixture(
            fixture,
            backend,
            join(root, 'artifacts', 'vault', basename(directory), prefix),
          );
          try {
            const { invitation } = await owner.next();
            assert.ok(typeof invitation === 'string' && invitation.startsWith('WHINV2-'));
            const { stdout, stderr } = await execute(
              application,
              [
                '-test.run=^TestVaultSharedInitialPostgresFixture$',
                '-test.timeout=35s',
                ...(prefix === 'before-submit'
                  ? [
                      '-test.coverprofile=' +
                        join(root, 'artifacts', 'vault', 'shared-enrollment-native.cover'),
                    ]
                  : []),
              ],
              {
                cwd: backend,
                windowsHide: true,
                timeout: 40_000,
                maxBuffer: 16384,
                env: {
                  ...process.env,
                  WORMHOLE_TEST_INITIAL_INVITATION: invitation,
                  WORMHOLE_TEST_INITIAL_RECOVERY_PREFIX: prefix,
                },
              },
            );
            assert.doesNotMatch(stdout + stderr, /real join password/);
            owner.server.stdin.end('verify\n');
            assert.deepEqual(await owner.next(), { confirmed: true });
            await owner.closed;
          } finally {
            owner.server.stdin.end();
            await owner.closed;
            owner.reader.close();
          }
        });
      }
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  },
);
