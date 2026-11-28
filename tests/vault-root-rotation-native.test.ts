import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import {
  prepareUnprotectedSourceInElectron,
  requestUnprotectedUpgradeInElectron,
} from './fixtures/vault-upgrade-native.ts';

const run = promisify(execFile),
  require = createRequire(import.meta.url);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test(
  'real protected Electron prompt resumes Go root rotation after cancel and wrong password',
  { timeout: 300_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-root-resume-'));
    t.after(async () => {
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-root-resume-')));
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    });
    const fixture = join(directory, 'fixture' + (process.platform === 'win32' ? '.exe' : ''));
    const backend = join(directory, 'backend' + (process.platform === 'win32' ? '.exe' : ''));
    const nativeBuild = {
      cwd: join(root, 'tools', 'wormhole-backend'),
      windowsHide: true,
      timeout: 120_000,
    };
    await run('go', ['test', '-c', '-o', fixture, '.'], nativeBuild);
    await run('go', ['build', '-o', backend, '.'], nativeBuild);
    await run(
      process.execPath,
      [
        join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
        '-p',
        join(root, 'electron', 'tsconfig.electron.json'),
      ],
      { cwd: root, windowsHide: true },
    );
    await run(process.execPath, [join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'build'], {
      cwd: root,
      windowsHide: true,
    });
    // DPAPI custody crosses these two real processes. Unix TestMain's mock
    // keyring is process-local; portable OS-retirement coverage lives in Go.
    for (const custodyMode of process.platform === 'win32' ? ['1', '2', '3', '4'] : ['1']) {
      const helper = spawn(fixture, ['-test.run=^TestVaultRootRotationBrowserFixture$'], {
        windowsHide: true,
        env: { ...process.env, WORMHOLE_ROOT_ROTATION_BROWSER_FIXTURE: custodyMode },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const helperExit = once(helper, 'exit');
      let diagnostic = '';
      helper.stderr.on('data', (chunk) => {
        diagnostic = (diagnostic + chunk.toString()).slice(-4096);
      });
      const lines = createInterface({ input: helper.stdout });
      try {
        const first = await Promise.race([
          once(lines, 'line').then(([line]) => line),
          helperExit.then(() => {
            throw Error('Native fixture exited before ready: ' + diagnostic);
          }),
        ]);
        const metadata = JSON.parse(first);
        assert.equal(typeof metadata.database, 'string');
        assert.match(metadata.vaultId, /^[0-9a-f-]{36}$/);
        if (custodyMode === '4') {
          const requested = await requestUnprotectedUpgradeInElectron(
            root,
            directory,
            metadata.database,
            backend,
          );
          if (requested.stdout.trim()) t.diagnostic(requested.stdout.trim());
          if (requested.stderr.trim()) t.diagnostic(requested.stderr.trim());
        }
        if (custodyMode === '3' || custodyMode === '4') {
          const prepared = await prepareUnprotectedSourceInElectron(
            root,
            directory,
            metadata.database,
            backend,
          );
          if (prepared.stdout.trim()) t.diagnostic(prepared.stdout.trim());
          if (prepared.stderr.trim()) t.diagnostic(prepared.stderr.trim());
        }
        const harness = join(directory, 'main.cjs');
        await writeFile(
          harness,
          `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
const {dirname,join}=require('node:path'),{readFileSync,existsSync,readdirSync}=require('node:fs');
const database=${JSON.stringify(metadata.database)},vaultId=${JSON.stringify(metadata.vaultId)},executable=${JSON.stringify(backend)};
assert.equal(JSON.parse(readFileSync(database+'.root-rotation','utf8')).version,${custodyMode === '1' ? 1 : 2});
const oldCustody=readdirSync(dirname(database)).filter(n=>n.startsWith('.wormhole-unprotected-')).map(n=>({path:join(dirname(database),n),bytes:readFileSync(join(dirname(database),n))}));
assert.equal(oldCustody.length,${custodyMode === '1' ? 0 : 1});
app.setPath('userData',dirname(database));app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
(async()=>{
 const {prepareVaultMigrationBoot}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-migration-boot.js')).href)});
 const boot=prepareVaultMigrationBoot({app,executable:()=>executable,databasePath:database});
 assert.equal(boot.primary,true);assert.equal(boot.unavailable,false);assert.ok(boot.migrationSessionData);assert.notEqual(app.getPath('userData'),dirname(database));
 await app.whenReady();
 const {VaultBackendHost}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-host.js')).href)});
 const {VaultBackendClient}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-client.js')).href)});
 const {VaultReauthenticationDialog}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-reauth-dialog.js')).href)});
 const {registerVaultRootRotationIpc}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-migration-ipc.js')).href)});
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath:database,userDataPath:dirname(database),migrationSessionData:boot.migrationSessionData}),()=>true);
 const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});await parent.loadURL('data:text/html,<html></html>');let child,activate=0,handler;
 const dialog=new VaultReauthenticationDialog({ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},stop:()=>host.stop(),url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-reauth.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-reauth-preload.cjs'))}});
 const event={sender:parent.webContents,senderFrame:parent.webContents.mainFrame};
 registerVaultRootRotationIpc({ipc:{handle:(channel,fn)=>{assert.equal(channel,'vault:rotation-resume');handler=fn}},host,dialog,parent:()=>parent,trusted:e=>e.sender===parent.webContents&&!parent.isDestroyed(),quiesced:()=>!!boot.migrationSessionData,activate:()=>activate++,retire:()=>host.stop()});
 const evaluate=code=>child.webContents.executeJavaScript(code),until=async code=>{for(let i=0;i<600;i++){if(child&&!child.isDestroyed()&&await evaluate(code))return;await new Promise(r=>setTimeout(r,20));}throw Error('Protected resume window did not advance');};
 const before=readFileSync(database),slots=readFileSync(database+'.slots');
 try {
  const cancelled=handler(event).then(()=>false,()=>true);await until('document.querySelector(".startup-subtitle")?.textContent==="Finish updating vault protection"');
  await evaluate('document.querySelector(".startup-button-secondary").click()').catch(()=>{});assert.equal(await cancelled,true);
  assert.equal(host.unlockedWorkspaceId,undefined);assert.deepEqual(readFileSync(database),before);assert.deepEqual(readFileSync(database+'.slots'),slots);assert.ok(existsSync(database+'.root-rotation'));
  for(const c of oldCustody)assert.deepEqual(readFileSync(c.path),c.bytes);
  const resumed=handler(event);await until('document.querySelector("input")&&!document.querySelector("input").disabled');
  assert.equal(await evaluate('typeof window.wormhole'),'undefined');assert.match(await evaluate('document.body.textContent'),/Finish updating vault protection/);
  assert.equal(child.webContents.getLastWebPreferences().sandbox,true);if(process.platform!=='linux')assert.equal(child.isContentProtected(),true);
  await evaluate('(()=>{const input=document.querySelector("input");input.value="incorrect public test password";input.dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
  await until('document.querySelector("p[role=status]").textContent.startsWith("Could not confirm")');assert.equal(host.unlockedWorkspaceId,undefined);assert.deepEqual(readFileSync(database),before);
  for(const c of oldCustody)assert.deepEqual(readFileSync(c.path),c.bytes);
  await evaluate('(()=>{const input=document.querySelector("input");input.value="new native transition password";input.dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()').catch(()=>{});
  assert.equal(await resumed,true);assert.equal(activate,1);assert.equal(host.unlockedWorkspaceId,vaultId);assert.equal(existsSync(database+'.root-rotation'),false);
  assert.equal(JSON.parse(readFileSync(database+'.slots','utf8')).rootKeyVersion,2);await host.workspace();
  for(const c of oldCustody)assert.equal(existsSync(c.path),false);
  console.log('root-resume-native: isolated boot, protected prompt, cancel, wrong factor, publication verified');
 }finally{await dialog.cancel();await host.stop();parent.destroy();}
 app.quit();
})().catch(error=>{console.error(error);app.exit(1)});
`,
        );
        await run(process.execPath, ['--check', harness], { windowsHide: true });
        const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
        const electron = require('electron') as string,
          headless = process.platform === 'linux' && !env.DISPLAY;
        const result = await run(
          headless ? 'xvfb-run' : electron,
          headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
          { windowsHide: true, env, timeout: 90_000 },
        );
        assert.match(result.stdout, /root-resume-native: isolated boot/);
        if (result.stdout.trim()) t.diagnostic(result.stdout.trim());
        if (result.stderr.trim()) t.diagnostic(result.stderr.trim());
      } finally {
        helper.stdin.end();
        const exited = await helperExit;
        assert.equal(exited[0], 0, diagnostic);
        lines.close();
      }
    }
  },
);
