import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { VaultBackendClient } from '../electron/vault-client.ts';
const run = promisify(execFile),
  require = createRequire(import.meta.url);

test(
  'real protected preparation and isolated resume migrate an OS-only legacy workspace without app admission',
  { timeout: 180_000, skip: process.platform !== 'win32' },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-os-migration-')),
      root = fileURLToPath(new URL('../', import.meta.url)),
      data = join(directory, 'data'),
      database = join(data, 'workspace.db'),
      executable = join(directory, 'backend.exe');
    let client: VaultBackendClient | undefined;
    try {
      await mkdir(data);
      await run('go', ['build', '-o', executable, '.'], {
        cwd: join(root, 'tools/wormhole-backend'),
        windowsHide: true,
        timeout: 120_000,
      });
      await run(
        process.execPath,
        [
          join(root, 'node_modules/typescript/bin/tsc'),
          '-p',
          join(root, 'electron/tsconfig.electron.json'),
        ],
        { cwd: root, windowsHide: true },
      );
      await run(executable, ['--operation', 'workspace', '--database', database], {
        windowsHide: true,
      });
      const before = await readFile(database);
      client = new VaultBackendClient({ executable, databasePath: database, userDataPath: data });
      assert.deepEqual((await client.startup()).legacy, { unprotectedAllowed: true });
      assert.deepEqual(await client.osMigrationContext(), { methods: ['none'] });
      await client.lock();
      client = undefined;
      const moduleURL = (name: string) =>
        JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const prepareHarness = join(directory, 'prepare.cjs');
      await writeFile(
        prepareHarness,
        `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
const database=${JSON.stringify(database)},data=${JSON.stringify(data)},executable=${JSON.stringify(executable)};
app.setPath('userData',data);app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
(async()=>{
 await app.whenReady();
 const {VaultBackendHost}=await import(${moduleURL('vault-host')}),{VaultBackendClient}=await import(${moduleURL('vault-client')}),{VaultMigrationSetupDialog}=await import(${moduleURL('vault-migration-setup-dialog')});
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath:database,userDataPath:data}),()=>true);
 const parent=new BrowserWindow({show:false,webPreferences:{offscreen:true}});let child;
 const dialog=new VaultMigrationSetupDialog({host,ipc:ipcMain,mode:'os-migration',createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist/vault-create.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron/vault-os-migration-preload.cjs'))}});
 try{
  await parent.loadURL('data:text/html,<html><body></body></html>');
  const prepared=dialog.open(parent,()=>true);
  let ready=false;for(let i=0;i<500;i++){try{if(await child.webContents.executeJavaScript("document.querySelector('select')?.value==='none'")){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,20));}
  assert.equal(ready,true);assert.equal(await child.webContents.executeJavaScript('typeof window.wormhole'),'undefined');assert.equal(await child.webContents.executeJavaScript('typeof window.vaultCreate'),'undefined');
  assert.equal(await child.webContents.executeJavaScript("document.querySelectorAll('input').length"),1);
  assert.equal(await child.webContents.executeJavaScript("document.querySelector('input').closest('label').hidden"),true);
  await child.webContents.executeJavaScript("document.querySelector('form').dispatchEvent(new SubmitEvent('submit',{cancelable:true}))");
  assert.equal(await prepared,true);assert.equal(host.unlockedWorkspaceId,undefined);assert.equal(child.isDestroyed(),true);
  console.log('os-prepare-native: actual protected preload bundled form old-factor native capsule no owner');
 }finally{await dialog.cancel();await host.stop();parent.destroy();}app.quit();
})().catch(error=>{console.error(error);app.exit(1)});`,
      );
      await run(process.execPath, ['--check', prepareHarness], { windowsHide: true });
      const preparation = await run(require('electron'), [prepareHarness], {
        env,
        windowsHide: true,
        timeout: 60_000,
      });
      assert.match(preparation.stdout, /os-prepare-native:/);
      t.diagnostic(preparation.stdout);
      assert.deepEqual(await readFile(database), before);
      const capsules = (await readdir(data)).filter((name) => name.endsWith('.setup'));
      assert.equal(capsules.length, 1);
      const capsule = JSON.parse(await readFile(join(data, capsules[0]), 'utf8'));
      assert.equal(capsule.document.formatVersion, 4);
      assert.equal(capsule.document.slots[0].kind, 'unprotected');
      const prepared = { vaultId: capsule.document.vaultId };
      const startupSource = stripTypeScriptTypes(
        await readFile(join(root, 'src/vault-migration-startup.ts'), 'utf8'),
      ).replace(/^export /gm, '');
      const renderer =
        startupSource +
        `\nwindow.testOpened=0;mountVaultOSMigrationStartup(document.getElementById('card'),window.wormhole,async()=>{window.testOpened++;});document.querySelector('button').click();`;
      const harness = join(directory, 'main.cjs');
      await writeFile(
        harness,
        `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict'),{dirname,join}=require('node:path'),{readFileSync,readdirSync}=require('node:fs');
const database=${JSON.stringify(database)},data=${JSON.stringify(data)},executable=${JSON.stringify(executable)},vaultId=${JSON.stringify(prepared.vaultId)};
app.setPath('userData',data);app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
(async()=>{
 const {prepareVaultMigrationBoot}=await import(${moduleURL('vault-migration-boot')});
 const boot=prepareVaultMigrationBoot({app,executable:()=>executable,databasePath:database});assert.equal(boot.unavailable,false);assert.ok(boot.migrationSessionData);assert.notEqual(app.getPath('userData'),data);
 await app.whenReady();
 const {VaultBackendHost}=await import(${moduleURL('vault-host')}),{VaultBackendClient}=await import(${moduleURL('vault-client')}),{registerVaultOSMigrationIpc}=await import(${moduleURL('vault-os-migration-ipc')});
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath:database,userDataPath:data,migrationSessionData:boot.migrationSessionData}),()=>true);
 const metadata=await host.startup();assert.equal(metadata.osMigration.vaultId,vaultId);assert.equal(host.unlockedWorkspaceId,undefined);
 const parent=new BrowserWindow({show:false,webPreferences:{preload:${JSON.stringify(join(root, 'dist-electron/preload.cjs'))},contextIsolation:true,sandbox:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});let activated=0;
 registerVaultOSMigrationIpc({ipc:ipcMain,host,trusted:event=>event.sender===parent.webContents&&event.senderFrame===parent.webContents.mainFrame&&!parent.isDestroyed(),quiesced:()=>!!boot.migrationSessionData,activate:()=>activated++,retire:()=>host.stop(),fatal:()=>{throw Error('unexpected uncertain cleanup');}});
 try{
  await parent.loadURL('data:text/html,<html><body><section id="card"></section></body></html>');assert.equal(await parent.webContents.executeJavaScript('typeof window.vaultCreate'),'undefined');
  await parent.webContents.executeJavaScript(${JSON.stringify(renderer)});
  let opened=false;for(let i=0;i<1000;i++){if(await parent.webContents.executeJavaScript('window.testOpened===1')){opened=true;break;}await new Promise(r=>setTimeout(r,20));}
  assert.equal(opened,true);assert.equal(activated,1);assert.equal(host.unlockedWorkspaceId,vaultId);assert.deepEqual(await host.protection(),{protected:false});await host.workspace();
  const slots=JSON.parse(readFileSync(database+'.slots','utf8'));assert.equal(slots.formatVersion,3);assert.equal(slots.migration,undefined);assert.equal(readdirSync(data).some(name=>name.endsWith('.setup')),false);
  console.log('os-migration-native: isolated boot actual preload startup button native publication authenticated owner');
 }finally{await host.stop();parent.destroy();}app.quit();
})().catch(error=>{console.error(error);app.exit(1)});`,
      );
      await run(process.execPath, ['--check', harness], { windowsHide: true });
      const result = await run(require('electron'), [harness], {
        env,
        windowsHide: true,
        timeout: 60_000,
      });
      assert.match(result.stdout, /os-migration-native:/);
      t.diagnostic(result.stdout);
      if (result.stderr.trim()) t.diagnostic(result.stderr);
    } finally {
      await client?.lock();
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-os-migration-')));
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  },
);
