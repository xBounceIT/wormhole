import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
const run = promisify(execFile),
  require = createRequire(import.meta.url);

export async function requestUnprotectedUpgradeInElectron(
  root: string,
  directory: string,
  database: string,
  executable: string,
) {
  const moduleURL = (name: string) =>
    JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
  const harness = join(directory, 'default-main.cjs');
  await writeFile(
    harness,
    `
const {app,BrowserWindow}=require('electron'),assert=require('node:assert/strict'),{dirname}=require('node:path'),{readFileSync,existsSync}=require('node:fs');
const database=${JSON.stringify(database)},executable=${JSON.stringify(executable)};
app.setPath('userData',dirname(database));app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
(async()=>{
 const {prepareVaultMigrationBoot}=await import(${moduleURL('vault-migration-boot')});
 const boot=prepareVaultMigrationBoot({app,executable:()=>executable,databasePath:database});assert.equal(boot.unavailable,false);assert.equal(boot.migrationSessionData,undefined);assert.equal(app.getPath('userData'),dirname(database));
 await app.whenReady();
 const {VaultBackendHost}=await import(${moduleURL('vault-host')}),{VaultBackendClient}=await import(${moduleURL('vault-client')}),{registerVaultUnprotectedIpc}=await import(${moduleURL('vault-unprotected-ipc')});
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath:database,userDataPath:dirname(database)}),()=>true);
 const handlers=new Map(),parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});await parent.loadURL('data:text/html,<html>Default</html>');let active=0,holds=0,restarts=0,quiesced=false;
 const event={sender:parent.webContents,senderFrame:parent.webContents.mainFrame};
 registerVaultUnprotectedIpc({ipc:{handle:(name,fn)=>handlers.set(name,fn)},host,trusted:e=>e.sender===parent.webContents&&!parent.isDestroyed(),parent:()=>parent,requireAccess:()=>assert.equal(active,1),canStart:()=>true,hold:()=>{holds++;return()=>holds--;},quiesce:async(_parent,retain)=>{assert.equal(retain,false);await host.stop();quiesced=true;return true;},activate:()=>active++,retire:async()=>{active=0;},restartUpgrade:()=>{assert.equal(quiesced,true);restarts++;},fatal:()=>{throw Error('unexpected cleanup failure');}});
 try{
  const startup=await host.startup();assert.ok(startup.unprotected);assert.equal(await handlers.get('vault:unprotected-open')(event),true);assert.equal(host.unlockedWorkspaceId,startup.unprotected.vaultId);assert.equal(active,1);assert.deepEqual(await handlers.get('vault:protection')(event),{protected:false});await host.workspace();
  const before=readFileSync(database),slots=readFileSync(database+'.slots');assert.equal(await handlers.get('vault:prepare-unprotected')(event),true);assert.equal(restarts,1);assert.equal(holds,1);assert.equal(host.hasOwner,false);assert.equal(host.unlockedWorkspaceId,undefined);assert.deepEqual(readFileSync(database),before);assert.deepEqual(readFileSync(database+'.slots'),slots);assert.equal(existsSync(database+'.root-rotation'),false);
  console.log('default-native: ordinary OS owner authenticated unprotected state retired before isolated restart');
 }finally{await host.stop();parent.destroy();}app.quit();
})().catch(error=>{console.error(error);app.exit(1)});`,
  );
  await run(process.execPath, ['--check', harness], { windowsHide: true });
  const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
  const result = await run(require('electron'), [harness], {
    env,
    windowsHide: true,
    timeout: 60_000,
  });
  assert.match(result.stdout, /default-native: ordinary OS owner/);
  return result;
}

// Called only with the Windows cross-process DPAPI fixture. Random recovery
// material never leaves its dedicated protected renderer or enters artifacts.
export async function prepareUnprotectedSourceInElectron(
  root: string,
  directory: string,
  database: string,
  executable: string,
) {
  const moduleURL = (name: string) =>
    JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
  const harness = join(directory, 'upgrade-main.cjs');
  await writeFile(
    harness,
    `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
const {dirname,join}=require('node:path'),{readFileSync,existsSync}=require('node:fs');
const database=${JSON.stringify(database)},executable=${JSON.stringify(executable)};
app.setPath('userData',dirname(database));app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
(async()=>{
 const {prepareVaultMigrationBoot}=await import(${moduleURL('vault-migration-boot')});
 const boot=prepareVaultMigrationBoot({app,executable:()=>executable,databasePath:database,prepareProtection:true});
 assert.equal(boot.unavailable,false);assert.ok(boot.migrationSessionData);assert.notEqual(app.getPath('userData'),dirname(database));
 await app.whenReady();
 const {VaultBackendHost}=await import(${moduleURL('vault-host')}),{VaultBackendClient}=await import(${moduleURL('vault-client')});
 const {VaultMigrationSetupDialog}=await import(${moduleURL('vault-migration-setup-dialog')}),{registerVaultUpgradeIpc}=await import(${moduleURL('vault-upgrade-ipc')});
 let activated=0,child,handler,restarts=0,holds=0;
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath:database,userDataPath:dirname(database),migrationSessionData:boot.migrationSessionData}),()=>true,()=>activated++);
 const initial=await host.startup();assert.ok(initial.upgrade);assert.equal(initial.slots,null);assert.equal(host.unlockedWorkspaceId,undefined);
 const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});await parent.loadURL('data:text/html,<html>ownerless</html>');
 const dialog=new VaultMigrationSetupDialog({host,ipc:ipcMain,mode:'upgrade',createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-create.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-upgrade-preload.cjs'))}});
 const evaluate=code=>child.webContents.executeJavaScript(code),until=async code=>{for(let i=0;i<600;i++){if(child&&!child.isDestroyed()&&await evaluate(code))return;await new Promise(r=>setTimeout(r,20));}throw Error('OS upgrade window timed out');};
 const display=async()=>{
  await until('document.querySelectorAll("input").length===2');assert.equal(await evaluate('typeof window.wormhole'),'undefined');assert.ok(child.isContentProtected());
  await evaluate('(()=>{const fields=document.querySelectorAll("input");fields[0].value=fields[1].value="new native transition password";fields[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
  await until('document.querySelector("h1").textContent==="Save your recovery code"');
 };
 const before=readFileSync(database),slots=readFileSync(database+'.slots');
 try {
  for(const mode of ['cancel','navigation']){
   await host.startup();const pending=dialog.open(parent,()=>true);await display();
   assert.deepEqual(readFileSync(database),before);assert.deepEqual(readFileSync(database+'.slots'),slots);assert.equal(existsSync(database+'.root-rotation'),false);
   if(mode==='cancel')await evaluate('document.querySelector(".startup-button-secondary").click()').catch(()=>{});else await parent.loadURL('data:text/html,<html>navigated</html>');
   assert.equal(await pending,false);assert.equal(host.unlockedWorkspaceId,undefined);
  }
  registerVaultUpgradeIpc({ipc:{handle:(channel,fn)=>{assert.equal(channel,'vault:upgrade-protection');handler=fn}},host,dialog,parent:()=>parent,trusted:e=>e.sender===parent.webContents&&!parent.isDestroyed(),quiesced:()=>!!boot.migrationSessionData,hold:()=>{holds++;return()=>holds--;},restart:()=>{restarts++;},fatal:()=>{throw Error('unexpected fatal cleanup');}});
  const pending=handler({sender:parent.webContents,senderFrame:parent.webContents.mainFrame});await display();
  await evaluate('window.testRecovery=document.querySelector("pre").textContent;document.querySelectorAll("button")[1].click()');
  await until('document.querySelector("h1").textContent==="Confirm your recovery code"');
  assert.equal(await evaluate('document.querySelector("pre").textContent'),'');
  await evaluate('(()=>{const fields=document.querySelectorAll("input");fields[0].value=fields[1].value="!!!!!";fields[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
  await until('document.querySelector("p[role=status]").textContent.startsWith("Those groups")');assert.deepEqual(readFileSync(database),before);assert.equal(existsSync(database+'.root-rotation'),false);
  await evaluate('(()=>{const groups=Array.from(document.querySelectorAll("label span")).map(e=>e.textContent).filter(s=>s.startsWith("Group ")).map(s=>Number(s.slice(6))),parts=window.testRecovery.slice(7).split("-"),fields=document.querySelectorAll("input");fields[0].value=parts[groups[0]-1];fields[1].value=parts[groups[1]-1];delete window.testRecovery;fields[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()').catch(()=>{});
  assert.equal(await pending,true);assert.equal(restarts,1);assert.equal(holds,1);assert.equal(activated,0);assert.equal(host.unlockedWorkspaceId,undefined);assert.equal(host.hasOwner,false);assert.ok(child.isDestroyed());assert.ok(existsSync(database+'.root-rotation'));
  console.log('upgrade-native: isolated ownerless enrollment cancel navigation wrong-groups prepared restart');
 }finally{await dialog.cancel();await host.stop();parent.destroy();}
 app.quit();
})().catch(error=>{console.error(error);app.exit(1)});
`,
  );
  await run(process.execPath, ['--check', harness], { windowsHide: true });
  const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
  const result = await run(require('electron'), [harness], {
    env,
    windowsHide: true,
    timeout: 100_000,
  });
  assert.match(result.stdout, /upgrade-native: isolated ownerless/);
  return result;
}
