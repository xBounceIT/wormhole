import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile),
  require = createRequire(import.meta.url);
test(
  'real isolated windows enroll replacement factors, export the encrypted vault and restore it through protected recovery',
  { timeout: 240_000 },
  async (t) => {
    const root = fileURLToPath(new URL('../', import.meta.url)),
      directory = await mkdtemp(join(tmpdir(), 'wormhole-root-setup-'));
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    try {
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
      await run(process.execPath, [join(root, 'node_modules/vite/bin/vite.js'), 'build'], {
        cwd: root,
        windowsHide: true,
      });
      const moduleURL = (name: string) =>
        JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
      const harness = join(directory, 'main.cjs');
      await writeFile(
        harness,
        `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
const {mkdirSync,readFileSync,existsSync,mkdtempSync}=require('node:fs'),{join}=require('node:path');
const executable=${JSON.stringify(executable)},directory=${JSON.stringify(directory)};
app.setPath('userData',directory);app.setPath('sessionData',directory);app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
app.whenReady().then(async()=>{
 const {VaultCreateDialog}=await import(${moduleURL('vault-create-dialog')});
 const {VaultMigrationSetupDialog}=await import(${moduleURL('vault-migration-setup-dialog')});
 const {VaultBackendHost}=await import(${moduleURL('vault-host')});
 const {VaultBackendClient}=await import(${moduleURL('vault-client')});
 const {registerVaultProtectionIpc}=await import(${moduleURL('vault-protection-ipc')});
 const {registerVaultLocalBackupIpc}=await import(${moduleURL('vault-local-backup-ipc')});
 const {VaultReauthenticationDialog}=await import(${moduleURL('vault-reauth-dialog')});
 const {selectVaultNativePaths}=await import(${moduleURL('vault-native-paths')});
 for(const mode of ['prepared','encrypted','cancelled','navigation']){
  const encrypt=mode==='encrypted';let restarts=0;
  const data=join(directory,mode);mkdirSync(data);const databasePath=join(data,'workspace.db');
  const host=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath,userDataPath:data}),()=>true);
  const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true,...(encrypt?{preload:${JSON.stringify(join(root, 'dist-electron/preload.cjs'))}}:{})}});await parent.loadURL('data:text/html,<html></html>');let child;
  const options={host,ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist/vault-create.html')).href)}};
  const create=new VaultCreateDialog({...options,activate:()=>{},preload:${JSON.stringify(join(root, 'dist-electron/vault-create-preload.cjs'))}});
  const rotation=new VaultMigrationSetupDialog({...options,mode:'rotation',preload:${JSON.stringify(join(root, 'dist-electron/vault-root-setup-preload.cjs'))}});
  if(encrypt)registerVaultProtectionIpc({
   ipc:ipcMain,host,dialog:rotation,rootDialog:rotation,allowDatabaseEncryption:true,
   trusted:event=>event.sender===parent.webContents&&event.senderFrame===parent.webContents.mainFrame,
   parent:()=>parent,requireAccess:()=>assert.ok(host.unlockedWorkspaceId),canStart:()=>true,hold:()=>()=>{},
   quiesce:async(window,retainOwner)=>{assert.equal(window,parent);assert.equal(retainOwner,true);return true;},
   restart:()=>{assert.equal(host.unlockedWorkspaceId,undefined);restarts++;},fatal:()=>{throw Error('unexpected native shutdown');},
  });
  const evaluate=code=>child.webContents.executeJavaScript(code),until=async code=>{for(let i=0;i<600;i++){if(child.isDestroyed())throw Error('window closed early');if(await evaluate(code))return;await new Promise(r=>setTimeout(r,20));}throw Error('protected screen timed out');};
  // The test controls only the two dedicated protected renderers. Random root
  // material stays in Go, and no recovery code is written to an artifact.
  const display=async rotating=>{
   await until('document.querySelectorAll("input").length==='+ (rotating?'3':'2'));
   assert.equal(await evaluate('typeof window.wormhole'),'undefined');
   assert.ok(child.webContents.getLastWebPreferences().sandbox);if(process.platform!=='linux')assert.ok(child.isContentProtected());
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");'+(rotating?'inputs[0].value="original native fixture";':'')+'inputs[inputs.length-2].value=inputs[inputs.length-1].value="'+(rotating?'replacement native fixture':'original native fixture')+'";inputs[inputs.length-1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
   await until('document.querySelector("h1").textContent==="Save your recovery code"');
  };
  const confirm=async()=>{
   // Retain and select groups inside the protected renderer only.
   await evaluate('window.testRecovery=document.querySelector("pre").textContent;document.querySelectorAll("button")[1].click()');
   await until('document.querySelector("h1").textContent==="Confirm your recovery code"');
   assert.equal(await evaluate('document.querySelector("pre").textContent'),'');
   await evaluate('(()=>{const groups=Array.from(document.querySelectorAll("label span")).map(e=>e.textContent).filter(s=>s.startsWith("Group ")).map(s=>Number(s.slice(6)));const parts=window.testRecovery.slice(7).split("-"),inputs=document.querySelectorAll("input");inputs[inputs.length-2].value=parts[groups[0]-1];inputs[inputs.length-1].value=parts[groups[1]-1];delete window.testRecovery;inputs[inputs.length-1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()').catch(()=>{});
  };
  let resumed,restoring,restarted,reauth,testCode;
  try{
   const creating=create.open(parent,()=>true);await display(false);await confirm();assert.equal(await creating,true);
   const vaultId=host.unlockedWorkspaceId;assert.ok(vaultId);const before=readFileSync(databasePath),slots=readFileSync(databasePath+'.slots');
   const previous=child;
   if(encrypt)assert.equal(await parent.webContents.executeJavaScript('window.wormhole.databaseEncryptionAvailable()'),true);
   const updating=encrypt?parent.webContents.executeJavaScript('window.wormhole.encryptVaultDatabase()'):rotation.open(parent,()=>true);
   if(encrypt){
    for(let i=0;i<600&&child===previous;i++)await new Promise(r=>setTimeout(r,20));
    assert.notEqual(child,previous);
    await until('document.querySelector("h1")?.textContent==="Encrypt the vault database"');
   }
   await display(true);
   if(encrypt)testCode=Buffer.from(await evaluate('document.querySelector("pre").textContent'),'ascii');
   assert.deepEqual(readFileSync(databasePath),before);assert.deepEqual(readFileSync(databasePath+'.slots'),slots);assert.ok(!existsSync(databasePath+'.root-rotation'));
   if(mode!=='prepared'&&!encrypt){
    if(mode==='navigation')await parent.loadURL('data:text/html,<html>changed</html>');else await evaluate('document.querySelector(".startup-button-secondary").click()').catch(()=>{});
    assert.equal(await updating,false);assert.ok(child.isDestroyed());assert.deepEqual(readFileSync(databasePath+'.slots'),slots);assert.ok(!existsSync(databasePath+'.root-rotation'));assert.equal(host.unlockedWorkspaceId,undefined);continue;
   }
   await confirm();assert.equal(await updating,true);assert.ok(child.isDestroyed());assert.equal(host.unlockedWorkspaceId,undefined);assert.ok(existsSync(databasePath+'.root-rotation'));
   if(encrypt)assert.equal(restarts,1);
   const migrationSessionData=mkdtempSync(join(directory,'.wormhole-vault-migration-'));
   resumed=new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath,userDataPath:data,migrationSessionData}),()=>true);
   const startup=await resumed.startup();assert.equal(startup.rotation.pending,true);assert.equal(startup.slots.encrypted,encrypt);const slot=startup.slots.slots.find(s=>s.kind==='password');
   await resumed.resumeRootRotation({vaultId,slotId:slot.id,kind:'password',factor:new TextEncoder().encode('replacement native fixture')});
   const stored=JSON.parse(readFileSync(databasePath+'.slots'));
   assert.equal(resumed.unlockedWorkspaceId,vaultId);assert.equal(stored.rootKeyVersion,2);assert.equal(stored.encrypted,encrypt);assert.ok(!existsSync(databasePath+'.root-rotation'));
   assert.equal(readFileSync(databasePath).subarray(0,15).toString()==='SQLite format 3',!encrypt);
   if(encrypt){
    const file=join(directory,'native.whvault');
    const backupChannels=['vault:local-backup-available','vault:local-backup-export','vault:local-backup-restore'];
    const common={ipc:ipcMain,parent:()=>parent,pickExport:async()=>file,pickRestore:async()=>file,
     trusted:event=>event.sender===parent.webContents&&event.senderFrame===parent.webContents.mainFrame};
    registerVaultLocalBackupIpc({...common,host:resumed,
     authenticate:()=>async()=>{throw Error('Default export unexpectedly requested authentication');},
     restart:async()=>{throw Error('Export unexpectedly requested restart');}});
    try{
     assert.equal(await parent.webContents.executeJavaScript('window.wormhole.localVaultBackupAvailable()'),true);
     assert.equal(await parent.webContents.executeJavaScript('window.wormhole.exportLocalVaultBackup()'),true);
     const archive=readFileSync(file);
     assert.equal(archive.subarray(0,8).toString(),'WHVLBK01');
     assert.deepEqual(archive.subarray(20,20+archive.readUInt32BE(8)),readFileSync(databasePath+'.slots'));
     await assert.rejects(parent.webContents.executeJavaScript('window.wormhole.exportLocalVaultBackup()'));
     assert.deepEqual(readFileSync(file),archive);
    }finally{for(const channel of backupChannels)ipcMain.removeHandler(channel);}
    const recoveredData=join(directory,'fresh-install');mkdirSync(recoveredData);
    const requestedDatabase=join(recoveredData,'workspace.db');
    const makeHost=databasePath=>new VaultBackendHost(()=>new VaultBackendClient({executable,databasePath,userDataPath:recoveredData}),()=>true);
    restoring=makeHost(requestedDatabase);
    reauth=new VaultReauthenticationDialog({...options,stop:()=>restoring.stop(),url:${JSON.stringify(pathToFileURL(join(root, 'dist/vault-reauth.html')).href)},
     preload:${JSON.stringify(join(root, 'dist-electron/vault-reauth-preload.cjs'))}});
    let didRestart=false;
    registerVaultLocalBackupIpc({...common,host:restoring,
     authenticate:(window,accepted)=>(operation,descriptor,submit)=>reauth.open(window,accepted,operation,descriptor,submit),
     restart:async()=>{await restoring.stop();didRestart=true;}});
    try{
     const recoveryWindowBefore=child;
     const restoringVault=parent.webContents.executeJavaScript('window.wormhole.restoreLocalVaultBackup()');
     let restoreError;void restoringVault.catch(error=>{restoreError=error;});
     for(let i=0;i<600&&child===recoveryWindowBefore;i++){if(restoreError)throw restoreError;await new Promise(r=>setTimeout(r,20));}
     assert.notEqual(child,recoveryWindowBefore);
     await until('document.querySelector("select")?.options.length===1 && !document.querySelector("button[type=submit]").disabled');
     assert.equal(await evaluate('typeof window.wormhole'),'undefined');
     assert.equal(await evaluate('document.querySelector("select").selectedOptions[0].textContent'),'Recovery key');
     assert.equal(existsSync(requestedDatabase+'.restored'),false);
     await evaluate('(()=>{document.querySelector("input").value=String.fromCharCode(...'+JSON.stringify([...testCode])+');document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
     testCode.fill(0);
     assert.equal(await restoringVault,true);
     assert.equal(didRestart,true);
     const next=selectVaultNativePaths(recoveredData,{WORMHOLE_DATABASE:requestedDatabase});
     assert.equal(next.databasePath,join(requestedDatabase+'.restored','wormhole.db'));
     assert.equal(existsSync(requestedDatabase),false);
     restarted=makeHost(next.databasePath);
     const recovered=await restarted.startup();
     assert.equal(recovered.slots.vaultId,vaultId);assert.equal(recovered.slots.encrypted,true);
     const restoredSlot=recovered.slots.slots.find(candidate=>candidate.kind==='password');
     await restarted.unlock({vaultId,slotId:restoredSlot.id,kind:'password',factor:new TextEncoder().encode('replacement native fixture')});
     assert.equal(restarted.unlockedWorkspaceId,vaultId);
    }finally{for(const channel of backupChannels)ipcMain.removeHandler(channel);}
   }
  }finally{testCode?.fill(0);await reauth?.cancel();await restarted?.stop();await restoring?.stop();await create.cancel();await rotation.cancel();await host.stop();await resumed?.stop();if(!parent.isDestroyed())parent.destroy();for(const [prefix,names] of [['vault-enrollment',['begin','confirm','cancel']],['vault-rotation-setup',['context','begin','confirm','cancel']]])for(const name of names)ipcMain.removeHandler(prefix+':'+name);if(encrypt)for(const channel of ['vault:protect-existing','vault:database-encryption-available','vault:encrypt-database','vault-reauth:context','vault-reauth:submit','vault-reauth:cancel'])ipcMain.removeHandler(channel);}
 }
 console.log('vault-root-enrollment-native: prepared encrypted cancelled navigation resumed');app.quit();
}).catch(error=>{console.error(error);app.exit(1)});
`,
      );
      await run(process.execPath, ['--check', harness], { windowsHide: true });
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      const { stdout, stderr } = await run(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
        { env, windowsHide: true, timeout: 120_000 },
      );
      assert.match(
        stdout,
        /vault-root-enrollment-native: prepared encrypted cancelled navigation resumed/,
      );
      if (stdout.trim()) t.diagnostic(stdout.trim());
      if (stderr.trim()) t.diagnostic(stderr.trim());
    } finally {
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-root-setup-')));
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  },
);
