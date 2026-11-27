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
  'real protected migration dialog prepares intact source, cancels safely and erases display on parent navigation',
  { timeout: 180_000 },
  async (t) => {
    const root = fileURLToPath(new URL('../', import.meta.url)),
      directory = await mkdtemp(join(tmpdir(), 'wormhole-migration-dialog-'));
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    try {
      await run('go', ['build', '-o', executable, '.'], {
        cwd: join(root, 'tools', 'wormhole-backend'),
        windowsHide: true,
        timeout: 120_000,
      });
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
      const harness = join(directory, 'main.cjs');
      await writeFile(
        harness,
        `
const {app,BrowserWindow,ipcMain}=require('electron'),assert=require('node:assert/strict');
const {mkdirSync,readFileSync,readdirSync,existsSync}=require('node:fs'),{join}=require('node:path'),{execFileSync}=require('node:child_process');
app.setPath('userData',${JSON.stringify(directory)});app.setPath('sessionData',${JSON.stringify(directory)});app.disableHardwareAcceleration();app.on('window-all-closed',()=>{});
app.whenReady().then(async()=>{
 const {VaultMigrationSetupDialog}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-migration-setup-dialog.js')).href)});
 const {VaultBackendHost}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-host.js')).href)});
 const {VaultBackendClient}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-client.js')).href)});
 for(const mode of ['prepared','cancelled','navigation','context-error']){
  const data=join(${JSON.stringify(directory)},mode);mkdirSync(data);const database=join(data,'workspace.db');
  execFileSync(${JSON.stringify(executable)},['--operation','workspace','--database',database],{windowsHide:true,stdio:'pipe'});const before=readFileSync(database);
  const host=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(executable)},databasePath:database,userDataPath:data}),()=>true);
  const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});await parent.loadURL('data:text/html,<html></html>');let child;
  const dialog=new VaultMigrationSetupDialog({host,ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-create.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-migration-setup-preload.cjs'))}});
  if(mode==='context-error')host.migrationSetupContext=async()=>{throw Error('private native context diagnostic');};
  const result=dialog.open(parent,()=>true),evaluate=code=>child.webContents.executeJavaScript(code);
  const until=async code=>{for(let i=0;i<600;i++){if(child.isDestroyed())throw Error('dialog closed early');if(await evaluate(code))return;await new Promise(r=>setTimeout(r,20));}throw Error('migration screen did not advance');};
  try{
   if(mode==='context-error'){await until('document.querySelector("p")?.textContent.includes("Existing authentication is unavailable")');assert.equal(await evaluate('document.body.textContent.includes("private")'),false);assert.equal(await evaluate('document.querySelectorAll("input").length'),0);await evaluate('document.querySelector("button").click()').catch(()=>{});assert.equal(await result,false);assert.deepEqual(readFileSync(database),before);continue;}
   await until('document.querySelectorAll("input").length===3');
   assert.equal(await evaluate('typeof window.wormhole'),'undefined');assert.equal(await evaluate('document.querySelector("select").value'),'none');
   assert.equal(child.webContents.getLastWebPreferences().sandbox,true);if(process.platform!=='linux')assert.ok(child.isContentProtected());
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");inputs[1].value=inputs[2].value="public-dialog-fixture";inputs[2].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
   await until('document.querySelector("h1").textContent==="Save your recovery code"');
   assert.deepEqual(readFileSync(database),before);assert.ok(!existsSync(database+'.slots'));assert.ok(!readdirSync(data).some(n=>n.endsWith('.setup')));
   const code=await evaluate('document.querySelector("pre").textContent');assert.equal(code.length,76);
   if(mode!=='prepared'){
    if(mode==='navigation')await parent.loadURL('data:text/html,<html>changed</html>');else await evaluate('document.querySelector(".startup-button-secondary").click()').catch(()=>{});
    assert.equal(await result,false);assert.deepEqual(readFileSync(database),before);assert.ok(!readdirSync(data).some(n=>n.endsWith('.setup')));assert.ok(child.isDestroyed());continue;
   }
   await evaluate('document.querySelectorAll("button")[1].click()');await until('document.querySelector("h1").textContent==="Confirm your recovery code"');
   assert.equal(await evaluate('document.querySelector("pre").textContent'),'');assert.equal(await evaluate('document.querySelector("button[type=submit]").textContent'),'Prepare and restart');
   const groups=await evaluate('Array.from(document.querySelectorAll("label span")).map(e=>e.textContent).filter(s=>s.startsWith("Group ")).map(s=>Number(s.slice(6)))');
   const parts=code.slice(7).split('-');
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");inputs[1].value='+JSON.stringify(parts[groups[0]-1])+';inputs[2].value='+JSON.stringify(parts[groups[1]-1])+';inputs[2].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()').catch(()=>{});
   assert.equal(await result,true);assert.deepEqual(readFileSync(database),before);assert.equal(host.unlockedWorkspaceId,undefined);assert.ok(!existsSync(database+'.slots'));
   const capsules=readdirSync(data).filter(n=>n.endsWith('.setup'));assert.equal(capsules.length,1);const capsule=readFileSync(join(data,capsules[0]));assert.ok(!capsule.includes(Buffer.from(code))&&!capsule.includes(Buffer.from('public-dialog-fixture')));
   assert.equal((await host.startup()).migration.pending,true);
  }finally{await dialog.cancel();await host.stop();parent.destroy();for(const name of ['context','begin','confirm','cancel'])ipcMain.removeHandler('vault-migration-setup:'+name);}
 }
 console.log('vault-migration-dialog-native: prepare cancel navigation verified');app.quit();
}).catch(error=>{console.error(error);app.exit(1);});
`,
      );
      await run(process.execPath, ['--check', harness], { windowsHide: true });
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      const { stdout, stderr } = await run(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
        { env, windowsHide: true, timeout: 90_000 },
      );
      assert.match(stdout, /vault-migration-dialog-native: prepare cancel navigation verified/);
      if (stdout.trim()) t.diagnostic(stdout.trim());
      if (stderr.trim()) t.diagnostic(stderr.trim());
    } finally {
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-migration-dialog-')));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
