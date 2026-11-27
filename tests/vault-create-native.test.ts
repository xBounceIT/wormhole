import { connectionInput } from './fixtures/vault-connection.ts';
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
  'isolated Electron dialog creates a real native vault and cancellation publishes nothing',
  { timeout: 180_000 },
  async (t) => {
    const root = fileURLToPath(new URL('../', import.meta.url)),
      directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-create-'));
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    try {
      await run('go', ['build', '-o', executable, '.'], {
        cwd: join(root, 'tools', 'wormhole-backend'),
        windowsHide: true,
        timeout: 120_000,
      });
      // Keep the entrypoint and sandboxed preload identical to the packaged build.
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
const {app,BrowserWindow,ipcMain}=require('electron');
const assert=require('node:assert/strict');const {existsSync,writeFileSync}=require('node:fs');const {join}=require('node:path');
app.setPath('userData',${JSON.stringify(directory)});
app.setPath('sessionData',${JSON.stringify(directory)});
app.disableHardwareAcceleration();
app.on('window-all-closed',()=>{});
app.whenReady().then(async()=>{
 const {VaultCreateDialog}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-create-dialog.js')).href)});
 const {VaultBackendHost}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-host.js')).href)});
 const {VaultBackendClient}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-client.js')).href)});
 for(const mode of ['created','cancelled']) {
  const path=join(${JSON.stringify(directory)},mode,'workspace.db');
  const host=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(executable)},databasePath:path}),()=>true);
  const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});await parent.loadURL('data:text/html,<html></html>');
  let child,activated=0;
  const controller=new VaultCreateDialog({host,ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-create.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-create-preload.cjs'))},activate:()=>activated++});
  const result=controller.open(parent,()=>true);
  const evaluate=code=>child.webContents.executeJavaScript(code);
  const until=async code=>{for(let i=0;i<600;i++){if(child.isDestroyed())throw Error('dialog closed early');if(await evaluate(code))return;await new Promise(r=>setTimeout(r,20));}throw Error('dialog did not reach expected state');};
  try {
   await until('document.querySelectorAll("input").length === 2');
   assert.equal(await evaluate('getComputedStyle(document.querySelectorAll("button")[1]).display'),'none');
   assert.equal(child.webContents.getLastWebPreferences().sandbox,true);if(process.platform!=='linux')assert.equal(child.isContentProtected(),true);
   assert.equal(await evaluate('window.vaultCreate.contentProtectionAvailable'),process.platform!=='linux');
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");inputs[0].value="dialog-password-fixture";inputs[1].value="different";inputs[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
   await until('document.querySelector("[role=status]").textContent.includes("do not match")');assert.equal(existsSync(path),false);
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");inputs[0].value=inputs[1].value="dialog-password-fixture";inputs[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()');
   await until('document.querySelector("h1").textContent === "Save your recovery code"');
   assert.equal(await evaluate('getComputedStyle(document.querySelector("form")).display'),'none');
   const code=await evaluate('document.querySelector("pre").textContent');assert.equal(code.length,76);assert.equal(existsSync(path),false);assert.equal(existsSync(path+".slots"),false);
   assert.equal(await evaluate('typeof window.wormhole'), 'undefined');
   if(process.env.WORMHOLE_VAULT_CREATE_SCREENSHOT && mode==='created')writeFileSync(process.env.WORMHOLE_VAULT_CREATE_SCREENSHOT,(await child.webContents.capturePage()).toPNG());
   if(mode==='cancelled'){await evaluate('document.querySelector(".startup-button-secondary").click()').catch(()=>{});assert.equal(await result,false);assert.equal(existsSync(path),false);continue;}
   await evaluate('document.querySelectorAll("button")[1].click()');
   await until('document.querySelector("h1").textContent === "Confirm your recovery code"');
   assert.equal(await evaluate('document.querySelector("pre").textContent'),'');
   const groups=await evaluate('Array.from(document.querySelectorAll("label span")).map(e=>Number(e.textContent.split(" ")[1]))');
   const parts=code.slice(7).split('-');
   await evaluate('(()=>{const inputs=document.querySelectorAll("input");inputs[0].value='+JSON.stringify(parts[groups[0]-1])+';inputs[1].value='+JSON.stringify(parts[groups[1]-1])+';inputs[1].dispatchEvent(new Event("input"));document.querySelector("form").dispatchEvent(new SubmitEvent("submit",{cancelable:true}));})()').catch(()=>{});
   assert.equal(await result,true);assert.equal(activated,1);assert.equal(existsSync(path),true);assert.equal((await host.workspace()).tree.length,0);
   const {VaultNotesDialog}=await import(${JSON.stringify(pathToFileURL(join(root, 'dist-electron', 'vault-notes-dialog.js')).href)});
   const input=${JSON.stringify(connectionInput())}; input.metadata.id='';input.rowVersion='0';input.metadata.inlinePasswordAction='clear';input.password=new Uint8Array();input.notesAction='set';
   const plaintext='<script>literal</script>'+String.fromCharCode(10)+ '界'.repeat(16350); input.notes=new TextEncoder().encode(plaintext);
   const saved=await host.saveConnection(input);
   let noteWindow;
   const display=new VaultNotesDialog({host,ipc:ipcMain,createWindow:options=>{noteWindow=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});noteWindow.show=()=>{};noteWindow.webContents.on('console-message',details=>{if(details.level==='error')console.error('notes renderer: '+details.message);});return noteWindow;},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-notes.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-notes-preload.cjs'))}});
   try {
    for (const stale of [false,true]) {
     const displayed=display.open(parent,()=>true,{nodeId:saved.nodeId,rowVersion:stale?'2':saved.rowVersion});
     for(let i=0;i<600;i++) {
      const ready=await noteWindow.webContents.executeJavaScript(stale?'document.querySelector("[role=status]")?.textContent.includes("unavailable")':'document.querySelector("pre")?.hidden === false');
      if(ready)break;if(i===599)throw Error('notes display timed out: '+await noteWindow.webContents.executeJavaScript('document.querySelector("[role=status]")?.textContent')); await new Promise(r=>setTimeout(r,20));
     }
     assert.equal(await noteWindow.webContents.executeJavaScript('typeof window.wormhole'),'undefined');
     assert.equal(await noteWindow.webContents.executeJavaScript('document.querySelector("pre").textContent'),stale?'':plaintext);
     assert.equal(noteWindow.webContents.getLastWebPreferences().sandbox,true);
     assert.equal(await noteWindow.webContents.executeJavaScript('getComputedStyle(document.querySelector("pre")).userSelect'),'none');
     if(process.platform!=='linux')assert.equal(noteWindow.isContentProtected(),true);
     display.cancel();await displayed;assert.equal(noteWindow.isDestroyed(),true);
    }
   } finally {display.cancel();for(const channel of ['context','read','close'])ipcMain.removeHandler('vault-notes:'+channel);}

  } finally {await controller.cancel();await host.stop();if(!parent.isDestroyed())parent.destroy();for(const channel of ['begin','confirm','cancel'])ipcMain.removeHandler('vault-enrollment:'+channel);}
 }
 console.log('vault-create-native: created and cancelled verified');
 app.quit();
}).catch(error=>{console.error(error);app.exit(1);});
`,
      );
      await run(process.execPath, ['--check', harness], { windowsHide: true });
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string;
      const headless = process.platform === 'linux' && !env.DISPLAY;
      const { stdout, stderr } = await run(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
        { env, windowsHide: true, timeout: 90_000 },
      );
      assert.match(stdout, /vault-create-native: created and cancelled verified/);
      if (stdout.trim()) t.diagnostic(stdout.trim());
      if (stderr.trim()) t.diagnostic(stderr.trim());
    } finally {
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-vault-create-')));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
