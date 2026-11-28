import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);
test('credentials screen clears plaintext and rejects late asynchronous completion', async (t) => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-credentials-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-credentials-screen-'));
  try {
    const renderer = `
let generated,opened,mode='normal',releaseGenerate,releaseOpen;
const context={workspaceId:'w',nodeId:'n',requestId:'r',rowVersion:'1'};
function parseVaultClipboardResult(value){return value?.expiresInSeconds===20||value?.expiresInSeconds===30?value:undefined;}
function parseVaultNotesContext(value){return value===context?value:undefined;}
function decodeCredentialDisplay(bytes){if(mode==='decode-error')throw Error('private');if(bytes[0]!==7)throw Error('premature erasure');return {username:'<script>literal</script>',domain:mode==='empty'?'':'CORP',secret:mode==='empty'?'':'sensitive',label:mode==='empty'?'Passphrase':'Password'};}
async function createCredentialsRecipient(){
 if(mode==='generate-error')throw Error('private');
 if(mode==='generate-late')await new Promise(resolve=>releaseGenerate=resolve);
 generated={disposed:false,publicKey:'public',dispose(){this.disposed=true;},async open(){if(mode==='open-error')throw Error('private');if(mode==='open-late')await new Promise(resolve=>releaseOpen=resolve);opened=new Uint8Array([7,8]);return opened;}};return generated;
}
${source}
(async()=>{
 const check=(ok,message)=>{if(!ok)throw Error(message);};const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
 function setup(overrides={}) {const card=document.createElement('section');document.body.append(card);let closed=0;
 const dispose=mountVaultCredentialsScreen(card,{copyAvailable:false,copy:async()=>({expiresInSeconds:30}),contentProtectionAvailable:true,context:async()=>context,read:async()=>({}),close:async()=>{closed++;},...overrides});return {card,dispose,get closed(){return closed;},remove(){dispose();card.remove();}};}
 for(const value of ['normal','empty','generate-error','open-error','decode-error']){mode=value;const v=setup();await tick();await tick();const fields=v.card.querySelector('dl'),status=v.card.querySelector('[role=status]');
 if(value.endsWith('error')){check(fields.hidden&&status.textContent.includes('unavailable')&&!status.textContent.includes('private'),'error disclosure');}else{check(!fields.hidden&&fields.textContent.includes('<script>literal</script>'),'literal identity');check(fields.textContent.includes(value==='empty'?'No stored secret.':'sensitive'),'secret');check(!fields.querySelector('script'),'HTML interpreted');check(opened.every(x=>x===0),'plaintext bytes retained');}
 for(const eventName of ['copy','cut']){const event=new Event(eventName,{cancelable:true,bubbles:true});fields.dispatchEvent(event);check(event.defaultPrevented,'clipboard copy allowed');}
 v.card.querySelector('button').click();await tick();check(fields.textContent===''&&v.closed===1,'close retained credentials');v.remove();}
 mode='normal';for(const overrides of [{context:async()=>null},{context:async()=>{throw Error('private');}},{read:async()=>{throw Error('private');}},{contentProtectionAvailable:false}]){const v=setup(overrides);await tick();await tick();if(overrides.contentProtectionAvailable===false)check(v.card.textContent.includes('unavailable on Linux'),'capture notice');else check(v.card.querySelector('[role=status]').textContent.includes('unavailable'),'request failure');v.remove();}
 for(const phase of ['context','generate-late','read','open-late']){mode=phase;let release;const overrides=phase==='context'?{context:()=>new Promise(resolve=>release=resolve)}:phase==='read'?{read:()=>new Promise(resolve=>release=resolve)}:{};const v=setup(overrides);await tick();v.dispose();if(phase==='context')release(context);else if(phase==='read')release({});else if(phase==='generate-late')releaseGenerate();else releaseOpen();await tick();check(v.card.querySelector('dl').textContent===''&&v.card.querySelector('dl').hidden,'late display');if(phase==='open-late')check(opened.every(x=>x===0),'late plaintext retained');v.remove();}
 mode='normal';for(const result of [{expiresInSeconds:20},{expiresInSeconds:30},null,'reject']){let calls=0,selected;const v=setup({copyAvailable:true,copy:async field=>{calls++;selected=field;if(result==='reject')throw Error('private');return result;}});await tick();const buttons=[...v.card.querySelectorAll('dd button')];check(buttons.length===3,'copy controls');for(let i=0;i<3;i++){buttons[i].click();await tick();check(selected===['username','domain','secret'][i],'only field identifier may cross bridge');}check(calls===3,'copy count');const status=v.card.querySelector('[role=status]').textContent;check(result?.expiresInSeconds?status.includes(String(result.expiresInSeconds)):status.includes('unavailable')&&!status.includes('private'),'copy result');v.remove();}
 mode='empty';const emptyCopy=setup({copyAvailable:true});await tick();check(emptyCopy.card.querySelectorAll('dd button').length===1,'empty field copy');emptyCopy.remove();
 mode='normal';for(const rejected of [false,true]){let release,calls=0;const v=setup({copyAvailable:true,copy:()=>{calls++;return new Promise((resolve,reject)=>release=()=>rejected?reject(Error('private')):resolve({expiresInSeconds:30}));}});await tick();const buttons=[...v.card.querySelectorAll('dd button')];const click=buttons[0].onclick;click();click();check(calls===1&&buttons.every(b=>b.disabled),'concurrent copy');v.dispose();await click();release();await tick();check(buttons.every(b=>b.disabled)&&v.card.querySelector('dl').textContent==='','late copy revived content');v.remove();}
 mode='normal';const v=setup();await tick();window.dispatchEvent(new Event('pagehide'));check(v.card.querySelector('dl').textContent==='','pagehide retained credentials');v.remove();
 const rejected=setup({close:async()=>{throw Error('private');}});await tick();rejected.card.querySelector('button').click();await tick();rejected.remove();
})()
//# sourceURL=wormhole-vault-credentials-screen.js`;
    const preload = join(directory, 'credentials.cjs');
    writeFileSync(
      preload,
      stripTypeScriptTypes(
        readFileSync(new URL('../electron/vault-credentials-preload.cts', import.meta.url), 'utf8'),
      ).replace(
        "import { contextBridge, ipcRenderer } from 'electron';",
        "const {contextBridge,ipcRenderer}=require('electron');",
      ),
    );
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
const {app,BrowserWindow,ipcMain}=require('electron');const assert=require('node:assert/strict');
app.setPath('userData',${JSON.stringify(directory)});app.setPath('sessionData',${JSON.stringify(directory)});
app.whenReady().then(async()=>{let reads=0,closes=0;ipcMain.handle('vault-credentials:context',(_event,...args)=>{assert.equal(args.length,0);return {safe:true};});ipcMain.handle('vault-credentials:read',(_event,key)=>{assert.equal(key,'public');reads++;return {ciphertext:'opaque'};});ipcMain.handle('vault-credentials:copy',(_event,...args)=>{assert.deepEqual(args,['secret']);return {expiresInSeconds:30};});ipcMain.handle('vault-credentials:close',(_event,...args)=>{assert.equal(args.length,0);closes++;});const window=new BrowserWindow({show:false,webPreferences:{preload:${JSON.stringify(preload)},sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
try{await window.loadURL('data:text/html,<html><body></body></html>');const bridge=await window.webContents.executeJavaScript("(async()=>({keys:Object.keys(window.vaultCredentials).sort(),context:await window.vaultCredentials.context(),reply:await window.vaultCredentials.read('public'),copied:await window.vaultCredentials.copy('secret'),available:window.vaultCredentials.copyAvailable,closed:await window.vaultCredentials.close(),ordinary:typeof window.wormhole,node:typeof require}))()");assert.deepEqual(bridge.keys,['close','contentProtectionAvailable','context','copy','copyAvailable','read']);assert.deepEqual(bridge.copied,{expiresInSeconds:30});assert.equal(bridge.available,['win32','darwin','linux'].includes(process.platform));assert.deepEqual(bridge.context,{safe:true});assert.deepEqual(bridge.reply,{ciphertext:'opaque'});assert.equal(bridge.ordinary,'undefined');assert.equal(bridge.node,'undefined');assert.equal(reads,1);assert.equal(closes,1);const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-vault-credentials-screen.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='mountVaultCredentialsScreen');assert.ok(fn);const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const coverage=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Vault credentials screen: '+coverage.toFixed(2)+'% V8 blocks');assert.ok(coverage>=${coverageThreshold});
}finally{window.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
    );
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const electron = require('electron') as string;
    const headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 30_000, windowsHide: true },
    );
    assert.match(stdout, /Vault credentials screen:/);
    if (stdout.trim()) t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
