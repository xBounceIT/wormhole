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
test('notes screen displays literal text, clears on close and rejects late asynchronous completion', async (t) => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-notes-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-notes-screen-'));
  try {
    const renderer = `

let generated,opened,mode='normal',releaseGenerate,releaseOpen;
const context={workspaceId:'w',nodeId:'n',requestId:'r',rowVersion:'1'};
function parseVaultNotesContext(value){return value===context?value:undefined;}
async function createNotesRecipient(){
 if(mode==='generate-error')throw Error('private');
 if(mode==='generate-late')await new Promise(resolve=>releaseGenerate=resolve);
 generated={disposed:false,publicKey:'public',dispose(){this.disposed=true;},async open(){if(mode==='open-error')throw Error('private');if(mode==='open-late')await new Promise(resolve=>releaseOpen=resolve);opened=new TextEncoder().encode(mode==='empty'?'':'<script>literal</script>');return opened;}};return generated;
}
${source}
(async()=>{
 const check=(ok,message)=>{if(!ok)throw Error(message);};const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
 function setup(overrides={}) {const card=document.createElement('section');document.body.append(card);let closed=0;
 const dispose=mountVaultNotesScreen(card,{contentProtectionAvailable:true,context:async()=>context,read:async()=>({}),close:async()=>{closed++;},...overrides});return {card,dispose,get closed(){return closed;},remove(){dispose();card.remove();}};}
 for(const value of ['normal','empty','generate-error','open-error']){mode=value;const v=setup();await tick();await tick();const pre=v.card.querySelector('pre'),status=v.card.querySelector('[role=status]');
 if(value.endsWith('error')){check(pre.hidden&&status.textContent.includes('unavailable')&&!status.textContent.includes('private'),'error disclosure');}else{check(!pre.hidden&&pre.textContent===(value==='empty'?'':'<script>literal</script>'),'literal text');check(!pre.querySelector('script'),'HTML interpreted');check(opened.every(x=>x===0),'plaintext bytes retained');}
 for(const eventName of ['copy','cut']){const event=new Event(eventName,{cancelable:true,bubbles:true});pre.dispatchEvent(event);check(event.defaultPrevented,'clipboard copy allowed');}
 v.card.querySelector('button').click();await tick();check(pre.textContent===''&&v.closed===1,'close retained notes');v.remove();}
 mode='normal';for(const overrides of [{context:async()=>null},{context:async()=>{throw Error('private');}},{read:async()=>{throw Error('private');}},{contentProtectionAvailable:false}]){const v=setup(overrides);await tick();await tick();if(overrides.contentProtectionAvailable===false)check(v.card.textContent.includes('unavailable on Linux'),'capture notice');else check(v.card.querySelector('[role=status]').textContent.includes('unavailable'),'request failure');v.remove();}
 for(const phase of ['context','generate-late','read','open-late']){mode=phase;let release;const overrides=phase==='context'?{context:()=>new Promise(resolve=>release=resolve)}:phase==='read'?{read:()=>new Promise(resolve=>release=resolve)}:{};const v=setup(overrides);await tick();v.dispose();if(phase==='context')release(context);else if(phase==='read')release({});else if(phase==='generate-late')releaseGenerate();else releaseOpen();await tick();check(v.card.querySelector('pre').textContent===''&&v.card.querySelector('pre').hidden,'late display');if(phase==='open-late')check(opened.every(x=>x===0),'late plaintext retained');v.remove();}
 mode='normal';const v=setup({close:async()=>{throw Error('private');}});await tick();window.dispatchEvent(new Event('pagehide'));check(v.card.querySelector('pre').textContent==='','pagehide retained notes');v.remove();
 const rejected=setup({close:async()=>{throw Error('private');}});await tick();rejected.card.querySelector('button').click();await tick();rejected.remove();
})()
//# sourceURL=wormhole-vault-notes-screen.js`;
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
try{await window.loadURL('data:text/html,<html><body></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-vault-notes-screen.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='mountVaultNotesScreen');assert.ok(fn);const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const coverage=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Vault notes screen: '+coverage.toFixed(2)+'% V8 blocks');assert.ok(coverage>=${coverageThreshold});
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
    assert.match(stdout, /Vault notes screen:/);
    if (stdout.trim()) t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
