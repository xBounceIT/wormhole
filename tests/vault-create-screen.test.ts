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
test('creation screen consumes factors, clears one-time recovery, and handles disposal and failures', async (t) => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-create-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-create-screen-'));
  try {
    const renderer = `
let generated, opened, mode='normal', resolveGenerate, resolveOpen;
async function createRecoveryRecipient(){
 if(mode==='generate-error')throw Error('private crypto diagnostic');
 if(mode==='generate-late')await new Promise(r=>resolveGenerate=r);
 generated={publicKey:new Uint8Array(32).fill(1),dispose(){this.publicKey.fill(0);},async open(){if(mode==='open-late')await new Promise(r=>resolveOpen=r);if(mode==='open-error')throw Error('private open diagnostic');opened=new TextEncoder().encode('WHREC1-'+Array(11).fill('ABCDE').join('-')+'-ABC');return opened;}};return generated;
}
${source}
(async()=>{
 const check=(ok,message)=>{if(!ok)throw Error(message);},tick=()=>new Promise(r=>setTimeout(r,0));
 const response={enrollmentId:'id',groups:[1,11]};
 const setup=(begin=async()=>response,confirm=async()=>({unlocked:true}),cancel=async()=>{},contentProtectionAvailable=true)=>{
  const card=document.createElement('section');document.body.append(card);const dispose=mountVaultCreateScreen(card,{begin,confirm,cancel,contentProtectionAvailable});
  const fields=card.querySelectorAll('input'),form=card.querySelector('form'),buttons=card.querySelectorAll('button'),status=card.querySelector('[role=status]');
  return {card,dispose,fields,form,buttons,status,fill(a,b=a){fields[0].value=a;fields[1].value=b;fields[1].dispatchEvent(new Event('input'));},send(){form.dispatchEvent(new SubmitEvent('submit',{cancelable:true}));},close(){dispose();card.remove();}};
 };
 const linux=setup(undefined,undefined,undefined,false);check(!Array.from(linux.card.querySelectorAll('p')).find(p=>p.textContent.startsWith('Screen capture')).hidden,'Linux capability notice missing');linux.close();
 let calls=0,borrowed,groups,cancelled=0;
 const f=setup(async input=>{calls++;borrowed=input.password;return response;},async input=>{groups=input.groups;},async()=>{cancelled++;});
 f.send();check(!calls&&f.buttons[0].disabled,'empty submission');f.fill('one','two');f.send();await tick();check(!calls&&f.status.textContent.includes('do not match'),'password mismatch');
 f.fill('pass');f.send();f.send();await tick();check(calls===1&&borrowed.every(x=>x===0)&&f.fields[0].value==='','password retained');
 check(f.form.hidden&&!f.buttons[1].hidden&&f.card.querySelector('pre').textContent.length===76,'missing display');
 for(const type of ['copy','cut','dragstart'])check(!f.card.dispatchEvent(new Event(type,{cancelable:true,bubbles:true})),'unmanaged secret output');
 f.buttons[1].click();check(opened.every(x=>x===0)&&f.card.querySelector('pre').textContent==='','recovery retained');f.buttons[1].click();
 check(f.fields[0].autocomplete==='off'&&f.fields[1].maxLength===5,'confirmation fields');f.fill('short','x');f.send();await tick();check(!groups&&f.fields[0].value==='','short groups forwarded');
 f.fill('ABCDE');f.send();await tick();check(groups.every(x=>x===0)&&f.buttons[0].disabled,'confirmation bytes retained');f.send();f.close();
 for(const kind of ['generate-error','open-error','reject','throw','oversize']){
  mode=kind;let count=0;const fail=setup(()=>{count++;if(kind==='throw')throw Error('private failure');if(kind==='reject')return Promise.reject(Error('private failure'));return Promise.resolve(response);});
  fail.fill(kind==='oversize'?'界'.repeat(400):'password');fail.send();await tick();
  check(fail.status.textContent.includes("couldn't prepare")&&!fail.status.textContent.includes('private'),'private failure exposed');check(fail.fields[0].value==='','failed factor retained');
  if(kind==='oversize'||kind==='generate-error')check(count===0,'invalid begin forwarded');fail.close();
 }

 {
  mode='normal';const card=document.createElement('section');document.body.append(card);let called=0;
  const dispose=mountVaultCreateScreen(card,{contentProtectionAvailable:true,begin:async(input,legacy,authentication)=>{check(!legacy&&!authentication,'old proof in ownerless upgrade');called++;return response;},confirm:async()=>{},cancel:async()=>{}},undefined,undefined,{vaultId:'native-vault'});
  const inputs=card.querySelectorAll('input'),form=card.querySelector('form'),buttons=card.querySelectorAll('button');
  check(inputs.length===2&&!card.querySelector('select')?.closest('label')?.offsetHeight,'ownerless upgrade requested old factor');
  inputs[0].value=inputs[1].value='new upgrade password';inputs[1].dispatchEvent(new Event('input'));form.dispatchEvent(new SubmitEvent('submit',{cancelable:true}));await tick();
  check(called===1&&inputs[0].value==='','upgrade password retained');buttons[1].click();check(buttons[0].textContent==='Prepare and restart','upgrade confirmation action');dispose();card.remove();
 }
 for(const kind of ['password','recovery']){
  mode='normal';let proof,called=0;const card=document.createElement('section');document.body.append(card);
  const rotation={slots:{vaultId:'native-vault',slots:[{id:'pw',kind:'password'},{id:'rc',kind:'recovery'},{id:'hello',kind:'hello'},{id:'touch',kind:'touch-id'}]}};
  const dispose=mountVaultCreateScreen(card,{contentProtectionAvailable:true,begin:async(input,legacy,authentication)=>{check(!legacy,'legacy proof in root flow');called++;proof=authentication;return response;},confirm:async()=>{},cancel:async()=>{}},undefined,rotation);
  const inputs=card.querySelectorAll('input'),select=card.querySelector('select'),form=card.querySelector('form'),buttons=card.querySelectorAll('button');
  check(select.value==='pw'&&inputs[0].autocomplete==='current-password','current factor default');
  check(select.options.length===2&&card.textContent.includes('Set up biometric unlock again'),'rotation offered an old biometric factor or hid the retirement notice');
  inputs[0].value='prior proof';if(kind==='recovery'){select.value='rc';select.dispatchEvent(new Event('change'));check(inputs[0].value===''&&inputs[0].maxLength===76&&inputs[0].autocomplete==='off','current recovery switch');}
  inputs[0].value='current factor';inputs[1].value=inputs[2].value='new password';inputs[2].dispatchEvent(new Event('input'));form.dispatchEvent(new SubmitEvent('submit',{cancelable:true}));await tick();
  check(called===1&&proof.vaultId==='native-vault'&&proof.slotId===select.value&&proof.kind===(kind==='password'?'password':'recovery-code'),'wrong current authentication');
  check(proof.factor.every(x=>x===0)&&inputs[0].value===''&&inputs[0].closest('label').hidden,'current factor retained');buttons[1].click();check(buttons[0].textContent==='Prepare and restart','root confirmation action');dispose();card.remove();
 }
 for(const methods of [['none'],['pin'],['password'],['password','pin']]){
  mode='normal';let called=0,legacy;
  const card=document.createElement('section');document.body.append(card);
  const dispose=mountVaultCreateScreen(card,{contentProtectionAvailable:true,begin:async(input,proof)=>{called++;legacy=proof;return response;},confirm:async()=>{},cancel:async()=>{}},{methods});
  const inputs=card.querySelectorAll('input'),select=card.querySelector('select'),form=card.querySelector('form'),buttons=card.querySelectorAll('button');
  inputs[1].value=inputs[2].value='new password';inputs[2].dispatchEvent(new Event('input'));
  const send=()=>form.dispatchEvent(new SubmitEvent('submit',{cancelable:true}));
  if(methods[0]!=='none'){send();await tick();check(!called,'missing old proof accepted');inputs[0].value='old proof';inputs[0].dispatchEvent(new Event('input'));}
  if(methods.length===2){select.value='pin';select.dispatchEvent(new Event('change'));check(inputs[0].value===''&&inputs[0].closest('label').textContent.includes('PIN'),'switch retained old proof');inputs[0].value='1234';}
  send();await tick();check(called===1&&legacy.legacyMethod===select.value&&legacy.legacyFactor.every(x=>x===0)&&inputs[0].value==='','legacy factor ownership');
  check(inputs[0].closest('label').hidden,'old proof visible with recovery');buttons[1].click();check(buttons[0].textContent==='Prepare and restart','wrong confirmation action');dispose();check(inputs[0].disabled&&select.disabled,'disposed old controls enabled');card.remove();
 }
 for(const kind of ['generate-error','oversize']){
  mode=kind;let calls=0;const card=document.createElement('section');document.body.append(card);const dispose=mountVaultCreateScreen(card,{begin:async()=>{calls++;return response;},confirm:async()=>{},cancel:async()=>{}},{methods:['pin']});const inputs=card.querySelectorAll('input');inputs[0].value=kind==='oversize'?'界'.repeat(400):'private';inputs[1].value=inputs[2].value='pass';card.querySelector('form').dispatchEvent(new SubmitEvent('submit',{cancelable:true}));await tick();check(inputs[0].value===''&&calls===0,'failed legacy factor retained or forwarded');dispose();card.remove();
 }
 mode='normal';const failedConfirm=setup(undefined,async()=>{throw Error('private confirmation');});failedConfirm.fill('pass');failedConfirm.send();await tick();failedConfirm.buttons[1].click();failedConfirm.fill('ABCDE');failedConfirm.send();await tick();check(failedConfirm.status.textContent.includes('could not be confirmed')&&!failedConfirm.status.textContent.includes('private'),'confirmation diagnostic');failedConfirm.close();
 for(const phase of ['generate-late','begin-late','open-late']){
  mode=phase;let release;const late=setup(()=>phase==='begin-late'?new Promise(r=>release=r):Promise.resolve(response));late.fill('pass');late.send();await tick();late.dispose();
  if(phase==='generate-late')resolveGenerate();else if(phase==='begin-late')release(response);else resolveOpen();await tick();
  check(late.fields[0].value===''&&late.buttons[0].disabled&&late.card.querySelector('pre').textContent==='','disposed view repopulated');if(phase==='open-late')check(opened.every(x=>x===0),'late code retained');late.close();
 }
 mode='normal';const cancel=setup(undefined,undefined,async()=>{cancelled++;throw Error('cancelled');});cancel.buttons[2].click();await tick();check(cancelled===1&&cancel.fields[0].disabled,'cancel did not dispose');cancel.close();
 const page=setup();page.fill('private');window.dispatchEvent(new Event('pagehide'));check(page.fields[0].value===''&&page.buttons[0].disabled,'pagehide retained input');page.close();
})()
//# sourceURL=wormhole-vault-create-screen.js`;
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
try{await window.loadURL('data:text/html,<html><body></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-vault-create-screen.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='mountVaultCreateScreen');assert.ok(fn);const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const coverage=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Vault creation screen: '+coverage.toFixed(2)+'% V8 blocks');assert.ok(coverage>=${coverageThreshold});
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
    assert.match(stdout, /Vault creation screen:/);
    if (stdout.trim()) t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
