import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { createVaultDialogWindow } from '../electron/vault-dialog-appearance.ts';
import type { BrowserWindow } from 'electron';
const require = createRequire(import.meta.url);
test('protected authentication keeps its own preload when palette registration is unavailable', () => {
  const window = {
    webContents: {
      session: {
        registerPreloadScript: () => {
          throw Error('unavailable');
        },
      },
    },
  } as unknown as BrowserWindow;
  const result = createVaultDialogWindow(
    { webPreferences: { preload: 'identity.cjs', additionalArguments: ['--example'] } },
    'light',
    'appearance.cjs',
    (options) => {
      assert.equal(options.webPreferences?.preload, 'identity.cjs');
      assert.deepEqual(options.webPreferences?.additionalArguments, [
        '--example',
        '--wormhole-appearance=light',
      ]);
      return window;
    },
  );
  assert.equal(result, window);
});
test('fresh-auth screen keeps factors out of app state and clears them on every completion', async (t) => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-reauth-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-reauth-screen-'));
  try {
    const renderer = `
const id='11111111-1111-4111-8111-111111111111',pw='22222222-2222-4222-8222-222222222222',recovery='33333333-3333-4333-8333-333333333333';
const descriptor={formatVersion:1,vaultId:id,encrypted:false,slots:[{id:pw,kind:'password',preset:'kdf-v1'},{id:recovery,kind:'recovery'}]};
function parseVaultDescriptor(value){return value===descriptor?descriptor:undefined;}
${source}
(async()=>{
 const check=(ok,message)=>{if(!ok)throw Error(message);};const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
 function setup(overrides={}){let seen,closed=0;const card=document.createElement('section');document.body.append(card);const dispose=mountVaultReauthenticationScreen(card,{context:async()=>({operation:'connection-save',slots:descriptor}),submit:async(value)=>{seen=value;return false;},cancel:async()=>{closed++;},...overrides});return{card,dispose,get seen(){return seen;},get closed(){return closed;},remove(){dispose();card.remove();}};}
 let v=setup();const form=v.card.querySelector('form');form.dispatchEvent(new Event('submit',{cancelable:true}));await tick();
 const input=v.card.querySelector('input'),method=v.card.querySelector('select'),button=v.card.querySelector('[type=submit]');
 check(!method.hidden&&v.card.textContent.includes('Save connection')&&!button.disabled,'context not shown');input.value='password';form.dispatchEvent(new Event('submit',{cancelable:true}));check(input.value==='','DOM factor retained');await tick();check(v.seen.kind==='password'&&v.seen.factor.every(x=>x===0),'password not cleared');check(v.card.querySelector('[role=status]').textContent.includes('Could not confirm'),'failure hidden');
 for(const value of ['', 'A'.repeat(1025)]){input.value=value;form.dispatchEvent(new Event('submit',{cancelable:true}));check(v.card.querySelector('[role=status]').textContent.includes('valid'),'bad length accepted');}
 method.value=recovery;method.dispatchEvent(new Event('change'));check(!method.hidden&&v.card.querySelector('label').textContent==='Recovery key','wrong method label');input.value='R'.repeat(76);form.dispatchEvent(new Event('submit',{cancelable:true}));await tick();check(v.seen.kind==='recovery-code'&&v.seen.factor.every(x=>x===0),'recovery not cleared');
 method.value='missing';form.dispatchEvent(new Event('submit',{cancelable:true}));v.card.querySelector('[type=button]').click();await tick();check(v.closed===1,'cancel not sent');v.remove();
 for(const accepted of [true,false,'unexpected']){v=setup({submit:async()=>accepted});await tick();v.card.querySelector('input').value='password';v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick();if(accepted!==true)check(v.card.querySelector('[role=status]').textContent.includes('Could not confirm'),'invalid success accepted');v.remove();}
 v=setup({submit:async()=>{throw Error('private');},cancel:async()=>{throw Error('private');}});await tick();v.card.querySelector('input').value='password';v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick();check(v.card.querySelector('[role=status]').textContent.includes('unavailable')&&!v.card.textContent.includes('private'),'private error');v.card.querySelector('[type=button]').click();await tick();v.remove();
 for(const context of [null,[],{}, {operation:'unknown',slots:descriptor},{operation:'folder-save',slots:null},{operation:'folder-save',slots:descriptor,extra:true}]){v=setup({context:async()=>context});await tick();check(v.card.querySelector('[type=submit]').disabled,'invalid context admitted');v.remove();}
 for(const [operation,label] of [['bitwarden-cleanup','Clean old Bitwarden extension packages'],['bitwarden-install-zip','Import Bitwarden extension ZIP'],['bitwarden-install-folder','Install Bitwarden extension'],['credential-edit','Save credential'],['credential-delete','Delete credential'],['node-move','Move selected items'],['credential-display','Show credentials'],['credential-copy','Copy credential'],['node-duplicate','Duplicate connection']]){v=setup({context:async()=>({operation,slots:descriptor})});await tick();check(v.card.textContent.includes(label)&&!v.card.querySelector('[type=submit]').disabled,'credential action missing');v.remove();}
 let release,borrowed,calls=0;v=setup({submit:value=>{calls++;borrowed=value.factor;return new Promise(resolve=>release=resolve);}});await tick();const input2=v.card.querySelector('input');input2.value='password';const pendingForm=v.card.querySelector('form');pendingForm.dispatchEvent(new Event('submit',{cancelable:true}));pendingForm.dispatchEvent(new Event('submit',{cancelable:true}));check(calls===1,'concurrent submit');window.dispatchEvent(new Event('pagehide'));check(borrowed.every(x=>x===0)&&input2.value==='','pending factor retained');release(false);await tick();check(v.card.querySelector('[type=submit]').disabled,'late reenabled screen');pendingForm.dispatchEvent(new Event('submit',{cancelable:true}));v.remove();
 v=setup({context:()=>new Promise(resolve=>release=resolve)});v.dispose();release({operation:'folder-save',slots:descriptor});await tick();check(v.card.querySelector('[type=submit]').disabled,'late context reenabled screen');v.remove();
 const saved=descriptor.slots;descriptor.slots=[saved[1]];v=setup();await tick();check(v.card.querySelector('select').hidden&&v.card.querySelector('label').textContent==='Recovery key'&&v.card.querySelector('input').maxLength===76&&v.card.querySelector('input').autocomplete==='off','initial recovery method incorrect');v.remove();descriptor.slots=[];v=setup();await tick();check(v.card.querySelector('[type=submit]').disabled,'empty methods admitted');v.remove();descriptor.slots=saved;
})()
//# sourceURL=wormhole-vault-reauth-screen.js`;
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
app.disableHardwareAcceleration();
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
try{await window.loadURL('data:text/html,<html><body></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-vault-reauth-screen.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='mountVaultReauthenticationScreen');assert.ok(fn);const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const coverage=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Vault reauthentication screen: '+coverage.toFixed(2)+'% V8 blocks');assert.ok(coverage>=${coverageThreshold});
await require(${JSON.stringify(resolve('tests/fixtures/vault-auth-dialogs.cjs'))})(window);
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
    assert.match(stdout, /Vault reauthentication screen:/);
    if (stdout.trim()) t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
