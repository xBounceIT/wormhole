import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

import { migrationReport, migrationSelection } from './fixtures/vault-migration.ts';

test('migration panel handles choices, CAS acknowledgements, lock and stale lifetimes in real React', async (t) => {
  const require = createRequire(import.meta.url);
  const source = readFileSync(
    new URL('../src/components/VaultMigrationChoices.tsx', import.meta.url),
    'utf8',
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const compiled = await transformWithOxc(source, 'vault-migration-panel.tsx', {
    jsx: { runtime: 'classic' },
  });
  const renderer = `
 const React=require(${JSON.stringify(require.resolve('react'))});const {useEffect,useRef,useState}=React;
 const {createRoot}=require(${JSON.stringify(require.resolve('react-dom/client'))});const primitive=require(${JSON.stringify(require.resolve('radix-ui'))}).Select;
 const assert=require('node:assert/strict');globalThis.IS_REACT_ACT_ENVIRONMENT=true;
 let selectChanges=[];
 const Button=({size,variant,...props})=>React.createElement('button',props);
 const Select=props=>{selectChanges.push(props.onValueChange);return React.createElement(primitive.Root,props);};
 const SelectTrigger=({size,...props})=>React.createElement(primitive.Trigger,props),SelectValue=primitive.Value;
 const SelectContent=props=>React.createElement(primitive.Content,null,React.createElement(primitive.Viewport,null,props.children));
 const SelectItem=props=>React.createElement(primitive.Item,{value:props.value},React.createElement(primitive.ItemText,null,props.children));
 ${compiled.code}
 (async()=>{
 const initial=${JSON.stringify(migrationReport())},selection=${JSON.stringify(migrationSelection)};
 const root=createRoot(document.getElementById('root'));let key=0,commits=[],ends=0,starts=0,allow=true,requests=[],refreshes=0;
 let props={...selection,disabled:false,beginChange:()=>{starts++;return allow;},endChange:()=>ends++,onCommitted:version=>commits.push(version),refreshAfterFailure:async()=>{refreshes++;}};
 const mount=async(api,extra={})=>{window.wormhole=api;selectChanges=[];await React.act(async()=>root.render(React.createElement(VaultMigrationChoices,{...props,...extra,key:++key})));};
 const select=async(index,value)=>React.act(async()=>selectChanges.slice(-2)[index](value));
 const click=async()=>React.act(async()=>document.querySelector('section button[type=button]:not([role=combobox])').click());
 const api={readVaultMigrationReport:async()=>structuredClone(initial),decideVaultMigration:async request=>{requests.push(structuredClone(request));return {nodeId:selection.nodeId,rowVersion:String(BigInt(request.rowVersion)+1n),updated:true};}};
 await mount(api);assert.equal(document.querySelectorAll('[role=combobox]').length,2);assert.ok(document.body.textContent.includes('Changed during import: username'));
 assert.equal(document.querySelector('section button[type=button]:not([role=combobox])').disabled,true);
 await select(0,'new');await select(1,'keep');await select(0,'invalid');await click();assert.deepEqual(commits,['3']);assert.equal(ends,1);assert.equal(requests[0].rowVersion,'2');assert.deepEqual(requests[0].choices,[{protocolPath:'ssh',choice:'new'},{protocolPath:'sftp',choice:'keep'}]);assert.ok(document.body.textContent.includes('Credential choices saved.'));
 await select(0,'keep');await click();assert.equal(requests[1].rowVersion,'3');assert.deepEqual(commits,['3','4']);
 await mount({...api,readVaultMigrationReport:async()=>({...initial,canDecide:false})});assert.ok(Array.from(document.querySelectorAll('[role=combobox]')).every(el=>el.disabled));assert.ok(document.body.textContent.includes('fresh authentication'));
 await mount(api,{disabled:true});assert.ok(Array.from(document.querySelectorAll('[role=combobox]')).every(el=>el.disabled));
 await mount({...api,readVaultMigrationReport:async()=>({...initial,entries:[],fingerprint:null})});assert.equal(document.querySelector('section'),null);
 const beforeRefresh=refreshes;await mount(undefined);assert.ok(document.querySelector('[role=alert]').textContent.includes('could not be loaded'));assert.equal(refreshes,beforeRefresh+1);
 await mount({...api,readVaultMigrationReport:async()=>{throw Error('private');}});assert.ok(!document.body.textContent.includes('private'));
 await mount({...api,readVaultMigrationReport:async()=>{throw Error('read');}},{refreshAfterFailure:async()=>{throw Error('refresh');}});assert.ok(document.querySelector('[role=alert]'));
 allow=false;await mount(api);await select(0,'new');const count=requests.length;await click();assert.equal(requests.length,count);allow=true;
 await mount({...api,decideVaultMigration:async()=>{throw Error('private failure');}});await select(0,'new');await click();assert.ok(document.querySelector('[role=alert]').textContent.includes('could not be saved'));assert.ok(!document.body.textContent.includes('private failure'));
 await mount(api);await select(0,'new');window.wormhole=undefined;await click();assert.ok(document.querySelector('[role=alert]'));
 let release;await mount({...api,readVaultMigrationReport:()=>new Promise(resolve=>release=resolve)});assert.ok(document.body.textContent.includes('Checking'));await mount(api);await React.act(async()=>release({...initial,entries:[],fingerprint:null}));assert.equal(document.querySelectorAll('[role=combobox]').length,2);
 let reject;await mount({...api,readVaultMigrationReport:()=>new Promise((_,no)=>reject=no)});await mount(api);await React.act(async()=>reject(Error('stale')));assert.equal(document.querySelector('[role=alert]'),null);
 let pending;await mount({...api,decideVaultMigration:request=>{requests.push(request);return new Promise(resolve=>pending=resolve);}});await select(0,'new');const before=starts;await React.act(async()=>{const button=document.querySelector('section button[type=button]:not([role=combobox])');button.click();button.click();});assert.equal(starts,before+1);
 const committed=commits.length,settled=ends;await mount(api);await React.act(async()=>pending({nodeId:selection.nodeId,rowVersion:'3',updated:true}));assert.equal(commits.length,committed);assert.equal(ends,settled+1);
 await React.act(async()=>root.unmount());
 })();
 //# sourceURL=wormhole-vault-migration-panel.js
 `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-migration-panel-'));
  try {
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
 const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
 app.setPath('userData',${JSON.stringify(directory)});app.setPath('sessionData',${JSON.stringify(directory)});app.disableHardwareAcceleration();
 app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{nodeIntegration:true,contextIsolation:false,offscreen:true,backgroundThrottling:false}});
 try{await window.loadURL('data:text/html,<html><body><div id="root"></div></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
 const coverage=await debug.sendCommand('Profiler.takePreciseCoverage');const script=coverage.result.find(s=>s.url==='wormhole-vault-migration-panel.js');const fn=script.functions.find(f=>f.functionName==='VaultMigrationChoices'),extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Migration panel '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=${coverageThreshold});
 }finally{window.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
    );
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const electron = require('electron') as string,
      headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 30000, windowsHide: true },
    );
    assert.match(stdout, /Migration panel/);
    t.diagnostic(stdout);
    if (stderr.trim()) t.diagnostic(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
