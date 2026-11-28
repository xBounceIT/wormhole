import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);

test(
  'persistent warning uses authenticated protection, survives cancellation, and ignores retired UI lifetimes',
  { timeout: 60_000 },
  async (t) => {
    const source = (
      await readFile(
        new URL('../src/components/VaultProtectionNotice.tsx', import.meta.url),
        'utf8',
      )
    )
      .replace(/^import .*?;\s*/gms, '')
      .replace(/^export /gm, '');
    const compiled = await transformWithOxc(source, 'notice.tsx', { jsx: { runtime: 'classic' } });
    const app = await readFile(new URL('../src/App.tsx', import.meta.url), 'utf8');
    const begin = app.indexOf(
      "{authState?.mode === 'vault' && authGate === 'unlocked' && <VaultProtectionNotice />}",
    );
    assert.ok(begin > 0);
    const expression = app.slice(begin, app.indexOf('\n', begin)).trim();
    const route = await transformWithOxc(
      'function Route({authState,authGate}){return <div>' + expression + '</div>;}',
      'route.tsx',
      { jsx: { runtime: 'classic' } },
    );
    const renderer = `
const React=require(${JSON.stringify(require.resolve('react'))}),{useEffect,useRef,useState}=React,{createRoot}=require(${JSON.stringify(require.resolve('react-dom/client'))}),assert=require('node:assert/strict');
globalThis.IS_REACT_ACT_ENVIRONMENT=true;const Button=({variant,size,...props})=>React.createElement('button',props);
${compiled.code}
${route.code}
(async()=>{
 const root=createRoot(document.getElementById('root'));let key=0;
 const mount=async(api,mode='vault',gate='unlocked')=>{window.wormhole=api;await React.act(async()=>root.render(React.createElement(Route,{key:++key,authState:mode?{mode}:null,authGate:gate})));};
 const text=()=>document.body.textContent,button=()=>document.querySelector('button'),click=async()=>React.act(async()=>button().click());
 let calls=0,reads=0;const api={loadVaultProtection:async()=>{reads++;return {protected:false};},getVaultStatus:async()=>({unlocked:true,lockedMemory:true}),prepareUnprotectedVaultProtection:async()=>{calls++;return false;}};
 await mount(api);assert.match(text(),/Wormhole isn't locked/);assert.equal(button().textContent,'Protect now');await click();assert.equal(calls,1);assert.equal(button().disabled,false);
 await mount({...api,loadVaultProtection:async()=>({protected:true})});assert.equal(text(),'');
 const pageable={...api,getVaultStatus:async()=>({unlocked:true,lockedMemory:false})};
 await mount({...pageable,loadVaultProtection:async()=>({protected:true})});assert.match(text(),/could not lock vault keys in memory/);assert.equal(button(),null);
 await mount(pageable);assert.match(text(),/Wormhole isn't locked/);assert.match(text(),/could not lock vault keys in memory/);assert.equal(button().textContent,'Protect now');
 await mount({...api,getVaultStatus:async()=>({unlocked:false,lockedMemory:false})});assert.match(text(),/could not be checked/);assert.equal(button(),null);
 await mount({...api,loadVaultProtection:async()=>{throw Error('private diagnosis');}});assert.match(text(),/could not be checked/);assert.doesNotMatch(text(),/private/);assert.equal(button(),null);
 await mount(undefined);assert.match(text(),/could not be checked/);await mount({});assert.match(text(),/could not be checked/);
 await mount({...api,prepareUnprotectedVaultProtection:async()=>{throw Error('private password');}});await click();assert.match(text(),/could not start/);assert.match(text(),/Wormhole isn't locked/);assert.equal(document.querySelector('[role=alert]').textContent,'Protection setup could not start. Try again.');assert.doesNotMatch(text(),/private/);assert.equal(button().disabled,false);
 let resolve;await mount({...api,prepareUnprotectedVaultProtection:()=>{calls++;return new Promise(r=>resolve=r);}});
 const before=calls;await React.act(async()=>{button().click();button().click();});assert.equal(calls,before+1);assert.equal(button().disabled,true);await React.act(async()=>resolve(true));assert.equal(button().disabled,true);
 let finish;await mount({...api,loadVaultProtection:()=>new Promise(r=>finish=r)});assert.match(text(),/Checking/);await mount(api,'password');await React.act(async()=>finish({protected:false}));assert.equal(text(),'');
 await mount(api,'vault','locked');assert.equal(text(),'');await mount(api,null,'loading');assert.equal(text(),'');
 let reject;await mount({...api,prepareUnprotectedVaultProtection:()=>new Promise((_,no)=>reject=no)});await click();await mount(api,'password');await React.act(async()=>reject(Error('private')));assert.equal(text(),'');
 await React.act(async()=>root.unmount());
})();
//# sourceURL=wormhole-vault-protection-notice.js
`;
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-protection-notice-'));
    try {
      const harness = join(directory, 'main.cjs');
      await writeFile(
        harness,
        `
const {app,BrowserWindow}=require('electron'),assert=require('node:assert/strict');app.setPath('userData',${JSON.stringify(directory)});app.disableHardwareAcceleration();
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{nodeIntegration:true,contextIsolation:false,offscreen:true,backgroundThrottling:false}});
try{await window.loadURL('data:text/html,<html><body><div id="root"></div></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
const coverage=await debug.sendCommand('Profiler.takePreciseCoverage'),script=coverage.result.find(s=>s.url==='wormhole-vault-protection-notice.js');for(const name of ['VaultProtectionNotice','Route']){const fn=script.functions.find(f=>f.functionName===name),extent=fn.ranges[0],ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges),percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log(name+': '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=${coverageThreshold});}
}finally{window.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
      );
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      const result = await promisify(execFile)(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
        { env, windowsHide: true, timeout: 40_000 },
      );
      assert.match(result.stdout, /VaultProtectionNotice:/);
      t.diagnostic(result.stdout);
      if (result.stderr.trim()) t.diagnostic(result.stderr);
    } finally {
      assert.ok(directory.startsWith(join(tmpdir(), 'wormhole-protection-notice-')));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
