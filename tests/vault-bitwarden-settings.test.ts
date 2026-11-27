import { runInNewContext } from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
import { Session } from 'node:inspector/promises';
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
import { mainSyntax, visitSyntax } from './fixtures/main-source.ts';

test('native Bitwarden settings show verified metadata, handle cancellation and ignore retired UI lifetimes', async (t) => {
  const require = createRequire(import.meta.url);
  const source = readFileSync(
    new URL('../src/components/VaultBitwardenInstallation.tsx', import.meta.url),
    'utf8',
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const compiled = await transformWithOxc(source, 'vault-bitwarden-settings.tsx', {
    jsx: { runtime: 'classic' },
  });
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const sectionStart = appSource.indexOf('<SettingsTabPanel value="extensions">');
  const sectionEnd = appSource.indexOf(') : (', sectionStart);
  assert.ok(sectionStart > 0 && sectionEnd > sectionStart);
  const section = await transformWithOxc(
    'function NativeSettings({authState, authGate}) { return (' +
      appSource.slice(sectionStart, sectionEnd) +
      ') : <p>Legacy controls</p>}</SettingsTabPanel>); }',
    'native-settings.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderer = `
 const React=require(${JSON.stringify(require.resolve('react'))});const {useEffect,useRef,useState}=React;
 const {createRoot}=require(${JSON.stringify(require.resolve('react-dom/client'))});
 const assert=require('node:assert/strict');globalThis.IS_REACT_ACT_ENVIRONMENT=true;
 const Button=({variant,...props})=>React.createElement('button',props);
 const SettingsTabPanel=({children})=>React.createElement('div',null,children);
 const SettingsSection=({children})=>React.createElement('section',null,children);
 ${compiled.code}
 ${section.code}
 (async()=>{
 const root=createRoot(document.getElementById('root'));let key=0;
 const plan=version=>({installation:version?{version}:null});
 const mount=async api=>{window.wormhole=api;await React.act(async()=>root.render(React.createElement(VaultBitwardenInstallation,{key:++key})));};
 const text=()=>document.body.textContent;
 const click=async()=>React.act(async()=>document.querySelector('button').click());
 let calls=0,zipCalls=0,cleanupCalls=0;const api={cleanupVaultBitwardenInstallations:async()=>{cleanupCalls++;return {revision:"3"};},installVaultBitwardenZip:async()=>{zipCalls++;return plan("1.2");},readVaultBitwardenInstallation:async()=>plan(null),installVaultBitwardenFolder:async()=>{calls++;return plan('1.2');}};
 await mount(api);assert.match(text(),/No extension installed/);assert.match(text(),/not yet available/);
 assert.doesNotMatch(text(),/Unlock Bitwarden CLI/);
 let unlocks=0;const cli={...api,vaultBitwardenCLIAvailable:async()=>true,unlockVaultBitwardenCLI:async()=>{unlocks++;return {unlocked:true};}};
 const unlock=async()=>React.act(async()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Unlock Bitwarden CLI').click());
 await mount(cli);await unlock();assert.equal(unlocks,1);assert.match(text(),/session saved in the vault/);
 cli.unlockVaultBitwardenCLI=async()=>{throw Error('private CLI error');};
 await unlock();assert.match(text(),/Could not unlock Bitwarden CLI/);assert.doesNotMatch(text(),/private CLI error|session saved/);
 cli.unlockVaultBitwardenCLI=async()=>({unlocked:false});await unlock();assert.match(text(),/Could not unlock Bitwarden CLI/);
 await mount({...cli,vaultBitwardenCLIAvailable:async()=>{throw Error('private availability');}});assert.doesNotMatch(text(),/Unlock Bitwarden CLI|private availability/);
 await mount(api);
 await click();assert.equal(calls,1);assert.match(text(),/Installed version: 1.2/);
 await React.act(async()=>document.querySelectorAll('button')[1].click());assert.equal(zipCalls,1);assert.equal(calls,1);assert.match(text(),/Installed version: 1.2/);
 await React.act(async()=>document.querySelectorAll('button')[2].click());assert.equal(cleanupCalls,1);assert.match(text(),/Old extension packages cleaned/);assert.match(text(),/Installed version: 1.2/);
 api.cleanupVaultBitwardenInstallations=async()=>{throw Error('private cleanup');};await React.act(async()=>document.querySelectorAll('button')[2].click());assert.match(text(),/Could not confirm package cleanup/);assert.doesNotMatch(text(),/private cleanup|Old extension packages cleaned/);
 await mount(api);await click();
 api.installVaultBitwardenFolder=async()=>null;await click();assert.match(text(),/Installed version: 1.2/);
 api.installVaultBitwardenFolder=async()=>{throw Error('private native detail');};await click();assert.match(text(),/Could not confirm/);assert.doesNotMatch(text(),/1.2|private native detail/);
 await mount({...api,readVaultBitwardenInstallation:async()=>{throw Error('private read');}});assert.match(text(),/Could not verify/);assert.doesNotMatch(text(),/private read/);
 await mount(undefined);assert.match(text(),/Could not verify/);await click();assert.match(text(),/Could not confirm/);
 let finish;await mount({...api,readVaultBitwardenInstallation:()=>new Promise(r=>finish=r)});assert.ok(document.querySelector('button').disabled);
 await mount({...api,readVaultBitwardenInstallation:async()=>plan('2.0')});await React.act(async()=>finish(plan('stale')));assert.match(text(),/2.0/);assert.doesNotMatch(text(),/stale/);
 await mount({...api,readVaultBitwardenInstallation:()=>new Promise((_r,reject)=>finish=reject)});
 await mount(api);await React.act(async()=>finish(Error('late private')));assert.doesNotMatch(text(),/late private|Could not verify/);
 await mount({...api,installVaultBitwardenFolder:()=>new Promise(r=>finish=r)});await click();assert.ok(document.querySelector('button').disabled);await mount(api);await React.act(async()=>finish(plan('stale')));assert.doesNotMatch(text(),/stale/);
 await mount({...api,installVaultBitwardenFolder:()=>new Promise((_r,reject)=>finish=reject)});await click();await mount(api);await React.act(async()=>finish(Error('late install')));assert.doesNotMatch(text(),/late install|Could not confirm/);
 await mount({...api,installVaultBitwardenFolder:async()=>plan(null)});await click();assert.match(text(),/No extension installed/);
 await mount({...api,cleanupVaultBitwardenInstallations:()=>new Promise(r=>finish=r)});await React.act(async()=>document.querySelectorAll('button')[2].click());assert.ok([...document.querySelectorAll('button')].every(b=>b.disabled));await mount(api);await React.act(async()=>finish({revision:'3'}));assert.doesNotMatch(text(),/Old extension packages cleaned/);
 await React.act(async()=>root.unmount());
 const routedRoot=createRoot(document.getElementById('root'));let reads=0;
 window.wormhole={...api,readVaultBitwardenInstallation:async()=>{reads++;return plan('3.0');}};
 const renderRoute=async(mode,gate)=>React.act(async()=>routedRoot.render(React.createElement(NativeSettings,{authState:mode?{mode}:null,authGate:gate})));
 await renderRoute('vault','unlocked');assert.equal(reads,1);assert.match(text(),/3.0/);
 await renderRoute('vault','locked');assert.doesNotMatch(text(),/3.0|Use folder/);
 await renderRoute('vault','unlocked');assert.equal(reads,2);
 await renderRoute('password','unlocked');assert.match(text(),/Legacy controls/);assert.equal(reads,2);
 await renderRoute(null,'loading');assert.match(text(),/Legacy controls/);
 await React.act(async()=>routedRoot.unmount());
 })();
 //# sourceURL=wormhole-vault-bitwarden-settings.js
 `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-bitwarden-settings-'));
  try {
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
 const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
 app.setPath('userData',${JSON.stringify(directory)});app.setPath('sessionData',${JSON.stringify(directory)});app.disableHardwareAcceleration();
 app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{nodeIntegration:true,contextIsolation:false,offscreen:true,backgroundThrottling:false}});
 try{await window.loadURL('data:text/html,<html><body><div id="root"></div></body></html>');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
 const coverage=await debug.sendCommand('Profiler.takePreciseCoverage');const script=coverage.result.find(s=>s.url==='wormhole-vault-bitwarden-settings.js');for(const name of ['VaultBitwardenInstallation','NativeSettings']) {const fn=script.functions.find(f=>f.functionName===name),extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Bitwarden settings '+name+' '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=${coverageThreshold});}
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
    assert.match(stdout, /Bitwarden settings/);
    t.diagnostic(stdout);
    if (stderr.trim()) t.diagnostic(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});

test('actual settings loading uses native preferences without invoking legacy Bitwarden backends', async (t) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const settingsEffects: string[] = [];
  visitSyntax(mainSyntax(source, true), (node) => {
    if (node.type !== 'CallExpression' || node.callee.name !== 'useEffect') return;
    const effect = source.slice(node.start, node.end);
    if (effect.includes('.readAppSettings(')) settingsEffects.push(effect);
  });
  assert.equal(settingsEffects.length, 1);
  const code = stripTypeScriptTypes(settingsEffects[0]);
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'vault-bitwarden-native-settings-load.js';
  let effects: any,
    values: boolean[] = [];
  let current = true;
  const execute = (api: unknown, gate = 'unlocked') => {
    runInNewContext(
      code,
      {
        useEffect: (effect: any, deps: any[]) => {
          assert.equal(deps[1], 'vault');
          effects = effect;
        },
        authGate: gate,
        isCurrentUnlock: () => current,
        authState: { mode: 'vault' },
        window: { wormhole: api },
        setPromptBeforeTunnelConnect: (value: boolean) => values.push(value),
      },
      { filename },
    );
    return effects();
  };
  const tick = () => new Promise((r) => setImmediate(r));
  const api = {
    readAppSettings: async () => ({ promptBeforeTunnelConnect: true }),
    readBitwardenExtension: () => {
      throw Error('legacy extension called');
    },
    readBitwardenCli: () => {
      throw Error('legacy CLI called');
    },
  };
  execute(api);
  await tick();
  assert.deepEqual(values, [true]);
  execute({ ...api, readAppSettings: async () => ({ promptBeforeTunnelConnect: false }) });
  current = false;
  await tick();
  assert.deepEqual(values, [true], 'an earlier unlock must not publish its settings');
  current = true;
  execute({
    ...api,
    readAppSettings: async () => {
      throw Error('settings unavailable');
    },
  });
  await tick();
  assert.deepEqual(values, [true]);
  let finishRead!: (value: unknown) => void;
  const dispose = execute({
    ...api,
    readAppSettings: () =>
      new Promise((r) => {
        finishRead = r;
      }),
  });
  dispose();
  finishRead({ promptBeforeTunnelConnect: false });
  await tick();
  assert.deepEqual(values, [true]);
  assert.equal(execute(api, 'locked'), undefined);
  assert.equal(execute(undefined), undefined);
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  const branchStart = code.indexOf("if (authState?.mode === 'vault')"),
    branchEnd = code.indexOf('const [settingsResult');
  const ranges = coverage.result
    .filter((s) => s.url === filename)
    .flatMap((s) => s.functions.flatMap((f) => f.ranges))
    .filter((r) => r.startOffset >= branchStart && r.endOffset <= branchEnd);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('Native settings load branch ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});
