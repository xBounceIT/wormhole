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

test('actual native connection fields keep secrets outside React state across tabs and clear explicit removals', async (t) => {
  const require = createRequire(import.meta.url),
    source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8').replaceAll('\r', '');
  const label = source.indexOf('<Label htmlFor="connection-notes">');
  const notesStart = source.lastIndexOf("{connectionEditorMode === 'saved' ? (", label),
    notesEnd = source.indexOf(
      '\n\n                    <div\n                      className={cn(',
      label,
    );
  const passwordLabel = source.indexOf('<Label htmlFor="connection-inline-password">');
  const passwordStart = source.lastIndexOf('<div className="grid gap-2">', passwordLabel),
    passwordEnd =
      source.indexOf(
        '\n                        </div>\n                      </div>',
        passwordLabel,
      ) + '\n                        </div>'.length;
  const tabStart = source.lastIndexOf('<TabsContent', label),
    tabEnd = source.indexOf('>', tabStart) + 1;
  assert.ok(
    notesStart > 0 &&
      notesEnd > notesStart &&
      passwordStart > 0 &&
      passwordEnd > passwordStart &&
      tabStart > 0,
  );
  const tabsStart = source.lastIndexOf('<Tabs\n', label),
    tabsEnd = source.indexOf('>', tabsStart) + 1;
  const tabEffect = source.slice(
    source.indexOf('  useEffect(() => {\n    setNativeConnectionTab('),
    source.indexOf('  const editingConnectionNotesId ='),
  );
  const transformed = await transformWithOxc(
    `
 const Label='label',Textarea='textarea',PasswordInput='input';
 const Button=({size,variant,...props})=><button {...props}/>;
 const clearSecretInput=input=>{if(input)input.value='';};
 const connectionInlinePasswordPlaceholder=has=>has?'Keep stored password':'Enter password';
 let state, controls,notesError; const connectionEditorGeneration={current:1},editingConnectionVersion={current:"1"};
 function Harness({native,edit}) {
  const editorBusy=false,setEditorError=value=>notesError=value;
  const nativeSavedConnection=native,connectionEditorMode='saved',connectionNotesReady=true,newConnectionOpen=true;
  const editingConnectionId=edit?'node':null,editingConnectionHasInlineCredential=edit;
  const nativeConnectionPassword=React.useRef(null),nativeConnectionNotes=React.useRef(null);
  const [newConnectionForm,setNewConnectionForm]=React.useState({notes:'',inlinePassword:'',removeInlinePassword:false,protocol:'ssh'});
  const [removeNativeNotes,setRemoveNativeNotes]=React.useState(false);
  const [nativeConnectionTab,setNativeConnectionTab]=React.useState('general');
  ${tabEffect}
  state=newConnectionForm;controls={setNewConnectionForm,setRemoveNativeNotes};
  return ${source.slice(tabsStart, tabsEnd)}<TabsList><TabsTrigger value="general">General</TabsTrigger><TabsTrigger value="other">Other</TabsTrigger></TabsList>
   ${source.slice(tabStart, tabEnd)}${source.slice(notesStart, notesEnd)}${source.slice(passwordStart, passwordEnd)}</TabsContent>
   <TabsContent value="other">Other settings</TabsContent></Tabs>;
 }
 `,
    'vault-connection-fields.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderer = `
 const React=require(${JSON.stringify(require.resolve('react'))});const {useEffect}=React;const connectionTypeForProtocol=value=>value;
 const {createRoot}=require(${JSON.stringify(require.resolve('react-dom/client'))});
 const primitive=require(${JSON.stringify(require.resolve('radix-ui'))}).Tabs;
 const Tabs=primitive.Root,TabsList=primitive.List,TabsTrigger=primitive.Trigger,TabsContent=primitive.Content;
 const assert=require('node:assert/strict');globalThis.IS_REACT_ACT_ENVIRONMENT=true;
 ${transformed.code}
 (async()=>{
 const root=createRoot(document.getElementById('root'));let key=0;
 const mount=async(native,edit)=>React.act(async()=>root.render(React.createElement(Harness,{native,edit,key:++key})));
 const input=async(id,value)=>React.act(async()=>{const el=document.getElementById(id);Object.getOwnPropertyDescriptor(el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));});
 const tab=async(value)=>React.act(async()=>{const el=document.querySelector('[role=tab][data-state=inactive]');el.dispatchEvent(new MouseEvent('mousedown',{bubbles:true,button:0}));});
 for(const edit of [false,true]) {
  await mount(true,edit);await input('connection-inline-password','native-password');await input('connection-notes','native-notes');
  assert.equal(state.inlinePassword,'');assert.equal(state.notes,'');
  await tab('other');assert.equal(document.getElementById('connection-notes').value,'native-notes');assert.equal(document.getElementById('connection-inline-password').value,'native-password');
  await tab('general');assert.equal(document.getElementById('connection-notes').value,'native-notes');
  await tab('other');await React.act(async()=>controls.setNewConnectionForm(f=>({...f,protocol:'rdp'})));assert.equal(document.querySelector('[role=tab][data-state=active]').textContent,'General');assert.equal(document.getElementById('connection-notes').value,'native-notes');assert.equal(document.getElementById('connection-inline-password').value,'native-password');
  if(edit) {
   const clear=async(text)=>React.act(async()=>Array.from(document.querySelectorAll('button')).find(b=>b.textContent===text).click());
   let requests=[];window.wormhole={showVaultNotes:async request=>{requests.push(request);}};
   await clear('View stored notes');assert.deepEqual(requests,[{nodeId:'node',rowVersion:'1'}]);
   window.wormhole.showVaultNotes=async()=>{throw Error('private');};await clear('View stored notes');assert.ok(notesError.includes('unavailable'));assert.ok(!notesError.includes('private'));
   notesError='';let reject;window.wormhole.showVaultNotes=()=>new Promise((_,no)=>reject=no);await clear('View stored notes');connectionEditorGeneration.current++;await React.act(async()=>reject(Error('late')));assert.equal(notesError,'');
   await clear('Clear password');assert.equal(document.getElementById('connection-inline-password').value,'');assert.equal(document.getElementById('connection-inline-password').disabled,true);
   await clear('Clear password');assert.equal(document.getElementById('connection-inline-password').disabled,false);
   await clear('Clear stored notes');assert.equal(document.getElementById('connection-notes').value,'');assert.equal(document.getElementById('connection-notes').disabled,true);
   await clear('Clear stored notes');assert.equal(document.getElementById('connection-notes').disabled,false);
  }
 }
 await mount(false,true);await input('connection-inline-password','legacy-password');await input('connection-notes','legacy-notes');assert.equal(state.inlinePassword,'legacy-password');assert.equal(state.notes,'legacy-notes');
 await React.act(async()=>controls.setNewConnectionForm(f=>({...f,removeInlinePassword:true})));assert.equal(document.getElementById('connection-inline-password').disabled,true);
 await mount(false,false);await React.act(async()=>root.unmount());
 })();
 //# sourceURL=wormhole-vault-connection-fields.js
 `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-connection-fields-'));
  try {
    const harness = join(directory, 'fields.cjs');
    writeFileSync(
      harness,
      `
   const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');
   app.setPath('userData',${JSON.stringify(directory)});app.setPath('sessionData',${JSON.stringify(directory)});
   app.whenReady().then(async()=>{const owner=new BrowserWindow({show:false,webPreferences:{nodeIntegration:true,contextIsolation:false}});
   owner.webContents.on('console-message',(event)=>{if(event.level==='error')console.error(event.message)});
   try {await owner.loadURL('data:text/html,<div id="root"></div>');const api=owner.webContents.debugger;api.attach('1.3');await api.sendCommand('Profiler.enable');await api.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});
   await owner.webContents.executeJavaScript(${JSON.stringify(renderer)});
   const report=await api.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-vault-connection-fields.js');const fn=script.functions.find(f=>f.functionName==='Harness');const scope=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=scope.startOffset&&f.ranges[0].endOffset<=scope.endOffset).flatMap(f=>f.ranges);const percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('Native connection fields: '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=${coverageThreshold});
   }finally {owner.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});
  `,
    );
    const { ELECTRON_RUN_AS_NODE: _run, ...env } = process.env,
      electron = require('electron') as string,
      headless = process.platform === 'linux' && !env.DISPLAY;
    const result = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...env, NODE_ENV: 'test' }, timeout: 30000, windowsHide: true },
    );
    t.diagnostic(result.stdout.trim());
    if (result.stderr.trim()) t.diagnostic(result.stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
