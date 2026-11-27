import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
const require = createRequire(import.meta.url);
const source = stripTypeScriptTypes(
  readFileSync(new URL('../electron/vault-tunnel-preload.cts', import.meta.url), 'utf8'),
).replace(
  "import { contextBridge, ipcRenderer } from 'electron';",
  "const { contextBridge, ipcRenderer } = require('electron');",
);

test('tunnel preload clears its copy immediately on synchronous IPC failure and malformed input', async () => {
  let api: any;
  runInNewContext(source, {
    process: { platform: 'linux' },
    Uint8Array,
    require: () => ({
      contextBridge: {
        exposeInMainWorld: (name: string, value: any) => {
          assert.equal(name, 'vaultTunnel');
          api = value;
        },
      },
      ipcRenderer: {
        invoke: () => {
          throw Error('send failure');
        },
      },
    }),
  });
  const patch = new Uint8Array([1, 2, 3]);
  assert.throws(() => api.save({ patch }), /send failure/);
  assert.deepEqual([...patch], [0, 0, 0]);
  assert.throws(() => api.save(null), /send failure/);
  assert.throws(() => api.save({ patch: [] }), /send failure/);
  assert.equal(api.contentProtectionAvailable, false);
});

test('actual isolated tunnel preload forwards patches once and erases its borrowed copy before a reply', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-tunnel-preload-'));
  try {
    const preload = join(directory, 'preload.cjs');
    writeFileSync(
      preload,
      `
      const electron = require('electron');
      const invoke = electron.ipcRenderer.invoke.bind(electron.ipcRenderer);
      let borrowed;
      electron.ipcRenderer.invoke = (channel, ...args) => {
        if (channel === 'vault-tunnel:save') borrowed=args[0].patch;
        return invoke(channel, ...args);
      };
      electron.contextBridge.exposeInMainWorld('testCleared', () => borrowed.every(b=>b===0));
      ${source}
    `,
    );
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
      const {app,BrowserWindow,ipcMain}=require('electron');const assert=require('node:assert/strict');
      app.setPath('userData',${JSON.stringify(directory)}); app.setPath('sessionData',${JSON.stringify(directory)});
      app.whenReady().then(async()=>{
        let calls=0,reads=0,closed=0;
        ipcMain.handle('vault-tunnel:context',(_event,...args)=>{assert.equal(args.length,0);return{workspaceId:'workspace',requestId:'request',selection:null};});
        ipcMain.handle('vault-tunnel:capabilities',()=>({openVpn:false}));
        ipcMain.handle('vault-tunnel:references',()=>({connections:[],credentials:[]}));
        ipcMain.handle('vault-tunnel:read',(_event,key)=>{assert.equal(key,'recipient');reads++;return{bundle:'sealed'};});
        ipcMain.handle('vault-tunnel:import',(_event,choice)=>{assert.deepEqual(choice,{kind:1,format:'openvpn',importId:'id',publicKey:'key'});return{sealed:'import'};});
        ipcMain.handle('vault-tunnel:discard-import',(_event,...args)=>{assert.equal(args.length,0);});
        ipcMain.handle('vault-tunnel:save',async(_event,value)=>{
          assert.equal(value.metadata.name,'Tunnel'); assert.equal(value.rowVersion,'0');
          assert.ok(value.patch instanceof Uint8Array);assert.deepEqual([...value.patch],[65,66,67]);value.patch.fill(0);
          const number=++calls;await new Promise(r=>setTimeout(r,10));if(number===2)throw Error('Save failed.');return true;
        });
        ipcMain.handle('vault-tunnel:close',(_event,...args)=>{assert.equal(args.length,0);closed++;});
        const window=new BrowserWindow({show:false,webPreferences:{preload:${JSON.stringify(preload)},sandbox:true,contextIsolation:true,nodeIntegration:false}});
        try{
          await window.loadURL('data:text/html,<html></html>');
          await window.webContents.executeJavaScript('('+ (async()=>{
            if(window.wormhole!==undefined||window.require!==undefined)throw Error('General API exposed');
            if(Object.keys(window.vaultTunnel).sort().join(',')!=='capabilities,close,contentProtectionAvailable,context,discardImport,importProfile,read,references,save')throw Error('Unexpected bridge');
            const context=await window.vaultTunnel.context();if(context.selection!==null)throw Error('Wrong context');
            if((await window.vaultTunnel.capabilities()).openVpn!==false)throw Error('Wrong capabilities');
            if((await window.vaultTunnel.references()).connections.length!==0)throw Error('Wrong references');
            const read=await window.vaultTunnel.read('recipient');if(read.bundle!=='sealed')throw Error('Wrong sealed response');
            if((await window.vaultTunnel.importProfile({kind:1,format:'openvpn',importId:'id',publicKey:'key'})).sealed!=='import')throw Error('Wrong import');
            await window.vaultTunnel.discardImport();
            for(let i=0;i<2;i++){
              const patch=new Uint8Array([65,66,67]);let pending;
              try{pending=window.vaultTunnel.save({metadata:{id:'',name:'Tunnel',kind:1},rowVersion:'0',forgetHostKey:false,patch});}
              finally{patch.fill(0);}
              if(!window.testCleared()||!patch.every(b=>b===0))throw Error('Patch retained during IPC');
              let failed=false;try{if(await pending!==true)throw Error('Wrong result');}catch(e){failed=true;if(!e.message.includes('Save failed.'))throw e;}
              if(failed!==(i===1))throw Error('Wrong failure handling');
            }
            await window.vaultTunnel.close();
          }).toString()+')()');
          assert.equal(calls,2);assert.equal(reads,1);assert.equal(closed,1);
        }finally{window.destroy();}app.quit();
      }).catch(error=>{console.error(error);app.exit(1);});
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...env } = process.env;
    const electron = require('electron') as string,
      headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, windowsHide: true, timeout: 30_000 },
    );
    if (stdout.trim()) t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
