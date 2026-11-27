import { runInNewContext } from 'node:vm';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

const require = createRequire(import.meta.url);

test('real sandboxed preload forwards typed unlock bytes before erasing its IPC copy', async (context) => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-preload-'));
  try {
    const preload = join(directory, 'preload.cjs');
    const source = stripTypeScriptTypes(
      readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8'),
    ).replace(
      "import { contextBridge, ipcRenderer, webUtils } from 'electron';",
      "const { contextBridge, ipcRenderer, webUtils } = require('electron');",
    );
    // Observe only clearing, never relay the borrowed factor back to the renderer.
    writeFileSync(
      preload,
      `
      const electron = require('electron');
      const invoke = electron.ipcRenderer.invoke.bind(electron.ipcRenderer);
      let factor, connection, credential;
      electron.ipcRenderer.invoke = (channel, ...args) => {
        if (channel === 'vault:unlock') factor = args[0].factor;
        if (channel === 'vault:save-connection') connection = args[0];
        if (channel === 'vault:edit-credential') credential=args[0];
        return invoke(channel, ...args);
      };
      electron.contextBridge.exposeInMainWorld('testCredentialCleared', () => credential.password.every(byte=>byte===0)&&credential.passphrase.every(byte=>byte===0));
      electron.contextBridge.exposeInMainWorld('testConnectionCleared', () => connection.password.every(byte => byte === 0) && connection.notes.every(byte => byte === 0));
      electron.contextBridge.exposeInMainWorld('testFactorCleared', () => factor.every(byte => byte === 0));
      ${source}
    `,
    );
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      const assert = require('node:assert/strict');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        let calls = 0;
        let workspaceCalls = 0;
        let startupCalls = 0;
        let sharedReads = 0;
        ipcMain.handle('vault:profile-status', (_event,...args) => {assert.equal(args.length,0);return {effective:'standard',source:'os',retainedUntilLock:false};});
        ipcMain.handle('vault:tighten-local-profile', (_event,...args) => {assert.equal(args.length,0);});
        ipcMain.handle('vault:tighten-shared-profile', (_event,...args) => {assert.equal(args.length,0);});
        ipcMain.handle('vault:shared-connection-context',(_event,request)=>{assert.deepEqual(request,{nodeId:'11111111-1111-4111-8111-111111111111'});sharedReads++;return {nodeId:request.nodeId,protocol:7}});
        ipcMain.handle('vault:shared-changes',(_event,request)=>{assert.deepEqual(request,{epoch:'0',changeSeq:'0'});sharedReads++;return {epoch:'1',changeSeq:'9',reset:true,nodes:[]};});
        ipcMain.handle('vault:shared-catalog',(_event,request)=>{assert.deepEqual(request,{after:'',epoch:'0',changeSeq:'0',limit:32});sharedReads++;return {epoch:'1',changeSeq:'9',nodes:[],next:null};});
        let revealCalls = 0, duplicateCalls = 0, moveCalls = 0, deleteCalls = 0, folderCalls = 0, connectionCalls = 0, notesCalls = 0, migrationReads = 0, migrationWrites = 0;
        ipcMain.handle('vault:migration-report',(_event,request)=>{assert.deepEqual(request,{nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'2'});migrationReads++;return {...request,canDecide:false,fingerprint:null,entries:[]};});
        ipcMain.handle('vault:migration-decide',(_event,request)=>{assert.deepEqual(request,{nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'2',fingerprint:'a'.repeat(64),choices:[{protocolPath:'ssh',choice:'new'}]});migrationWrites++;return {nodeId:request.nodeId,rowVersion:'3',updated:true};});
        ipcMain.handle('vault:show-credentials',(_event,request)=>{assert.deepEqual(request,{nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'7'});revealCalls++;});
        ipcMain.handle('vault:show-notes' ,(_event,request)=>{assert.deepEqual(request,{nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'1'});notesCalls++;});
        ipcMain.handle('vault:save-connection', (_event, request) => {
          connectionCalls++;
          assert.ok(request.password instanceof Uint8Array);assert.ok(request.notes instanceof Uint8Array);
          assert.deepEqual([...request.password],[1,2,3]);assert.deepEqual([...request.notes],[4,5,6]);
          request.password.fill(0);request.notes.fill(0);
          return {nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'1',updated:true};
        });
        ipcMain.handle('vault:edit-credential',(_event,request)=>{assert.deepEqual([...request.password],[1,2]);assert.deepEqual([...request.passphrase],[3,4]);return {id:'11111111-1111-4111-8111-111111111111',rowVersion:'1',updated:true};});
        ipcMain.handle('vault:edit-tunnel',(_event,selection)=>{assert.equal(selection,null);return {id:'11111111-1111-4111-8111-111111111111',rowVersion:'1',updated:true};});
        ipcMain.handle('vault:delete-tunnel',(_event,selection)=>{assert.deepEqual(selection,{id:'11111111-1111-4111-8111-111111111111',rowVersion:'1'});return {...selection,rowVersion:'2',deleted:true};});
        ipcMain.handle('vault:delete-credential',(_event,request)=>{assert.deepEqual(request,{id:'11111111-1111-4111-8111-111111111111',rowVersion:'1'});return {...request,rowVersion:'2',deleted:true};});
        ipcMain.handle('vault:save-folder', (_event, request) => {
          assert.deepEqual(request,{id:'',rowVersion:'0',parentId:'',name:'Folder',sshAutoSudo:null,tunnelEnabled:false,tunnelConfigId:'',credentialMode:0,credentialId:''});
          folderCalls++;
          return {nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'1',updated:true};
        });
        ipcMain.handle('vault:duplicate-connection',(_event,request)=>{assert.deepEqual(request,{id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'});duplicateCalls++;return {nodeId:'22222222-2222-4222-8222-222222222222',name:'Copy',rowVersion:'1'};});
        ipcMain.handle('vault:move-nodes', (_event, request) => {
          assert.deepEqual(request,{nodes:[{id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'}],target:{id:'22222222-2222-4222-8222-222222222222',rowVersion:'3'},placement:'after'});moveCalls++;return {moved:true,updatedCount:'0'};
        });
        ipcMain.handle('vault:delete-nodes', (_event, request) => {
          assert.deepEqual(request,{nodes:[{id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'}]});
          deleteCalls++;
          return {deleted:true,deletedCount:'2'};
        });
        ipcMain.handle('vault:sftp-recovery-scopes',(_event,after)=>{assert.equal(after,'');return {nodeIds:['11111111-1111-4111-8111-111111111111'],after:''};});
        ipcMain.handle('vault:sftp-recovery-records',(_event,q)=>{assert.deepEqual(q,{nodeId:'11111111-1111-4111-8111-111111111111',operation:'discard',editId:'22222222-2222-4222-8222-222222222222',decision:'discard'});return {edits:[],after:'',busy:false};});
        ipcMain.handle('vault:startup', (_event, ...args) => {
          assert.equal(args.length, 0);
          startupCalls++;
          return { slots: null, cosmetics: { theme: 'system' }, newWorkspace: false };
        });
        ipcMain.handle('vault:workspace', (_event, ...args) => {
          assert.equal(args.length, 0);
          workspaceCalls++;
          return { tree: [], credentials: [], credentialOptions: { ssh: [], rdp: [], vnc: [] }, tunnels: [] };
        });
        ipcMain.handle('vault:unlock', (_event, request) => {
          assert.ok(request.factor instanceof Uint8Array);
          assert.deepEqual([...request.factor], [1, 2, 3]);
          request.factor.fill(0);
          if (++calls === 2) throw Error('Vault operation failed.');
          return { unlocked: true, lockedMemory: true };
        });
        const window = new BrowserWindow({ show: false, webPreferences: {
          preload: ${JSON.stringify(preload)}, sandbox: true, contextIsolation: true, nodeIntegration: false,
        } });
        try {
          await window.loadURL('data:text/html,<html></html>');
          const result = await window.webContents.executeJavaScript(
            '(' + (async () => {
              let rejected = false;
              for (let i = 0; i < 2; i++) {
                const factor = new Uint8Array([1, 2, 3]);
                let pending;
                try { pending = window.wormhole.unlockVault({ vaultId: '11111111-1111-4111-8111-111111111111', slotId: '22222222-2222-4222-8222-222222222222', kind: 'password', factor }); }
                finally { factor.fill(0); }
                if (!window.testFactorCleared() || !factor.every(byte => byte === 0)) throw Error('Factor retained');
                try {
                  const value = await pending;
                  if (i !== 0 || !value.unlocked || !value.lockedMemory) throw Error('Unexpected result');
                } catch (error) {
                  if (i !== 1 || !error.message.includes('Vault operation failed.')) throw error;
                  rejected = true;
                }
              }
              const saved = await window.wormhole.saveVaultConnection({metadata:{},rowVersion:'0',notesAction:'set',password:new Uint8Array([1,2,3]),notes:new Uint8Array([4,5,6])});
              if(!saved.updated || !window.testConnectionCleared()) throw Error('Connection bytes retained in preload');
              const credential=await window.wormhole.editVaultCredential({metadata:{},rowVersion:'0',password:new Uint8Array([1,2]),passphrase:new Uint8Array([3,4])});
              if(!credential.updated||!window.testCredentialCleared())throw Error('Credential bridge retained bytes');
              const tunnel=await window.wormhole.editVaultTunnel(null);
              if(tunnel.updated!==true)throw Error('Tunnel editor result lost');
              const removedTunnel=await window.wormhole.deleteVaultTunnel({id:tunnel.id,rowVersion:tunnel.rowVersion});
              if(removedTunnel.deleted!==true)throw Error('Tunnel deletion result lost');
              const removedCredential=await window.wormhole.deleteVaultCredential({id:credential.id,rowVersion:credential.rowVersion});
              if(!removedCredential.deleted||removedCredential.rowVersion!=='2')throw Error('Credential deletion bridge failed');
              const folder = await window.wormhole.saveVaultFolder({id:'',rowVersion:'0',parentId:'',name:'Folder',sshAutoSudo:null,tunnelEnabled:false,tunnelConfigId:'',credentialMode:0,credentialId:''});
              if(!folder.updated || folder.rowVersion!=='1' || folder.nodeId!=='11111111-1111-4111-8111-111111111111') throw Error('Folder bridge failed');
              await window.wormhole.showVaultCredentials({nodeId:'11111111-1111-4111-8111-111111111111',rowVersion:'7'});
              const workspace = await window.wormhole.loadVaultWorkspace();
              const scopes=await window.wormhole.readVaultSftpRecoveryScopes();
              if(scopes.nodeIds[0]!=='11111111-1111-4111-8111-111111111111')throw Error('Recovery scope bridge failed');
              const copies=await window.wormhole.vaultSftpRecovery({nodeId:scopes.nodeIds[0],operation:'discard',editId:'22222222-2222-4222-8222-222222222222',decision:'discard'});
              if(copies.busy||copies.edits.length)throw Error('Recovery action bridge failed');

              const duplicated=await window.wormhole.duplicateVaultConnection({id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'});
              if(duplicated.nodeId!=='22222222-2222-4222-8222-222222222222'||duplicated.rowVersion!=='1'||duplicated.name!=='Copy')throw Error('Duplicate bridge failed');
              const movement=await window.wormhole.moveVaultNodes({nodes:[{id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'}],target:{id:'22222222-2222-4222-8222-222222222222',rowVersion:'3'},placement:'after'});
              if(!movement.moved||movement.updatedCount!=='0')throw Error('Move bridge failed');
              const deletion = await window.wormhole.deleteVaultNodes({nodes:[{id:'11111111-1111-4111-8111-111111111111',rowVersion:'7'}]});
              if(!deletion.deleted || deletion.deletedCount!=='2')throw Error('Deletion bridge failed');
              const startup = await window.wormhole.loadVaultStartup();
              const connectionContext=await window.wormhole.readSharedConnectionContext('11111111-1111-4111-8111-111111111111');if(connectionContext.protocol!==7||connectionContext.nodeId!=='11111111-1111-4111-8111-111111111111')throw Error('Invalid native connection context bridge');
              const changes=await window.wormhole.loadSharedChanges({epoch:'0',changeSeq:'0'});
              const catalog=await window.wormhole.loadSharedCatalogPage({after:'',epoch:'0',changeSeq:'0',limit:32});
              if(!changes.reset||changes.changeSeq!=='9'||catalog.next!==null||catalog.nodes.length!==0)throw Error('Shared catalog bridge failed');
              if (startup.slots !== null || startup.cosmetics.theme !== 'system') throw Error('Startup bridge failed');
              if (!Array.isArray(workspace.tree) || workspace.tree.length !== 0 || !Array.isArray(workspace.credentialOptions.ssh)) throw Error('Workspace bridge failed');
              return rejected;
            }).toString() + ')()');
          assert.equal(result, true);
          assert.equal(calls, 2);
          assert.equal(workspaceCalls, 1);
          assert.equal(startupCalls, 1);
          assert.equal(sharedReads, 3);
          assert.equal(deleteCalls, 1);
          assert.equal(moveCalls, 1);
          assert.equal(duplicateCalls, 1);
          assert.equal(revealCalls, 1);
          assert.equal(folderCalls, 1);
          assert.equal(connectionCalls, 1);
          await window.webContents.executeJavaScript(\`
            window.lockCount = 0;
            window.lockEvent = new Promise(resolve => {
              window.removeLockListener = window.wormhole.onVaultLocked((...args) => {
                window.lockCount++;
                resolve(args.length);
              });
            });
            true;
          \`);
          window.webContents.send('vault:locked', { ignored: 'never-forward' });
          assert.equal(await window.webContents.executeJavaScript('window.lockEvent'), 0);
          await window.webContents.executeJavaScript('window.removeLockListener(); true;');
          window.webContents.send('vault:locked');
          assert.equal(await window.webContents.executeJavaScript('window.lockCount'), 1);
          await window.webContents.executeJavaScript('window.changeCount=0;window.changeEvent=new Promise(resolve=>{window.removeChange=window.wormhole.onSharedCatalogChanged((...args)=>{window.changeCount++;resolve(args.length)});});true;');
          window.webContents.send('vault:shared-catalog-changed',{untrusted:'ignored'});
          assert.equal(await window.webContents.executeJavaScript('window.changeEvent'),0);
          await window.webContents.executeJavaScript('window.removeChange();true;');
          window.webContents.send('vault:shared-catalog-changed');
          assert.equal(await window.webContents.executeJavaScript('window.changeCount'),1);
          assert.deepEqual(await window.webContents.executeJavaScript('window.wormhole.getVaultSecurityProfile("ignored")'),{effective:'standard',source:'os',retainedUntilLock:false});
          await window.webContents.executeJavaScript('window.wormhole.tightenLocalVaultProfile("ignored")');
          await window.webContents.executeJavaScript('window.wormhole.tightenSharedVaultProfile("ignored")');
          await window.webContents.executeJavaScript('window.profileCount=0;window.profileEvent=new Promise(resolve=>{window.removeProfile=window.wormhole.onVaultSecurityProfileChanged((...args)=>{window.profileCount++;resolve(args.length)});});true;');
          window.webContents.send('vault:profile-changed',{ignored:true});
          assert.equal(await window.webContents.executeJavaScript('window.profileEvent'),0);
          await window.webContents.executeJavaScript('window.removeProfile();true;');
          window.webContents.send('vault:profile-changed');
          assert.equal(await window.webContents.executeJavaScript('window.profileCount'),1);
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...env } = process.env;
    const electron = require('electron') as string;
    const headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...env, NODE_ENV: 'test' }, windowsHide: true, timeout: 30_000 },
    );
    if (stdout.trim()) context.diagnostic(stdout.trim());
    if (stderr.trim()) context.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});

test('credential preload clears borrowed factors even when IPC throws synchronously', () => {
  const source = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const begin = source.indexOf('  editVaultCredential:'),
    end = source.indexOf('  deleteVaultCredential:', begin);
  assert.ok(begin > 0 && end > begin);
  for (const throws of [true, false]) {
    const request = { password: new Uint8Array([1]), passphrase: new Uint8Array([2]) };
    const api = runInNewContext(stripTypeScriptTypes('({' + source.slice(begin, end) + '})'), {
      Uint8Array,
      ipcRenderer: {
        invoke: (channel: string, value: any) => {
          assert.equal(channel, 'vault:edit-credential');
          assert.deepEqual([...value.password], [1]);
          assert.deepEqual([...value.passphrase], [2]);
          if (throws) throw Error('IPC unavailable');
          return Promise.resolve({ updated: true });
        },
      },
    });
    if (throws) assert.throws(() => api.editVaultCredential(request), /IPC unavailable/);
    else api.editVaultCredential(request);
    assert.deepEqual([...request.password], [0]);
    assert.deepEqual([...request.passphrase], [0]);
  }
});
