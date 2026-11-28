import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { cp, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { appRdpDefaults, connectionInput } from './fixtures/vault-connection.ts';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const backend = join(root, 'tools', 'wormhole-backend');
const nativeSuffix = process.platform === 'win32' ? '.exe' : '';
const syntheticServerFactor = 'synthetic-standalone-server-key-factor';
const electron = createRequire(import.meta.url)('electron') as string;
const wizardBackend =
  process.env.WORMHOLE_TEST_SETUP_BACKEND ??
  join(root, 'dist-electron', `wormhole-backend-${process.arch}${nativeSuffix}`);

function startDatabase(fixture: string, scratch: string, withCSR: boolean, generated: boolean) {
  const server = spawn(
    fixture,
    ['-test.run=^TestPostgresSetupApplicationFixture$', '-test.timeout=240s'],
    {
      cwd: backend,
      windowsHide: true,
      stdio: 'pipe',
      env: {
        ...process.env,
        WORMHOLE_TEST_SETUP_APPLICATION: '1',
        WORMHOLE_TEST_SETUP_CSR: withCSR ? '1' : '',
        WORMHOLE_TEST_SETUP_GENERATED: generated ? '1' : '',
        ...(generated ? { WORMHOLE_TEST_SETUP_KEY_PASSPHRASE: syntheticServerFactor } : {}),
        WORMHOLE_TEST_POSTGRES_SCRATCH: scratch,
      },
    },
  );
  server.stderr.resume();
  const closed = new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('close', (code) =>
      code === 0 ? resolve() : reject(Error('Wizard database fixture failed.')),
    );
  });
  void closed.catch(() => undefined);
  const lines = createInterface({ input: server.stdout })[Symbol.asyncIterator]();
  return {
    send: (value: object) => server.stdin.write(JSON.stringify(value) + '\n'),
    async read() {
      for (;;) {
        const line = await lines.next();
        if (line.done) throw Error('Wizard database fixture closed early.');
        if (line.value.startsWith('{')) return JSON.parse(line.value);
        if (line.value.startsWith('    ')) throw Error(line.value.trim());
      }
    },
    async close() {
      server.stdin.end();
      await closed;
    },
  };
}

async function exerciseWizard(
  directory: string,
  mode:
    | 'run'
    | 'export'
    | 'csr-prepare'
    | 'generated-prepare'
    | 'csr-run'
    | 'reopen'
    | 'catalog-mismatch'
    | 'admin-prepare'
    | 'admin-enroll'
    | 'admin-reopen'
    | 'admin-suspend-before-restart'
    | 'admin-resume-suspension'
    | 'custodian-resume-suspension'
    | 'admin-group-suspension'
    | 'admin-renew'
    | 'admin-renew-denied'
    | 'admin-ca-status'
    | 'admin-ca-rotate'
    | 'admin-ca-retire'
    | 'admin-tls-export'
    | 'admin-offline-no-bundle'
    | 'admin-offline-signin'
    | 'admin-refresh-recovery-kit'
    | 'admin-backup'
    | 'admin-issue-reset'
    | 'admin-revoke-live'
    | 'local-create',
  target: {
    schemaVersion: number;
    directConnectionDevices?: number;
    expectConnectionLimit?: boolean;
    importLocal?: boolean;
    checkStandardPin?: boolean;
    chooseStandard?: boolean;
    webFixturePort?: number;
    generated?: boolean;
    hbaInstalled?: boolean;
    csr?: string;
    tlsBundlePath?: string;
    rejectTLSUpdate?: boolean;
    recoveryKitSource?: string;
    recoveryKitDestination?: string;
    recoveryKitAuthentication?: 'retry' | 'cancel';
    adminRecovery?: { workspaceId: string; roleTag: string };
    backupPath?: string;
    backupRoleTag?: string;
    restoreTarget?: { host: string; port: number; database: string };
    denyBackup?: boolean;
    resetOfferPaths?: [string, string];
    groupRotation?: { subject: string; groupId: string; boundaryId: string };
    resumeGroup?: boolean;
    groupHandoff?: boolean;
  },
  withASK = true,
  existingLocal = false,
  inspectConnections?: () => Promise<void>,
) {
  const signingGroupSuspension =
    mode === 'admin-group-suspension' &&
    target.groupHandoff &&
    target.groupRotation &&
    !target.resumeGroup;
  const appData = join(
      directory,
      signingGroupSuspension
        ? 'group-issuer'
        : mode === 'custodian-resume-suspension'
          ? 'recovered'
          : 'profile',
    ),
    resultPath = join(directory, `receipt-${mode}.json`),
    harness = join(directory, `wizard-${mode}.cjs`);
  await mkdir(appData, { recursive: true });
  const fromDist = (file: string) =>
    JSON.stringify(pathToFileURL(join(root, 'dist-electron', file)).href);
  await writeFile(
    harness,
    `
const {app,BrowserWindow,ipcMain}=require('electron');
const {writeFileSync}=require('node:fs');
const assert=require('node:assert/strict');
app.setPath('userData',${JSON.stringify(appData)});
app.disableHardwareAcceleration();
app.on('window-all-closed',()=>{});
app.whenReady().then(async()=>{
 const {VaultBackendHost}=await import(${fromDist('vault-host.js')});
 const {VaultBackendClient}=await import(${fromDist('vault-client.js')});
 const {VaultSharedSetupDialog}=await import(${fromDist('vault-shared-setup-dialog.js')});
 let native,onAdmissionLost,onCatalogChanged;
 const makeHost=()=>new VaultBackendHost(()=>native=new VaultBackendClient({executable:${JSON.stringify(resolve(wizardBackend))},databasePath:${JSON.stringify(join(appData, 'workspace.db'))},userDataPath:${JSON.stringify(appData)},onUnavailable:reason=>onAdmissionLost?.(reason),onSharedCatalogChanged:()=>onCatalogChanged?.()}),()=>true);
 let host=makeHost();
 const target=${JSON.stringify(target)},mode=${JSON.stringify(mode)},existingLocal=${existingLocal};
 const exerciseSlotBinding=target.importLocal&&!target.checkStandardPin&&!target.webFixturePort;
 const exerciseSharedDefault=exerciseSlotBinding||target.checkStandardPin;
 const slotConnectionName='Slot binding test connection';
 const overrideConnectionName='Credential review RDP';
 const sharedCredentialName='Operations RDP account';
 const personalCredentialName='My RDP account';
 const accountPassword='synthetic-administrator-password';
 const localPassword='synthetic-local-vault-password';
 const ask=${withASK ? "'4b'.repeat(32)" : "''"};
 const suspensionRestart=mode==='admin-suspend-before-restart'||mode==='admin-resume-suspension'||mode==='custodian-resume-suspension';
 if(suspensionRestart||mode==='admin-group-suspension'||mode==='admin-reopen'||mode==='admin-renew'||mode==='admin-renew-denied'||mode.startsWith('admin-ca-')||mode==='admin-tls-export'||mode==='admin-offline-no-bundle'||mode==='admin-refresh-recovery-kit'||mode==='admin-backup'||mode==='admin-issue-reset'||mode==='admin-revoke-live') {
   let window;
   try {
     const startup=await host.startup();
     assert.ok(startup.shared && !startup.sharedJoin && startup.slots);
     if(mode==='custodian-resume-suspension')assert.equal(startup.shared.lastLoginName,'recovered-admin');
     const slot=startup.slots.slots.find(slot=>slot.kind==='password');
     const admit=()=>host.sharedUnlock({vaultId:startup.slots.vaultId,slotId:slot.id,password:new TextEncoder().encode(accountPassword),...(ask?{ask:Buffer.from(ask,'hex')}:{})},'2.4.3',()=>true);
     if(target.expectConnectionLimit){
       const {SharedConnectionLimit}=await import(${fromDist('vault-shared-unlock.js')});
       await assert.rejects(admit(),SharedConnectionLimit);
       assert.equal(host.unlockedWorkspaceId,undefined);
       writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({limited:true}),{mode:0o600});
       app.quit();
       return;
     }
     if(mode==='admin-offline-no-bundle'){
       await assert.rejects(admit());
       writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({rejected:true}),{mode:0o600});
       app.quit();
       return;
     }
     const admission=await admit();
     assert.ok(admission.admitted);
     assert.equal(admission.tls,'verified');
     if(process.env.WORMHOLE_TEST_INSPECT_PORT){
       const before=await host.sharedChanges({epoch:'0',changeSeq:'0'},()=>true);
       const notified=new Promise(resolve=>{onCatalogChanged=resolve});
       const result=await fetch('http://127.0.0.1:'+process.env.WORMHOLE_TEST_INSPECT_PORT);
       assert.equal(result.status,204,'device connection inspection failed');
       if(target.directConnectionDevices>0 && target.directConnectionDevices<=300){
         const stop=new AbortController();
         try {
           await Promise.race([notified,require('node:timers/promises').setTimeout(12_000,undefined,{signal:stop.signal}).then(()=>{throw Error('PostgreSQL change hint did not reach Electron')})]);
         } finally { stop.abort(); }
         const after=await host.sharedChanges({epoch:before.epoch,changeSeq:before.changeSeq},()=>true);
         assert.equal(after.epoch,before.epoch);
         assert.equal(after.changeSeq,before.changeSeq);
       }
       onCatalogChanged=undefined;
     }
     if(mode==='admin-reopen'){
       const profile=await host.security();
       assert.equal(profile.effective,ask?'standard':'default');
       assert.equal(profile.workspace,profile.effective);
       assert.equal(profile.source,'workspace');
       assert.equal(profile.retainedUntilLock,undefined);
       if(target.chooseStandard){
         assert.equal(profile.canTightenToStandard,true);
         const currentWorkspace=host.unlockedWorkspaceId;
         let locked=0;
         await host.tightenSharedProfile(async (metadata,current,submit)=>{
           assert.ok(current());
           const factors=(password)=>({vaultId:metadata.slots.vaultId,slotId:slot.id,password:new TextEncoder().encode(password),appVersion:'2.4.3'});
           const outdated=factors(accountPassword);
           await assert.rejects(native.tightenSharedProfile(String(BigInt(profile.sequence)+1n),outdated));
           assert.ok(outdated.password.every(byte=>byte===0));
           const wrong=factors('wrong-synthetic-password');
           await assert.rejects(submit(wrong,()=>true));
           assert.ok(wrong.password.every(byte=>byte===0));
           const afterDenial=await host.security().catch(()=>{throw Error('Shared owner retired after incorrect profile factor')});
           assert.equal(afterDenial.effective,'default');
           const correct=factors(accountPassword);
           const saved=await submit(correct,()=>true).catch(()=>{throw Error('Could not commit authenticated personal Standard')});
           assert.ok(correct.password.every(byte=>byte===0));
           return saved;
         },()=>true,async()=>{locked++;await host.stop();});
         assert.equal(locked,1);
         await host.startup().catch(()=>{throw Error('Could not read startup after personal Standard')});
         assert.ok((await admit().catch(()=>{throw Error('Could not admit device with persisted personal Standard')})).admitted);
         assert.equal(host.unlockedWorkspaceId,currentWorkspace);
         const updated=await host.security();
         assert.equal(updated.workspace,'default');
         assert.equal(updated.user,'standard');
         assert.equal(updated.source,'user');
         assert.equal(updated.effective,'standard');
         assert.equal(updated.canTightenToStandard,undefined);
         assert.equal(updated.sequence,profile.sequence);
       }
     }
     let result={workspaceId:host.unlockedWorkspaceId,admitted:true};
     if(mode==='admin-group-suspension'){
       const {prepareGroup,suspendAccount,waitForRotation}=await import(${JSON.stringify(pathToFileURL(join(root, 'tests', 'fixtures', 'vault-shared-suspension.mjs')).href)});
       assert.equal(startup.shared.lastLoginName,${signingGroupSuspension ? "'group-issuer'" : "'first-admin'"});
       await host.openSharedAdministration(()=>true,async(_current,ports)=>{
         if(!target.groupRotation){result=await prepareGroup(ports);return;}
         if(!target.resumeGroup)await suspendAccount(ports,target.groupRotation);
         const status=target.resumeGroup?'resolved':target.groupHandoff?'needs-removal':'queued';
         await waitForRotation(ports,target.groupRotation,status);
         result={status};
       });
     }
     if(suspensionRestart){
       await host.openSharedAdministration(()=>true,async(current,ports)=>{
         const accounts=await ports.read({kind:'accounts'});
         assert.equal(accounts.status,'ready');
         const accountId=accounts.page.entries.find(entry=>entry.login==='restart-test-account')?.id;
         assert.ok(current()&&accountId);
         const inventory=async()=>{
           const read=await ports.suspension({accountId,kind:'roots'});
           assert.equal(read.status,'ready');
           assert.equal(read.page.entries.length,1);
           return read.page.entries[0].status;
         };
         if(mode==='admin-suspend-before-restart'){
           const request={action:'disable-account',targetId:accountId};
           const review=await ports.access(request);
           assert.equal(review.status,'review');
           assert.equal((await ports.access({...request,revision:review.review.revision})).status,'changed');
           assert.equal(await inventory(),'active');
         } else {
           const deadline=Date.now()+10_000;
           while(await inventory()!=='retired'){
             assert.ok(Date.now()<deadline,'reopened vault did not resume the confirmed rotation');
             await new Promise(resolve=>setTimeout(resolve,50));
           }
         }
       });
     }
     if(mode==='admin-revoke-live'){
       const recoveryRoot=${JSON.stringify(join(directory, 'recovered'))};
       const actor=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(resolve(wizardBackend))},databasePath:require('node:path').join(recoveryRoot,'workspace.db'),userDataPath:recoveryRoot}),()=>true);
       const {setTimeout:deadline}=require('node:timers/promises');
       try {
         const recovered=await actor.startup();
         assert.equal(recovered.shared.lastLoginName,'recovered-admin');
         const actorSlot=recovered.slots.slots.find(slot=>slot.kind==='password');
         await actor.sharedUnlock({vaultId:recovered.slots.vaultId,slotId:actorSlot.id,password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex')},'2.4.3',()=>true);
         await actor.openSharedAdministration(()=>true,async(current,ports)=>{
           const find=async kind=>{
             const result=await ports.read({kind});
             assert.equal(result.status,'ready');
             const entry=result.page.entries.find(e=>e.login==='first-admin'&&(kind==='accounts'||e.status==='active'));
             assert.ok(entry,'the victim must be directly admitted or have an active device');
             return entry.id;
           };
           const change=async(action,targetId)=>{
             assert.ok(current());
             const reviewed=await ports.access({action,targetId});
             assert.equal(reviewed.status,'review');
             assert.equal((await ports.access({action,targetId,revision:reviewed.review.revision})).status,'changed');
           };
           const withdraw=async(action,id)=>{
             const aborted=new AbortController();
             const retired=new Promise(resolve=>{onAdmissionLost=resolve});
             try {
               await change(action,id);
               // Heartbeat traffic is still active. The victim issues no catalog or
               // runtime-state requests between admission and the native exit.
               // This enrollment uses the 30-second polling fallback.
               const reason=await Promise.race([
                 retired,
                 deadline(40_000,undefined,{signal:aborted.signal}).then(()=>{throw Error('The idle victim retained its backend after '+action+'.')}),
               ]);
               // Electron can observe the pipe closing before the process exit.
               assert.ok(reason==='protocol'||reason==='exited','unexpected retirement signal: '+reason);
             } finally {
               onAdmissionLost=undefined;
               aborted.abort();
             }
             await host.stop();
             assert.equal(host.unlockedWorkspaceId,undefined);
           };
           const subject=await find('accounts');
           await withdraw('disable-account',subject);
           const suspension=await ports.suspension({accountId:subject,kind:'roots'});
           assert.equal(suspension.status,'ready');
           assert.equal((await ports.personalRecovery({accountId:subject,suspension:suspension.page.revision},undefined,current)).status,'unavailable');
           await change('enable-account',subject);
           await host.startup();
           assert.ok((await admit()).admitted);
           await withdraw('revoke-device',await find('devices'));
         });
         result={idleRetirements:2};
       } finally { await actor.stop(); }
     }
     if(mode==='admin-reopen'&&target.webFixturePort){
       const {exerciseSharedWebCookies}=await import(${JSON.stringify(pathToFileURL(join(root, 'tests', 'fixtures', 'vault-shared-web-cookie.mjs')).href)});
       await exerciseSharedWebCookies(host,admit,target.webFixturePort);
     } else if(mode==='admin-reopen'&&target.importLocal){
       const page=()=>host.sharedCatalog({after:'',epoch:'0',changeSeq:'0',limit:32},()=>true);
       const catalog=await page();
       assert.equal(catalog.nodes.length,2+(exerciseSlotBinding?1:0)+(exerciseSharedDefault?1:0));
       const imported=catalog.nodes.find(node=>node.name==='Preserved local connection');
       assert.ok(imported && !imported.grantRevision);
       const ssh={workspaceId:host.unlockedWorkspaceId,nodeId:imported.id,credentialOverride:'',route:null,epoch:1,
         sessionId:require('node:crypto').randomUUID(),requestId:require('node:crypto').randomUUID()};
       const initial=await host.sshHostPlan(ssh);
       const fingerprint=byte=>'SHA256:'+Buffer.alloc(32,byte).toString('base64').slice(0,-1);
       const confirm=async(metadata,current,submit)=>{
         assert.ok(target.checkStandardPin && current());
         const credentials=(password,secret)=>({vaultId:metadata.slots.vaultId,slotId:slot.id,appVersion:'2.4.3',
           password:Buffer.from(password),ask:Buffer.from(secret,'hex')});
         for(const wrong of [credentials('wrong',ask),credentials(accountPassword,'19'.repeat(32))]){
           await assert.rejects(submit(wrong,()=>true));
           assert.ok(wrong.password.every(n=>n===0)&&wrong.ask.every(n=>n===0));
         }
         return submit(credentials(accountPassword,ask),()=>true);
       };
       const decide=async(expected,byte)=>{
         const received=fingerprint(byte);
         await host.trustSharedSshHost({...ssh,expected,received},confirm,()=>true);
         const current=await host.sshHostPlan(ssh);
         assert.equal(current.fingerprint,received);
         assert.notEqual(current.revision,expected.revision);
         return current;
       };
       if(target.checkStandardPin){
         await host.openSharedAdministration(()=>true,async(current,ports)=>{
           const slotId=require('node:crypto').randomUUID();
           assert.equal((await ports.createSlot({id:slotId,name:'Remote desktops',protocol:'rdp',allowSelfService:true})).status,'saved');
           const {confirmedSlotDefault}=await import(${fromDist('vault-shared-slot-default.js')});
           const nodeId=catalog.nodes.find(n=>n.name===overrideConnectionName).id;
           const action={nodeId,scope:'personal',credentialName:personalCredentialName};
           const override=await ports.nodeCredential(action,undefined,current);
           assert.equal(override.status,'review');
           assert.equal(override.authenticationRequired,true);
           const commitOverride={...action,confirmation:override.review};
           assert.equal((await ports.nodeCredential(commitOverride,undefined,current)).status,'authentication-required');
           for(const [password,secret] of [['wrong',ask],[accountPassword,'5b'.repeat(32)],[accountPassword,'']]){
             assert.equal((await ports.nodeCredential(commitOverride,{password:Buffer.from(password),...(secret?{ask:Buffer.from(secret,'hex')}:{})},current)).status,'unavailable');
           }
           assert.equal((await ports.nodeCredential(commitOverride,{password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex')},current)).status,'saved');
           for(const [change,credentialName] of [[ports.slotDefault,sharedCredentialName],[ports.personalSlot,personalCredentialName]]){
             const review=await change({slotId,credentialName},undefined,current);
             assert.equal(review.status,'review');
             assert.equal(review.authenticationRequired,true);
             const commit=confirmedSlotDefault(review);
             assert.equal((await change(commit,undefined,current)).status,'authentication-required');
             for(const [password,secret] of [['wrong',ask],[accountPassword,'5b'.repeat(32)],[accountPassword,'']]){
               assert.equal((await change(commit,{password:Buffer.from(password),...(secret?{ask:Buffer.from(secret,'hex')}:{})},current)).status,'unavailable');
             }
             assert.equal((await change(commit,{password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex')},current)).status,'saved');
           }
         });
         await assert.rejects(native.trustSharedSshHost({...ssh,expected:initial,received:fingerprint(1)}));
         assert.equal((await host.sshHostPlan(ssh)).revision,initial.revision);
       }
       const pinned=await decide(initial,1);
       await assert.rejects(native.trustSharedSshHost({...ssh,expected:initial,received:fingerprint(2)}));
       await decide(pinned,2);
       assert.ok((await page()).nodes.find(node=>node.id===ssh.nodeId)?.notesRevision);
       const readEdit=async()=>{
         const selected=(await page()).nodes.find(node=>node.id===ssh.nodeId);
         assert.ok(selected.editRevision);
         const ready=await host.sharedNodeEdit({nodeId:selected.id,revision:selected.editRevision},()=>true,confirm);
         assert.equal(ready.status,'ready');
         assert.equal(ready.workspaceId,host.unlockedWorkspaceId);
         return ready;
       };
       const request=(ready,changes)=>({nodeId:ready.nodeId,revision:ready.revision,epoch:ready.epoch,
         workspaceId:ready.workspaceId,changeSeq:ready.changeSeq,changes});
       const first=await readEdit();
       const rename=request(first,{name:'Renamed shared connection'});
       const noPrompt=()=>{throw Error('Unexpected authentication prompt for metadata rename.')};
       assert.equal((await host.sharedNodeEdit(request(first,{credentialMode:3,credentialSlotId:null}),()=>true,noPrompt)).status,'unavailable');
       assert.equal((await host.sharedNodeEdit({...rename,changeSeq:'0'},()=>true,noPrompt)).status,'unavailable');
       const {registerSharedNodeEditIpc}=await import(${fromDist('vault-shared-ipc.js')});
       const editThroughPreload=async(action,open)=>{
         const editorWindow=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,
           preload:${JSON.stringify(join(root, 'dist-electron', 'preload.cjs'))}}});
         try{
           await editorWindow.loadURL('data:text/html,<html>Shared catalog</html>');
           registerSharedNodeEditIpc({ipc:ipcMain,host,dialog:{open},parent:()=>editorWindow,
             trusted:event=>event.sender===editorWindow.webContents&&event.senderFrame===editorWindow.webContents.mainFrame});
           const result=await editorWindow.webContents.executeJavaScript('window.wormhole.editSharedNode('+JSON.stringify(action)+')');
           assert.deepEqual(result,{status:'saved',nodeId:action.nodeId,revision:String(BigInt(action.revision)+1n)});
         }finally{
           ipcMain.removeHandler('vault:shared-node-edit');
           editorWindow.destroy();
         }
       };
       await editThroughPreload(rename,noPrompt);
       assert.equal((await host.sharedNodeEdit(rename,()=>true,noPrompt)).status,'unavailable');
       const renamed=await readEdit();
       assert.equal(renamed.fields.name,rename.changes.name);
       const change=request(renamed,{host:'shared-edit.example'});
       if(target.checkStandardPin) {
         assert.equal((await native.sharedNodeEdit(change)).status,'authentication-required');
         assert.equal((await host.sharedNodeEdit(change,()=>true,async()=>null)).status,'unavailable');
       }
       assert.equal((await host.sharedNodeEdit(change,()=>true,confirm)).status,'saved');
       const changed=await readEdit();
       assert.equal(changed.fields.host,change.changes.host);
       assert.equal((await host.sharedNodeEdit(request(changed,{name:first.fields.name,host:first.fields.host}),()=>true,confirm)).status,'saved');
       const moving=await readEdit();
       assert.equal(moving.canMove,true);
       const folder=(await page()).nodes.find(node=>node.name==='Shared grant folder');
       assert.ok(folder.editRevision);
       assert.equal(imported.parentId,null);
       const parent={id:folder.id,revision:folder.editRevision};
       assert.equal((await host.sharedNodeEdit(request(moving,{parent:{...parent,revision:String(BigInt(parent.revision)+1n)}}),()=>true,noPrompt)).status,'unavailable');
       const move=request(moving,{parent});
       if(target.checkStandardPin){
         assert.equal((await native.sharedNodeEdit(move)).status,'authentication-required');
         assert.equal((await host.sharedNodeEdit(move,()=>true,async()=>null)).status,'unavailable');
       }
       await editThroughPreload(move,(_parent,current,_operation,metadata,submit)=>confirm(metadata,current,submit));
       const moved=(await page()).nodes.find(node=>node.id===imported.id);
       assert.equal(moved.parentId,folder.id);
       assert.ok(moved.notesRevision);
       assert.equal((await host.sharedNodeEdit(move,()=>true,noPrompt)).status,'unavailable');
       const restore=request(await readEdit(),{parent:null});
       assert.equal((await host.sharedNodeEdit(restore,()=>true,confirm)).status,'saved');
       assert.equal((await page()).nodes.find(node=>node.id===imported.id).parentId,null);
     }
     if(mode==='admin-reopen' && exerciseSlotBinding){
       const catalog=await host.sharedCatalog({after:'',epoch:'0',changeSeq:'0',limit:32},()=>true);
       const imported=catalog.nodes.find(node=>node.name==='Preserved local connection');
       const {VaultNotesDialog}=await import(${fromDist('vault-notes-dialog.js')});
       assert.ok(catalog.nodes.find(node=>node.name==='Shared grant folder')?.grantRevision);
       window=new BrowserWindow({show:false,webPreferences:{sandbox:true,preload:${JSON.stringify(join(root, 'dist-electron', 'preload.cjs'))}}});
       await window.loadURL('data:text/html,<html>Workspace</html>');
       let noteWindow;
       const notes=new VaultNotesDialog({host,ipc:ipcMain,url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-notes.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-notes-preload.cjs'))},createWindow:options=>{
         noteWindow=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
         noteWindow.show=()=>{};
         return noteWindow;
       }});
       const opened=notes.open(window,()=>true,{nodeId:imported.id,rowVersion:imported.notesRevision});
       try{
         let visible=false;
         for(let n=0;n<200&&!visible;n++){
           await new Promise(resolve=>setTimeout(resolve,25));
           visible=await noteWindow.webContents.executeJavaScript('document.querySelector("pre")?.textContent==="Synthetic local notes"').catch(()=>false);
         }
         assert.equal(visible,true,'protected notes dialog did not display the imported note');
       }finally{notes.cancel();await opened;}
       assert.equal(admission.administrator,true);
       const {registerSharedAdministrationIpc,registerSharedNodeEditIpc}=await import(${fromDist('vault-shared-ipc.js')});
       let adminWindow;
       const administration=new VaultSharedSetupDialog({host,ipc:ipcMain,pickExport:async()=>null,colorScheme:()=> 'oled',
         url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared-setup.html')).href)},
         preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-setup-preload.cjs'))},
         createWindow:options=>{
           adminWindow=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
           adminWindow.show=()=>{};
           return adminWindow;
         }
       });
       let currentDeviceRevocations=0;
       registerSharedAdministrationIpc({host,ipc:ipcMain,dialog:administration,parent:()=>window,
         currentDeviceRevoked:()=>{currentDeviceRevocations++},
         trusted:event=>event.sender===window.webContents&&event.senderFrame===event.sender.mainFrame});
       registerSharedNodeEditIpc({host,ipc:ipcMain,dialog:{open:()=>{throw Error('Unexpected authentication on read')}},
         parent:()=>window,trusted:event=>event.sender===window.webContents&&event.senderFrame===event.sender.mainFrame});
       const slotPage=(edit,slotAfter='')=>{
         const {nodeId,revision,workspaceId,epoch,changeSeq}=edit;
         return window.webContents.executeJavaScript('window.wormhole.editSharedNode('+JSON.stringify({nodeId,revision,workspaceId,epoch,changeSeq,slotAfter})+')');
       };
       assert.equal(await window.webContents.executeJavaScript('typeof window.vaultSharedSetup'),'undefined');
       let adminOpened;
       const waitForAdmin=async expression=>{
         for(let n=0;n<200;n++){
           if(adminWindow&&!adminWindow.isDestroyed()&&await adminWindow.webContents.executeJavaScript(expression).catch(()=>false))return;
           await new Promise(resolve=>setTimeout(resolve,25));
         }
         throw Error('Expected administrative state was not displayed: '+expression);
       };
       const waitForRecord=text=>waitForAdmin('[...document.querySelectorAll(".shared-administration-list")].some(list=>!list.hidden&&list.textContent.includes('+JSON.stringify(text)+'))');
       const section=async kind=>{
         await waitForAdmin('document.querySelector("select")?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript('(()=>{const menu=document.querySelector("select");menu.value='+JSON.stringify(kind)+';menu.dispatchEvent(new Event("change"));})()');
       };
       const fieldsetButton=async text=>{
         const button='[...document.querySelectorAll("fieldset button")].find(b=>b.textContent==='+JSON.stringify(text)+')';
         await waitForAdmin('('+button+')?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript('('+button+').click()');
       };
       const groupForm=(label, value)=>adminWindow.webContents.executeJavaScript('(()=>{const field=document.querySelector("input[aria-label="+JSON.stringify('+JSON.stringify(label)+')+"]");field.value='+JSON.stringify(value)+';field.form.requestSubmit();})()');
       try{
         const node=catalog.nodes.find(n=>n.name===overrideConnectionName);
         assert.ok(node?.canUse);
         for(const [source,name] of [['shared',sharedCredentialName],['personal',personalCredentialName],['inherit','']]){
           const opened=window.webContents.executeJavaScript('window.wormhole.openSharedAdministration('+JSON.stringify(node.id)+')');
           void opened.catch(()=>{});
           try {
             await waitForAdmin('!!document.querySelector("select[name=scope]")');
             assert.equal(await adminWindow.webContents.executeJavaScript('document.documentElement.matches(".dark.oled")'),true);
             await adminWindow.webContents.executeJavaScript('(()=>{const form=document.querySelector("form");form.elements.scope.value='+JSON.stringify(source)+';form.elements.scope.dispatchEvent(new Event("change"));form.elements.account.value='+JSON.stringify(name)+';form.requestSubmit()})()');
             await waitForAdmin('document.querySelector("h2")?.textContent==='+JSON.stringify(node.name));
             if(name) assert.equal(await adminWindow.webContents.executeJavaScript('document.querySelector(".slot-credential strong").textContent'),name);
             await fieldsetButton(name?'Set my credential':'Use connection settings');
             await opened;
             if(name){
               const crypto=require('node:crypto');
               const publicKey=Buffer.from(crypto.generateKeyPairSync('x25519').publicKey.export({format:'jwk'}).x,'base64url').toString('base64');
               const bundle=await native.rdpBundle({workspaceId:host.unlockedWorkspaceId,nodeId:node.id,credentialOverride:'',epoch:1,sessionId:crypto.randomUUID(),requestId:crypto.randomUUID(),publicKey});
               assert.equal(bundle.binding.nodeId,node.id);
             }
           } finally {await administration.cancel();await opened;}
         }
         adminOpened=window.webContents.executeJavaScript('window.wormhole.openSharedAdministration()');
         void adminOpened.catch(()=>{});
         await waitForRecord('administrator');
         await section('slots');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No records on this page.")');
         await adminWindow.webContents.executeJavaScript('(()=>{const details=document.querySelector("details");details.open=true;const form=details.querySelector("form");form.querySelector("input").value="Operations remote desktop";form.querySelector("select").value="rdp";form.querySelector("input[type=checkbox]").checked=true;form.requestSubmit()})()');
         await waitForRecord('Operations remote desktop');
         await waitForRecord('RDP · Users can choose a credential');
         const publicId=await adminWindow.webContents.executeJavaScript('[...document.querySelectorAll(".shared-administration-list li")].find(row=>row.querySelector("strong")?.textContent==="Operations remote desktop")?.querySelector("code")?.textContent');
         assert.match(publicId,/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
         const selected=catalog.nodes.find(node=>node.name===slotConnectionName);
         const noFactors=()=>{throw Error('Unexpected authentication for Default slot selection')};
         const readSelection=revision=>host.sharedNodeEdit({nodeId:selected.id,revision},()=>true,noFactors);
         const inlineEditor=await host.sharedNodeEdit({nodeId:imported.id,revision:imported.editRevision},()=>true,noFactors);
         assert.equal(inlineEditor.status,'ready');
         assert.equal(inlineEditor.usesInlinePassword,true);
         assert.deepEqual(await slotPage(inlineEditor),{status:'unavailable'});
         assert.equal((await host.sharedNodeEdit({nodeId:imported.id,revision:inlineEditor.revision,workspaceId:inlineEditor.workspaceId,
           epoch:inlineEditor.epoch,changeSeq:inlineEditor.changeSeq,changes:{credentialMode:3,credentialSlotId:publicId}},()=>true,noFactors)).status,
           'unavailable','an inline password would still take precedence over the saved slot');
         const editor=await readSelection(selected.editRevision);
         assert.equal(editor.status,'ready');
         assert.equal(editor.usesInlinePassword,undefined);
         const choices=await slotPage(editor);
         assert.equal(choices.status,'slot-choices');
         for(const key of ['nodeId','revision','workspaceId','epoch','changeSeq'])assert.equal(choices[key],editor[key]);
         assert.deepEqual(choices.slotPage,{kind:'slots',entries:[
           {id:publicId,name:'Operations remote desktop',protocol:'rdp',allowSelfService:true}
         ]});
         const chosenId=choices.slotPage.entries[0].id;
         assert.deepEqual((await slotPage(editor,chosenId)).slotPage,{kind:'slots',entries:[]});
         const choose=changes=>host.sharedNodeEdit({workspaceId:editor.workspaceId,nodeId:editor.nodeId,revision:editor.revision,
           epoch:editor.epoch,changeSeq:editor.changeSeq,changes:{credentialMode:3,credentialSlotId:chosenId,...changes}},()=>true,noFactors);
         assert.equal((await choose({})).status,'unavailable','an SSH connection accepted an RDP slot');
         const saved=await choose({protocol:1,port:3389});
         assert.equal(saved.status,'saved');
         assert.deepEqual(await slotPage(editor),{status:'unavailable'});
         const bound=await readSelection(saved.revision);
         assert.equal(bound.status,'ready');
         assert.equal(bound.fields.credentialSlotId,publicId);
         assert.equal(bound.fields.protocol,1);
         const crypto=require('node:crypto');
         const publicKey=Buffer.from(crypto.generateKeyPairSync('x25519').publicKey.export({format:'jwk'}).x,'base64url').toString('base64');
         const connect=()=>native.rdpBundle({workspaceId:editor.workspaceId,nodeId:selected.id,credentialOverride:'',
           epoch:1,sessionId:crypto.randomUUID(),requestId:crypto.randomUUID(),publicKey});
         const openDefault=async()=>{
           const manage='([...document.querySelectorAll("li button")].find(b=>b.textContent==="Manage shared default"))';
           await waitForAdmin(manage+'?.matches(":enabled")');
           await adminWindow.webContents.executeJavaScript(manage+'.click()');
           await waitForAdmin('document.querySelector("fieldset input")?.matches(":enabled")');
         };
         await openDefault();
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input").value='+JSON.stringify(sharedCredentialName));
         await fieldsetButton('Review default');
         await fieldsetButton('Set shared default');
         await waitForRecord('Operations remote desktop');
         assert.equal((await connect()).binding.nodeId,selected.id);
         await openDefault();
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input").value='+JSON.stringify(sharedCredentialName));
         await fieldsetButton('Review default');
         await waitForAdmin('document.body.textContent.includes("This is already the shared default.")');
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input[type=checkbox]").click()');
         await fieldsetButton('Review default');
         await fieldsetButton('Remove shared default');
         await waitForRecord('Operations remote desktop');
         await openDefault();
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input[type=checkbox]").click()');
         await fieldsetButton('Review default');
         await waitForAdmin('document.body.textContent.includes("This is already the shared default.")');
         await fieldsetButton('Back to slots');
         await section('my-slots');
         await waitForRecord('Operations remote desktop');
         const openPersonal=async()=>{
           const button='[...document.querySelectorAll("li button")].find(b=>b.textContent==="Manage my credential")';
           await waitForAdmin('('+button+')?.matches(":enabled")');
           await adminWindow.webContents.executeJavaScript('('+button+').click()');
         };
         await openPersonal();
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input").value='+JSON.stringify(personalCredentialName));
         await fieldsetButton('Review assignment');
         await fieldsetButton('Set my credential');
         await waitForRecord('Operations remote desktop');
         assert.equal((await connect()).binding.nodeId,selected.id,'connection must use the personal assignment when there is no shared default');
         await openPersonal();
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset input[type=checkbox]").click()');
         await fieldsetButton('Review assignment');
         await waitForAdmin('document.body.textContent.includes("This slot has no shared default.")');
         await fieldsetButton('Clear my assignment');
         await waitForRecord('Operations remote desktop');
         await section('unencrypted-clients');
         await waitForAdmin('document.body.textContent.includes("No unencrypted clients connected.")');
         await section('accounts');
         await waitForRecord('administrator');
         const rowButton=(label, verb)=>'([...document.querySelectorAll(".shared-administration-list li")].find(row=>row.textContent.includes('+JSON.stringify(label)+'))?.querySelector("button[aria-label^="+JSON.stringify('+JSON.stringify(verb)+')+"]"))';
         const accountRow=rowButton('suspension-test-account','Disable account');
         await waitForAdmin(accountRow+'?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript(accountRow+'.click()');
         const suspend='[...document.querySelectorAll("button")].find(b=>b.textContent==="Disable account"&&!b.closest("li"))';
         await waitForAdmin('('+suspend+')?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript('('+suspend+').click()');
         const inventoryLink=rowButton('suspension-test-account','Review access at suspension');
         await waitForAdmin(inventoryLink+'?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript(inventoryLink+'.click()');
         await waitForAdmin('document.body.textContent.includes("Access at suspension · suspension-test-account")&&document.body.textContent.includes("No entries were recorded.")');
         await adminWindow.webContents.executeJavaScript('(()=>{const inventory=[...document.querySelectorAll("select")].find(menu=>[...menu.options].some(option=>option.value==="groups"&&option.textContent==="Groups at suspension"));inventory.value="groups";inventory.dispatchEvent(new Event("change"));})()');
         await waitForAdmin('document.body.textContent.includes("No entries were recorded.")&&[...document.querySelectorAll("select")].some(menu=>menu.value==="groups")');
         await adminWindow.webContents.executeJavaScript('(()=>{const inventory=[...document.querySelectorAll("select")].find(menu=>menu.value==="groups");inventory.value="web-sessions";inventory.dispatchEvent(new Event("change"));})()');
         await waitForAdmin('document.body.textContent.includes("No entries were recorded.")&&[...document.querySelectorAll("select")].some(menu=>menu.value==="web-sessions"&&menu.matches(":enabled"))');
         await adminWindow.webContents.executeJavaScript('[...document.querySelectorAll("button")].find(b=>b.textContent==="Back to accounts").click()');
         for(const [kind,entry] of [['devices','active'],['sessions','2.4.3'],['audit','begin_note_view']]){
           await section(kind);
           await waitForRecord(entry);
         }
         await section('groups');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No groups on this page.")');
         await groupForm('Group name','Operations');
         await waitForRecord('Operations');
         await fieldsetButton('Operations');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No members on this page.")');
         await groupForm('Account sign-in name','first-admin');
         await waitForRecord('first-admin');
         await groupForm('Group name','Incident response');
         await waitForAdmin('document.querySelector("fieldset h2")?.textContent==="Incident response"');
         await waitForRecord('first-admin');
         await fieldsetButton('Remove');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No members on this page.")');
         await section('grants');
         await waitForAdmin('[...document.querySelectorAll("fieldset button")].some(b=>b.textContent==="Shared grant folder")');
         await fieldsetButton('Shared grant folder');
         await waitForAdmin('document.querySelector("fieldset h2")?.textContent==="Shared grant folder"');
         await waitForAdmin('document.querySelector("fieldset")?.textContent.includes("requires Reveal on that credential.")');
         await fieldsetButton('Group grants');
         await waitForAdmin('[...document.querySelectorAll("select[aria-label] option")].some(option=>option.textContent==="Incident response")');
         await adminWindow.webContents.executeJavaScript('(()=>{const group=document.querySelector("fieldset select");group.selectedIndex=1;group.parentElement.querySelector("input[type=checkbox]").checked=true;})()');
         await fieldsetButton('Add grant');
         await waitForAdmin('[...document.querySelectorAll("legend")].some(e=>e.textContent==="Incident response")');
         await fieldsetButton('Revoke grant');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No direct grants on this page.")');
         await section('groups');
         await waitForAdmin('[...document.querySelectorAll("fieldset button")].some(b=>b.textContent==="Incident response")');
         await fieldsetButton('Incident response');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No members on this page.")');
         await fieldsetButton('Delete group');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No groups on this page.")');
         await groupForm('Group name','Certified operators');
         await waitForRecord('Certified operators');
         await fieldsetButton('Certified operators');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No members on this page.")');
         await groupForm('Account sign-in name','first-admin');
         await waitForRecord('first-admin');
         await fieldsetButton('Review group key recipients');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent.startsWith("Confirm the certified recipients."))');
         await fieldsetButton('Issue group key');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Group encryption key issued.")');
         await fieldsetButton('Back to groups');
         await fieldsetButton('Certified operators');
         await fieldsetButton('Remove');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent.includes("require updating its keys"))');
         await section('grants');
         await fieldsetButton('Shared grant folder');
         await fieldsetButton('Group grants');
         await fieldsetButton('Boundary keys');
         await waitForAdmin('[...document.querySelectorAll("select option")].some(option=>option.textContent==="Certified operators")');
         await adminWindow.webContents.executeJavaScript('(()=>{const group=document.querySelector("fieldset select");group.selectedIndex=1;})()');
         await fieldsetButton('Review boundary grant');
         await waitForAdmin('document.querySelector("ul[aria-label]")?.textContent==="first-admin"');
         await waitForAdmin('[...document.querySelectorAll("fieldset p")].some(p=>p.textContent==="Certified operators · None → View")');
         await fieldsetButton('Confirm and issue boundary keys');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Boundary grant saved and keys issued.")');
         await fieldsetButton('Back to item grants');
         await fieldsetButton('Rotate boundary keys');
         await waitForAdmin('[...document.querySelectorAll("select option")].some(option=>option.textContent==="Certified operators")');
         await adminWindow.webContents.executeJavaScript('(()=>{document.querySelector("fieldset select").selectedIndex=1;document.querySelectorAll("fieldset select")[1].value="0";})()');
         await fieldsetButton('Review boundary rotation');
         await waitForAdmin('[...document.querySelectorAll("fieldset p")].some(p=>p.textContent==="Certified operators · View → None")');
         await fieldsetButton('Confirm and rotate boundary keys');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Boundary grant reduced and keys rotated.")');
         await fieldsetButton('Back to item grants');
         await fieldsetButton('Boundary keys');
         await waitForAdmin('[...document.querySelectorAll("select option")].some(option=>option.textContent==="Certified operators")');
         await adminWindow.webContents.executeJavaScript('document.querySelector("fieldset select").selectedIndex=1');
         await fieldsetButton('Review boundary grant');
         await fieldsetButton('Confirm and issue boundary keys');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Boundary grant saved and keys issued.")');
         await section('groups');
         await fieldsetButton('Certified operators');
         await fieldsetButton('Remove');
         await fieldsetButton('Review member removal');
         await waitForAdmin('[...document.querySelectorAll("fieldset p")].some(p=>p.textContent==="Remove first-admin. 1 shared boundary needs new keys.")');
         await fieldsetButton('Confirm member removal and rotate keys');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Group key rotation complete.")');
         await fieldsetButton('Certified operators');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="No members on this page.")');
         await groupForm('Account sign-in name','first-admin');
         await waitForAdmin('[...document.querySelectorAll("fieldset p")].some(p=>p.textContent==="Add first-admin. This grants access to group keys for 1 shared boundary.")');
         await fieldsetButton('Confirm member addition');
         await waitForRecord('first-admin');
         await waitForAdmin('[...document.querySelectorAll("[role=status]")].some(s=>s.textContent==="Member added and group keys updated.")');
         await section('audit');
         await waitForRecord('group_delete');
         await waitForRecord('node_grant_change');
         await waitForRecord('group_key_provision');
         await waitForRecord('boundary_group_grant');
         await waitForRecord('boundary_group_rotation');
         await waitForRecord('group_member_rotation');
         await waitForRecord('member_boundary_rotation');
         await waitForRecord('group_keyed_member_addition');
         await section('accounts');
         const rotateAccount=rowButton('rotation-test-account','Disable account');
         await waitForAdmin(rotateAccount+'?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript(rotateAccount+'.click()');
         await waitForAdmin('('+suspend+')?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript('('+suspend+').click()');
         const inspectRotation=rowButton('rotation-test-account','Review access at suspension');
         await waitForAdmin(inspectRotation+'?.matches(":enabled")');
         await adminWindow.webContents.executeJavaScript(inspectRotation+'.click()');
         // Inventory reads never start rotations. The original suspension is
         // the only mutation confirmed by this device.
         await waitForAdmin('(()=>{if(document.body.textContent.includes("retired"))return true;const refresh=[...document.querySelectorAll("button")].find(b=>b.textContent==="Refresh inventory");if(refresh&&!refresh.disabled)refresh.click();return false;})()');
         await adminWindow.webContents.executeJavaScript('[...document.querySelectorAll("button")].find(b=>b.textContent==="Back to accounts").click()');
         await section('my-devices');
         await waitForRecord('active');
         const myDevice='document.querySelector(".shared-administration-list button[aria-label^=Revoke]")';
         await adminWindow.webContents.executeJavaScript(myDevice+'.click()');
         const confirms='[...document.querySelectorAll("button")].find(b=>b.textContent==="Revoke device"&&!b.closest("li"))';
         await waitForAdmin('('+confirms+')?.matches(":enabled")&&document.body.textContent.includes("This device will be signed out")');
         assert.equal(currentDeviceRevocations,0);
         await adminWindow.webContents.executeJavaScript('('+confirms+').click()');
         await waitForAdmin('document.body.textContent.includes("Device revoked.")');
         assert.equal(currentDeviceRevocations,1);
         await assert.rejects(native.sharedRuntime());
       }finally{ipcMain.removeHandler('vault:shared-node-edit');await administration.cancel();await adminOpened;}
     }
     if(!suspensionRestart&&mode!=='admin-group-suspension'&&mode!=='admin-reopen'&&mode!=='admin-revoke-live'){
       const {registerSharedCertificateRenewalIpc,registerSharedRecoveryBackupIpc,registerSharedRecoveryInspectionIpc,registerSharedAccountResetIpc}=await import(${fromDist('vault-shared-ipc.js')});
       window=new BrowserWindow({show:false,webPreferences:{sandbox:true,preload:${JSON.stringify(join(root, 'dist-electron', 'preload.cjs'))}}});
       let authentication,child;
       if(mode==='admin-refresh-recovery-kit'){
         const {VaultSharedAuthenticationDialog}=await import(${fromDist('vault-shared-dialog.js')});
         authentication=new VaultSharedAuthenticationDialog({host,ipc:ipcMain,appVersion:'2.4.3',url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-preload.cjs'))},createWindow:options=>{
           child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
           child.show=()=>{};
           return child;
         }});
       }
       registerSharedCertificateRenewalIpc({ipc:ipcMain,host,trusted:event=>event.sender===window.webContents&&event.senderFrame===event.sender.mainFrame,pickTLSExport:async()=>target.tlsBundlePath,pickRecoveryKit:async(_,intent)=>intent==='open'?target.recoveryKitSource:target.recoveryKitDestination,
         confirmRecoveryKit:authentication?(_,startup,current,submit)=>authentication.open(window,current,'refresh-recovery-kit',startup,submit):undefined});
       await window.loadURL('data:text/html,<html>Workspace</html>');
       const renew=csr=>window.webContents.executeJavaScript('window.wormhole.renewSharedServerCertificate('+JSON.stringify({csr})+')');
       if(mode==='admin-renew'){
         assert.deepEqual(await renew('-----BEGIN CERTIFICATE REQUEST-----\\nAAAA\\n-----END CERTIFICATE REQUEST-----'),{status:'invalid-csr'});
       }
       if(mode.startsWith('admin-ca-')){
         const action=mode.slice('admin-ca-'.length);
         const request=action==='rotate'?{action,csr:target.csr}:{action};
         result=await window.webContents.executeJavaScript('window.wormhole.sharedWorkspaceCA('+JSON.stringify(request)+')');
       } else if(mode==='admin-tls-export'){
         assert.equal(await window.webContents.executeJavaScript('window.wormhole.exportSharedTLSBundle()'),true);
         assert.equal(await window.webContents.executeJavaScript('window.wormhole.exportSharedTLSBundle()'),false);
         result={exported:true};
       } else if(mode==='admin-issue-reset'){
         assert.equal(admission.recoveryBackup,true);
         let picks=0;
         const [firstPath,secondPath]=target.resetOfferPaths;
         const occupied=firstPath+'.occupied.whreset';
         writeFileSync(occupied,'existing test file',{mode:0o600});
         const checkIssue=(login,recipient,targetUserId)=>native.issueSharedAccountReset(firstPath,{
           requestId:require('node:crypto').randomUUID(),targetLogin:login,recipient,
           ...(targetUserId?{targetUserId}:{}),
           password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex'),
         },{vaultId:startup.slots.vaultId,slotId:slot.id});
         assert.deepEqual(await checkIssue('first-admin',new Uint8Array(32)),{status:'invalid-recipient'});
         assert.deepEqual(await checkIssue('BadLogin',new Uint8Array(32)),{status:'invalid-login'});
         assert.deepEqual(await checkIssue('missing-user',new Uint8Array(32)),{status:'unavailable'});
         assert.deepEqual(await checkIssue('first-admin',new Uint8Array(32),require('node:crypto').randomUUID()),{status:'unavailable'});
         const wizard=new VaultSharedSetupDialog({
           ipc:ipcMain,host,pickExport:async()=>null,
           pickAccountReset:async()=>[null,firstPath,occupied,firstPath,secondPath][picks++],
           url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared-setup.html')).href)},
           preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-setup-preload.cjs'))},
           createWindow:options=>{
             child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
             child.show=()=>{};
             return child;
           },
         });
         registerSharedAccountResetIpc({ipc:ipcMain,host,dialog:wizard,
           trusted:event=>event.sender===window.webContents&&event.senderFrame===event.sender.mainFrame,parent:()=>window});
         assert.equal(await window.webContents.executeJavaScript('typeof window.vaultSharedSetup'),'undefined');
         const open=()=>{
           const opened=window.webContents.executeJavaScript('window.wormhole.openSharedAccountReset()');
           void opened.catch(()=>{});
           return opened;
         };
         let opened=open();
         const wait=async expression=>{
           for(let i=0;i<400;i++){
             if(child&&!child.isDestroyed()&&await child.webContents.executeJavaScript(expression).catch(()=>false))return;
             await new Promise(resolve=>setTimeout(resolve,20));
           }
           throw Error('Reset window condition was not reached: '+expression);
         };
         const click=text=>child.webContents.executeJavaScript('[...document.querySelectorAll("button")].find(button=>button.textContent==='+JSON.stringify(text)+').click()');
         const message=text=>wait('document.querySelector("[role=status]")?.textContent.includes('+JSON.stringify(text)+')&&![...document.querySelectorAll("button")].find(button=>button.textContent==="Close").disabled');
         const submit=(login,factor)=>child.webContents.executeJavaScript('(()=>{for(const [name,value] of Object.entries('+JSON.stringify({'target-login':login,password:accountPassword,ask:factor})+'))document.querySelector("[name="+name+"]").value=value;document.querySelector("form").requestSubmit();})()');
         const runJS=source=>child.webContents.executeJavaScript(source);
         const currentLogin=()=>runJS('document.querySelector("[name=target-login]").value');
         const noFactors='[...document.querySelectorAll("code")].every(code=>code.textContent==="")';
         const readHandover=login=>runJS('(()=>{const codes=document.querySelectorAll("code");return codes.length===2&&/^[0-9a-f]{32}$/.test(codes[0].textContent)&&/^[0-9a-f]{64}$/.test(codes[1].textContent)&&document.querySelector("h2").textContent==='+JSON.stringify('Deliver to '+login)+'})()');
         const close=async()=>{
           await click('Close').catch(error=>{if(!child.isDestroyed())throw error;});
           await opened;
         };
         try{
           await wait('document.querySelectorAll(".shared-reset-targets input:enabled").length===2');
           await click('Select accounts that need an offer');
           await click('Issue resets for selected accounts');
           const first=await currentLogin();
           await submit(first,ask);await message('File selection cancelled');
           await submit(first,'5b'.repeat(32));await message('Check your password');
           await submit(first,ask);await message('Could not save the offer');
           await submit(first,ask);await message('Offer issued.');
           assert.equal(await readHandover(first),true);
           assert.equal(await child.webContents.executeJavaScript('document.querySelector("[name=password]").value===""&&document.querySelector("[name=ask]").value===""'),true);
           assert.equal(await child.webContents.executeJavaScript('document.dispatchEvent(new Event("copy",{cancelable:true}))'),false);
           await click('Mark handed over and continue');
           await message('0 remaining after this account');
           const second=await currentLogin();
           assert.deepEqual([first,second].sort(),['first-admin','recovered-admin']);
           assert.equal(await runJS(noFactors),true);
           await submit(second,ask);await message('Offer issued.');
           assert.equal(await readHandover(second),true);
           await click('Leave pending and continue');
           await wait('document.querySelector(".shared-reset-targets").textContent.includes("Awaiting handover")');
           assert.equal(await runJS(noFactors),true);
           await close();
           opened=open();
           const markSecond='document.querySelector('+JSON.stringify('[aria-label="Mark handover for '+second+'"]')+')';
           await wait('!!'+markSecond);
           assert.equal(await runJS(noFactors),true);
           await runJS(markSecond+'.click()');
           await message('Handover recorded.');
           await close();
           result={issued:2};
         }finally{await wizard.cancel();}
       } else if(mode==='admin-backup'){
         const {generateKeyPairSync}=require('node:crypto');
         const {mkdirSync,readFileSync}=require('node:fs');
         const publicKey=generateKeyPairSync('x25519').publicKey.export({type:'spki',format:'der'}).subarray(-32);
         const restoreData=${JSON.stringify(join(appData, 'restore-preview'))};
         mkdirSync(restoreData,{recursive:true});
         const restoreHost=new VaultBackendHost(()=>new VaultBackendClient({
           executable:${JSON.stringify(resolve(wizardBackend))},
           databasePath:${JSON.stringify(join(appData, 'restore-preview', 'workspace.db'))},
           userDataPath:restoreData,
         }),()=>true);
         const deployPath=target.backupPath+'.sql';
         let picked=0;
         const wizard=new VaultSharedSetupDialog({
           ipc:ipcMain,host,pickExport:async()=>deployPath,
           pickBackup:async(_,accepted)=>{assert.ok(accepted());return ++picked===1?null:target.backupPath;},
           restore:{choose:async()=>target.backupPath,inspect:(input,current)=>restoreHost.inspectSharedRecoveryBackup(input,current),
                    apply:(input,current)=>restoreHost.restoreSharedRecoveryBackup(input,current)},
           url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared-setup.html')).href)},
           preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-setup-preload.cjs'))},
           createWindow:options=>{
             child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
             child.show=()=>{};
             return child;
           },
         });
         const owner={ipc:ipcMain,dialog:wizard,
           trusted:event=>event.sender===window.webContents&&event.senderFrame===event.sender.mainFrame,parent:()=>window};
         registerSharedRecoveryBackupIpc({...owner,host});
         registerSharedRecoveryInspectionIpc({...owner,host:restoreHost});
         const open=()=>window.webContents.executeJavaScript('window.wormhole.openSharedRecoveryBackup()');
         assert.equal(await window.webContents.executeJavaScript('typeof window.vaultSharedSetup'),'undefined');
         if(ask)assert.deepEqual(await native.exportSharedRecoveryBackup(target.backupPath,publicKey),{status:'authentication-required'});
         if(target.denyBackup){
           assert.equal(admission.recoveryBackup,undefined);
           await assert.rejects(open());
           assert.equal(child,undefined);
           assert.deepEqual(await native.exportSharedRecoveryBackup(target.backupPath,publicKey,{
             vaultId:startup.slots.vaultId,slotId:slot.id,password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex'),
           }),{status:'unavailable'});
           result={status:'unavailable'};
         }else{
           assert.equal(admission.recoveryBackup,true);
           const pending=open(); void pending.catch(()=>{});
           const waitFor=async expression=>{
             for(let i=0;i<400;i++){
               if(child&&!child.isDestroyed()&&await child.webContents.executeJavaScript(expression).catch(()=>false))return;
               await new Promise(resolve=>setTimeout(resolve,20));
             }
             throw Error('Workspace backup screen did not reach its expected state.');
           };
           const pageStatus=message=>waitFor('document.querySelector("[role=status]")?.textContent.includes('+JSON.stringify(message)+')');
           const submit=askHex=>child.webContents.executeJavaScript('(()=>{'+(ask?
             'document.querySelector("[name=password]").value='+JSON.stringify(accountPassword)+';document.querySelector("[name=ask]").value='+JSON.stringify(askHex)+';':'')+
             'document.querySelector("form").requestSubmit()})()');
           await waitFor('!!document.querySelector("form")');
           assert.equal(await child.webContents.executeJavaScript('!!document.querySelector("[name=password]")'),Boolean(ask));
           await submit(ask);await pageStatus('File selection cancelled');
           if(ask){await submit('5b'.repeat(32));await pageStatus('Check your Wormhole password');}
           await submit(ask);await pageStatus('Backup saved');
           assert.equal(picked,ask?3:2);
           const protectedDisplay=await child.webContents.executeJavaScript(${JSON.stringify(`(()=>{
             const code=document.querySelector("code[data-recovery]");
             const notice=document.querySelector("[role=status]");
             return !!code&&!code.hidden&&code.textContent.startsWith("WHREC1-")&&code.textContent.length===76&&
               !code.dispatchEvent(new Event("copy",{bubbles:true,cancelable:true}))&&
               notice.textContent.includes("displayed once")&&
               [...document.querySelectorAll('input[type=password]')].every(input=>input.value==="");
           })()`)});
           assert.equal(protectedDisplay,true);
           // Simulate the operator re-entering the disposable fixture password in the fresh wizard.
           let handwrittenCode=await child.webContents.executeJavaScript('document.querySelector("code[data-recovery]").textContent');
           await child.webContents.executeJavaScript('document.querySelector("button[type=button]").click()').catch(()=>{});
           assert.equal(await pending,undefined);
           assert.equal(child.isDestroyed(),true);
           try {
             const preparing=window.webContents.executeJavaScript('window.wormhole.prepareSharedWorkspaceRestore()');
             void preparing.catch(()=>{});
             await waitFor('document.querySelector("h1")?.textContent==="Restore a shared workspace"');
             await child.webContents.executeJavaScript('(()=>{document.querySelector("input[type=password]").value='+JSON.stringify(handwrittenCode)+';document.querySelector("form").requestSubmit(document.querySelectorAll("button[type=submit]")[1])})()');
             await pageStatus('Deployment SQL saved');
             assert.equal(await child.webContents.executeJavaScript('document.querySelector("input[type=password]").value'), '');
             const shown=await child.webContents.executeJavaScript('[...document.querySelectorAll("li")].map(item=>item.textContent)');
             assert.ok(shown.includes('Workspace ID '+host.unlockedWorkspaceId));
             assert.ok(shown.includes('Role tag '+target.backupRoleTag));
             assert.ok(shown.includes('Source schema '+target.schemaVersion+' · '+(ask?'Standard':'Default')));
             const sql=readFileSync(deployPath,'utf8');
             assert.ok(sql.includes(host.unlockedWorkspaceId)&&sql.includes('wh_'+target.backupRoleTag+'_owner'));
             assert.equal(sql.includes(handwrittenCode),false);
             if(target.restoreTarget){
               const entries={...target.restoreTarget,deployerPassword:'synthetic-wizard-password'};
               await child.webContents.executeJavaScript('(()=>{const form=document.querySelector("form");'+
                 'for(const [name,value] of Object.entries('+JSON.stringify(entries)+'))form.elements[name].value=value;'+
                 'form.querySelector("input[type=password]").value='+JSON.stringify(handwrittenCode)+';'+
                 'form.elements.confirmed.checked=true;form.requestSubmit(form.querySelector("fieldset button"));})()');
               await pageStatus('Workspace restored.');
               assert.equal(await child.webContents.executeJavaScript('[...document.querySelectorAll("input[type=password]")].every(field=>!field.value)'),true);
             }
             await child.webContents.executeJavaScript('document.querySelector("button[type=button]").click()').catch(()=>{});
             assert.equal(await preparing,undefined);
           } finally {
             handwrittenCode='';
             await restoreHost.stop();
           }
           result={status:'exported'};
         }
       } else if(mode==='admin-refresh-recovery-kit'){
         let finished=false;
         const pending=window.webContents.executeJavaScript('window.wormhole.refreshSharedRecoveryKit()').finally(()=>finished=true);
         void pending.catch(()=>{});
         const ready=async fragment=>{
           for(let i=0;i<350&&!finished;i++){
             const condition='!document.querySelector("button[type=submit]")?.disabled&&document.querySelector("h1")?.textContent==="Confirm recovery kit update"'+(fragment?'&&document.querySelector("[role=status]").textContent.includes('+JSON.stringify(fragment)+')':'');
             if(child&&!child.isDestroyed()&&await child.webContents.executeJavaScript(condition).catch(()=>false))return true;
             await new Promise(resolve=>setTimeout(resolve,20));
           }
           return false;
         };
         if(await ready('')){
           // The confirmation window closes on success or cancel. Wait for the request
           // in the parent even when Electron retires the child's reply channel first.
           const closingAction=async expression=>{
             try {await child.webContents.executeJavaScript(expression)}
             catch(error){if(!child.isDestroyed()||!String(error).includes('Render frame was disposed'))throw error}
           };
           const send=async factor=>closingAction('(()=>{const fields=document.querySelectorAll("input[type=password]");fields[0].value='+JSON.stringify(accountPassword)+';fields[1].value='+JSON.stringify(factor)+';document.querySelector("form").requestSubmit()})()');
           if(target.recoveryKitAuthentication==='cancel'){
             await closingAction('Array.from(document.querySelectorAll("button")).find(button=>button.textContent==="Cancel").click()');
           } else {
             if(target.recoveryKitAuthentication==='retry'){
               await send('');assert.ok(await ready('Check your details'));
               await send('5b'.repeat(32));assert.ok(await ready('Check your details'));
             }
             await send(ask);
           }
         } else assert.ok(finished,'Required recovery confirmation did not open');
         result=await pending;
       } else result=await renew(target.csr);
     }
     writeFileSync(${JSON.stringify(resultPath)},JSON.stringify(result),{mode:0o600});
   } finally { window?.destroy(); await host.stop(); }
   app.quit();
   return;
 }
 const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true}});
 await parent.loadURL('data:text/html,<html>Workspace</html>');
 let child;
 const createWindow=options=>{
   child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});
   child.show=()=>{};
   return child;
 };
 const runJS=fn=>child.webContents.executeJavaScript(fn,true);
 const wait=async code=>{for(let i=0;i<350;i++){if(child&&!child.isDestroyed()&&await runJS(code).catch(()=>false))return;await new Promise(resolve=>setTimeout(resolve,20));}throw Error('Wizard condition was not observed: '+code);};
 const click=name=>runJS('Array.from(document.querySelectorAll("button")).find(button=>button.textContent==='+JSON.stringify(name)+').click()');
 const fill=values=>runJS('for(const [name,value] of Object.entries('+JSON.stringify(values)+'))document.querySelector("[name="+name+"]").value=value');
 const credentials=async password=>{await fill({role:target.role,password});};
 const waitStatus=fragment=>wait('document.querySelector("[role=status]")?.textContent.includes('+JSON.stringify(fragment)+')');
 const waitButton=name=>wait('Array.from(document.querySelectorAll("button")).some(button=>button.textContent==='+JSON.stringify(name)+')');
 const localName='Preserved local connection';
 const checkLocal=async()=>{
   assert.ok(host.unlockedWorkspaceId && !host.isSharedWorkspace);
   const workspace=await host.workspace();
   assert.equal(workspace.tree.length,(target.importLocal?2:1)+(target.webFixturePort?1:0)+(exerciseSlotBinding?1:0)+(exerciseSharedDefault?1:0));
   assert.ok(workspace.tree.some(node=>node.name===localName));
 };
 if(mode==='admin-offline-signin'){
   const {VaultSharedAuthenticationDialog}=await import(${fromDist('vault-shared-dialog.js')});
   const authentication=new VaultSharedAuthenticationDialog({host,ipc:ipcMain,createWindow,url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-preload.cjs'))},appVersion:'2.4.3',pickTLSUpdate:async()=>target.tlsBundlePath});
   try{
     const signingIn=authentication.open(parent,()=>true,'admit',await host.startup());
     void signingIn.catch(()=>{});
     await wait('document.querySelector("button[type=submit]")?.disabled===false');
     await click('Choose signed trust update…');
     await waitStatus('Trust update selected.');
     await runJS('(()=>{const inputs=document.querySelectorAll("input[type=password]");inputs[0].value='+JSON.stringify(accountPassword)+';inputs[1].value='+JSON.stringify(ask)+';document.querySelector("form").requestSubmit();})()').catch(error=>{if(!child.isDestroyed())throw error;});
     let result;
     if(target.rejectTLSUpdate){
       await waitStatus('Check your account details and the selected trust update.');
       await click('Cancel').catch(error=>{if(!child.isDestroyed())throw error;});
       assert.equal(await signingIn,null);
       assert.equal(host.unlockedWorkspaceId,undefined);
       result={rejected:true};
     } else {
       const admission=await signingIn;
       assert.equal(admission?.tls,'verified');
       assert.ok(admission.admitted);
       result={workspaceId:host.unlockedWorkspaceId,admitted:true};
     }
     writeFileSync(${JSON.stringify(resultPath)},JSON.stringify(result),{mode:0o600});
   }finally{await authentication.cancel();parent.destroy();await host.stop();}
   app.quit();
   return;
 }
 if(mode==='local-create') {
   const {VaultCreateDialog}=await import(${fromDist('vault-create-dialog.js')});
   const create=new VaultCreateDialog({host,ipc:ipcMain,createWindow,url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-create.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-create-preload.cjs'))},activate:()=>{}});
   try {
     const created=create.open(parent,()=>true);
     void created.catch(()=>{});
     await wait('document.querySelectorAll("input").length === 2');
     await runJS('(()=>{const inputs=document.querySelectorAll("input");inputs[0].value=inputs[1].value='+JSON.stringify(localPassword)+';inputs[1].dispatchEvent(new Event("input"));document.querySelector("form").requestSubmit();})()');
     await wait('document.querySelector("h1").textContent === "Save your recovery code"');
     await runJS('(()=>{const parts=document.querySelector("pre").textContent.slice(7).split("-");document.querySelectorAll("button")[1].click();const inputs=document.querySelectorAll("input");document.querySelectorAll("label span").forEach((label,index)=>inputs[index].value=parts[Number(label.textContent.split(" ")[1])-1]);inputs[1].dispatchEvent(new Event("input"));document.querySelector("form").requestSubmit();})()').catch(error=>{if(!child.isDestroyed())throw error});
     assert.equal(await created,true);
     const input=${JSON.stringify(connectionInput())};
     input.metadata.name=localName;
     input.password=new TextEncoder().encode('synthetic-local-connection-password');
     input.notes=new TextEncoder().encode('Synthetic local notes');
     await host.saveConnection(input);
     if(exerciseSharedDefault){
       const metadata={...input.metadata,id:'',name:overrideConnectionName,protocol:'rdp',rdp:${JSON.stringify(appRdpDefaults())},port:3389,inlinePasswordAction:'clear'};
       await host.saveConnection({rowVersion:'0',notesAction:'clear',metadata,password:new Uint8Array(),notes:new Uint8Array()});
       for (const name of [sharedCredentialName, personalCredentialName]) {
         await host.editCredential({rowVersion:'0',metadata:{id:'',name,protocol:'rdp',
         kind:'password',username:'fixture-user',domain:'FIXTURE',provider:'Local',bitwardenItemId:'',bitwardenItemName:'',
         privateKeyPath:'',certificatePath:'',clearPassphrase:false,clearCertificate:false},
         password:new TextEncoder().encode('synthetic-slot-'+name),passphrase:new Uint8Array()});
       }
     }
     if(exerciseSlotBinding){
       const metadata={...input.metadata,id:'',name:slotConnectionName,inlinePasswordAction:'clear'};
       await host.saveConnection({rowVersion:'0',notesAction:'clear',metadata,password:new Uint8Array(),notes:new Uint8Array()});
     }
     if(target.webFixturePort){
       const metadata={...input.metadata,id:'',name:'Shared web fixture',protocol:'http',host:'127.0.0.1/login',
         port:target.webFixturePort,username:'',inlinePasswordAction:'clear'};
       await host.saveConnection({rowVersion:'0',notesAction:'clear',metadata,
         password:new Uint8Array(),notes:new Uint8Array()});
     }
     if(target.importLocal) await host.saveFolder({id:'',rowVersion:'0',parentId:'',name:'Shared grant folder',
       sshAutoSudo:null,tunnelEnabled:null,tunnelConfigId:'',credentialMode:0,credentialId:''});
     await checkLocal();
     writeFileSync(${JSON.stringify(resultPath)},'true');
   } finally {await create.cancel();await host.stop();parent.destroy();}
   app.quit();
   return;
 }
 if(existingLocal) {
   const startup=await host.startup();
   assert.ok(startup.slots && !startup.shared && !startup.sharedJoin);
   const slot=startup.slots.slots.find(slot=>slot.kind==='password');
   await host.unlock({vaultId:startup.slots.vaultId,slotId:slot.id,kind:'password',factor:new TextEncoder().encode(localPassword)});
   await checkLocal();
 }
 const recoveryTrust=${JSON.stringify(join(directory, 'admin-recovery.whtls'))};
 let recoveredHost;
 const wizard=new VaultSharedSetupDialog({host,ipc:ipcMain,createWindow,url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-shared-setup.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-setup-preload.cjs'))},pickExport:async(_,format)=>format==='hba'?${JSON.stringify(join(directory, 'workspace-hba.conf'))}:${JSON.stringify(join(directory, 'workspace.sql'))},pickRecovery:async()=>${JSON.stringify(join(directory, 'organisation.whrecovery'))},join:(value,accepted)=>host.sharedJoinAdministrator(value,'2.4.3',accepted),
   recover:{
     choose:async(_,artifact)=>artifact==='kit'?${JSON.stringify(join(directory, 'organisation.whrecovery'))}:recoveryTrust,
     submit:(value,accepted)=>recoveredHost.sharedRecoverAdministrator(value,'2.4.3',accepted)
   }});
 const opened=wizard.open(parent,()=>!host.isSharedWorkspace,()=>!parent.isDestroyed(),existingLocal);
 const closeWizard=async()=>{
   await click('Close').catch(error=>{
     if(!String(error).includes('Render frame was disposed'))throw error;
   });
   await opened;
   assert.ok(child.isDestroyed());
 };
 void opened.catch(()=>{});
 try {
   if(mode==='run'||mode==='export'){
     await wait('!!document.querySelector("[name=host]")');
     await fill({hosting:mode==='export'?'self-hosted':'managed',host:target.host,port:target.port,database:target.database,caPem:target.caPem});
     if(mode==='export')await fill({tlsSource:'external'});
     await runJS('document.querySelector("[name=hosting]").dispatchEvent(new Event("change"))');
     await click('Continue');
     await wait('!!document.querySelector("[name=role]")');
   }
   if(mode==='generated-prepare'){
     await wait('!!document.querySelector("[name=tlsSource]")');
     await fill({host:target.host,port:target.port,database:target.database,aliases:'db.example.test',tlsSource:'generate'});
     await runJS('document.querySelector("[name=tlsSource]").dispatchEvent(new Event("change"))');
     const keyPassphrase=process.env.WORMHOLE_TEST_SETUP_KEY_PASSPHRASE;
     await fill({accountPassword,confirm:accountPassword,ask,keyPassphrase,confirmPassphrase:keyPassphrase});
     await click('Generate server key');
     await waitButton('Save server files');
     assert.equal(await runJS('!!document.querySelector("[name=keyPassphrase]")'),false);
     const pending=await host.sharedSetup({action:'plan'},()=>true);
     assert.equal(pending.serverKit.state,'pending');
     await click('Save server files');
     await waitStatus('Server files saved.');
     assert.equal(await runJS('Array.from(document.querySelectorAll("button")).some(button=>button.textContent==="Delete local server key")'),false);
     const {plan,tls,serverKit}=await host.sharedSetup({action:'plan'},()=>true);
     assert.equal(serverKit.state,'saved');
     assert.equal(await runJS('document.querySelector("[name=serverKitFolder]").value'),serverKit.folder);
     await assert.rejects(host.sharedSetup({action:'delete-server-key',workspaceId:plan.workspaceId},()=>true));
     writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({plan,tls,serverKit}),{mode:0o600});
     await closeWizard();
   } else if(mode==='csr-prepare'){
     await wait('!!document.querySelector("[name=csr]")');
     await fill({host:target.host,port:target.port,database:target.database,aliases:'other.example.test',csr:target.csr,accountPassword,confirm:accountPassword,ask});
     await click('Show server commands');
     assert.ok(await runJS('document.querySelector("pre").textContent.includes("IP:127.0.0.1,DNS:other.example.test")'));
     await click('Sign certificate request');
     await waitStatus('could not be signed');
     assert.equal(await runJS('document.querySelector("[name=accountPassword]").value'),'');
     await fill({aliases:'db.example.test',accountPassword,confirm:accountPassword,ask});
     await click('Sign certificate request');
     await waitStatus('Install the signed certificate');
     await credentials('synthetic-wizard-password');
     await click('Test connection');
     await waitStatus('TLS verification failed');
     const {plan,tls}=await host.sharedSetup({action:'plan'},()=>true);
     assert.equal(await runJS('document.querySelector("[name=serverCertificate]").value'),tls.serverPem);
     assert.equal(await runJS('document.querySelector("[name=workspaceCA]").value'),tls.caPem);
     writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({plan,tls}),{mode:0o600});
     await closeWizard();
   } else if(mode==='run'||mode==='csr-run'){
     await waitButton('Test connection');
     assert.equal(await runJS('Array.from(document.querySelectorAll("button")).find(button=>button.textContent==="Deploy schema").disabled'),true);
     await credentials('synthetic-wrong-password');
     await click('Test connection');
     await waitStatus('SCRAM authentication failed');
     assert.equal(await runJS('document.querySelector("[name=password]").value'),'');
     await credentials('synthetic-wizard-password');
     await click('Test connection');
     await wait('document.body.textContent.includes("SCRAM channel binding") && !Array.from(document.querySelectorAll("button")).find(button=>button.textContent==="Deploy schema").disabled');
     await credentials('synthetic-wizard-password');
     await click('Deploy schema');
     await waitStatus('first administrator');
   } else if(mode==='export') {
     await runJS('document.querySelector("details summary").click()');
     await fill({hbaNetworks:'192.0.2.5/24'});
     await click('Export pg_hba.conf rules');
     await waitStatus('Use the network address');
     await fill({hbaNetworks:'127.0.0.1, ::1'});
     await click('Export pg_hba.conf rules');
     await waitStatus('Client access rules saved.');
     await click('Export SQL');
     await waitStatus('SQL saved.');
   } else if(mode!=='admin-enroll') {
     await wait('Array.from(document.querySelectorAll("button")).some(button=>button.textContent==="Check deployment")');
     await credentials('synthetic-wizard-password');
     await click('Check deployment');
     if(mode==='catalog-mismatch'){
       await waitStatus('SQL functions and access grants');
       assert.equal(await runJS('Array.from(document.querySelectorAll("button")).some(button=>button.textContent==="Create first administrator")'),false);
     } else {
       await waitStatus('first administrator');
       if(mode==='reopen'){
         const observation=target.hbaInstalled?'PostgreSQL refused plaintext startup':'PostgreSQL accepted plaintext startup or offered authentication';
         assert.ok((await runJS('document.body.textContent')).includes(observation));
       }
     }
     if(mode==='reopen'&&target.generated){
       await waitButton('Delete local server key');
       await click('Delete local server key');
       await waitStatus('local server key was removed');
       const checked=await host.sharedSetup({action:'plan'},()=>true);
       assert.equal(checked.serverKit.state,'removed');
     }
   }
   if(mode==='admin-prepare') {
     await waitButton('Create first administrator');
     await click('Create first administrator');
     if(target.directConnectionDevices) await fill({directConnectionDevices:String(target.directConnectionDevices)});
     if(target.csr){
       await fill({role:target.role,password:'synthetic-wizard-password',loginName:'first-admin',profile:ask?'standard':'default',accountPassword:'wrong-setup-factor',confirm:'wrong-setup-factor',ask});
       await click('Prepare administrator');
       await waitStatus('could not complete');
     }
     await fill({role:target.role,password:'synthetic-wizard-password',loginName:'first-admin',profile:ask?'standard':'default',accountPassword,confirm:accountPassword,ask});
     await click('Prepare administrator');
     await waitButton('Save recovery kit and show key');
     const reply=await host.sharedSetup({action:'plan'},()=>true);
     assert.equal(reply.adminPending,true);
   }
   if(mode==='admin-enroll') {
     await waitButton('Unlock setup');
     await fill({accountPassword:'synthetic-wrong-administrator',ask});
     await click('Unlock setup');
     await waitStatus('could not be completed');
     await fill({accountPassword,ask});
     await click('Unlock setup');
     await waitButton('Save recovery kit and show key');
     await fill({accountPassword,ask});
     await click('Save recovery kit and show key');
     await wait('document.querySelector("code[data-recovery]")?.textContent.startsWith("WHREC1-")');
     let offlineCode=target.adminRecovery?await runJS('document.querySelector("code[data-recovery]").textContent'):undefined;
     assert.equal(await runJS('document.querySelector("code[data-recovery]").dispatchEvent(new Event("copy",{bubbles:true,cancelable:true}))'),false);
     assert.equal(await runJS('!!document.querySelector("[name=groupFirst]")'),false);
     await runJS('(()=>{const parts=document.querySelector("code[data-recovery]").textContent.split("-"); Array.from(document.querySelectorAll("button")).find(b=>b.textContent==="I saved the recovery key").click(); for(const name of ["groupFirst","groupSecond"]){const field=document.querySelector("[name="+name+"]"); const index=Number(field.closest("label").textContent.split(" ").at(-1)); field.value=parts[index];}})()');
     await fill({accountPassword,ask});
     await click('Confirm offline recovery');
     await waitButton('Create administrator invitation');
     assert.equal(await runJS('document.body.textContent.includes("WHREC1-")'),false);
     await fill({accountPassword,ask,role:target.role,password:'synthetic-wrong-password'});
     await click('Create administrator invitation');
     await waitStatus('SCRAM authentication failed');
     await fill({accountPassword,ask,role:target.role,password:'synthetic-wizard-password'});
     await click('Create administrator invitation');
     let joinButton=existingLocal?'Join and switch on restart':'Join workspace';
     await waitButton(joinButton);
     if(target.importLocal){
       await fill({accountPassword,ask});
       await click('Preview local import');
       await waitButton('Import and switch on restart');
       assert.equal(await runJS('document.querySelector("select").value'),'personal');
       assert.equal(await runJS('document.body.textContent.includes("Synthetic local notes")'),false);
       const folderSelect='[...document.querySelectorAll("label")].find(l=>l.textContent.includes("Shared grant folder"))?.querySelector("select")';
       const destination=value=>runJS('(()=>{const s='+folderSelect+';s.value='+JSON.stringify(value)+';s.dispatchEvent(new Event("change"));})()');
       await destination('shared');
       assert.equal(await runJS('[...document.querySelectorAll("button")].find(b=>b.textContent==="Import and switch on restart").disabled'),true);
       await click('Review selections');
       await waitStatus('Review the destinations, then confirm');
       assert.equal(await runJS('('+folderSelect+').value'),'shared');
       await destination('personal');
       await click('Review selections');
       await waitStatus('Review the destinations, then confirm');
       await destination('shared');
       if(exerciseSharedDefault){
         await runJS('(()=>{const s=[...document.querySelectorAll("label")].find(l=>l.textContent.includes('+JSON.stringify(sharedCredentialName)+'))?.querySelector("select");s.value="shared";s.dispatchEvent(new Event("change"));})()');
         await runJS('(()=>{const s=[...document.querySelectorAll("label")].find(l=>l.textContent.includes('+JSON.stringify(personalCredentialName)+'))?.querySelector("select");s.value="personal";s.dispatchEvent(new Event("change"));})()');
       }
       await click('Review selections');
       await waitStatus('Review the destinations, then confirm');
       joinButton='Import and switch on restart';
     }
     await fill({accountPassword,ask,deviceName:'Fixture administrator device'});
     await click(joinButton).catch(error=>{if(!child.isDestroyed())throw error});
     for(let attempt=0;!child.isDestroyed() && attempt<500;attempt++){
       await new Promise(resolve=>setTimeout(resolve,20));
     }
     if(!child.isDestroyed())throw Error('Administrator Join did not close: '+await runJS('document.querySelector("[role=status]")?.textContent'));
     const admission=await opened;
     if(existingLocal){
       assert.deepEqual(admission,{switchOnRestart:true});
       await checkLocal();
       const retry=await host.sharedJoinAdministrator({action:'admin-join',workspaceId:(await host.sharedSetup({action:'plan'},()=>true)).plan.workspaceId,accountPassword:new TextEncoder().encode(accountPassword),...(ask?{ask:Buffer.from(ask,'hex')}:{}) ,deviceName:'Fixture administrator device'},'2.4.3',()=>true);
       assert.deepEqual(retry,admission);
       await checkLocal();
       writeFileSync(${JSON.stringify(resultPath)},JSON.stringify(admission),{mode:0o600});
     } else {
       assert.ok(admission?.admitted);
       assert.equal(admission.tls,'verified');
       assert.ok(host.isSharedWorkspace && host.unlockedWorkspaceId);
     }
     if(target.adminRecovery){
       if(existingLocal){
         await host.stop();
         host=makeHost();
         const selected=await host.startup();
         const slot=selected.slots.slots.find(slot=>slot.kind==='password');
         const unlocked=await host.sharedUnlock({vaultId:selected.slots.vaultId,slotId:slot.id,password:Buffer.from(accountPassword),ask:Buffer.from(ask,'hex')},'2.4.3',()=>true);
         assert.ok(unlocked.admitted);
       }
       assert.equal(await host.exportSharedTLSBundle(async()=>recoveryTrust,()=>true),true);
       const {mkdirSync,readFileSync,existsSync}=require('node:fs');
       const recoveryProfiles=target.groupHandoff?[['recovered','recovered-admin'],['group-issuer','group-issuer']]:[['recovered','recovered-admin']];
       for(const [profile,loginName] of recoveryProfiles){
         const recoveryRoot=require('node:path').join(${JSON.stringify(directory)},profile);
         const recoveredPath=require('node:path').join(recoveryRoot,'workspace.db');
         mkdirSync(recoveryRoot,{recursive:true});
         recoveredHost=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(resolve(wizardBackend))},databasePath:recoveredPath,userDataPath:recoveryRoot}),()=>true);
         const recovering=wizard.open(parent,()=>true,()=>!parent.isDestroyed(),false,'recovery');
         await waitButton('Choose recovery files and continue…');
         const factors={...target.adminRecovery, role:'wh_'+target.adminRecovery.roleTag+'_deployer',host:target.host,port:target.port,database:target.database,
           accountPassword,confirmPassword:accountPassword,deployerPassword:'synthetic-wizard-password',recoveryCode:offlineCode,loginName,deviceName:'Replacement device'};
         delete factors.roleTag;
         await fill(factors);
         await runJS('document.querySelector("[name=confirmed]").checked=true');
         await click('Choose recovery files and continue…');
         await waitStatus('Could not recover access');
         const checkpoint=recoveredPath+'.shared-admin-recovery';
         assert.ok(existsSync(checkpoint));
         assert.ok(readFileSync(checkpoint).length>128);
         await fill({...factors,ask});
         await click('Choose recovery files and continue…').catch(error=>{if(!child.isDestroyed())throw error});
         const result=await recovering;
         factors.recoveryCode=undefined;
         assert.ok(result?.admitted);
         assert.equal(result.tls,'verified');
         assert.equal(recoveredHost.unlockedWorkspaceId,host.unlockedWorkspaceId);
         assert.equal((await recoveredHost.startup()).shared.lastLoginName,loginName);
         assert.equal(existsSync(checkpoint),false);
         await recoveredHost.stop();
       }
       offlineCode=undefined;
     }
     if(!existingLocal){
       writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({workspaceId:host.unlockedWorkspaceId,admitted:true}),{mode:0o600});
     }
   } else if(mode!=='csr-prepare'&&mode!=='generated-prepare') {
     const reply=await host.sharedSetup({action:'plan'},()=>true);
     writeFileSync(${JSON.stringify(resultPath)},JSON.stringify(reply.plan),{mode:0o600});
     await closeWizard();
     if(existingLocal)await checkLocal();
     else assert.equal(host.unlockedWorkspaceId,undefined);
   }
 } finally { await wizard.cancel(); await recoveredHost?.stop(); await host.stop(); parent.destroy(); }
 app.quit();
}).catch(error=>{console.error(error);app.exit(1)});`,
  );
  const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
  if (target.generated) {
    const cache = join(directory, 'server-export');
    await mkdir(cache, { recursive: true });
    env[process.platform === 'win32' ? 'LOCALAPPDATA' : 'XDG_CACHE_HOME'] = cache;
    env.WORMHOLE_TEST_SETUP_KEY_PASSPHRASE = syntheticServerFactor;
  }
  const headless = process.platform === 'linux' && !env.DISPLAY;
  let inspected = false;
  let inspectionFailure: unknown;
  const inspector =
    inspectConnections &&
    createServer(async (_request, response) => {
      try {
        await inspectConnections();
        inspected = true;
        response.writeHead(204).end();
      } catch (error) {
        inspectionFailure = error;
        response.writeHead(500).end();
      }
    });
  if (inspector) {
    inspector.listen(0, '127.0.0.1');
    await once(inspector, 'listening');
    const address = inspector.address();
    assert.ok(address && typeof address !== 'string');
    env.WORMHOLE_TEST_INSPECT_PORT = String(address.port);
  }
  const result = await run(
    headless ? 'xvfb-run' : electron,
    headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
    {
      env,
      windowsHide: true,
      timeout: 90_000,
      maxBuffer: 16 * 1024,
    },
  ).finally(() => {
    inspector?.close();
    if (inspectionFailure) throw inspectionFailure;
  });
  if (inspector) assert.ok(inspected, 'admitted Electron device was not inspected');
  assert.doesNotMatch(
    result.stdout + result.stderr,
    /synthetic-(wizard|administrator|local-vault|local-connection)-password|synthetic-standalone-server-key-factor|WHREC1-/,
  );
  return JSON.parse(await readFile(resultPath, 'utf8'));
}

async function checkWorkspaceBackupArchive(path: string) {
  const archive = await readFile(path, 'utf8');
  const sealed = JSON.parse(archive);
  assert.equal(sealed.schemaVersion, 3);
  assert.equal(sealed.encryption, 'aes-gcm');
  assert.equal(sealed.payload, undefined);
  assert.ok(sealed.encryptedPayload.ciphertextB64.length > 1000);
  assert.doesNotMatch(archive, /WHREC1-|first-admin|synthetic-administrator-password/);
}

for (const mode of [
  'run',
  'export',
  'local',
  'local-import',
  'local-ssh-standard',
  'local-group-suspension',
  'local-group-handoff',
  'local-web',
  'csr',
  'csr-default',
  'generated',
  'recovery',
] as const) {
  const groupScenario = mode === 'local-group-suspension' || mode === 'local-group-handoff';
  const groupTitle =
    mode === 'local-group-handoff'
      ? 'a different Standard custodian completes a signed group suspension after the issuer exits'
      : 'a Standard account suspension automatically rotates certified group and boundary keys';
  test(
    groupScenario
      ? groupTitle
      : mode === 'run'
        ? 'protected direct deploy resumes offline recovery and admits its first Standard administrator with ASK'
        : mode === 'export'
          ? 'protected exported SQL deploy admits its first Default administrator and retains personal Standard after restart without an ASK'
          : mode === 'local'
            ? 'an unlocked local vault stages shared admission and switches on restart without overwriting local data'
            : mode === 'local-ssh-standard'
              ? 'Standard shared SSH host key changes require the enrolled password and ASK in Electron'
              : mode === 'local-import'
                ? 'local import reviews destinations in Electron and opens imported notes after PostgreSQL admission'
                : mode === 'local-web'
                  ? 'Chromium restores a saved web cookie after a real shared vault restart on PostgreSQL'
                  : mode === 'csr'
                    ? 'self-hosted PostgreSQL rotates its CA and an offline device imports the signed update'
                    : mode === 'csr-default'
                      ? 'Default administrator exports an encrypted backup in the isolated window without fresh factors'
                      : mode === 'recovery'
                        ? 'protected emergency recovery admits a new administrator and the reset queue delivers two offers'
                        : 'self-hosted generation installs an encrypted server key and retires the local copy after Check deployment',
    {
      timeout: 240_000,
      skip:
        !process.env.WORMHOLE_TEST_POSTGRES_BIN ||
        (mode === 'generated' && process.platform === 'darwin'),
    },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), 'wormhole-setup-'));
      let database: ReturnType<typeof startDatabase> | undefined;
      let restoreTarget: ReturnType<typeof startDatabase> | undefined;
      let webServer: Server | undefined;
      let scenarioFailed = false;
      const receivedCookies = new Map<string, string>();
      try {
        const fixture = join(directory, 'postgres.test' + nativeSuffix);
        await run('go', ['test', '-c', '-o', fixture, './internal/sharedpg'], {
          cwd: backend,
          windowsHide: true,
          timeout: 120_000,
        });
        const withCSR = mode === 'csr' || mode === 'csr-default';
        const generated = mode === 'generated';
        const withASK =
          mode === 'run' ||
          mode === 'recovery' ||
          mode === 'csr' ||
          mode === 'local-ssh-standard' ||
          groupScenario ||
          generated;
        database = startDatabase(
          fixture,
          join(root, 'artifacts', 'vault', basename(directory)),
          withCSR,
          generated,
        );
        const target = await database.read();
        if (mode === 'export') target.directConnectionDevices = 300;
        if (mode === 'run') target.directConnectionDevices = 301;
        if (mode === 'local-web') {
          webServer = createServer((request, response) => {
            receivedCookies.set(request.url ?? '', request.headers.cookie ?? '');
            if (request.url === '/login')
              response.setHeader(
                'Set-Cookie',
                'shared_fixture=synthetic_shared_cookie; HttpOnly; Secure; Path=/',
              );
            response.end('Shared browser fixture');
          });
          webServer.listen(0, '127.0.0.1');
          await once(webServer, 'listening');
          const address = webServer.address();
          assert.ok(address && typeof address !== 'string');
          target.webFixturePort = address.port;
        }
        if (generated) target.generated = true;
        assert.equal(target.host, '127.0.0.1');
        const existingLocal = mode.startsWith('local');
        if (existingLocal && mode !== 'local') target.importLocal = true;
        if (mode === 'local-ssh-standard') target.checkStandardPin = true;
        const sourceDatabase = join(directory, 'profile', 'workspace.db');
        const sourceFiles = [sourceDatabase, sourceDatabase + '.slots'];
        if (existingLocal)
          assert.equal(await exerciseWizard(directory, 'local-create', target), true);
        const original = existingLocal
          ? await Promise.all(sourceFiles.map((file) => readFile(file)))
          : [];
        let installedCA: X509Certificate | undefined;
        let installedSerial: string | undefined;
        let generatedFolder: string | undefined;
        if (withCSR || generated) {
          const {
            plan: draft,
            tls,
            serverKit,
          } = await exerciseWizard(
            directory,
            generated ? 'generated-prepare' : 'csr-prepare',
            target,
            withASK,
          );
          installedCA = new X509Certificate(tls.caPem);
          const certificate = new X509Certificate(tls.serverPem);
          installedSerial = certificate.serialNumber;
          assert.ok(certificate.verify(installedCA.publicKey));
          assert.equal(certificate.checkIP(target.host), target.host);
          assert.equal(certificate.checkHost('db.example.test'), 'db.example.test');
          let keyPem: string | undefined;
          if (generated) {
            generatedFolder = serverKit.folder as string;
            assert.equal(
              await realpath(resolve(generatedFolder, '../..')),
              await realpath(join(directory, 'server-export')),
            );
            keyPem = await readFile(join(generatedFolder, 'server.key'), 'utf8');
            assert.match(keyPem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            assert.doesNotMatch(keyPem, new RegExp(syntheticServerFactor));
            assert.equal(
              await readFile(join(generatedFolder, 'server.pem'), 'utf8'),
              tls.serverPem,
            );
            assert.equal(
              await readFile(join(generatedFolder, 'workspace-ca.pem'), 'utf8'),
              tls.caPem,
            );
            assert.match(
              await readFile(join(generatedFolder, 'postgresql-tls.conf'), 'utf8'),
              /ssl_passphrase_command/,
            );
          }
          database.send({
            action: 'installTLS',
            workspaceId: draft.workspaceId,
            roleTag: draft.roleTag,
            ...tls,
            ...(keyPem ? { keyPem } : {}),
          });
          assert.deepEqual(await database.read(), { installed: true });
        }
        const plan = await exerciseWizard(
          directory,
          mode === 'export' ? 'export' : withCSR || generated ? 'csr-run' : 'run',
          target,
          true,
          existingLocal,
        );
        assert.equal(plan.state, mode === 'export' ? 'exported' : 'submitted');
        assert.equal(plan.host, target.host);
        assert.equal(plan.database, target.database);
        assert.equal(
          plan.hosting,
          mode === 'export' || withCSR || generated ? 'self-hosted' : 'managed',
        );
        const command = {
          action: 'check',
          workspaceId: plan.workspaceId,
          roleTag: plan.roleTag,
          digest: '',
        };
        if (mode === 'export') {
          const script = await readFile(join(directory, 'workspace.sql'));
          const hba = await readFile(join(directory, 'workspace-hba.conf'), 'utf8');
          database.send({ ...command, action: 'installHBA', hba });
          assert.deepEqual(await database.read(), { installed: true });
          target.hbaInstalled = true;
          command.action = 'applyExport';
          command.digest = createHash('sha256').update(script).digest('hex');
        }
        database.send(command);
        const verified = await database.read();
        assert.deepEqual(verified, {
          version: target.schemaVersion,
          provisioning: true,
          requiresTls: true,
        });
        if (mode === 'export') {
          database.send({ ...command, action: 'enableRowSecurity' });
          assert.deepEqual(await database.read(), { confirmed: true });
          database.send({ ...command, action: 'changeRoutineConfiguration' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'catalog-mismatch', target, true, existingLocal),
            plan,
          );
          database.send({ ...command, action: 'restoreRoutineConfiguration' });
          assert.deepEqual(await database.read(), { confirmed: true });
        }
        const resumed = await exerciseWizard(directory, 'reopen', target, true, existingLocal);
        assert.deepEqual(resumed, plan);
        if (generatedFolder) {
          await assert.rejects(readFile(join(generatedFolder, 'server.key')), { code: 'ENOENT' });
          assert.ok((await readFile(join(generatedFolder, 'server.pem'))).length);
        }
        const sealed = await readFile(join(directory, 'profile', 'workspace.db.shared-setup'));
        assert.equal(sealed.includes(Buffer.from('synthetic-wizard-password')), false);
        assert.equal(sealed.includes(Buffer.from('synthetic-wrong-password')), false);
        assert.equal(sealed.includes(Buffer.from(target.role)), false);
        if (mode === 'recovery' || groupScenario) {
          database.send({ ...command, action: 'enableRecoveryDeployer' });
          assert.deepEqual(await database.read(), { confirmed: true });
          target.adminRecovery = { workspaceId: plan.workspaceId, roleTag: plan.roleTag };
          target.groupHandoff = mode === 'local-group-handoff';
        }
        const prepared = await exerciseWizard(
          directory,
          'admin-prepare',
          target,
          withASK,
          existingLocal,
        );
        assert.deepEqual(prepared, plan);
        database.send({ ...command, action: 'checkUnpublished' });
        assert.deepEqual(await database.read(), {
          version: target.schemaVersion,
          provisioning: true,
          requiresTls: true,
        });
        const checkpoint = await readFile(
          join(directory, 'profile', 'workspace.db.shared-setup.administrator'),
        );
        assert.equal(checkpoint.includes(Buffer.from('synthetic-administrator-password')), false);
        assert.equal(checkpoint.includes(Buffer.from('first-admin')), false);
        assert.equal(checkpoint.includes(Buffer.from('WHREC1-')), false);
        if (existingLocal) {
          await assert.rejects(readFile(sourceDatabase + '.shared-selection'), { code: 'ENOENT' });
        }
        const admitted = { workspaceId: plan.workspaceId, admitted: true };
        const joined = await exerciseWizard(
          directory,
          'admin-enroll',
          target,
          withASK,
          existingLocal,
        );
        assert.deepEqual(joined, existingLocal ? { switchOnRestart: true } : admitted);
        if (mode === 'local-group-suspension') {
          database.send({ ...command, action: 'seedBlockedRotation' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-suspend-before-restart', target, withASK),
            admitted,
          );
          database.send({ ...command, action: 'releaseRotationLock' });
          assert.deepEqual(await database.read(), { released: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'custodian-resume-suspension', target, withASK),
            admitted,
          );
          database.send({ ...command, action: 'checkCustodianHandoff' });
          assert.deepEqual(await database.read(), { confirmed: true });
        }
        if (groupScenario) {
          const groupRotation = await exerciseWizard(
            directory,
            'admin-group-suspension',
            target,
            withASK,
          );
          database.send({
            ...command,
            action: 'lockGroupBoundary',
            boundaryId: groupRotation.boundaryId,
            groupHandoff: target.groupHandoff,
          });
          assert.deepEqual(await database.read(), { locked: true });
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-group-suspension',
              { ...target, groupRotation },
              withASK,
            ),
            { status: target.groupHandoff ? 'needs-removal' : 'queued' },
          );
          database.send({ ...command, action: 'releaseRotationLock' });
          assert.deepEqual(await database.read(), { released: true });
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-group-suspension',
              { ...target, groupRotation, resumeGroup: true },
              withASK,
            ),
            { status: 'resolved' },
          );
          database.send({
            ...command,
            action: 'checkSuspendedGroupRotation',
            groupHandoff: target.groupHandoff,
          });
          assert.deepEqual(await database.read(), { confirmed: true });
          return;
        }
        if (mode === 'local-import') {
          database.send({ ...command, action: 'seedBlockedRotation' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-suspend-before-restart', target, withASK),
            admitted,
          );
          database.send({ ...command, action: 'releaseRotationLock' });
          assert.deepEqual(await database.read(), { released: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-resume-suspension', target, withASK),
            admitted,
          );
          database.send({ ...command, action: 'seedSuspensionAccount' });
          assert.deepEqual(await database.read(), { confirmed: true });
        }
        if (mode === 'run') {
          database.send({ ...command, action: 'limitDeviceConnections' });
          assert.deepEqual(await database.read(), { limited: true });
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-reopen',
              { ...target, expectConnectionLimit: true },
              withASK,
            ),
            { limited: true },
          );
          database.send({ ...command, action: 'restoreDeviceConnections' });
          assert.deepEqual(await database.read(), { limited: false });
        }
        assert.deepEqual(
          await exerciseWizard(
            directory,
            'admin-reopen',
            { ...target, chooseStandard: mode === 'export' },
            withASK,
            false,
            ['export', 'run', 'local'].includes(mode)
              ? async () => {
                  database!.send({ ...command, action: 'inspectDeviceConnections' });
                  const listen = mode === 'export';
                  assert.deepEqual(await database!.read(), {
                    connections: listen ? '2' : '1',
                    listeners: listen ? '1' : '0',
                  });
                }
              : undefined,
          ),
          admitted,
        );
        if (mode === 'local-web')
          assert.match(
            receivedCookies.get('/shared-resume') ?? '',
            /shared_fixture=synthetic_shared_cookie/,
          );
        if (mode === 'local-import') {
          database.send({ ...command, action: 'checkLocalImport' });
          assert.deepEqual(await database.read(), { confirmed: true });
        }
        if (mode === 'csr-default') {
          const backupPath = join(directory, 'shared-recovery.json');
          restoreTarget = startDatabase(fixture, join(directory, 'restore-cluster'), true, false);
          const destination = await restoreTarget.read();
          const leaf = await exerciseWizard(
            directory,
            'admin-renew',
            { ...target, csr: destination.csr },
            false,
          );
          assert.equal(leaf.status, 'issued');
          restoreTarget.send({
            ...command,
            action: 'installTLS',
            caPem: installedCA!.toString(),
            serverPem: leaf.serverPem,
          });
          assert.deepEqual(await restoreTarget.read(), { installed: true });
          restoreTarget.send({ ...command, action: 'deployRestoreTarget' });
          assert.deepEqual(await restoreTarget.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-backup',
              {
                ...target,
                backupPath,
                backupRoleTag: plan.roleTag,
                restoreTarget: {
                  host: destination.host,
                  port: destination.port,
                  database: destination.database,
                },
              },
              withASK,
            ),
            { status: 'exported' },
          );
          await checkWorkspaceBackupArchive(backupPath);
          restoreTarget.send({ ...command, action: 'checkRestoredWorkspace' });
          assert.deepEqual(await restoreTarget.read(), { confirmed: true });
          database.send({ ...command, action: 'damageRecoveryRecipient' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-reopen', target, withASK),
            admitted,
          );
        }
        if (mode === 'csr') {
          const recoveryKitSource = join(directory, 'organisation.whrecovery');
          const recoveryKitDestination = join(directory, 'organisation-updated.whrecovery');
          const refreshKit = (
            source = recoveryKitSource,
            destination = recoveryKitDestination,
            recoveryKitAuthentication?: 'retry' | 'cancel',
          ) =>
            exerciseWizard(
              directory,
              'admin-refresh-recovery-kit',
              {
                ...target,
                recoveryKitSource: source,
                recoveryKitDestination: destination,
                recoveryKitAuthentication,
              },
              withASK,
            );
          database.send({ ...command, action: 'demoteFixtureAdmin' });
          assert.deepEqual(await database.read(), { demoted: true });
          assert.deepEqual(await exerciseWizard(directory, 'admin-renew-denied', target, withASK), {
            status: 'unavailable',
          });
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-rotate', target, withASK), {
            status: 'unavailable',
          });
          assert.equal(await refreshKit(), 'unavailable');
          const deniedBackup = join(directory, 'denied-recovery.json');
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-backup',
              { ...target, backupPath: deniedBackup, denyBackup: true },
              withASK,
            ),
            { status: 'unavailable' },
          );
          await assert.rejects(readFile(deniedBackup), { code: 'ENOENT' });
          database.send({ ...command, action: 'restoreFixtureAdmin' });
          assert.deepEqual(await database.read(), { demoted: false });
          const renewed = await exerciseWizard(directory, 'admin-renew', target, withASK);
          assert.equal(renewed.status, 'issued');
          const certificate = new X509Certificate(renewed.serverPem);
          assert.ok(installedCA && certificate.verify(installedCA.publicKey));
          assert.notEqual(certificate.serialNumber, installedSerial);
          assert.equal(certificate.checkIP(target.host), target.host);
          assert.equal(certificate.checkHost('db.example.test'), 'db.example.test');
          database.send({
            ...command,
            action: 'installTLS',
            caPem: installedCA.toString(),
            serverPem: renewed.serverPem,
          });
          assert.deepEqual(await database.read(), { installed: true });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-reopen', target, withASK),
            admitted,
          );
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-status', target, withASK), {
            status: 'ready',
          });
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-retire', target, withASK), {
            status: 'unavailable',
          });
          // Simulate a device that stays offline from this point using its
          // existing encrypted enrollment and old OS-protected startup pin.
          const sharedDirectory = sourceDatabase + '.shared';
          const offlineCopy = join(directory, 'offline-device');
          assert.equal(resolve(sharedDirectory, '../..'), resolve(directory));
          await cp(sharedDirectory, offlineCopy, {
            recursive: true,
            force: false,
            errorOnExist: true,
          });
          const overlap = await exerciseWizard(directory, 'admin-ca-rotate', target, withASK);
          assert.equal(overlap.status, 'staged');
          assert.equal(overlap.reconnect, true);
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-status', target, withASK), {
            status: 'staged',
            serverPem: overlap.serverPem,
          });
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-retire', target, withASK), {
            status: 'installation-required',
          });
          assert.equal(await refreshKit(), 'unavailable');
          const overlapPath = join(directory, 'overlap.whtls');
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-tls-export',
              { ...target, tlsBundlePath: overlapPath },
              withASK,
            ),
            { exported: true },
          );
          assert.equal(JSON.parse(await readFile(overlapPath, 'utf8')).sequence, 2);
          database.send({ ...command, action: 'rotationCA' });
          const { caPem } = await database.read();
          const rotatedCA = new X509Certificate(caPem);
          assert.notEqual(rotatedCA.fingerprint256, installedCA.fingerprint256);
          assert.ok(new X509Certificate(overlap.serverPem).verify(rotatedCA.publicKey));
          database.send({ ...command, action: 'installTLS', caPem, serverPem: overlap.serverPem });
          assert.deepEqual(await database.read(), { installed: true });
          assert.deepEqual(await exerciseWizard(directory, 'admin-ca-retire', target, withASK), {
            status: 'retired',
            reconnect: true,
          });
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-reopen', target, withASK),
            admitted,
          );
          const afterRotation = await exerciseWizard(directory, 'admin-renew', target, withASK);
          assert.equal(afterRotation.status, 'issued');
          assert.ok(new X509Certificate(afterRotation.serverPem).verify(rotatedCA.publicKey));
          const backupPath = join(directory, 'shared-recovery.json');
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-backup',
              { ...target, backupPath, backupRoleTag: plan.roleTag },
              withASK,
            ),
            { status: 'exported' },
          );
          await checkWorkspaceBackupArchive(backupPath);
          const originalKit = await readFile(recoveryKitSource, 'utf8');
          const oldKit = JSON.parse(originalKit);
          assert.equal(await refreshKit(recoveryKitSource, recoveryKitDestination, 'cancel'), null);
          await assert.rejects(readFile(recoveryKitDestination), { code: 'ENOENT' });
          assert.equal(
            await refreshKit(recoveryKitSource, recoveryKitDestination, 'retry'),
            'updated',
          );
          const refreshed = await readFile(recoveryKitDestination, 'utf8');
          const newKit = JSON.parse(refreshed);
          assert.deepEqual({ ...newKit, ca: oldKit.ca }, oldKit);
          assert.notEqual(newKit.ca.key.key.id, oldKit.ca.key.key.id);
          assert.equal(newKit.ca.certificateDer, rotatedCA.raw.toString('base64'));
          assert.doesNotMatch(refreshed, /WHREC1-|synthetic-administrator-password/);
          assert.equal(await refreshKit(), 'save-failed');
          assert.equal(await readFile(recoveryKitDestination, 'utf8'), refreshed);
          assert.equal(await readFile(recoveryKitSource, 'utf8'), originalKit);
          const capsule = Buffer.from(oldKit.capsule.ciphertext, 'base64');
          capsule[0] ^= 1;
          const badKit = join(directory, 'altered.whrecovery');
          await writeFile(
            badKit,
            JSON.stringify({
              ...oldKit,
              capsule: { ...oldKit.capsule, ciphertext: capsule.toString('base64') },
            }),
            { mode: 0o600 },
          );
          const rejectedKit = join(directory, 'rejected.whrecovery');
          assert.equal(await refreshKit(badKit, rejectedKit), 'invalid-kit');
          await assert.rejects(readFile(rejectedKit), { code: 'ENOENT' });
          const finalPath = join(directory, 'rotated.whtls');
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-tls-export',
              { ...target, tlsBundlePath: finalPath },
              withASK,
            ),
            { exported: true },
          );
          const bundle = JSON.parse(await readFile(finalPath, 'utf8'));
          assert.equal(bundle.sequence, 3);
          assert.deepEqual(bundle.cas, [rotatedCA.raw.toString('base64')]);
          const forgedPath = join(directory, 'forged.whtls');
          const signature = Buffer.from(bundle.signature, 'base64');
          signature[0] ^= 1;
          await writeFile(
            forgedPath,
            JSON.stringify({ ...bundle, signature: signature.toString('base64') }),
            { mode: 0o600 },
          );
          await rename(sharedDirectory, join(directory, 'online-device'));
          await rename(offlineCopy, sharedDirectory);
          const anchor = join(sharedDirectory, 'device.trust.startup');
          const beforeImport = await readFile(anchor);
          assert.deepEqual(
            await exerciseWizard(directory, 'admin-offline-no-bundle', target, withASK),
            {
              rejected: true,
            },
          );
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-offline-signin',
              { ...target, tlsBundlePath: forgedPath, rejectTLSUpdate: true },
              withASK,
            ),
            { rejected: true },
          );
          assert.deepEqual(await readFile(anchor), beforeImport);
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-offline-signin',
              { ...target, tlsBundlePath: finalPath },
              withASK,
            ),
            admitted,
          );
          assert.notDeepEqual(await readFile(anchor), beforeImport);
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-offline-signin',
              { ...target, tlsBundlePath: overlapPath, rejectTLSUpdate: true },
              withASK,
            ),
            { rejected: true },
          );
        }
        if (existingLocal) {
          const { stdout } = await run(
            wizardBackend,
            ['--operation', 'vault-startup', '--database', sourceDatabase],
            { windowsHide: true, timeout: 15_000 },
          );
          const startup = JSON.parse(stdout);
          assert.equal(startup.shared.lastLoginName, 'first-admin');
          assert.ok(startup.slots && !startup.newWorkspace && !startup.sharedJoin);
          assert.deepEqual(await Promise.all(sourceFiles.map((file) => readFile(file))), original);
        }
        const kit = await readFile(join(directory, 'organisation.whrecovery'), 'utf8');
        const recovery = JSON.parse(kit);
        assert.equal(recovery.workspaceId, plan.workspaceId);
        assert.equal(recovery.version, withCSR || generated ? 2 : 1);
        if (installedCA)
          assert.equal(recovery.ca.certificateDer, installedCA.raw.toString('base64'));
        assert.doesNotMatch(kit, /WHREC1-|synthetic-administrator-password/);
        if (mode === 'recovery') {
          database.send({ ...command, action: 'checkRecoveryAdministrator' });
          assert.deepEqual(await database.read(), { confirmed: true });
          const resetOfferPaths: [string, string] = [
            join(directory, 'first.whreset'),
            join(directory, 'second.whreset'),
          ];
          database.send({ ...command, action: 'enableAccountReset' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(
            await exerciseWizard(
              directory,
              'admin-issue-reset',
              { ...target, resetOfferPaths },
              withASK,
            ),
            { issued: 2 },
          );
          const offers = await Promise.all(
            resetOfferPaths.map(async (path) => JSON.parse(await readFile(path, 'utf8'))),
          );
          assert.deepEqual(offers.map((offer) => offer.subject.loginName).sort(), [
            'first-admin',
            'recovered-admin',
          ]);
          for (const offer of offers) {
            assert.equal(offer.workspaceId, plan.workspaceId);
            assert.ok(offer.signature && offer.code === undefined && offer.ask === undefined);
          }
          assert.equal(
            await readFile(resetOfferPaths[0] + '.occupied.whreset', 'utf8'),
            'existing test file',
          );
          database.send({ ...command, action: 'checkAccountResetIssued' });
          assert.deepEqual(await database.read(), { confirmed: true });
          assert.deepEqual(await exerciseWizard(directory, 'admin-revoke-live', target, withASK), {
            idleRetirements: 2,
          });
          return;
        }
        database.send({
          ...command,
          action: 'checkAdministrator',
          checkInitialRecoveryExport: mode === 'csr-default',
        });
        assert.deepEqual(await database.read(), {
          version: target.schemaVersion,
          provisioning: false,
          requiresTls: true,
        });
      } catch (error) {
        scenarioFailed = true;
        throw error;
      } finally {
        try {
          const closed = await Promise.allSettled([
            restoreTarget?.close(),
            database?.close(),
            webServer
              ? new Promise<void>((resolve) => webServer!.close(() => resolve()))
              : undefined,
          ]);
          const failed = closed.find((cleanup) => cleanup.status === 'rejected');
          if (!scenarioFailed && failed) await Promise.reject(failed.reason);
        } finally {
          assert.equal(resolve(directory, '..'), resolve(tmpdir()));
          await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
        }
      }
    },
  );
}
