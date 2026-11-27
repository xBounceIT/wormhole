import assert from 'node:assert/strict';
import { Script } from 'node:vm';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);
test('isolated shared page crosses the real sandbox bridge and erases preload copies', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-shared-bridge-'));
  try {
    const preload = join(directory, 'preload.cjs');
    const source = stripTypeScriptTypes(
      readFileSync(new URL('../electron/vault-shared-preload.cts', import.meta.url), 'utf8'),
    ).replace(
      "import { contextBridge, ipcRenderer } from 'electron';",
      "const { contextBridge, ipcRenderer } = require('electron');",
    );
    writeFileSync(
      preload,
      `const electron=require('electron'),invoke=electron.ipcRenderer.invoke.bind(electron.ipcRenderer);let borrowed;electron.ipcRenderer.invoke=(channel,...args)=>{if(channel==='vault-shared:submit')borrowed=args[0];return invoke(channel,...args);};electron.contextBridge.exposeInMainWorld('testCleared',()=>borrowed.password.every(n=>n===0)&&(!borrowed.ask||borrowed.ask.every(n=>n===0)));\n${source}`,
    );
    const renderer = [
      'electron/vault-contract.ts',
      'electron/vault-shared-transport.ts',
      'electron/vault-shared-invitation.ts',
      'src/vault-shared-initial-screen.ts',
      'src/vault-shared-screen.ts',
    ]
      .map((path) =>
        stripTypeScriptTypes(readFileSync(new URL('../' + path, import.meta.url), 'utf8'))
          .replace(/^import .*?;\s*/gms, '')
          .replace(/^export \{[\s\S]*?\};/gm, '')
          .replace(/^export /gm, ''),
      )
      .join('\n');
    writeFileSync(
      join(directory, 'screen.js'),
      renderer +
        "\nmountSharedAuthenticationScreen(document.querySelector('.startup-card'),window.vaultSharedAuthentication);",
    );
    writeFileSync(
      join(directory, 'startup.css'),
      readFileSync(new URL('../src/startup.css', import.meta.url)),
    );
    writeFileSync(
      join(directory, 'index.html'),
      `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; form-action 'none'"><link rel="stylesheet" href="startup.css"></head><body><main class="startup-shell"><section class="startup-card"></section></main><script src="screen.js"></script></body></html>`,
    );
    new Script(renderer);
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `const {app,BrowserWindow,ipcMain}=require('electron');const assert=require('node:assert/strict');let calls=0;app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,width:540,height:590,webPreferences:{preload:${JSON.stringify(preload)},sandbox:true,contextIsolation:true,nodeIntegration:false}});try{
      ipcMain.handle('vault-shared:context',()=>({mode:'admit',startup:{slots:{formatVersion:1,vaultId:'11111111-1111-4111-8111-111111111111',encrypted:true,slots:[{id:'22222222-2222-4222-8222-222222222222',kind:'password',preset:'kdf-v1'}]},cosmetics:{theme:'system'},newWorkspace:false,shared:{lastLoginName:'alice',serverDisplayName:'Team'}}}));
      ipcMain.handle('vault-shared:submit',(event,input)=>{assert.equal(event.sender,window.webContents);assert.equal(event.senderFrame,event.sender.mainFrame);calls++;assert.deepEqual([...input.password],[104,101,108,108,111]);if(calls===1)assert.ok(input.ask.every(n=>n===171));else assert.equal(input.ask,undefined);input.password.fill(0);input.ask?.fill(0);if(calls===2)throw Error('fixture rejection');return false;});ipcMain.handle('vault-shared:cancel',()=>{});
      await window.loadFile(${JSON.stringify(join(directory, 'index.html'))});await window.webContents.executeJavaScript('new Promise(resolve=>setTimeout(resolve,50))');
      assert.equal(await window.webContents.executeJavaScript("document.querySelector('[type=submit]').disabled"),false);
      assert.equal(await window.webContents.executeJavaScript("document.querySelector('[type=button]').getBoundingClientRect().bottom <= innerHeight"),true);
      for(let i=0;i<2;i++){await window.webContents.executeJavaScript("document.querySelectorAll('input')[0].value='hello';document.querySelectorAll('input')[1].value="+(i===0?JSON.stringify('ab'.repeat(32)):JSON.stringify(''))+";document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));new Promise(resolve=>setTimeout(resolve,50))");assert.equal(await window.webContents.executeJavaScript('window.testCleared()'),true);assert.equal(await window.webContents.executeJavaScript("[...document.querySelectorAll('input[type=password]')].every(input=>input.value==='')"),true);}
      assert.equal(calls,2);console.log('shared sandbox bridge passed');
    }finally{window.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
    );
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const electron = require('electron') as string,
      headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 30000, windowsHide: true },
    );
    assert.match(stdout, /shared sandbox bridge passed/);
    t.diagnostic(stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
test('shared input and startup screens consume factors and keep admission separate from workspace access', async (t) => {
  const browserSource = (path: string) =>
    stripTypeScriptTypes(readFileSync(new URL('../' + path, import.meta.url), 'utf8'))
      .replace(/^import .*?;\s*/gms, '')
      .replace(/^export \{[\s\S]*?\};/gm, '')
      .replace(/^export /gm, '');
  const sources = [
    'electron/vault-contract.ts',
    'electron/vault-shared-transport.ts',
    'electron/vault-shared-invitation.ts',
    'src/vault-shared-initial-screen.ts',
    'src/vault-shared-screen.ts',
    'src/shared-connection-mode.ts',
    'src/vault-shared-catalog-screen.ts',
    'src/vault-shared-startup.ts',
  ].map(browserSource);
  sources.push(
    'const {parseSharedNodeEditRequest,sharedEditFields} = (()=>{const vaultRecord=record,vaultFields=fields,vaultRevision=decimal,vaultMetadataText=metadataText,vaultID=id;\n' +
      browserSource('electron/vault-shared-node-edit.ts') +
      '\nreturn {parseSharedNodeEditRequest,sharedEditFields};})();',
    browserSource('src/vault-shared-node-editor.ts'),
  );
  sources.push(
    'const mountSharedCertificateRenewal = (() => {\n' +
      browserSource('electron/vault-shared-setup-contract.ts') +
      '\n' +
      browserSource('src/vault-shared-certificate.ts') +
      '\nreturn mountSharedCertificateRenewal;\n})();',
  );
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-shared-screen-'));
  try {
    const renderer =
      sources.join('\n') +
      `
    (async()=>{
      const check=(ok,message)=>{if(!ok)throw Error(message);},tick=()=>new Promise(resolve=>setTimeout(resolve,0));
      const vaultId='11111111-1111-4111-8111-111111111111',slotId='22222222-2222-4222-8222-222222222222';
      const metadata=()=>({slots:{formatVersion:1,vaultId,encrypted:true,slots:[{id:slotId,kind:'password',preset:'kdf-v1'}]},cosmetics:{theme:'system'},newWorkspace:false,shared:{lastLoginName:'<alice>',serverDisplayName:'Team'}});
      const inviteHints=tls=>({invitation:'WHINV2-public',workspaceId:vaultId,loginName:'<alice>',tls});
      const initialMeta=()=>({slots:null,cosmetics:{theme:'system'},newWorkspace:true});
      function joinForm(overrides={}){const card=document.createElement('section');document.body.append(card);let seen,copy,calls=0,inspections=0;const dispose=mountSharedInitialJoinScreen(card,{inspectInvitation:async()=>{inspections++;return inviteHints('verified')},openInvitation:async()=>inviteHints('verified'),submit:value=>{calls++;seen=value;copy={code:[...value.code],password:[...value.password],ask:value.ask?[...value.ask]:undefined,acknowledgeTLSOff:value.acknowledgeTLSOff};return Promise.resolve(false)},cancel:async()=>{},...overrides});return{card,dispose,get seen(){return seen},get copy(){return copy},get calls(){return calls},get inspections(){return inspections},remove(){dispose();dispose();card.remove()}}}
      const checkInvite=async(v,file=false)=>{v.card.querySelector('textarea').value='WHINV2-public';v.card.querySelectorAll('button')[file?0:1].click();await tick()};
      const sendJoin=(v,changes={})=>{for(const [name,value] of Object.entries({code:'ab'.repeat(16),password:'hello','password-confirm':'hello','device-name':'Device',ask:'cd'.repeat(32),...changes}))v.card.querySelector('[name="'+name+'"]').value=value;v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));check(['code','password','password-confirm','ask'].every(name=>v.card.querySelector('[name="'+name+'"]').value===''),'initial factors remained in DOM')};
      {
        const v=joinForm();v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));check(v.calls===0,'uninspected invitation submitted');await checkInvite(v);
        check(v.card.textContent.includes('<alice>')&&!v.card.querySelector('alice'),'invitation hints executed');sendJoin(v);check(v.copy.code.every(n=>n===171)&&v.copy.ask.every(n=>n===205)&&v.copy.password.length===5,'initial input altered');check(v.seen.code.every(n=>n===0)&&v.seen.password.every(n=>n===0)&&v.seen.ask.every(n=>n===0),'initial bytes retained');await tick();
        for(const changes of [{code:'bad'},{password:''},{password:'x'.repeat(1025),'password-confirm':'x'.repeat(1025)},{'password-confirm':'different'},{ask:'bad'},{'device-name':''},{'device-name':'bad'+String.fromCharCode(1)+'name'}]){sendJoin(v,changes);check(v.calls===1,'invalid initial factors submitted')}
        sendJoin(v,{ask:''});await tick();check(v.calls===2&&v.copy.ask===undefined,'optional ASK');v.card.querySelector('textarea').value='WHINV2-other';sendJoin(v);check(v.calls===2,'changed uninspected token submitted');
        await checkInvite(v,true);check(v.card.querySelector('textarea').value==='WHINV2-public','invite file lost');v.card.querySelector('textarea').dispatchEvent(new Event('input'));check(v.card.querySelector('[type=submit]').disabled,'changed invite remained enabled');v.remove();
      }
      {
        const v=joinForm({inspectInvitation:async()=>inviteHints('off')});await checkInvite(v);sendJoin(v);check(v.calls===0,'TLS Off omitted acknowledgement');const checkbox=v.card.querySelector('[type=checkbox]');check(!checkbox.parentElement.hidden,'TLS warning missing');checkbox.checked=true;sendJoin(v);await tick();check(v.calls===1&&v.copy.acknowledgeTLSOff,'TLS acknowledgement lost');v.remove();
      }
      {
        let picks=0;
        const v=joinForm({openResetOffer:async()=>{picks++;if(picks===1)return false;if(picks===2)throw Error('private picker failure');return true}});
        const buttons=v.card.querySelectorAll('button'),mode=buttons[4],open=buttons[0],submit=v.card.querySelector('[type=submit]');
        mode.click();check(v.card.querySelector('textarea').parentElement.hidden&&buttons[1].hidden&&submit.disabled,'reset mode exposed invitation controls');
        v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));check(!v.calls,'no reset file selected');
        open.click();await tick();check(submit.disabled,'canceled reset picker enabled submit');
        open.click();await tick();check(submit.disabled&&!v.card.textContent.includes('private'),'reset picker failure leaked details');
        open.click();await tick();check(!submit.disabled&&v.card.textContent.includes('Reset file selected.'),'selected reset file did not enable submit');
        sendJoin(v,{ask:''});check(!v.calls,'reset accepted missing ASK');
        sendJoin(v);await tick();check(v.calls===1&&v.seen.kind==='account-reset'&&!Object.hasOwn(v.seen,'offerPath')&&!Object.hasOwn(v.seen,'invitation'),'incorrect reset IPC shape');
        check(v.copy.code.every(n=>n===171)&&v.copy.ask.every(n=>n===205)&&v.seen.code.every(n=>n===0)&&v.seen.ask.every(n=>n===0),'reset factors changed or retained');
        mode.click();check(!v.card.querySelector('textarea').parentElement.hidden&&submit.disabled,'switch to invitation reused reset selection');v.remove();
      }
      {
        let submissions=0,closed=false;
        const v=joinForm({openResetOffer:async()=>true,submit:async()=>{submissions++;return 'awaiting-activation'},cancel:async()=>{closed=true}});
        const buttons=v.card.querySelectorAll('button');
        buttons[4].click();buttons[0].click();await tick();sendJoin(v);await tick();
        check(v.card.querySelector('.startup-status').textContent.includes('This device is registered'),'registration presented as an authentication failure');
        check(v.card.querySelector('[type=submit]').disabled,'a registered device could submit a second offer');sendJoin(v);
        check(submissions===1,'a second submission escaped the registered state');
        const close=[...buttons].find(button=>button.textContent==='Close');check(close&&!close.disabled,'unable to leave after registration');
        close.click();await tick();check(closed,'close did not leave registration');v.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);
        const startup=metadata();startup.sharedJoin={...startup.shared,canContinue:true,accountReset:true};delete startup.shared;
        let submitted;
        const dispose=mountSharedAuthenticationScreen(card,{context:async()=>({mode:'recover-enrollment',startup}),submit:value=>{submitted={...value,...(value.code?{code:[...value.code]}:{})};return Promise.resolve('awaiting-activation')},cancel:async()=>{}});
        await tick();check(card.querySelector('h1').textContent==='Continue resetting your account','pending reset was rendered as invitation');
        const continuation=card.querySelector('[name=continue-enrollment]');continuation.click();
        check(!card.querySelector('[name=code]').parentElement.hidden&&card.querySelector('[name=acknowledge-tls-off]').parentElement.hidden,'reset continuation exposed transport downgrade');
        const password=card.querySelector('[autocomplete=current-password]'),ask=card.querySelectorAll('input[type=password]')[1];
        const submit=()=>card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));
        password.value='hello';submit();check(!submitted,'reset recovery accepted missing ASK');
        password.value='hello';ask.value='ab'.repeat(32);card.querySelector('[name=code]').value='cd'.repeat(16);submit();await tick();
        check(submitted.code.every(n=>n===205)&&submitted.acknowledgeTLSOff===false,'reset continuation sent wrong code or allowed downgrade');
        check(card.querySelector('.startup-status').textContent.includes('Try again after your administrator')&&!card.querySelector('[type=submit]').disabled,'confirmation did not remain retryable while suspended');
        dispose();card.remove();
      }
      for(const outcome of ['cancel','invalid','reject','late','late-error','success','throw-submit','reject-submit','cancel-error']){
        let resolveInspect,rejectInspect,inspectRequests=0;const overrides={};
        if(outcome==='cancel')overrides.openInvitation=async()=>null;
        if(outcome==='invalid')overrides.inspectInvitation=async()=>({tls:'verified'});
        if(outcome==='reject')overrides.inspectInvitation=async()=>{throw Error('private')};
        if(outcome.startsWith('late'))overrides.inspectInvitation=()=>{inspectRequests++;return new Promise((resolve,reject)=>{resolveInspect=resolve;rejectInspect=reject})};
        if(outcome==='success')overrides.submit=async()=>true;
        if(outcome==='throw-submit')overrides.submit=()=>{throw Error('private')};
        if(outcome==='reject-submit')overrides.submit=async()=>{throw Error('private')};
        if(outcome==='cancel-error')overrides.cancel=async()=>{throw Error('private')};
        const v=joinForm(overrides);await checkInvite(v,outcome==='cancel');
        if(outcome.startsWith('late')){v.card.querySelectorAll('button')[1].onclick();check(inspectRequests===1,'duplicate initial inspection');v.dispose();if(outcome==='late')resolveInspect(inviteHints('verified'));else rejectInspect(Error('private'));await tick();check(v.card.querySelector('[type=submit]').disabled,'late invitation enabled disposed form')}
        else if(['cancel','invalid','reject'].includes(outcome))check(v.card.querySelector('[type=submit]').disabled,'invalid invitation enabled submit');
        else if(outcome==='cancel-error'){v.card.querySelectorAll('button')[3].click();await tick()}
        else{sendJoin(v);await tick();check(outcome!=='success'||v.card.querySelector('[type=submit]').disabled,'successful initial form stayed alive')}
        v.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);const dispose=mountSharedAuthenticationScreen(card,{context:async()=>({startup:initialMeta(),mode:'join-initial'}),inspectInvitation:async()=>inviteHints('verified'),openInvitation:async()=>null,submit:async()=>false,cancel:async()=>{}});await tick();check(card.querySelector('textarea')&&card.textContent.includes('Join a shared workspace'),'initial context not routed');dispose();check(!card.querySelector('textarea').value,'initial context disposal failed');card.remove();
      }
      for(const orgEscrow of [false,true]){
        const card=document.createElement('section');document.body.append(card);let authCalls=0;const dispose=mountSharedStartup(card,metadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),lockAuthentication:async()=>{},authenticateSharedVault:async()=>{authCalls++;throw Error('duplicate admission')}},undefined,{admitted:true,lockedMemory:false,orgEscrow,tls:'off'});await tick();check(authCalls===0&&card.textContent.includes('Signed in.')&&card.textContent.includes('memory'),'initial admission asked for another password');check(card.textContent.includes(orgEscrow?'Your admin can see your personal items.':'Your admin cannot see your personal items.'),'authenticated personal visibility notice missing');dispose();card.remove();
      }
      for(const orgEscrow of [undefined,null,0,'false']){
        const card=document.createElement('section');document.body.append(card);let locked=0,pages=0;
        const dispose=mountSharedStartup(card,metadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>{pages++;return{epoch:'1',changeSeq:'0',reset:true,nodes:[]}},loadSharedCatalogPage:async()=>{pages++;return{epoch:'1',changeSeq:'0',nodes:[],next:null}},lockAuthentication:async()=>{locked++},authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,tls:'off',...(orgEscrow===undefined?{}:{orgEscrow})})});
        card.querySelector('button').click();await tick();check(locked===1&&pages===0&&!card.textContent.includes('Your admin'),'unverified notice displayed or workspace mounted');dispose();card.remove();
      }
      for(const tls of ['off','encrypted','verified']){
        const card=document.createElement('section');document.body.append(card);let locks=0,pages=0,currentTLS=tls;
        const dispose=mountSharedStartup(card,metadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>{pages++;return{epoch:'1',changeSeq:'0',nodes:[],next:null}},lockAuthentication:async()=>{locks++},authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls:currentTLS})});
        card.querySelector('button').click();await tick();const notice=card.querySelector('.shared-transport-notice');check(notice.hidden===(tls==='verified'),'incorrect transport warning');if(tls!=='verified')check(notice.textContent.includes(tls==='off'?'not encrypted':'certificate is not verified'),'transport warning missing details');
        card.querySelector('.shared-workspace-catalog button').click();await tick();check(notice.hidden===(tls==='verified')&&pages>=2,'catalog refresh changed transport warning');
        [...card.querySelectorAll('button')].find(b=>b.textContent==='Sign out').click();await tick();check(locks===1&&notice.hidden,'signed-out warning retained');currentTLS=tls==='verified'?'off':'verified';card.querySelector('button').click();await tick();check(notice.hidden===(currentTLS==='verified'),'new admission kept stale transport');dispose();card.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);
        let grant=false,tls='verified',exports=0,rejectExport;
        const dispose=mountSharedStartup(card,metadata(),{
          authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls,...(grant?{recoveryBackup:true}:{})}),
          lockAuthentication:async()=>{},
          onSharedCatalogChanged:()=>()=>{},
          loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),
          loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),
          openSharedRecoveryBackup:()=>{exports++;return new Promise((_,reject)=>rejectExport=reject);}
        });
        const signIn=card.querySelector('button'),signOut=[...card.querySelectorAll('button')].find(b=>b.textContent==='Sign out');
        const backup=[...card.querySelectorAll('button')].find(b=>b.textContent.includes('Export workspace recovery backup'));
        signIn.click();await tick();check(backup.hidden,'regular account was offered backup export');
        signOut.click();await tick();grant=true;tls='encrypted';signIn.click();await tick();
        check(backup.hidden,'unverified transport was offered export');
        signOut.click();await tick();tls='verified';signIn.click();await tick();
        backup.click();backup.click();check(exports===1&&backup.disabled,'duplicate or missing backup modal');
        rejectExport(Error('private'));await tick();
        check(!backup.disabled&&card.textContent.includes('Could not open workspace backup')&&!card.textContent.includes('private'),'private failure leaked');
        backup.click();signOut.click();await tick();rejectExport(Error('late'));await tick();
        check(backup.hidden&&card.textContent.includes('Signed out.')&&!card.textContent.includes('Could not open workspace backup'),'stale modal updated a signed-out screen');
        dispose();card.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);
        let administrator=false,tls='verified',opens=0,fail;
        const dispose=mountSharedStartup(card,metadata(),{
          authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:false,tls,...(administrator?{administrator:true}:{})}),
          lockAuthentication:async()=>{},
          onSharedCatalogChanged:()=>()=>{},
          loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),
          loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),
          openSharedAdministration:()=>{opens++;return new Promise((_,reject)=>fail=reject);}
        });
        const signIn=card.querySelector('button'),signOut=[...card.querySelectorAll('button')].find(b=>b.textContent==='Sign out');
        const admin=[...card.querySelectorAll('button')].find(b=>b.textContent.startsWith('Workspace administration'));
        signIn.click();await tick();
        check(!admin.hidden&&admin.textContent==='My devices…','verified member could not manage their own devices');
        signOut.click();await tick();administrator=true;tls='encrypted';signIn.click();await tick();
        check(admin.hidden,'unverified transport was offered administration');
        signOut.click();await tick();tls='verified';signIn.click();await tick();
        check(!admin.hidden&&admin.textContent==='Workspace administration…','verified administrator without escrow could not inspect inventory');
        admin.click();admin.click();
        check(admin.disabled&&opens===1,'duplicate administration window');
        fail(Error('private diagnostic'));await tick();
        check(card.textContent.includes('Could not open workspace administration.')&&!card.textContent.includes('private diagnostic'),'private administration error leaked');
        admin.click();signOut.click();await tick();fail(Error('closed'));await tick();
        check(admin.hidden&&card.textContent.includes('Signed out.')&&!card.textContent.includes('Could not open workspace administration.'),'late modal error updated a signed-out screen');
        dispose();card.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);
        const csr='-----BEGIN CERTIFICATE REQUEST-----\\nAAAA\\n-----END CERTIFICATE REQUEST-----';
        let calls=0,locks=0,tls='off',outcome='unavailable',release;
        const dispose=mountSharedStartup(card,metadata(),{
          authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls}),
          lockAuthentication:async()=>{locks++},
          onSharedCatalogChanged:()=>()=>{},
          loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),
          loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),
          renewSharedServerCertificate:async request=>{
            calls++;check(request.csr===csr,'public CSR altered');
            if(outcome==='issued')return {status:outcome,serverPem:'public certificate'};
            if(outcome==='pending')return new Promise(resolve=>release=resolve);
            if(outcome==='error')throw Error('private');
            return {status:outcome};
          }
        });
        const signIn=card.querySelector('button'),signOut=[...card.querySelectorAll('button')].find(b=>b.textContent==='Sign out');
        signIn.click();await tick();check(!card.querySelector('details'),'renewal on unverified transport');
        signOut.click();await tick();tls='verified';signIn.click();await tick();
        const form=card.querySelector('details form'),[input,output]=form.querySelectorAll('textarea');
        const send=()=>form.dispatchEvent(new Event('submit',{cancelable:true}));
        input.value='private key data';send();check(calls===0&&!input.value&&form.textContent.includes('Paste a PEM certificate signing request'),'invalid PEM retained or submitted');
        input.value=csr;send();await tick();check(calls===1&&form.textContent.includes('requires an administrator')&&output.parentElement.hidden,'denial not displayed');
        outcome='invalid-csr';send();await tick();check(calls===2&&form.textContent.includes('Check the CSR'),'invalid CSR feedback missing');
        outcome='issued';send();await tick();check(calls===3&&output.readOnly&&!output.parentElement.hidden&&output.value==='public certificate','certificate missing');
        outcome='pending';send();send();check(calls===4&&input.disabled,'duplicate renewal was permitted');
        signOut.click();await tick();release({status:'issued',serverPem:'late certificate'});await tick();check(locks===2&&!card.querySelector('details')&&!input.value&&!output.value,'signed-out screen retained certificate');
        signIn.click();await tick();outcome='error';const active=card.querySelector('details form');active.querySelector('textarea').value=csr;active.dispatchEvent(new Event('submit',{cancelable:true}));await tick();check(locks===3&&!card.querySelector('details'),'failed owner remained active');
        dispose();card.remove();
      }
      {
        const card=document.createElement('section');document.body.append(card);
        const csr='-----BEGIN CERTIFICATE REQUEST-----\\nAAAA\\n-----END CERTIFICATE REQUEST-----';
        let locks=0,staged=false,stageOutcome='invalid-csr',canRetire=false,saved=null,kitResult=null;
        const dispose=mountSharedStartup(card,metadata(),{
          authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls:'verified'}),
          lockAuthentication:async()=>{locks++},
          onSharedCatalogChanged:()=>()=>{},
          loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),
          loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),
          renewSharedServerCertificate:async()=>{throw Error('wrong operation')},
          exportSharedTLSBundle:async()=>{if(saved==='error')throw Error('private path');return saved;},
          refreshSharedRecoveryKit:async()=>{if(kitResult==='error')throw Error('private path');return kitResult;},
          sharedWorkspaceCA:async request=>{
            if(request.action==='status')return staged?{status:'staged',serverPem:'staged certificate'}:{status:'ready'};
            if(request.action==='retire'){if(canRetire){staged=false;return{status:'retired',reconnect:true};}return{status:'installation-required'};}
            check(request.action==='rotate'&&request.csr===csr,'rotation received an invalid request');
            if(stageOutcome!=='staged')return {status:stageOutcome};
            staged=true;return {status:'staged',serverPem:'staged certificate',reconnect:true};
          }
        });
        const open=async()=>{
          card.querySelector('button').click();await tick();const details=card.querySelector('details');
          const toggled=new Promise(resolve=>details.addEventListener('toggle',resolve,{once:true}));
          details.open=true;await toggled;await tick();return details.querySelector('form');
        };
        let form=await open();
        const find=(text)=>[...form.querySelectorAll('button')].find(button=>button.textContent===text);
        const rotate=find('Stage a new workspace CA');
        const stage=()=>form.dispatchEvent(new SubmitEvent('submit',{cancelable:true,submitter:rotate}));
        check(!rotate.hidden,'rotation unavailable in ready state');
        form.querySelector('textarea').value=csr;
        stage();await tick();check(form.textContent.includes('Check the CSR'),'invalid rotation CSR not shown');
        stageOutcome='unavailable';stage();await tick();check(form.textContent.includes('requires an administrator'),'rotation denial not shown');
        stageOutcome='staged';stage();await tick();check(locks===1&&!card.querySelector('details')&&card.textContent.includes('Sign in again'),'staged rotation retained old owner');
        form=await open();
        const retire=find('Check installation and retire the previous CA');
        const output=form.querySelector('textarea[readonly]');
        check(!retire.hidden&&find('Sign server CSR').hidden&&output.value==='staged certificate','staged state was not resumed');
        check(find('Update offline recovery kit…').hidden,'refresh offered during CA overlap');
        const exportBundle=find('Export signed trust bundle…');
        exportBundle.click();await tick();check(form.textContent.includes('Both CAs are trusted'),'cancelled picker changed the state');
        saved=false;exportBundle.click();await tick();check(form.textContent.includes('Could not save the trust bundle'),'write refusal was hidden');
        saved=true;exportBundle.click();await tick();check(form.textContent.includes('Signed trust bundle saved.'),'export confirmation missing');
        retire.click();await tick();check(form.textContent.includes('on every configured endpoint')&&locks===1,'premature retirement not rejected');
        canRetire=true;retire.click();await tick();check(locks===2&&!card.querySelector('details'),'retirement retained pre-update transport');
        form=await open();
        const refresh=find('Update offline recovery kit…');
        check(!refresh.hidden,'refresh unavailable after retirement');
        const status=form.querySelector('[role=status]');
        const previous=status.textContent;
        refresh.click();await tick();check(status.textContent===previous,'cancelled kit picker changed the status');
        for(const [result, message] of [
          ['invalid-kit','Choose the original recovery kit'],
          ['unavailable','requires an administrator'],
          ['save-failed','Choose a new file'],
          ['updated','Keep it with your existing recovery code'],
        ]){kitResult=result;refresh.click();await tick();check(status.textContent.includes(message),'incorrect kit feedback for '+result);}
        kitResult='error';refresh.click();await tick();check(locks===3&&!card.querySelector('details')&&!card.textContent.includes('private path'),'failed refresh retained the inactive owner');
        form=await open();saved='error';find('Export signed trust bundle…').click();await tick();check(locks===4&&!card.querySelector('details')&&!card.textContent.includes('private path'),'failed export retained the inactive owner');
        dispose();card.remove();
      }
      for(const tls of [undefined,null,'','prefer','VERIFIED',0,{}]){
        const card=document.createElement('section');document.body.append(card);let locked=0,pages=0;
        const dispose=mountSharedStartup(card,metadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>{pages++;return{epoch:'1',changeSeq:'0',reset:true,nodes:[]}},loadSharedCatalogPage:async()=>{pages++;return{epoch:'1',changeSeq:'0',nodes:[],next:null}},lockAuthentication:async()=>{locked++},authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls})});
        card.querySelector('button').click();await tick();check(locked===1&&pages===0&&card.querySelector('.shared-transport-notice').hidden,'unverified transport admitted');dispose();card.remove();
      }
      function setup(overrides={}){const card=document.createElement('section');document.body.append(card);let seen,copy,calls=0;const dispose=mountSharedAuthenticationScreen(card,{context:async()=>({startup:metadata(),mode:'admit'}),submit:value=>{calls++;seen=value;copy={password:[...value.password],ask:value.ask?[...value.ask]:undefined};return Promise.resolve(false);},cancel:async()=>{},...overrides});return{card,dispose,get seen(){return seen},get copy(){return copy},get calls(){return calls},remove(){dispose();card.remove()}};}
      let v=setup();v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick();
      check(v.card.textContent.includes('<alice>')&&!v.card.querySelector('alice'),'unsafe display');
      function send(v,password='hello',ask=''){const inputs=v.card.querySelectorAll('input');inputs[0].value=password;inputs[1].value=ask;v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));check([...inputs].filter(x=>x.type==='password').every(x=>x.value===''),'DOM retained');}
      {
        let selected=true,picks=[],resolvePick;
        const u=setup({selectTLSUpdate:async action=>{picks.push(action);if(selected==='pending')return new Promise(resolve=>resolvePick=resolve);if(selected==='error')throw Error('private path');return selected;}});
        await tick();const pick=[...u.card.querySelectorAll('button')].find(button=>button.textContent.includes('signed trust update'));
        u.card.querySelector('input[type=password]').value='sensitive';
        pick.click();await tick();check(!u.card.querySelector('input[type=password]').value&&pick.textContent.startsWith('Remove'),'chooser retained a factor or missed selection');
        send(u);await tick();check(!('tlsUpdatePath' in u.seen)&&u.card.textContent.includes('selected trust update'),'renderer passed a path or dropped selection after failure');
        selected=false;pick.click();await tick();check(picks.join(',')==='choose,clear'&&pick.textContent.startsWith('Choose'),'could not clear selection');
        selected='error';pick.click();await tick();check(u.card.textContent.includes('Could not select')&&!u.card.textContent.includes('private path'),'chooser leaked a diagnostic');
        selected=42;pick.click();await tick();check(u.card.textContent.includes('Could not select'),'invalid picker reply accepted');
        selected='pending';pick.click();check(pick.disabled,'pending picker allowed another choice');u.dispose();resolvePick(true);await tick();check(pick.disabled&&pick.textContent.startsWith('Choose'),'late picker selection reused');
        u.remove();
      }
      send(v,'hello','ab'.repeat(32));check(v.copy.password.length===5&&v.copy.ask.every(n=>n===171),'factor altered before call');check(v.seen.password.every(n=>n===0)&&v.seen.ask.every(n=>n===0),'factor retained');await tick();check(v.card.textContent.includes('Could not sign in'),'failure missing');
      for(const [pw,ask] of [['',''],['x'.repeat(1025),''],['ok','bad']]){send(v,pw,ask);check(v.card.textContent.includes('valid password'),'bad input accepted');}
      send(v);await tick();check(v.copy.ask===undefined,'optional ASK became required');
      const method=v.card.querySelector('select');v.card.querySelector('input').value='secret';method.dispatchEvent(new Event('change'));check(v.card.querySelector('input').value==='','slot change retains factor');method.value='missing';send(v);v.remove();
      for(const form of ['initial','admit']){
        const limited={submit:async()=>'connection-limit'};
        const view=form==='initial'?joinForm(limited):setup(limited);
        if(form==='initial'){await checkInvite(view);sendJoin(view)}else{await tick();send(view)}
        await tick();
        check(view.card.querySelector('.startup-status').textContent.includes('The workspace server is at its connection limit.')&&!view.card.querySelector('[type=submit]').disabled,'capacity diagnosis or retry unavailable');
        view.remove();
      }
      for(const outcome of [true,false,'invalid']){v=setup({submit:async()=>outcome});await tick();send(v);await tick();check(outcome===true?v.card.querySelector('[type=submit]').disabled:v.card.textContent.includes('Could not'),'bad completion');v.remove();}
      for(const submit of [()=>{throw Error('private')},async()=>{throw Error('private')}]){v=setup({submit,cancel:async()=>{throw Error('private')}});await tick();send(v);await tick();check(v.card.textContent.includes('unavailable')&&!v.card.textContent.includes('private'),'raw error');v.card.querySelector('[type=button]').click();await tick();v.remove();}
      for(const context of [null,[],{}, {startup:metadata(),mode:'bad'}, {startup:{...metadata(),shared:undefined},mode:'admit'}, {startup:{...metadata(),slots:{...metadata().slots,slots:[{id:slotId,kind:'recovery'}]}},mode:'admit'}]){v=setup({context:async()=>context});await tick();check(v.card.querySelector('[type=submit]').disabled,'bad context');v.remove();}
      v=setup({context:async()=>({startup:metadata(),mode:'recover-password'})});await tick();check(v.card.textContent.includes('new password'),'recovery context');v.remove();
      v=setup({context:async()=>({startup:metadata(),mode:'tighten-profile'})});
      await tick();
      check(v.card.querySelector('h1').textContent==='Use Standard protection on this device','personal profile scope');
      check(v.card.querySelector('[type=submit]').textContent==='Confirm and lock workspace','lock action missing');
      send(v);await tick();
      check(v.card.textContent.includes('Could not confirm Standard protection'),'incorrect factor feedback');
      v.remove();
      v=setup({context:async()=>({startup:metadata(),mode:'trust-ssh-host'})});
      await tick();
      check(v.card.querySelector('h1').textContent==='Confirm SSH host key','missing host confirmation');
      check(v.card.querySelector('[type=submit]').textContent==='Save verified key','wrong host key action');
      send(v);await tick();
      check(v.card.textContent.includes('Could not save the host key'),'missing host verification feedback');
      v.remove();
      v=setup({context:async()=>({startup:metadata(),mode:'edit-shared-node'})});
      await tick();
      check(v.card.querySelector('h1').textContent==='Confirm shared catalog edit','missing edit confirmation');
      send(v);await tick();
      check(v.card.textContent.includes('Could not confirm the change'),'missing edit verification feedback');
      v.remove();
      const joiningMetadata=()=>{const value=metadata();const {shared,...rest}=value;return{...rest,sharedJoin:shared}};
      {
        const card=document.createElement('section');document.body.append(card);
        const metadata=joiningMetadata();metadata.sharedJoin.adminRecovery=true;
        let normal=0,resumes=0;
        const dispose=mountSharedStartup(card,metadata,{
          onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),
          loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),lockAuthentication:async()=>{},
          authenticateSharedVault:async mode=>{check(mode==='recover-enrollment','wrong continuation');normal++;return null;},
          recoverSharedWorkspace:async()=>{resumes++;return{admitted:true,lockedMemory:true,orgEscrow:true,tls:'verified'};}
        });
        const buttons=[...card.querySelectorAll('button')];
        const resume=buttons.find(button=>button.textContent==='Resume emergency recovery');
        check(!resume.hidden,'durable recovery has no continuation');
        buttons.find(button=>button.textContent==='Continue').click();await tick();
        check(normal===1&&resumes===0,'ordinary post-commit enrollment was overridden');
        resume.click();await tick();
        check(resumes===1&&resume.hidden&&card.textContent.includes('Signed in.'),'emergency continuation did not admit');
        dispose();card.remove();
      }
      v=setup({context:async()=>({startup:joiningMetadata(),mode:'recover-enrollment'})});await tick();check(v.card.textContent.includes('when joining')&&!v.card.querySelector('[type=submit]').disabled,'enrollment recovery context');check(v.card.querySelector('[name=continue-enrollment]').parentElement.hidden,'legacy continuation exposed');v.remove();
      {
        let seen, copied, calls=0;
        v=setup({context:async()=>{const m=joiningMetadata();m.sharedJoin.canContinue=true;return{startup:m,mode:'recover-enrollment'}},submit:value=>{calls++;seen=value;copied=[...value.code];check(value.acknowledgeTLSOff===true,'TLS acknowledgement missing');return Promise.resolve(false)}});await tick();
        const choice=v.card.querySelector('[name=continue-enrollment]'),code=v.card.querySelector('[name=code]'),tls=v.card.querySelector('[name=acknowledge-tls-off]');
        check(!choice.parentElement.hidden&&code.parentElement.hidden,'continuation choice missing');choice.checked=true;choice.dispatchEvent(new Event('change'));check(!code.parentElement.hidden,'code field hidden');
        send(v);check(calls===0,'missing code submitted');code.value='1f'.repeat(16);tls.checked=true;send(v);check(calls===1&&copied.every(n=>n===31)&&seen.code.every(n=>n===0)&&seen.password.every(n=>n===0),'continuation factors not consumed');check(!tls.checked&&!code.value,'continuation DOM retained');await tick();choice.checked=false;choice.dispatchEvent(new Event('change'));check(code.parentElement.hidden,'code remained exposed');v.remove();
      }
      {const card=document.createElement('section');document.body.append(card);const modes=[];const dispose=mountSharedStartup(card,joiningMetadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),lockAuthentication:async()=>{},authenticateSharedVault:async mode=>{modes.push(mode);return{admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'}}});const buttons=card.querySelectorAll('button');check(buttons[0].textContent==='Continue'&&buttons[1].hidden,'pending join actions');buttons[1].onclick();await tick();check(modes.length===0,'wrong pending action');buttons[0].click();await tick();check(modes[0]==='recover-enrollment'&&buttons[0].hidden,'enrollment not admitted');buttons[2].click();await tick();buttons[0].click();await tick();check(modes[1]==='admit','completed enrollment replayed recovery');dispose();card.remove();}
      let release,calls=0;v=setup({submit:()=>{calls++;return new Promise(resolve=>release=resolve)}});await tick();send(v);v.card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));check(calls===1,'duplicate');window.dispatchEvent(new Event('pagehide'));release(false);await tick();check(v.card.querySelector('[type=submit]').disabled,'stale completion');v.remove();
      v=setup({context:()=>new Promise(resolve=>release=resolve)});v.dispose();release({startup:metadata(),mode:'admit'});await tick();v.remove();
      for(const outcome of [null,{admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'},{admitted:true,lockedMemory:false,orgEscrow:true,tls:'off'},{recovered:true},{bad:true},'throw']){
        const card=document.createElement('section');document.body.append(card);let requests=0;
        const dispose=mountSharedStartup(card,metadata(),{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),lockAuthentication:async()=>{},authenticateSharedVault:async mode=>{requests++;check(mode==='admit'||mode==='recover-password','operation');if(outcome==='throw')throw Error('private');return outcome;}});
        const buttons=card.querySelectorAll('button');buttons[outcome&&outcome.recovered?1:0].click();await tick();
        check(requests===1,'missing launcher');if(outcome&&outcome.admitted)check(buttons[0].disabled&&card.textContent.includes('No visible items.'),'catalog not mounted');
        if(outcome&&outcome.recovered)check(card.textContent.includes('completed')&&!buttons[0].disabled,'recovery state');
        if(outcome==='throw')check(!card.textContent.includes('private'),'raw launcher error');if(outcome&&outcome.admitted){buttons[2].click();await tick();check(buttons[2].hidden&&!buttons[0].disabled,'sign out');}dispose();card.remove();
      }
      const card=document.createElement('section');document.body.append(card);const dispose=mountSharedStartup(card,metadata(),{authenticateSharedVault:()=>new Promise(resolve=>release=resolve)});const button=card.querySelector('button');button.click();button.onclick();dispose();release({admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'});await tick();check(button.disabled,'late launcher result');card.remove();
      for(const mode of ['page-error','signout-error','signout-pending']){
        const card=document.createElement('section');document.body.append(card);let releasePage;
        const dispose=mountSharedStartup(card,metadata(),{authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'}),onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:()=>mode==='page-error'?Promise.reject(Error('private')):new Promise(resolve=>releasePage=resolve),lockAuthentication:async()=>{if(mode==='signout-error')throw Error('private')}});
        const buttons=card.querySelectorAll('button');buttons[0].click();await tick();
        if(mode==='page-error')check(card.textContent.includes('Could not open the workspace')&&!buttons[0].disabled&&!card.textContent.includes('private'),'catalog error not sanitized');
        else {buttons[2].click();await tick();releasePage({nodes:[{name:'stale',kind:0}],next:null});await tick();check(!card.textContent.includes('stale'),'signout late page');if(mode==='signout-error')check(buttons[0].disabled&&card.textContent.includes('Could not confirm'),'uncertain signout unlocked');else check(!buttons[0].disabled,'signed out stayed busy');}
        dispose();card.remove();
      }

      for(const mode of ['saved','unavailable','canceled','load-failed','read-denied','write-failed','disposed','late-save']) {
        const card=document.createElement('section');document.body.append(card);
        const row={id:vaultId,name:'Office',kind:1,editRevision:'4'};
        const values=Object.fromEntries(Object.keys(sharedEditFields).map(key=>[key,null]));
        Object.assign(values,{name:'Office',host:'old.example',protocol:0,tunnelEnabled:false,httpPath:'/path'+String.fromCharCode(10)+'next'});
        let saved,reads=0,finishRead,finishSave;
        const edit=async request=>{
          if(request.changes){
            saved=request;
            if(mode==='write-failed')throw Error('workspace changed');
            if(mode==='late-save')return new Promise(resolve=>{finishSave=resolve});
            return {status:mode==='saved'?'saved':'unavailable'};
          }
          reads++;
          if(mode==='load-failed')throw Error('unavailable');
          if(mode==='read-denied')return {status:'unavailable'};
          if(mode==='disposed')await new Promise(resolve=>{finishRead=resolve});
          return {status:'ready',...request,workspaceId:slotId,epoch:'2',changeSeq:'5',fields:values};
        };
        const remove=mountSharedCatalogScreen(card,{
          editSharedNode:edit,loadSharedCatalogPage:async()=>({epoch:'2',changeSeq:'5',nodes:[row],next:null}),
          loadSharedChanges:async()=>({epoch:'2',changeSeq:'5',reset:true,nodes:[]}),onSharedCatalogChanged:()=>()=>{},
        },()=>{throw Error('editor retired catalog')});
        await tick();card.querySelector('[aria-label="Edit Office"]').click();await tick();
        const dialog=card.querySelector('dialog');
        check(reads===1&&dialog.open,'missing edit dialog');
        if(mode==='disposed'){remove();finishRead();await tick();check(!card.childElementCount,'late dialog reopened');}
        else if(mode==='load-failed'||mode==='read-denied'){check(dialog.textContent.includes('unavailable'),'missing read failure');dialog.querySelector('[type=button]').click();}
        else if(mode==='canceled'){dialog.dispatchEvent(new Event('cancel',{cancelable:true}));check(!saved&&!dialog.isConnected,'cancel saved an edit');}
        else {
          const form=dialog.querySelector('form'),save=dialog.querySelector('[type=submit]');
          check(save.disabled,'unchanged edit enabled');
          const rowFor=key=>dialog.querySelector('fieldset').children[Object.keys(sharedEditFields).indexOf(key)];
          const inheritedHost=rowFor('host').querySelector('[type=checkbox]');inheritedHost.click();
          const port=rowFor('port');port.querySelector('[type=checkbox]').click();port.querySelector('[type=number]').value='444';
          rowFor('protocol').querySelector('select').value='4';rowFor('tunnelEnabled').querySelector('select').value='true';
          form.dispatchEvent(new Event('input',{bubbles:true}));
          check(!save.disabled,'typed changes invalid');save.click();await tick();
          check(saved&&saved.epoch==='2'&&saved.changeSeq==='5'&&saved.workspaceId===slotId&&saved.revision==='4'&&
            saved.changes.host===null&&saved.changes.port===444&&saved.changes.protocol===4&&saved.changes.tunnelEnabled===true&&Object.keys(saved.changes).length===4,'wrong shared edit');
          if(mode==='late-save'){dialog.dispatchEvent(new Event('cancel',{cancelable:true}));check(dialog.open,'closed while saving');remove();finishSave({status:'saved'});await tick();check(!card.childElementCount,'late save reopened catalog');}
          else if(mode==='saved')check(!dialog.isConnected,'saved dialog remained open');
          else {check(dialog.textContent.includes('Refresh')||dialog.textContent.includes('refresh'),'missing save failure');dialog.querySelector('[type=button]').click();}
        }
        remove();card.remove();
      }
      for(const mode of ['folder','root','stale','denied','disposed','older']) {
        const card=document.createElement('section');document.body.append(card);
        const folderId='31292945-a7ca-45ed-a393-a76cf7c357a9';
        const row={id:vaultId,name:'Office',kind:0,editRevision:'4',parentId:mode==='root'?slotId:null};
        const values=Object.fromEntries(Object.keys(sharedEditFields).map(key=>[key,key==='name'?row.name:null]));
        let reads=0,writes=0,saved,finish;
        const edit=async request=>{
          if(request.changes){writes++;saved=request;return {status:'saved'};}
          return {status:'ready',...request,workspaceId:slotId,epoch:'2',changeSeq:'5',fields:values,canMove:mode!=='older'};
        };
        const page=async cursor=>{
          reads++;
          if(mode==='denied')throw Error('unavailable');
          if(mode==='disposed')await new Promise(resolve=>{finish=resolve});
          const writable={id:folderId,kind:0,parentId:null,editRevision:'7',name:'Design'};
          if(reads===1)return {epoch:'2',changeSeq:'5',next:{after:slotId,epoch:'2',changeSeq:'5'},nodes:[
            row,{...writable,parentId:row.id},{...writable,editRevision:undefined},{...writable,kind:1},
            ...(row.parentId?[{...writable,id:row.parentId}]:[])
          ]};
          check(cursor.after===slotId&&cursor.epoch==='2'&&cursor.changeSeq==='5','wrong folder cursor');
          return {epoch:'2',changeSeq:mode==='stale'?'6':'5',nodes:[writable],next:null};
        };
        const dispose=openSharedNodeEditor(card,row,edit,()=>{},page);await tick();
        const button=text=>[...card.querySelectorAll('button')].find(b=>b.textContent===text);
        const start=button('Move to folder…');
        if(mode==='older'){check(!start,'older deployment offered move');dispose();card.remove();continue;}
        const name=card.querySelector('fieldset input');name.value='Edited';name.dispatchEvent(new Event('input',{bubbles:true}));
        check(start.disabled,'move discarded pending scalar edits');name.value=row.name;name.dispatchEvent(new Event('input',{bubbles:true}));
        start.click();await tick();
        if(mode==='disposed'){dispose();finish();await tick();check(!card.childElementCount,'late folder response reopened editor');}
        else {
          const select=card.querySelector('fieldset select'),save=button('Move');
          check(save.disabled&&writes===0,'opening picker submitted a move');
          if(mode==='denied')check(select.disabled&&card.textContent.includes('refresh'),'denied folders enabled');
          else {
            check([...select.options].every(o=>!o.value||o.value==='root'),'ineligible folder shown');
            if(mode!=='root'){button('Next page').click();await tick();}
            if(mode==='stale')check(save.disabled&&select.disabled&&card.textContent.includes('refresh'),'stale page enabled move');
            else {
              select.value=mode==='root'?'root':folderId;select.dispatchEvent(new Event('change',{bubbles:true}));
              check(!save.disabled,'valid destination refused');save.click();await tick();
              check(writes===1&&saved.revision==='4'&&saved.changeSeq==='5'&&saved.epoch==='2'&&
                Object.keys(saved.changes).length===1&&(mode==='root'?saved.changes.parent===null:
                saved.changes.parent.id===folderId&&saved.changes.parent.revision==='7'),'wrong move payload');
            }
          }
        }
        dispose();card.remove();
      }
      // The actual launcher owns lazy session mounting, including late modules and failures.
      for(const mode of ['ready','late-mount','mount-error','render-error','lock-error']) {
        const card=document.createElement('section');document.body.append(card);let resolveMount,failView,removed=0,locked=0,observed=0,connected=0;
        const port={connect:(node,kind)=>{check(node.name==='server'&&kind==='terminal','catalog connection payload');connected++},observeNodes:nodes=>{observed+=nodes.length},dispose:()=>{removed++}};
        const api={authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'}),onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'1',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'1',nodes:[{id:vaultId,name:'server',kind:1,protocol:0,canUse:true}],next:null}),lockAuthentication:async()=>{locked++;if(mode==='lock-error'&&locked===1)throw Error('private')}};
        const dispose=mountSharedStartup(card,metadata(),api,async(container,failed)=>{failView=failed;if(mode==='mount-error')throw Error('private');if(mode==='late-mount')return new Promise(resolve=>resolveMount=resolve);container.textContent='Session area';return port;});
        const signIn=card.querySelector('button');signIn.click();await tick();
        if(mode==='late-mount'){dispose();resolveMount(port);await tick();check(removed===1&&!card.classList.contains('shared-workspace'),'late module mounted');}
        else if(mode==='mount-error'){check(locked===1&&!signIn.disabled&&!signIn.hidden&&!card.textContent.includes('private'),'module failure did not lock');}
        else if(mode==='render-error'||mode==='lock-error'){failView();await tick();check(removed===1&&locked===1&&!card.textContent.includes('Session area'),'failed view kept sessions');if(mode==='lock-error'){check(signIn.disabled&&card.textContent.includes('Could not confirm'),'failed lock readmitted');card.querySelectorAll('button')[2].click();await tick();check(locked===2&&!signIn.disabled,'failed lock retry');}else check(!signIn.disabled,'render failure kept admission');}
        else {check(card.classList.contains('shared-workspace')&&signIn.hidden&&observed===1,'workspace not mounted');const connect=card.querySelector('[aria-label="Connect · server"]');connect.click();check(connected===1,'Connect not routed');card.querySelectorAll('button')[2].click();await tick();connect.onclick();check(connected===1&&removed===1&&!card.classList.contains('shared-workspace'),'stale Connect after signout');}
        dispose();card.remove();
      }
      {
        const container=document.createElement('section');document.body.append(container);let calls=0;
        const nodes=[{name:'ssh',kind:1,protocol:0,canUse:true},{name:'files',kind:1,protocol:7,canUse:true},{name:'view',kind:1,protocol:0,canUse:false},{name:'other',kind:1,protocol:2,canUse:true},{name:'serial',kind:1,protocol:5,canUse:true},{name:'web',kind:1,protocol:3,canUse:true}];
        const port={connect:()=>{calls++},observeNodes:()=>{},dispose:()=>{}};
        const remove=mountSharedCatalogScreen(container,{onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes,next:null})},()=>{throw Error('catalog failed')},port);await tick();
        const actions=container.querySelectorAll('.shared-catalog-actions button');check(actions.length===5&&container.textContent.includes('View only')&&container.textContent.includes('not available'),'permission/protocol controls');check(container.querySelector('[aria-label="Connect · serial"]'),'serial control missing');actions.forEach(button=>button.click());check(calls===5,'actions not routed');remove();actions[0].onclick();check(calls===5,'disposed action routed');container.remove();
      }
      {
        const container=document.createElement('section');document.body.append(container);let rejectRead,finishRead;
        const requests=[];
        const nodes=[{id:vaultId,name:'view',kind:1,protocol:0,canUse:false,notesRevision:'9'},{id:slotId,name:'older',kind:1,protocol:0,canUse:true}];
        const api={onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes,next:null}),showVaultNotes:request=>{requests.push(request);return new Promise((resolve,reject)=>{finishRead=resolve;rejectRead=reject;})}};
        const port={connect:()=>{throw Error('note tried to connect')},observeNodes:()=>{},dispose:()=>{}};
        const remove=mountSharedCatalogScreen(container,api,()=>{throw Error('note failure locked the catalog')},port);await tick();
        const open=container.querySelector('[aria-label="View stored notes · view"]');
        check(open&&!container.querySelector('[aria-label="View stored notes · older"]')&&container.textContent.includes('View only'),'incorrect notes eligibility');
        open.click();open.onclick();check(open.disabled&&requests.length===1,'note display opened twice');
        check(JSON.stringify(requests[0])===JSON.stringify({nodeId:vaultId,rowVersion:'9'}),'note selection leaked extra parameters');
        rejectRead(Error('private diagnostics'));await tick();
        check(!open.disabled&&container.textContent.includes('Stored notes are unavailable.')&&!container.textContent.includes('private diagnostics'),'note failure stayed busy or leaked');
        open.click();check(requests.length===2,'note could not reopen');remove();finishRead();await tick();
        open.onclick();check(requests.length===2,'disposed note action routed');container.remove();
      }


      {
        const card=document.createElement('section');document.body.append(card);let releaseOld,failOld,unmountedOld=0,unmountedNew=0,locked=0,mounts=0;
        const port=old=>({connect:()=>{},observeNodes:()=>{},dispose:()=>{if(old)unmountedOld++;else unmountedNew++}});
        const api={authenticateSharedVault:async()=>({admitted:true,lockedMemory:true,orgEscrow:true,tls:'off'}),onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'0',nodes:[],next:null}),lockAuthentication:async()=>{locked++}};
        const dispose=mountSharedStartup(card,metadata(),api,async(container,failed)=>{if(++mounts===1){failOld=failed;queueMicrotask(failed);return new Promise(resolve=>releaseOld=resolve)}container.textContent='Current sessions';return port(false)});
        const signIn=card.querySelector('button');signIn.click();await tick();check(locked===1&&!signIn.disabled,'early render failure stayed busy');signIn.click();await tick();check(mounts===2&&card.textContent.includes('Current sessions'),'new admission not mounted');releaseOld(port(true));await tick();failOld();await tick();check(unmountedOld===1&&unmountedNew===0&&locked===1&&card.textContent.includes('Current sessions'),'old module replaced or locked current owner');dispose();check(unmountedNew===1,'current root not disposed');card.remove();
      }

      for(const mode of ['pages','dispose-loaded','error','late-success','late-error']){
        const container=document.createElement('section');document.body.append(container);let calls=0,failed=0,resolvePage,rejectPage;
        const cursor={after:vaultId,epoch:'1',changeSeq:'9'};
        const node={id:vaultId,parentId:null,name:'<img src=x>',kind:1,sortOrder:'0',protocol:0,host:'<script>',port:0,username:'alice'};
        const api={onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async()=>({epoch:'1',changeSeq:'0',reset:true,nodes:[]}),loadSharedCatalogPage:async request=>{calls++;check(request.limit===32,'page bound');if(mode==='error')throw Error('private');if(mode.startsWith('late'))return new Promise((resolve,reject)=>{resolvePage=resolve;rejectPage=reject});if(calls===1){check(request.after==='','initial cursor');return{nodes:[node,{...node,kind:0,name:'folder'}],next:cursor}}if(calls===2){check(request.after===vaultId&&request.epoch==='1'&&request.changeSeq==='9','continuation');return{nodes:[{...node,name:'second',host:null,port:null,username:''}],next:null}}check(request.after==='','refresh cursor');return{nodes:[],next:null}}};
        const remove=mountSharedCatalogScreen(container,api,()=>{failed++});
        if(mode.startsWith('late')){await tick();remove();if(mode==='late-success')resolvePage({nodes:[node],next:null});else rejectPage(Error('private'));await tick();check(!container.textContent&&failed===0,'late page republished');}
        else if(mode==='error'){await tick();check(failed===1&&!container.textContent,'failed page retained');}
        else if(mode==='dispose-loaded'){await tick();const list=container.querySelector('ul');check(list.textContent.includes('<img'),'loaded fixture');remove();check(!list.textContent&&!container.textContent,'detached metadata retained');}
        else {const controls=container.querySelectorAll('button');controls[0].onclick();await tick();check(calls===1,'duplicate load');check(container.textContent.includes('<img src=x>')&&!container.querySelector('img')&&!container.querySelector('script'),'metadata executed');check(container.textContent.includes('0')&&container.textContent.includes('Folder'),'display fields');const firstRow=container.querySelector('ul');controls[1].click();await tick();check(container.textContent.includes('second')&&!container.textContent.includes('<img'),'page not replaced');check(controls[1].hidden,'final next visible');controls[1].onclick();check(calls===2,'null cursor request');controls[0].click();await tick();check(container.textContent.includes('No visible items.'),'empty refresh');remove();controls[0].onclick();check(calls===3&&!container.textContent&&!firstRow.textContent,'disposed request');}
        remove();container.remove();
      }
      {
        const container=document.createElement('section');document.body.append(container);let hint,unsubscribed=0,polls=0,releasePoll;
        const api={onSharedCatalogChanged:callback=>{hint=callback;return()=>{unsubscribed++}},loadSharedChanges:async()=>{polls++;if(polls===2)return new Promise(resolve=>releasePoll=resolve);return{epoch:'1',changeSeq:'9',reset:polls===1,nodes:[]}},loadSharedCatalogPage:async()=>({epoch:'1',changeSeq:'9',nodes:[{name:'visible',kind:0}],next:null})};
        const remove=mountSharedCatalogScreen(container,api,()=>{throw Error('unexpected failure')});await tick();
        hint();await tick();await tick();check(polls===2,'hint did not check authenticated changes');hint();hint();check(polls===2,'hint overlapped pending request');releasePoll({epoch:'1',changeSeq:'9',reset:false,nodes:[]});
        for(let i=0;i<10&&polls<3;i++)await tick();check(polls===3,'pending hint lost');check(container.textContent.includes('visible'),'unchanged hint cleared page');
        remove();remove();hint();await tick();check(unsubscribed===1&&polls===3&&!container.textContent,'notification survived dispose');container.remove();
      }
      const originalTimeout=window.setTimeout,originalClear=window.clearTimeout;
      try {
        let scheduled;
        window.setTimeout=(callback,ms,...args)=>{if(ms===30000){scheduled=callback;return -1}return originalTimeout(callback,ms,...args)};
        window.clearTimeout=id=>{if(id===-1)scheduled=undefined;else originalClear(id)};
        for(const mode of ['same','changed','error','late','late-error','initial-error']) {
          const container=document.createElement('section');document.body.append(container);let polls=0,reads=0,failures=0,resolvePoll,rejectPoll;
          const api={onSharedCatalogChanged:()=>()=>{},loadSharedChanges:async request=>{polls++;if(mode==='initial-error'||(mode==='error'&&polls===2))throw Error('private');if(polls===1){check(request.epoch==='0'&&request.changeSeq==='0','initial changes missing');return{epoch:'1',changeSeq:'9',reset:true,nodes:[]}}check(request.epoch==='1'&&request.changeSeq==='9','poll cursor');if(mode.startsWith('late'))return new Promise((resolve,reject)=>{resolvePoll=resolve;rejectPoll=reject});return{epoch:'1',changeSeq:mode==='same'?'9':'10',reset:false,nodes:mode==='same'?[]:[vaultId]}},loadSharedCatalogPage:async()=>{reads++;return{epoch:'1',changeSeq:String(8+reads),nodes:[{name:'page '+reads,kind:0}],next:null}}};
          const remove=mountSharedCatalogScreen(container,api,()=>{failures++});await tick();
          if(mode==='initial-error'){check(failures===1&&reads===0&&!scheduled,'failed initial probe loaded catalog');remove();container.remove();continue;}
          check(reads===1&&typeof scheduled==='function','poll not scheduled');const fire=scheduled;fire();fire();await tick();check(polls===2,'overlapping polls');
          if(mode.startsWith('late')){remove();if(mode==='late')resolvePoll({epoch:'1',changeSeq:'10',reset:true,nodes:[]});else rejectPoll(Error('private'));await tick();check(!container.textContent&&!scheduled&&failures===0,'late poll retained state');}
          else if(mode==='error')check(failures===1&&!container.textContent&&!scheduled,'poll failure retained catalog');
          else check(reads===(mode==='same'?1:2)&&typeof scheduled==='function','poll refresh mismatch');
          remove();fire();await tick();check(polls===2&&!scheduled,'disposed polling resumed');container.remove();
        }
      } finally {window.setTimeout=originalTimeout;window.clearTimeout=originalClear;}
    })().catch(error=>({testFailure:String(error.stack)}));\n//# sourceURL=wormhole-shared-screens.js`;
    new Script(renderer);
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false}});try{await window.loadURL('about:blank');const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});const outcome=await window.webContents.executeJavaScript(${JSON.stringify(renderer)});assert.equal(outcome?.testFailure,undefined);const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-shared-screens.js');assert.ok(script);for(const name of ['mountSharedAuthenticationScreen','mountSharedInitialJoinScreen','mountSharedStartup','mountSharedCatalogScreen','openSharedNodeEditor','mountMovePicker','editControl','mountSharedCertificateRenewal']){const fn=script.functions.find(f=>f.functionName===name);assert.ok(fn);const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const coverage=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log(name+': '+coverage.toFixed(2)+'% V8 blocks');assert.ok(coverage>=${coverageThreshold});}}finally{window.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
    );
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const electron = require('electron') as string,
      headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 30000, windowsHide: true },
    );
    assert.match(stdout, /mountSharedAuthenticationScreen:/);
    t.diagnostic(stdout.trim());
    if (stderr.trim()) t.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
