import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { rootCertificates } from 'node:tls';
const require = createRequire(import.meta.url);

test(
  'protected initial invitation document reads a real native invite file and erases its code over the sandbox bridge',
  { timeout: 120_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-initial-invitation-'));
    const root = fileURLToPath(new URL('../', import.meta.url));
    try {
      const data = join(directory, 'data');
      await mkdir(data);
      const workspaceId = '11111111-1111-4111-8111-111111111111';
      const invitation = {
        formatVersion: 2,
        workspaceId,
        loginName: 'alice',
        endpoints: [{ host: '127.0.0.1', port: 1 }],
        database: 'workspace',
        tls: 'off',
        caPem: null as string | null,
        organisationFingerprint: Buffer.alloc(32).toString('base64'),
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        enrollment: {
          roleTag: 'testscope',
          context: {
            workspaceId,
            userId: '22222222-2222-4222-8222-222222222222',
            inviteId: '33333333-3333-4333-8333-333333333333',
            keyId: '44444444-4444-4444-8444-444444444444',
            keyVersion: 1,
            loginName: 'alice',
          },
        },
      };
      const encode = (value: typeof invitation) => {
        const payload = 'WHINV2-' + Buffer.from(JSON.stringify(value)).toString('base64url');
        return payload + '.' + createHash('sha256').update(payload).digest('hex');
      };
      const token = encode(invitation);
      const certificate = rootCertificates[0] + '\n';
      const demoToken = encode({
        ...invitation,
        endpoints: [{ host: 'workspace.example.test', port: 5432 }],
        tls: 'verified',
        caPem: Buffer.from(certificate).toString('base64'),
      });
      const ca = certificate.repeat(Math.ceil((96 * 1024) / Buffer.byteLength(certificate)));
      assert.ok(Buffer.byteLength(ca) > 65536 && Buffer.byteLength(ca) < 256 * 1024);
      const largeToken = encode({
        ...invitation,
        loginName: 'a'.repeat(256),
        tls: 'verified',
        caPem: Buffer.from(ca).toString('base64'),
        enrollment: {
          ...invitation.enrollment,
          context: { ...invitation.enrollment.context, loginName: 'a'.repeat(256) },
        },
      });
      const file = join(directory, 'workspace.whinv');
      const largeFile = join(directory, 'verified.whinv');
      await writeFile(file, token);
      await writeFile(largeFile, largeToken);
      const url = pathToFileURL(join(root, 'dist', 'vault-shared.html')).href;
      const moduleURL = (name: string) =>
        JSON.stringify(pathToFileURL(join(root, 'dist-electron', name + '.js')).href);
      const capture = join(root, 'artifacts', 'vault', 'initial-invitation-screen.png');
      await mkdir(dirname(capture), { recursive: true });
      const harness = join(directory, 'main.cjs');
      await writeFile(
        harness,
        `
const {app,BrowserWindow,ipcMain,nativeTheme}=require('electron');const assert=require('node:assert/strict');const fs=require('node:fs');
app.whenReady().then(async()=>{
 nativeTheme.themeSource='dark';
 const {VaultBackendClient}=await import(${moduleURL('vault-client')});const {VaultSharedAuthenticationDialog}=await import(${moduleURL('vault-shared-dialog')});
 const client=new VaultBackendClient({executable:${JSON.stringify(join(root, 'dist-electron', `wormhole-backend-${process.arch}${process.platform === 'win32' ? '.exe' : ''}`))},databasePath:${JSON.stringify(join(data, 'workspace.db'))},userDataPath:${JSON.stringify(data)}});
 const parent=new BrowserWindow({show:false});let child,submissions=0,borrowed,picks=0;
 const dialog=new VaultSharedAuthenticationDialog({host:{startup:()=>client.startup(),stop:()=>client.lock(),inspectSharedInvitation:token=>client.inspectSharedInvitation(token),readSharedInvitationFile:path=>client.readSharedInvitationFile(path),sharedJoinInitial:async input=>{submissions++;borrowed=input;assert.ok(input.code.every(n=>n===171));assert.equal(input.acknowledgeTLSOff,true);assert.equal(input.deviceName,'Test device');throw Error('synthetic refusal before SQL');}},ipc:ipcMain,createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child},pickInvitation:async()=>++picks===1?${JSON.stringify(largeFile)}:${JSON.stringify(file)},url:${JSON.stringify(url)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-shared-preload.cjs'))},appVersion:'2.4.3'});
 try{
  const startup=await client.startup();assert.equal(startup.newWorkspace,true);const result=dialog.open(parent,()=>true,'join-initial',startup);
  for(let i=0;i<100;i++){if(child&&await child.webContents.executeJavaScript('!!document.querySelector("textarea")').catch(()=>false))break;await new Promise(r=>setTimeout(r,25))}
  const press=async label=>{
    const clicked=await child.webContents.executeJavaScript('(()=>{const button=[...document.querySelectorAll("button")].find(b=>b.textContent==='+JSON.stringify(label)+'&&b.checkVisibility()&&!b.disabled);if(!button)return false;button.click();return true})()');
    assert.ok(clicked,'Unavailable control: '+label);
  };
  await press('Open invite file…');
  for(let i=0;i<100;i++){if(await child.webContents.executeJavaScript('!document.querySelector("[type=submit]").disabled'))break;await new Promise(r=>setTimeout(r,25))}
  assert.equal((await child.webContents.executeJavaScript('document.querySelector("textarea").value'))===${JSON.stringify(largeToken)},true,'Large verified invitation was not loaded');
  assert.equal(await child.webContents.executeJavaScript('document.querySelector("[type=checkbox]").parentElement.hidden'),true);
  const layout=await child.webContents.executeJavaScript('({width:innerWidth,scroll:document.documentElement.scrollWidth})');assert.ok(layout.scroll<=layout.width+1,'Invitation hints overflow the dialog');
  await press('Change invitation');
  await child.webContents.executeJavaScript('document.querySelector("textarea").value='+JSON.stringify(${JSON.stringify(demoToken)}));
  await press('Check invitation');
  for(let i=0;i<100;i++){if(await child.webContents.executeJavaScript('!document.querySelector("[type=submit]").disabled'))break;await new Promise(r=>setTimeout(r,25))}
  assert.equal(await child.webContents.executeJavaScript('document.querySelector(".shared-invitation-account strong").textContent'),'alice');
  assert.ok(await child.webContents.executeJavaScript('document.querySelector("[type=checkbox]").parentElement.hidden && !document.querySelector(".shared-invitation-account details").open'));
  await child.webContents.executeJavaScript('document.fonts.ready.then(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))))');
  fs.writeFileSync(${JSON.stringify(capture)},(await child.webContents.capturePage(undefined,{stayHidden:true,stayAwake:true})).toPNG());
  await press('Change invitation');
  await press('Open invite file…');
  for(let i=0;i<100;i++){if(await child.webContents.executeJavaScript('!document.querySelector("[type=submit]").disabled'))break;await new Promise(r=>setTimeout(r,25))}
  assert.equal(await child.webContents.executeJavaScript('document.querySelector("textarea").value'),${JSON.stringify(token)});
  assert.equal(await child.webContents.executeJavaScript('document.querySelector("[type=checkbox]").parentElement.hidden'),false);
  const appearance=await child.webContents.executeJavaScript(\`(async()=>{
    await document.fonts.ready;
    return {
      dark: document.documentElement.classList.contains('dark'),
      geist: [...document.fonts].some(face=>face.family.includes('Geist')&&face.status==='loaded'),
      collapsed: !document.querySelector('textarea').checkVisibility(),
      visible: document.querySelector('[type=submit]').getBoundingClientRect().bottom <= innerHeight
    };
  })()\`);
  assert.deepEqual(appearance,{dark:true,geist:true,collapsed:true,visible:true});
  const bottom=await child.webContents.executeJavaScript('(()=>{const cancel=[...document.querySelectorAll("button")].find(b=>b.textContent==="Cancel");cancel.scrollIntoView({block:"end"});const bounds=cancel.getBoundingClientRect();return {top:bounds.top,bottom:bounds.bottom,height:innerHeight}})()');assert.ok(bottom.top>=0&&bottom.bottom<=bottom.height,'Dialog actions are not reachable by scrolling');
  await child.webContents.executeJavaScript('for(const [name,value] of Object.entries({code:"ab".repeat(16),password:"test password","password-confirm":"test password","device-name":"Test device"}))document.querySelector("[name="+name+"]").value=value;document.querySelector("[type=checkbox]").checked=true;document.querySelector("form").dispatchEvent(new Event("submit",{cancelable:true}))');
  for(let i=0;i<100&&!submissions;i++)await new Promise(r=>setTimeout(r,25));assert.equal(submissions,1);
  for(let i=0;i<100;i++){if(await child.webContents.executeJavaScript('document.querySelector(".startup-status").textContent.startsWith("Could not join.")'))break;await new Promise(r=>setTimeout(r,25))}
  assert.equal(await child.webContents.executeJavaScript('document.querySelector(".startup-status").textContent.startsWith("Could not join.")'),true);
  assert.ok(borrowed.code.every(n=>n===0)&&borrowed.password.every(n=>n===0));
  assert.equal(await child.webContents.executeJavaScript('["code","password","password-confirm","ask"].every(name=>!document.querySelector("[name="+name+"]").value)'),true);
  assert.equal((await client.startup()).newWorkspace,true);await dialog.cancel();assert.equal(await result,null);
 }finally{await dialog.cancel();await client.lock();if(child&&!child.isDestroyed())child.destroy();parent.destroy()}
 app.quit();
}).catch(error=>{console.error(error);app.exit(1)});
`,
      );
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string;
      const headless = process.platform === 'linux' && !env.DISPLAY;
      const { stdout, stderr } = await promisify(execFile)(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
        { env, windowsHide: true, timeout: 90_000, maxBuffer: 16384 },
      );
      assert.doesNotMatch(stdout + stderr, /test password/);
    } finally {
      assert.equal(join(directory, '..'), join(tmpdir()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
