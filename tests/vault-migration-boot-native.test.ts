import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { createRecoveryRecipient } from '../src/vault-recovery-recipient.ts';

test(
  'real Electron isolates the whole Chromium profile before readiness and resumes a real Go migration',
  { timeout: 180_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-migration-boot-native-'));
    const root = fileURLToPath(new URL('../', import.meta.url));
    const original = join(directory, 'original-user-data');
    const databasePath = join(directory, 'workspace.db');
    const executable = join(directory, process.platform === 'win32' ? 'vault.exe' : 'vault');
    const run = promisify(execFile);
    const host = new VaultBackendHost(
      () => new VaultBackendClient({ executable, databasePath, userDataPath: original }),
      () => true,
    );
    let code: Uint8Array | undefined;
    try {
      await mkdir(original);
      await writeFile(join(original, 'original-sentinel'), 'original profile fixture');
      await run('go', ['build', '-o', executable, '.'], {
        cwd: join(root, 'tools', 'wormhole-backend'),
        windowsHide: true,
        timeout: 120_000,
      });
      await run(executable, ['--operation', 'workspace', '--database', databasePath], {
        windowsHide: true,
        timeout: 30_000,
      });
      const recipient = await createRecoveryRecipient();
      const enrollment = await host.beginMigrationSetup({
        password: new TextEncoder().encode('native migration fixture password'),
        publicKey: new Uint8Array(recipient.publicKey),
        legacyMethod: 'none',
        legacyFactor: new Uint8Array(),
      });
      code = await recipient.open(enrollment);
      recipient.dispose();
      const groups = new Uint8Array(10);
      enrollment.groups.forEach((n, i) =>
        groups.set(code!.subarray(7 + (n - 1) * 6, 12 + (n - 1) * 6), i * 5),
      );
      await host.confirmMigrationSetup({ enrollmentId: enrollment.enrollmentId, groups });
      await host.stop();
      await run(
        process.execPath,
        [
          join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
          '-p',
          join(root, 'electron', 'tsconfig.electron.json'),
        ],
        { cwd: root, windowsHide: true, timeout: 120_000 },
      );
      await run(process.execPath, [join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'build'], {
        cwd: root,
        windowsHide: true,
        timeout: 120_000,
      });
      const parentPreload = join(directory, 'parent-preload.cjs');
      const parentPage = join(directory, 'parent.html');
      await writeFile(
        parentPreload,
        "const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('fixture',{start:()=>ipcRenderer.invoke('vault:migration-resume')});",
      );
      await writeFile(
        parentPage,
        '<!doctype html><html><body>Native migration parent</body></html>',
      );
      const script = join(directory, 'electron-main.mjs');
      const moduleURL = (name: string) =>
        JSON.stringify(pathToFileURL(join(root, 'dist-electron', name)).href);
      const secondary = join(directory, 'secondary.mjs');
      await writeFile(
        secondary,
        `import {app} from 'electron';import assert from 'node:assert/strict';import {prepareVaultMigrationBoot} from ${moduleURL('vault-migration-boot.js')};app.setName('Wormhole migration fixture');app.setPath('userData',${JSON.stringify(original)});const boot=prepareVaultMigrationBoot({app,executable:()=>{throw Error('secondary must not probe');},databasePath:${JSON.stringify(databasePath)}});assert.equal(boot.primary,false);process.stdout.write('VAULT_SECONDARY_REJECTED\\n');app.exit(0);`,
      );

      await writeFile(
        script,
        `
import {app,BrowserWindow,session,ipcMain} from 'electron';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {prepareVaultMigrationBoot} from ${moduleURL('vault-migration-boot.js')};
import {selectVaultNativePaths} from ${moduleURL('vault-native-paths.js')};
import {VaultBackendClient} from ${moduleURL('vault-client.js')};
import {VaultBackendHost} from ${moduleURL('vault-host.js')};
import {VaultReauthenticationDialog} from ${moduleURL('vault-reauth-dialog.js')};
import {registerVaultMigrationIpc} from ${moduleURL('vault-migration-ipc.js')};
app.setName('Wormhole migration fixture');
app.setPath('userData',${JSON.stringify(original)});
app.setPath('sessionData',${JSON.stringify(original)});
app.disableHardwareAcceleration();
const native=selectVaultNativePaths(app.getPath('userData'),{WORMHOLE_DATABASE:${JSON.stringify(databasePath)}});
const boot=prepareVaultMigrationBoot({app,executable:()=>${JSON.stringify(executable)},databasePath:native.databasePath});
assert.equal(boot.primary,true);assert.equal(boot.unavailable,false);assert.ok(boot.migrationSessionData);
assert.equal(app.isReady(),false);assert.equal(app.getPath('userData'),boot.migrationSessionData);assert.equal(app.getPath('sessionData'),boot.migrationSessionData);
assert.equal(native.userDataPath,${JSON.stringify(original)});

let stage="profile";
app.whenReady().then(async()=>{
 const host=new VaultBackendHost(()=>new VaultBackendClient({executable:${JSON.stringify(executable)},databasePath:native.databasePath,userDataPath:native.userDataPath,migrationSessionData:boot.migrationSessionData}),()=>true);
 let window;
 try {
  assert.equal(session.defaultSession.storagePath,boot.migrationSessionData);
  window=new BrowserWindow({show:false,webPreferences:{preload:${JSON.stringify(parentPreload)},sandbox:true,contextIsolation:true,nodeIntegration:false}});
  stage='window';await window.loadFile(${JSON.stringify(parentPage)});
  stage='metadata';const startup=await host.startup();assert.equal(startup.migration.pending,true);
  stage='ownership';const rejected=await new Promise((yes,no)=>execFile(process.execPath,[${JSON.stringify(secondary)}],{windowsHide:true,timeout:20_000},(error,stdout)=>error?no(error):yes(stdout)));assert.match(rejected,/VAULT_SECONDARY_REJECTED/);

  let child,activated=0,borrowed;
  const resume=host.resumeMigration.bind(host);host.resumeMigration=input=>{borrowed=input.factor;return resume(input);};
  const dialog=new VaultReauthenticationDialog({ipc:ipcMain,stop:()=>host.stop(),createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:${JSON.stringify(pathToFileURL(join(root, 'dist', 'vault-reauth.html')).href)},preload:${JSON.stringify(join(root, 'dist-electron', 'vault-reauth-preload.cjs'))}});
  registerVaultMigrationIpc({ipc:ipcMain,host,dialog,parent:event=>BrowserWindow.fromWebContents(event.sender)??undefined,trusted:event=>event.sender===window.webContents&&event.senderFrame===window.webContents.mainFrame,quiesced:()=>!!boot.migrationSessionData,activate:()=>activated++,retire:()=>host.stop()});
  stage='prompt';const admitted=window.webContents.executeJavaScript('window.fixture.start()');admitted.catch(()=>{});
  let ready=false;
  for(let i=0;i<400;i++){if(child&&!child.isDestroyed()&&await child.webContents.executeJavaScript("!!document.querySelector('input')&&!document.querySelector('button[type=submit]').disabled").catch(()=>false)){ready=true;break;}await new Promise(r=>setTimeout(r,20));}
  assert.equal(ready,true);
  stage='resume';await child.webContents.executeJavaScript("document.querySelector('input').value='native migration fixture password';document.querySelector('input').dispatchEvent(new Event('input'));document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));");
  assert.equal(await admitted,true);
  stage='owner';assert.equal(activated,1);assert.ok(borrowed.every(b=>b===0));assert.ok(host.unlockedWorkspaceId);assert.equal(child.isDestroyed(),true);
  assert.equal((await host.startup()).migration,undefined);
  stage='workspace';await host.workspace();
  process.stdout.write('VAULT_MIGRATION_BOOT_OK\\n');
 } finally {await host.stop();if(window&&!window.isDestroyed())window.destroy();}
 app.exit(0);
}).catch(()=>{process.stderr.write('Native migration boot fixture failed at '+stage+'.\\n');app.exit(1);});
`,
      );
      const electron = createRequire(import.meta.url)('electron') as string;
      const environment = { ...process.env };
      delete environment.ELECTRON_RUN_AS_NODE;
      const output = await new Promise<string>((resolve, reject) => {
        const child = execFile(
          electron,
          [script],
          { env: environment, windowsHide: true, timeout: 90_000, maxBuffer: 256 * 1024 },
          (error, stdout) => (error ? reject(error) : resolve(stdout)),
        );
        child.stdin?.end();
      });
      assert.match(output, /VAULT_MIGRATION_BOOT_OK/);
      assert.equal(
        await readFile(join(original, 'original-sentinel'), 'utf8'),
        'original profile fixture',
      );
    } finally {
      code?.fill(0);
      await host.stop();
      await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  },
);
