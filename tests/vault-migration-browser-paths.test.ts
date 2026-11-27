import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { tunnelAuthPartition } from '../electron/tunnel-auth.ts';
import { getBitwardenBrowserPartition } from '../electron/bitwarden-browser-profile.ts';

const run = promisify(execFile);
const require = createRequire(import.meta.url);

test(
  'native Chromium SSO profile paths and complete persisted files enter the Go migration archive',
  { timeout: 120000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-browser-migration-'));
    try {
      const token = randomUUID();
      const partitions = [
        tunnelAuthPartition({ completion: 'oauth-code' }),
        tunnelAuthPartition({
          completion: 'query-token',
          origin: 'https://firebox.example.invalid',
          ignoreCertificateErrors: false,
        }),
        getBitwardenBrowserPartition('', false),
        'persist:wormhole-tunnel-auth-fortinet',
        'persist:wormhole-tunnel-auth-watchguard',
      ];
      await writeFile(join(directory, 'wormhole-browser-migration-fixture'), token);
      await writeFile(
        join(directory, 'main.cjs'),
        `
const {app,session}=require('electron');
const {join}=require('node:path');
app.disableHardwareAcceleration();
app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);
app.whenReady().then(async()=>{
 const result=[];
 for(const [index,partition] of ${JSON.stringify(partitions)}.entries()) {
  const profile=session.fromPartition(partition,{cache:false});
  await profile.cookies.set({url:'https://sso.example.invalid',name:'migration_fixture',value:'synthetic-'+index,secure:true,httpOnly:true,sameSite:'lax'});
  profile.flushStorageData();await profile.cookies.flushStore();
  result.push({partition,path:profile.storagePath});
 }
 process.stdout.write('WORMHOLE_BROWSER_PATHS:'+JSON.stringify(result)+'\\n');app.quit();
}).catch(()=>{process.stderr.write('Native browser migration fixture failed.\\n');app.exit(1)});
`,
      );
      const env = { ...process.env };
      delete env.ELECTRON_RUN_AS_NODE;
      const executable = require('electron') as string;
      const headless = process.platform === 'linux' && !env.DISPLAY;
      const output = await run(
        headless ? 'xvfb-run' : executable,
        headless
          ? ['--auto-servernum', executable, join(directory, 'main.cjs')]
          : [join(directory, 'main.cjs')],
        { env, timeout: 45000, windowsHide: true, maxBuffer: 1024 * 1024 },
      );
      const line = output.stdout
        .split(/\r?\n/)
        .find((line) => line.startsWith('WORMHOLE_BROWSER_PATHS:'));
      assert.ok(line, 'Native fixture did not report its owned profile paths');
      const profiles = JSON.parse(line.slice('WORMHOLE_BROWSER_PATHS:'.length));
      assert.equal(profiles.length, partitions.length);
      for (const [index, profile] of profiles.entries()) {
        assert.equal(profile.partition, partitions[index]);
        assert.equal(
          resolve(profile.path),
          resolve(directory, 'Partitions', partitions[index].slice('persist:'.length)),
        );
      }
      const native = await run(
        'go',
        [
          'test',
          '.',
          '-run',
          '^TestVaultMigrationBrowserNativeProfileFixture$',
          '-count=1',
          '-json',
          '-count=1',
          '-timeout',
          '60s',
        ],
        {
          cwd: resolve('tools/wormhole-backend'),
          timeout: 75000,
          windowsHide: true,
          maxBuffer: 1024 * 1024,
          env: {
            ...env,
            WORMHOLE_TEST_BROWSER_ROOT: directory,
            WORMHOLE_TEST_BROWSER_TOKEN: token,
          },
        },
      );
      const events = native.stdout
        .trim()
        .split(/\r?\n/)
        .map((line) => JSON.parse(line));
      assert.ok(
        events.some(
          (event) =>
            event.Action === 'pass' &&
            event.Test === 'TestVaultMigrationBrowserNativeProfileFixture',
        ),
        'The Go integration case did not execute successfully',
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
