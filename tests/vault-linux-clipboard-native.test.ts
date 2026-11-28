import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

// Always use a fresh X server, including on developer machines with DISPLAY set.
// This test must never read or replace a user's system clipboard.
test(
  'Linux native clipboard publishes text and privacy hints atomically without mirroring PRIMARY',
  { skip: process.platform !== 'linux', timeout: 45000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-private-clipboard-'));
    try {
      const source = stripTypeScriptTypes(
        await readFile(new URL('../electron/vault-linux-clipboard.ts', import.meta.url), 'utf8'),
      )
        .replace(/^import[\s\S]*?;\s*/gm, '')
        .replace(/^export /gm, '');
      const fixture = join(directory, 'clipboard.cjs');
      await writeFile(
        fixture,
        `
const assert = require('node:assert/strict');
const { app, clipboard, ClipboardItem } = require('electron');
${source}
app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  const io=linuxClipboardIO(clipboard,ClipboardItem);
  const marker='application/x-wormhole-clipboard-fixture';
  await clipboard.selection.writeText('private PRIMARY fixture');
  const bytes=Buffer.from('synthetic-secret-🪱');
  await io.write(bytes,marker);bytes.fill(0);
  assert.equal(await clipboard.readText(),'synthetic-secret-🪱');
  assert.equal(await clipboard.selection.readText(),'private PRIMARY fixture');
  assert.equal(await io.has(marker),true);
  assert.equal(await clipboard.has(rawFormat('x-kde-passwordManagerHint')),true);
  const items=await clipboard.read();
  const hint=await items[0].getType(rawFormat('x-kde-passwordManagerHint'));
  assert.equal(await hint.text(),'secret');
  if(await io.has(marker))io.clear();
  assert.equal(await clipboard.readText(),'');
  await io.write(Buffer.from('second synthetic fixture'),marker);
  await clipboard.writeText('replacement fixture');
  if(await io.has(marker))io.clear();
  assert.equal(await clipboard.readText(),'replacement fixture');
  app.exit(0);
}).catch(error=>{console.error(error);app.exit(1);});
`,
      );
      const environment = { ...process.env };
      delete environment.ELECTRON_RUN_AS_NODE;
      delete environment.WAYLAND_DISPLAY;
      const executable = createRequire(import.meta.url)('electron') as string;
      await promisify(execFile)(
        'xvfb-run',
        ['--auto-servernum', executable, '--no-sandbox', '--ozone-platform=x11', fixture],
        { env: environment, timeout: 35000, windowsHide: true },
      );
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
