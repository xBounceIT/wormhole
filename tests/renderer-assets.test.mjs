import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createPackage } from '@electron/asar';
import { build } from 'vite';
import afterPack, { verifyRendererAssets } from '../scripts/verify-renderer-assets.mjs';

test('the production renderer survives ASAR packaging with exact asset casing', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wormhole-renderer-pack-'));
  try {
    const source = path.join(directory, 'app');
    const dist = path.join(source, 'dist');
    await build({ build: { outDir: dist }, logLevel: 'silent' });
    const dirs = await readdir(dist);
    assert.equal(
      new Set(dirs.map((name) => name.toLowerCase())).size,
      dirs.length,
      'Public and generated output must not differ only by case',
    );
    const archive = path.join(directory, 'app.asar');
    await createPackage(source, archive);
    verifyRendererAssets(archive);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('packaging rejects missing resources and the macOS 2.2.1 Assets/assets regression', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wormhole-renderer-invalid-'));
  try {
    for (const scenario of [
      'valid',
      'case',
      'missing',
      'empty',
      'escape',
      'query-missing',
      'single-quoted-missing',
      'query-valid',
      'absolute',
    ]) {
      const source = path.join(directory, scenario);
      const folder = scenario === 'case' ? 'Assets' : 'assets';
      await mkdir(path.join(source, 'dist', folder), { recursive: true });
      await writeFile(
        path.join(source, 'dist', 'index.html'),
        scenario === 'empty'
          ? '<html></html>'
          : scenario === 'single-quoted-missing'
            ? `<script src='./assets/absent.js'></script><link href="./assets/style.css">`
            : scenario === 'query-valid'
              ? `<script src='./assets/ma%69n.js?v=1#entry'></script><link href="./assets/style.css">`
              : scenario === 'absolute'
                ? `<script src='/assets/main.js'></script><link href="./assets/style.css">`
                : `<script src="./${scenario === 'escape' ? '../' : ''}assets/${scenario === 'query-missing' ? 'absent.js?v=1' : 'main.js'}"></script><link href="./assets/style.css"><img src="./assets/logo.png">`,
      );
      for (const file of ['main.js', 'style.css', 'logo.png']) {
        if (scenario !== 'missing' || file !== 'logo.png')
          await writeFile(path.join(source, 'dist', folder, file), 'content');
      }
      const archive = path.join(directory, `${scenario}.asar`);
      await createPackage(source, archive);
      if (scenario === 'valid' || scenario === 'query-valid') verifyRendererAssets(archive);
      else
        assert.throws(
          () => verifyRendererAssets(archive),
          /no local assets|missing or has incorrect casing|relative asset URLs/,
        );
    }
    for (const platform of ['darwin', 'win32', 'linux']) {
      const output = path.join(directory, platform);
      const resources =
        platform === 'darwin'
          ? path.join(output, 'Wormhole.app', 'Contents', 'Resources')
          : path.join(output, 'resources');
      await mkdir(resources, { recursive: true });
      await createPackage(path.join(directory, 'valid'), path.join(resources, 'app.asar'));
      const context = {
        appOutDir: output,
        electronPlatformName: platform,
        packager: { appInfo: { productFilename: 'Wormhole' } },
      };
      if (platform === 'darwin') {
        assert.throws(() => afterPack(context), /bundled macOS FreeRDP client is missing/);
      } else {
        await afterPack(context);
        if (platform === 'win32') {
          for (const productFilename of ['Wormhole', 'Wormhole Preview Ω']) {
            await writeFile(path.join(output, 'electron_wer.dll'), 'matching WER helper');
            const renamed = { ...context, packager: { appInfo: { productFilename } } };
            await afterPack(renamed);
            assert.equal(
              await readFile(path.join(output, `${productFilename}_wer.dll`), 'utf8'),
              'matching WER helper',
            );
            await assert.rejects(readFile(path.join(output, 'electron_wer.dll')), {
              code: 'ENOENT',
            });
            await afterPack(renamed);
          }
          await mkdir(path.join(output, 'Blocked_wer.dll'));
          await writeFile(path.join(output, 'electron_wer.dll'), 'retain on failure');
          await assert.rejects(
            afterPack({ ...context, packager: { appInfo: { productFilename: 'Blocked' } } }),
          );
          assert.equal(
            await readFile(path.join(output, 'electron_wer.dll'), 'utf8'),
            'retain on failure',
          );
        } else {
          await writeFile(path.join(output, 'electron_wer.dll'), 'not a Windows runtime');
          await afterPack(context);
          assert.equal(
            await readFile(path.join(output, 'electron_wer.dll'), 'utf8'),
            'not a Windows runtime',
          );
        }
      }
      await createPackage(path.join(directory, 'case'), path.join(resources, 'app.asar'));
      assert.throws(
        () =>
          afterPack({
            appOutDir: output,
            electronPlatformName: platform,
            packager: { appInfo: { productFilename: 'Wormhole' } },
          }),
        /incorrect casing/,
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
