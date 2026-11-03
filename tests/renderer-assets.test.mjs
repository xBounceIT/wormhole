import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
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
      afterPack({
        appOutDir: output,
        electronPlatformName: platform,
        packager: { appInfo: { productFilename: 'Wormhole' } },
      });
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
