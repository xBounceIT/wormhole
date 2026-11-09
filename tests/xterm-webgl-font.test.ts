import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { optimizeDeps, resolveConfig } from 'vite';
import { xtermWebglFontFix } from '../scripts/xterm-webgl-font.ts';

const modulePath = '/node_modules/@xterm/addon-webgl/lib/addon-webgl.mjs';
const atlasFont =
  '`${style} ${weight} ${this._config.fontSize*this._config.devicePixelRatio}px ${this._config.fontFamily}`';
const layerFont =
  '`${italic?"italic":""} ${weight} ${terminal.options.fontSize*dpr}px ${terminal.options.fontFamily}`';
const transform = xtermWebglFontFix().transform as (
  code: string,
  id: string,
) => { code: string } | null;

test('both WebGL font paths preserve the original family, size, weight and style', () => {
  const source = `return [${atlasFont}, ${layerFont}];`;
  for (const id of [modulePath, modulePath.replaceAll('/', '\\').replace('.mjs', '.js')]) {
    const patched = transform(source, id)!.code;
    const getFonts = new Function('style', 'italic', 'weight', 'terminal', 'dpr', patched);
    for (const dpr of [1, 1.25, 2]) {
      for (const italic of [false, true]) {
        for (const weight of ['normal', 'bold', 400, 700]) {
          const family = '"Cascadia Mono", "Consolas", monospace';
          const options = { fontFamily: family, fontSize: 13 };
          const fonts = getFonts.call(
            { _config: { ...options, devicePixelRatio: dpr } },
            italic ? 'italic' : '',
            italic,
            weight,
            { options },
            dpr,
          );
          const expected = `${italic ? 'italic ' : ''}${weight} ${13 * dpr}px ${family}`;
          assert.deepEqual(fonts, [expected, expected]);
        }
      }
    }
  }
});

test('font patch leaves other modules alone and rejects changed dependency templates', () => {
  for (const id of ['/src/terminal.ts', '/node_modules/other/lib/addon-webgl.mjs'])
    assert.equal(transform('unchanged', id), null);
  for (const source of ['', atlasFont, `${atlasFont};${layerFont};${atlasFont}`])
    assert.throws(() => transform(source, modulePath), /Unexpected xterm WebGL font templates/);
});

test('development dependency optimization applies the font fix to the installed addon', async () => {
  const cacheDir = await mkdtemp(join(tmpdir(), 'wormhole-xterm-font-'));
  try {
    const config = await resolveConfig(
      {
        configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
        cacheDir,
        logLevel: 'silent',
        optimizeDeps: { noDiscovery: true, include: ['@xterm/addon-webgl'] },
      },
      'serve',
    );
    const result = await optimizeDeps(config, true);
    const bundle = await readFile(result.optimized['@xterm/addon-webgl'].file, 'utf8');
    assert.equal(bundle.match(/fontFamily\}`\.trimStart\(\)/g)?.length, 2);
  } finally {
    await rm(cacheDir, { force: true, recursive: true });
  }
});
