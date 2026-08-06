// Patches the packaged Wormhole.exe (the renamed Electron runtime) with the Wormhole icon and
// product/version metadata, so the installed app no longer shows the default Electron icon.
// Uses rcedit (the same resource editor electron-packager relies on); the binary ships inside
// the rcedit npm package, so no extra download is needed at build time.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rcedit } from 'rcedit';

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.dirname(scriptRoot);

const [, , exePath, version, iconPath] = process.argv;
if (!exePath || !version) {
  console.error('usage: node scripts/patch-electron-exe.mjs <Wormhole.exe> <version> [icon.ico]');
  process.exit(2);
}

await rcedit(path.resolve(exePath), {
  icon: path.resolve(iconPath ?? path.join(repoRoot, 'Assets', 'Wormhole.ico')),
  'version-string': {
    ProductName: 'Wormhole',
    FileDescription: 'Wormhole',
    CompanyName: 'Wormhole project',
    LegalCopyright: 'Wormhole project',
    OriginalFilename: 'Wormhole.exe',
    FileVersion: version,
    ProductVersion: version,
  },
  'file-version': version,
  'product-version': version,
});

console.log(`OK    patched ${path.resolve(exePath)} (icon + version ${version})`);
