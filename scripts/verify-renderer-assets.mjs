import path from 'node:path';
import { extractFile, listPackage, uncache } from '@electron/asar';
import { verifyMacFreeRdp } from './build-macos-freerdp.mjs';
import { renameElectronWerHelper } from './rename-electron-wer.mjs';

export function verifyRendererAssets(archive) {
  // Packagers can replace an archive at the same path during a universal merge/rebuild.
  uncache(archive);
  const entries = new Set(listPackage(archive).map((entry) => entry.replaceAll('\\', '/')));
  const html = extractFile(archive, path.join('dist', 'index.html')).toString('utf8');
  const references = [...html.matchAll(/\b(?:src|href)\s*=\s*(["'])(.*?)\1/g)];
  if (references.length === 0) throw new Error('Packaged renderer has no local assets.');
  for (const [, , reference] of references) {
    // Vite's file:// entrypoint must use relative URLs. Resolve query strings and
    // percent escapes as Chromium does rather than silently omitting these assets.
    if (!reference.startsWith('./'))
      throw new Error('Packaged renderer must use relative asset URLs.');
    const asset = decodeURIComponent(new URL(reference, 'file:///dist/index.html').pathname).slice(
      1,
    );
    if (!asset.startsWith('dist/') || !entries.has(`/${asset}`)) {
      throw new Error(`Packaged renderer asset is missing or has incorrect casing: ${asset}`);
    }
    // Also verifies unpacked resources are actually present beside the archive.
    extractFile(archive, path.normalize(asset));
  }
}

export default function afterPack(context) {
  const resources =
    context.electronPlatformName === 'darwin'
      ? path.join(
          context.appOutDir,
          `${context.packager.appInfo.productFilename}.app`,
          'Contents',
          'Resources',
        )
      : path.join(context.appOutDir, 'resources');
  verifyRendererAssets(path.join(resources, 'app.asar'));
  if (context.electronPlatformName === 'darwin') verifyMacFreeRdp(resources);
  if (context.electronPlatformName === 'win32') {
    return renameElectronWerHelper(
      path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`),
    );
  }
}
