// Patches the packaged Wormhole.exe (the renamed Electron runtime) with the Wormhole icon and
// product/version metadata, so the installed app no longer shows the default Electron icon.
// Uses resedit to update the PE resources without downloading a native helper at build time.
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ResEdit from 'resedit';

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.dirname(scriptRoot);

const [, , exePath, version, iconPath] = process.argv;
if (!exePath || !version) {
  console.error('usage: node scripts/patch-electron-exe.mjs <Wormhole.exe> <version> [icon.ico]');
  process.exit(2);
}

const inputPath = path.resolve(exePath);
const inputIconPath = path.resolve(iconPath ?? path.join(repoRoot, 'Assets', 'Wormhole.ico'));

const versionMatch = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-+_.]\S*)?$/.exec(version);
if (!versionMatch) {
  throw new Error(
    `version must start with one to four numeric components and contain no whitespace: '${version}'`,
  );
}

const versionParts = versionMatch.slice(1, 5).map((part) => Number(part ?? 0));
if (versionParts.some((part) => !Number.isInteger(part) || part < 0 || part > 65535)) {
  throw new Error(`numeric version components must be between 0 and 65535: '${version}'`);
}

const [input, inputStats] = await Promise.all([fs.readFile(inputPath), fs.stat(inputPath)]);
const executable = ResEdit.NtExecutable.from(input);
const resources = ResEdit.NtExecutableResource.from(executable);
const iconFile = ResEdit.Data.IconFile.from(await fs.readFile(inputIconPath));
if (iconFile.icons.length === 0) {
  throw new Error(`icon file contains no images: '${inputIconPath}'`);
}

const iconData = iconFile.icons.map(({ data }) => data);
const iconGroups = ResEdit.Resource.IconGroupEntry.fromEntries(resources.entries);
if (iconGroups.length === 0) {
  ResEdit.Resource.IconGroupEntry.replaceIconsForResource(resources.entries, 1, 1033, iconData);
} else {
  for (const iconGroup of iconGroups) {
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
      resources.entries,
      iconGroup.id,
      iconGroup.lang,
      iconData,
    );
  }
}

const versionValues = {
  ProductName: 'Wormhole',
  FileDescription: 'Wormhole',
  CompanyName: 'Wormhole project',
  LegalCopyright: 'Wormhole project',
  OriginalFilename: 'Wormhole.exe',
  FileVersion: version,
  ProductVersion: version,
};
const versionInfos = ResEdit.Resource.VersionInfo.fromEntries(resources.entries);
if (versionInfos.length === 0) {
  throw new Error(`executable contains no version information: '${inputPath}'`);
}

for (const versionInfo of versionInfos) {
  const [major, minor, micro, revision] = versionParts;
  versionInfo.fixedInfo.fileVersionMS = (major << 16) | minor;
  versionInfo.fixedInfo.fileVersionLS = (micro << 16) | revision;
  versionInfo.fixedInfo.productVersionMS = (major << 16) | minor;
  versionInfo.fixedInfo.productVersionLS = (micro << 16) | revision;

  const languages = versionInfo.getAllLanguagesForStringValues();
  if (languages.length === 0) {
    const resourceLanguage = Number(versionInfo.lang);
    languages.push({
      lang: Number.isFinite(resourceLanguage) ? resourceLanguage : 1033,
      codepage: 1200,
    });
  }
  for (const language of languages) {
    versionInfo.setStringValues(language, versionValues);
  }
  versionInfo.outputToResourceEntries(resources.entries);
}

resources.outputResource(executable);
const output = Buffer.from(executable.generate());
const temporaryPath = path.join(
  path.dirname(inputPath),
  `.${path.basename(inputPath)}.resedit-${process.pid}-${randomUUID()}.tmp`,
);
try {
  await fs.writeFile(temporaryPath, output, { flag: 'wx', mode: inputStats.mode });
  await fs.rename(temporaryPath, inputPath);
} finally {
  await fs.rm(temporaryPath, { force: true });
}

console.log(`OK    patched ${inputPath} (icon + version ${version})`);
