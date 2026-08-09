import { cp, mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const [manifestPath, sourceNodeModules, destinationNodeModules] = process.argv.slice(2);

if (!manifestPath || !sourceNodeModules || !destinationNodeModules) {
  throw new Error(
    'Usage: node stage-electron-runtime-dependencies.mjs <manifest> <source-node-modules> <destination-node-modules>',
  );
}

const dependencyNames = JSON.parse(await readFile(manifestPath, 'utf8'));
if (!Array.isArray(dependencyNames) || dependencyNames.length === 0) {
  throw new Error('The Electron runtime dependency manifest must be a non-empty array.');
}
for (const dependencyName of dependencyNames) {
  if (
    typeof dependencyName !== 'string' ||
    !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(dependencyName)
  ) {
    throw new Error(`Invalid Electron runtime dependency name: ${String(dependencyName)}`);
  }
}

await mkdir(destinationNodeModules, { recursive: true });
for (const dependencyName of dependencyNames) {
  const packageSegments = dependencyName.split('/');
  const source = path.join(sourceNodeModules, ...packageSegments);
  const destination = path.join(destinationNodeModules, ...packageSegments);
  const sourceMetadata = await stat(source).catch(() => undefined);
  if (!sourceMetadata?.isDirectory()) {
    throw new Error(`Missing Electron runtime dependency: ${dependencyName}`);
  }
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, force: true });
}
