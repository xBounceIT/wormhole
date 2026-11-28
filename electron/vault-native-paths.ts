import path from 'node:path';
import { lstatSync } from 'node:fs';

// Pin native selections before a migration changes Electron's Chromium paths.
export function selectVaultNativePaths(
  userData: string,
  environment: { WORMHOLE_DATABASE?: string; LOCALAPPDATA?: string },
) {
  const userDataPath = path.resolve(userData);
  const configured = environment.WORMHOLE_DATABASE?.trim();
  const databasePath = configured
    ? path.resolve(configured)
    : path.resolve(environment.LOCALAPPDATA || userDataPath, 'Wormhole', 'wormhole.db');
  const restored = `${databasePath}.restored`;
  const directory = lstatSync(restored, { throwIfNoEntry: false });
  if (!directory) return Object.freeze({ userDataPath, databasePath });
  const unavailable = () => Error('Restored vault selection is unavailable.');
  if (
    !directory.isDirectory() ||
    lstatSync(databasePath, { throwIfNoEntry: false }) ||
    lstatSync(`${databasePath}.slots`, { throwIfNoEntry: false })
  )
    throw unavailable();
  const recoveredDatabase = path.join(restored, 'wormhole.db');
  const files = ['', '.slots', '.root-rotation'].map((suffix) =>
    lstatSync(`${recoveredDatabase}${suffix}`, { throwIfNoEntry: false }),
  );
  const [database, slots, rotation] = files;
  // Root rotation may temporarily retire the old database. Native startup
  // authenticates the recovery journal before it can resume that transition.
  if (files.some((entry) => entry && !entry.isFile()) || (!rotation && (!database || !slots)))
    throw unavailable();
  return Object.freeze({ userDataPath, databasePath: recoveredDatabase });
}
