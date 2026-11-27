import type { App } from 'electron';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseVaultStartup } from './vault-contract.ts';

type BootApp = Pick<App, 'isReady' | 'getPath' | 'setPath' | 'requestSingleInstanceLock'>;
export type VaultMigrationBoot = {
  primary: boolean;
  unavailable: boolean;
  unsafeInstallation?: true;
  migrationSessionData?: string;
  legacyMigrationRequired?: true;
  legacyLocalCrashCapture?: true;
};
type Options = {
  app: BootApp;
  executable: () => string;
  databasePath: string;
  prepareProtection?: boolean;
  probe?: (
    executable: string,
    args: string[],
  ) => { status: number | null; stdout: string; stderr?: string; error?: unknown };
  createSessionData?: (original: string) => string;
};

// Called synchronously before Chromium readiness and any browser session. The
// original native selections must already be pinned by main. Neither selection
// nor restart authority is ever accepted from a renderer.
export function prepareVaultMigrationBoot(options: Options): VaultMigrationBoot {
  const { app } = options;
  if (app.isReady()) throw Error('Vault startup must precede Chromium readiness.');
  if (!app.requestSingleInstanceLock()) return { primary: false, unavailable: false };
  let pending = false,
    legacy = false,
    legacyLocalCrashCapture = false,
    unsafeInstallation = false,
    unavailable = false;
  try {
    const result = (
      options.probe ??
      ((executable, args) =>
        spawnSync(executable, args, {
          encoding: 'utf8',
          windowsHide: true,
          timeout: 15_000,
          maxBuffer: 64 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
        }))
    )(options.executable(), ['--operation', 'vault-startup', '--database', options.databasePath]);
    const diagnostic = result.stderr?.trim();
    unsafeInstallation =
      !result.error &&
      result.status === 1 &&
      (diagnostic === 'vault_installation_location_untrusted' ||
        diagnostic === 'vault_installation_signature_untrusted');
    if (
      result.error ||
      result.status !== 0 ||
      typeof result.stdout !== 'string' ||
      Buffer.byteLength(result.stdout) > 64 * 1024
    )
      throw Error('Vault startup unavailable.');
    const startup = parseVaultStartup(JSON.parse(result.stdout));
    if (!startup) throw Error('Vault startup unavailable.');
    legacy = startup.legacy !== undefined;
    legacyLocalCrashCapture = startup.legacy?.unprotectedAllowed === true;
    pending =
      startup.migration?.pending === true ||
      startup.rotation?.pending === true ||
      startup.osMigration !== undefined ||
      startup.upgrade !== undefined ||
      (options.prepareProtection === true && startup.unprotected !== undefined);
  } catch {
    unavailable = true;
  }
  if (!pending && !unavailable)
    return {
      primary: true,
      unavailable: false,
      ...(legacy ? { legacyMigrationRequired: true as const } : {}),
      ...(legacyLocalCrashCapture ? { legacyLocalCrashCapture: true as const } : {}),
    };
  // A sibling on the same native volume avoids both source overlap and a
  // different-drive temporary directory. Never clean a live Chromium profile.
  const sessionData = (
    options.createSessionData ??
    ((original) => mkdtempSync(join(dirname(realpathSync(original)), '.wormhole-vault-migration-')))
  )(app.getPath('userData'));
  app.setPath('userData', sessionData);
  app.setPath('sessionData', sessionData);
  return {
    primary: true,
    unavailable,
    ...(unsafeInstallation ? { unsafeInstallation: true as const } : {}),
    ...(!unavailable ? { migrationSessionData: sessionData } : {}),
  };
}
