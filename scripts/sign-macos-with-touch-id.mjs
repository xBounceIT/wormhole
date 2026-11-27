import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { signAsync } from '@electron/osx-sign';
import plist from 'plist';

export const touchIDBundleIdentifier = 'com.xbounceit.wormhole.vault-touch-id';

export function touchIDVerificationRequirement(team) {
  return `=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "${team}" and identifier "${touchIDBundleIdentifier}"`;
}

export function touchIDEntitlements(profile, team, now = Date.now()) {
  const applicationID = `${team}.${touchIDBundleIdentifier}`;
  if (
    !/^[A-Z0-9]{10}$/.test(team) ||
    !Array.isArray(profile?.TeamIdentifier) ||
    !profile.TeamIdentifier.includes(team) ||
    !(profile.ExpirationDate instanceof Date) ||
    !(profile.ExpirationDate.getTime() > now) ||
    profile.Entitlements?.['com.apple.application-identifier'] !== applicationID ||
    profile.Entitlements?.['com.apple.security.get-task-allow'] === true
  ) {
    throw Error('The Touch ID provisioning profile must authorize the release helper and Team ID.');
  }
  return {
    'com.apple.application-identifier': applicationID,
    'com.apple.developer.team-identifier': team,
  };
}

export default async function signMacWithTouchID(options) {
  const encoded = process.env.WORMHOLE_TOUCH_ID_PROFILE_BASE64;
  if (!encoded) return signAsync(options);

  const team = process.env.APPLE_TEAM_ID;
  if (
    options.platform !== 'darwin' ||
    options.type !== 'distribution' ||
    typeof options.identity !== 'string' ||
    options.identity === '-' ||
    !team ||
    encoded.length > 2_000_000 ||
    !/^[a-zA-Z0-9+/=\s]+$/.test(encoded)
  ) {
    throw Error(
      'Touch ID requires a Developer ID distribution identity and its provisioning profile.',
    );
  }
  const helper = path.join(options.app, 'Contents', 'Helpers', 'Wormhole Vault Touch ID.app');
  const binary = path.join(helper, 'Contents', 'MacOS', 'WormholeVaultTouchID');
  const profileLocation = path.join(helper, 'Contents', 'embedded.provisionprofile');
  writeFileSync(profileLocation, Buffer.from(encoded, 'base64'));
  const decoded = execFileSync('/usr/bin/security', ['cms', '-D', '-i', profileLocation], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const entitlements = touchIDEntitlements(plist.parse(decoded), team);
  const temporary = mkdtempSync(path.join(tmpdir(), 'wormhole-touch-id-sign-'));
  try {
    const entitlementsPath = path.join(temporary, 'entitlements.plist');
    writeFileSync(entitlementsPath, plist.build(entitlements), { mode: 0o600 });
    await signAsync({
      ...options,
      optionsForFile: (file) =>
        file === helper || file === binary
          ? { hardenedRuntime: true, entitlements: entitlementsPath }
          : options.optionsForFile?.(file),
    });
    execFileSync(
      '/usr/bin/codesign',
      ['--verify', '--strict', '-R', touchIDVerificationRequirement(team), helper],
      { stdio: ['ignore', 'ignore', 'ignore'] },
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
