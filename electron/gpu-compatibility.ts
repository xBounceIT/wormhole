import { execFileSync } from 'node:child_process';

const legacyIntelMacSoftwareRenderingModels = new Set(['MacBookAir7,1', 'MacBookAir7,2']);
const lastSupportedLegacyIntelMacOSMajor = 12;

export type HardwareAccelerationStartupContext = {
  platform: NodeJS.Platform;
  architecture: string;
  hardwareModel?: string;
  systemVersion?: string;
};

/**
 * Chromium must choose its rendering path before Electron becomes ready. These Broadwell MacBook
 * Air models can expose an unusable EGL/ANGLE device on newer patched macOS installations, leaving
 * the renderer without a first frame. Keep the software fallback limited to the affected hardware.
 */
export function shouldDisableHardwareAcceleration({
  platform,
  architecture,
  hardwareModel,
  systemVersion,
}: HardwareAccelerationStartupContext): boolean {
  if (platform !== 'darwin' || architecture !== 'x64') return false;
  if (!legacyIntelMacSoftwareRenderingModels.has(hardwareModel?.trim() ?? '')) return false;

  const majorVersion = /^(\d+)(?:\.|$)/.exec(systemVersion?.trim() ?? '')?.[1];
  return majorVersion === undefined || Number(majorVersion) > lastSupportedLegacyIntelMacOSMajor;
}

export function readDarwinHardwareModel(
  platform: NodeJS.Platform = process.platform,
  readModel: () => string = () =>
    execFileSync('/usr/sbin/sysctl', ['-n', 'hw.model'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 1_000,
    }),
): string | undefined {
  if (platform !== 'darwin') return undefined;
  try {
    const model = readModel().trim();
    return model || undefined;
  } catch {
    return undefined;
  }
}
