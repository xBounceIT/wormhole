import path from 'node:path';

export type DevRuntimeBuildStep = {
  name: string;
  command: string;
  args: string[];
};

type DevRuntimeBuildPlanOptions = {
  platform: NodeJS.Platform;
  architecture: NodeJS.Architecture;
  scriptDirectory: string;
  nodeExecutable: string;
};

function windowsBuildStep(
  name: string,
  scriptName: string,
  scriptDirectory: string,
  architecture: 'x64' | 'arm64',
  extraArgs: string[] = [],
): DevRuntimeBuildStep {
  return {
    name,
    command: 'powershell.exe',
    args: [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      path.join(scriptDirectory, scriptName),
      ...extraArgs,
      '-Arch',
      architecture,
    ],
  };
}

export function createDevRuntimeBuildPlan({
  platform,
  architecture,
  scriptDirectory,
  nodeExecutable,
}: DevRuntimeBuildPlanOptions): DevRuntimeBuildStep[] {
  if (architecture !== 'x64' && architecture !== 'arm64') {
    throw new Error(`Unsupported development architecture '${architecture}'.`);
  }

  const backendStep: DevRuntimeBuildStep = {
    name: 'Go backend',
    command: nodeExecutable,
    args: [path.join(scriptDirectory, 'Build-ElectronBackend.mjs'), '--arch', architecture],
  };

  if (platform !== 'win32') return [backendStep];

  // Stage the real OpenVPN3 sidecar before the generic backend builder runs. The backend build
  // then reuses that verified binary instead of briefly producing (and warning about) its
  // development-only fallback.
  return [
    windowsBuildStep(
      'Windows VPN sidecars',
      'Build-ElectronVpnSidecars.ps1',
      scriptDirectory,
      architecture,
      ['-RequireRealOvpn'],
    ),
    backendStep,
    windowsBuildStep(
      'Windows credential reader',
      'Build-CredentialReader.ps1',
      scriptDirectory,
      architecture,
    ),
    windowsBuildStep('Windows RDP host', 'Build-RdpHost.ps1', scriptDirectory, architecture),
  ];
}
