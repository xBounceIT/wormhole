import path from 'node:path';

export type DevRuntimeBuildStep = {
  name: string;
  command: string;
  args: string[];
  inputs: string[];
  outputs: string[];
  excludedInputs?: string[];
  bootstrap?: { command: string; args: string[]; outputs: string[] };
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
  inputs: string[] = [],
  outputs: string[] = [],
  excludedInputs: string[] = [],
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
    inputs: [`scripts/${scriptName}`, ...inputs],
    outputs,
    excludedInputs,
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
    inputs: [
      'scripts/Build-ElectronBackend.mjs',
      'tools/internal',
      'go.work',
      'go.work.sum',
      ...['backend', 'wgproxy', 'fortiproxy', 'ciscoproxy'].map((name) => `tools/wormhole-${name}`),
      ...(platform === 'win32'
        ? [`obj/ovpnproxy/${architecture}/wormhole-ovpnproxy.exe`]
        : ['tools/wormhole-ovpnproxy']),
    ],
    outputs: [
      `dist-electron/wormhole-backend-${architecture}${platform === 'win32' ? '.exe' : ''}`,
      ...['wgproxy', 'ovpnproxy', 'fortiproxy', 'ciscoproxy'].map(
        (name) => `dist-electron/wormhole-${name}${platform === 'win32' ? '.exe' : ''}`,
      ),
    ],
    excludedInputs: [
      'tools/wormhole-ovpnproxy/ovpn_shim/build',
      'tools/wormhole-ovpnproxy/shim_buildinfo.go',
    ],
  };

  if (platform !== 'win32') return [backendStep];

  // Stage the real OpenVPN3 sidecar before the generic backend builder runs. The backend build
  // then reuses that verified binary instead of briefly producing (and warning about) its
  // development-only fallback.
  return [
    {
      ...windowsBuildStep(
        'Windows OpenVPN sidecar',
        'Fetch-OvpnProxy.ps1',
        scriptDirectory,
        architecture,
        ['-RequireReal'],
        ['tools/wormhole-ovpnproxy', 'tools/internal', '.gitmodules', 'go.work', 'go.work.sum'],
        [`obj/ovpnproxy/${architecture}/wormhole-ovpnproxy.exe`],
        ['tools/wormhole-ovpnproxy/ovpn_shim/build', 'tools/wormhole-ovpnproxy/shim_buildinfo.go'],
      ),
      bootstrap: {
        command: 'git',
        args: [
          '-C',
          path.dirname(scriptDirectory),
          'submodule',
          'update',
          '--init',
          '--recursive',
          '--',
          'tools/wormhole-ovpnproxy/third_party/openvpn3',
          'tools/wormhole-ovpnproxy/third_party/mbedtls',
        ],
        outputs: [
          'tools/wormhole-ovpnproxy/third_party/openvpn3/client/ovpncli.hpp',
          'tools/wormhole-ovpnproxy/third_party/mbedtls/include/mbedtls/ssl.h',
        ],
      },
    },
    backendStep,
    windowsBuildStep(
      'Windows credential reader',
      'Build-CredentialReader.ps1',
      scriptDirectory,
      architecture,
      [],
      ['tools/wormhole-credential-reader', 'go.work', 'go.work.sum'],
      [`dist-electron/wormhole-credential-reader-${architecture}.exe`],
    ),
    windowsBuildStep(
      'Windows RDP host',
      'Build-RdpHost.ps1',
      scriptDirectory,
      architecture,
      [],
      [
        'tools/wormhole-rdp-host',
        'global.json',
        'NuGet.Config',
        'Directory.Build.props',
        'Directory.Build.targets',
        'Directory.Packages.props',
      ],
      [`dist-electron/wormhole-rdp-host-${architecture}.exe`],
      [
        'tools/wormhole-rdp-host/bin',
        'tools/wormhole-rdp-host/obj',
        'tools/wormhole-rdp-host/Tests/bin',
        'tools/wormhole-rdp-host/Tests/obj',
      ],
    ),
  ];
}

export function devRuntimeToolchainCommands(architecture: NodeJS.Architecture): string[] {
  return [
    'go',
    'dotnet',
    'cmake',
    'gcc',
    'g++',
    ...(architecture === 'arm64'
      ? [
          'aarch64-w64-mingw32-gcc',
          'aarch64-w64-mingw32-g++',
          'aarch64-w64-mingw32-clang',
          'aarch64-w64-mingw32-clang++',
        ]
      : []),
  ];
}

export function devRuntimeGoBuildEnvironment(
  platform: NodeJS.Platform,
  architecture: NodeJS.Architecture,
  moduleDirectory: string,
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const moduleName = path.basename(moduleDirectory);
  return {
    ...environment,
    GOOS: platform === 'win32' ? 'windows' : platform,
    GOARCH: architecture === 'arm64' ? 'arm64' : 'amd64',
    CGO_ENABLED:
      (platform === 'darwin' && moduleName === 'wormhole-backend') ||
      (platform === 'win32' && moduleName === 'wormhole-ovpnproxy')
        ? '1'
        : '0',
  };
}
