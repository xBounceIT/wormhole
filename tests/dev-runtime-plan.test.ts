import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {
  createDevRuntimeBuildPlan,
  devRuntimeGoBuildEnvironment,
  devRuntimeToolchainCommands,
} from '../scripts/dev-runtime-plan.ts';

const planOptions = {
  architecture: 'x64' as const,
  scriptDirectory: path.join('repo', 'scripts'),
  nodeExecutable: 'node',
};

test('Go probes override inherited cross-compilation targets exactly as each native build', () => {
  const inherited = {
    GOOS: 'freebsd',
    GOARCH: 'riscv64',
    CGO_ENABLED: '0',
    CC: 'custom-cc',
    GOFLAGS: '-trimpath',
  };
  for (const platform of ['win32', 'darwin', 'linux'] as const) {
    for (const architecture of ['x64', 'arm64'] as const) {
      for (const module of [
        'backend',
        'ovpnproxy',
        'wgproxy',
        'fortiproxy',
        'ciscoproxy',
        'credential-reader',
      ]) {
        const environment = devRuntimeGoBuildEnvironment(
          platform,
          architecture,
          path.join('tools', `wormhole-${module}`),
          inherited,
        );
        assert.equal(environment.GOOS, platform === 'win32' ? 'windows' : platform);
        assert.equal(environment.GOARCH, architecture === 'arm64' ? 'arm64' : 'amd64');
        assert.equal(
          environment.CGO_ENABLED,
          (platform === 'darwin' && module === 'backend') ||
            (platform === 'win32' && module === 'ovpnproxy')
            ? '1'
            : '0',
        );
        assert.equal(environment.CC, 'custom-cc');
        assert.equal(environment.GOFLAGS, '-trimpath');
      }
    }
  }
  assert.equal(inherited.GOOS, 'freebsd');
  const probe = spawnSync('go', ['env', '-json', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'CC'], {
    encoding: 'utf8',
    windowsHide: true,
    env: devRuntimeGoBuildEnvironment('darwin', 'arm64', path.join('tools', 'wormhole-backend'), {
      ...process.env,
      ...inherited,
    }),
  });
  assert.equal(probe.status, 0, probe.stderr);
  assert.deepEqual(JSON.parse(probe.stdout), {
    GOOS: 'darwin',
    GOARCH: 'arm64',
    CGO_ENABLED: '1',
    CC: 'custom-cc',
  });
});

test('non-Windows development builds only the portable runtime', () => {
  for (const platform of ['linux', 'darwin'] as const) {
    const plan = createDevRuntimeBuildPlan({ ...planOptions, platform });

    assert.deepEqual(
      plan.map((step) => step.name),
      ['Go backend'],
    );
    assert.equal(path.basename(plan[0].args[0]), 'Build-ElectronBackend.mjs');
  }
});

test('Windows development builds all native runtime components', () => {
  const plan = createDevRuntimeBuildPlan({ ...planOptions, platform: 'win32' });

  assert.deepEqual(
    plan.map((step) => step.name),
    ['Windows OpenVPN sidecar', 'Go backend', 'Windows credential reader', 'Windows RDP host'],
  );
  assert.equal(path.basename(plan[0].args[4]), 'Fetch-OvpnProxy.ps1');
  assert.equal(path.basename(plan[1].args[0]), 'Build-ElectronBackend.mjs');
  assert.deepEqual(
    plan.slice(2).map((step) => path.basename(step.args[4])),
    ['Build-CredentialReader.ps1', 'Build-RdpHost.ps1'],
  );
  assert.ok(plan[0].args.includes('-RequireReal'));
  assert.ok(plan.slice(1).every((step) => !step.args.includes('-RequireReal')));
  assert.ok(plan.every((step) => step.args.at(-1) === 'x64'));
});

test('cache dependencies cover native sources and architecture-specific outputs', () => {
  for (const platform of ['win32', 'linux', 'darwin'] as const) {
    for (const architecture of ['x64', 'arm64'] as const) {
      const plan = createDevRuntimeBuildPlan({ ...planOptions, platform, architecture });
      const backend = plan.find((step) => step.name === 'Go backend')!;
      assert.ok(backend.inputs.includes('tools/wormhole-backend'));
      assert.ok(backend.inputs.includes('tools/internal'));
      for (const provider of ['wgproxy', 'fortiproxy', 'ciscoproxy']) {
        assert.ok(backend.inputs.includes(`tools/wormhole-${provider}`));
      }
      assert.ok(
        backend.outputs.includes(
          `dist-electron/wormhole-backend-${architecture}${platform === 'win32' ? '.exe' : ''}`,
        ),
      );
      if (platform === 'win32') {
        const ovpn = `obj/ovpnproxy/${architecture}/wormhole-ovpnproxy.exe`;
        assert.ok(backend.inputs.includes(ovpn));
        assert.deepEqual(plan[0].outputs, [ovpn]);
        assert.ok(plan[0].inputs.includes('tools/wormhole-ovpnproxy'));
        assert.ok(plan[0].inputs.includes('tools/internal'));
        assert.ok(plan[2].inputs.includes('tools/wormhole-credential-reader'));
        assert.ok(plan[2].inputs.includes('go.work'));
        assert.equal(plan[0].bootstrap?.command, 'git');
        assert.ok(plan[0].bootstrap?.args.includes('--recursive'));
        assert.ok(
          plan[0].bootstrap?.outputs.every((output) =>
            output.startsWith('tools/wormhole-ovpnproxy/third_party/'),
          ),
        );
        assert.ok(plan[0].excludedInputs?.includes('tools/wormhole-ovpnproxy/ovpn_shim/build'));
        assert.ok(plan[3].excludedInputs?.includes('tools/wormhole-rdp-host/obj'));
        assert.ok(plan[3].inputs.includes('tools/wormhole-rdp-host'));
      } else {
        assert.ok(backend.inputs.includes('tools/wormhole-ovpnproxy'));
      }
      assert.ok(plan.every((step) => step.inputs.length > 0 && step.outputs.length > 0));
    }
  }
});

test('ARM64 cache identity includes both supported llvm-mingw compiler aliases', () => {
  assert.deepEqual(devRuntimeToolchainCommands('x64'), ['go', 'dotnet', 'cmake', 'gcc', 'g++']);
  const arm = devRuntimeToolchainCommands('arm64');
  for (const compiler of [
    'aarch64-w64-mingw32-gcc',
    'aarch64-w64-mingw32-g++',
    'aarch64-w64-mingw32-clang',
    'aarch64-w64-mingw32-clang++',
  ])
    assert.ok(arm.includes(compiler));
});

test('development runtime uses the current ARM64 architecture', () => {
  const plan = createDevRuntimeBuildPlan({
    ...planOptions,
    platform: 'win32',
    architecture: 'arm64',
  });

  assert.ok(plan.every((step) => step.args.at(-1) === 'arm64'));
});

test('unsupported development architectures fail instead of building the wrong binaries', () => {
  assert.throws(
    () =>
      createDevRuntimeBuildPlan({
        ...planOptions,
        platform: 'linux',
        architecture: 'ia32',
      }),
    /Unsupported development architecture 'ia32'/,
  );
});
