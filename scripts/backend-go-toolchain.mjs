import { readFileSync } from 'node:fs';

// setup-go reads this same go.mod in CI and release builds. GOTOOLCHAIN needs
// an exact version to select the same compiler on a developer's machine.
export function backendGoToolchain(
  goMod = readFileSync(new URL('../tools/wormhole-backend/go.mod', import.meta.url), 'utf8'),
) {
  const directives = goMod.replace(/\/\/[^\r\n]*/g, '');
  const toolchain = /^[ \t]*toolchain\b([^\r\n]*)/m.exec(directives);
  const version = /^[ \t]*go\b([^\r\n]*)/m.exec(directives);
  const name = toolchain ? toolchain[1].trim() : `go${version?.[1].trim() ?? ''}`;
  if (!/^go1\.\d+\.\d+$/.test(name)) {
    throw new Error(
      'The backend go.mod must select an exact Go toolchain including its patch version.',
    );
  }
  return name;
}
