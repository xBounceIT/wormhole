import type { Plugin } from 'vite';

// Electron 45.2.3 rejects the leading space in xterm's non-italic canvas fonts,
// silently retaining 10px sans-serif. Normalize only the two WebGL font templates.
// https://github.com/xtermjs/xterm.js/issues/6297
export function xtermWebglFontFix(): Plugin {
  return {
    name: 'xterm-webgl-font-fix',
    enforce: 'pre',
    transform(code, id) {
      if (!/\/@xterm\/addon-webgl\/lib\/addon-webgl\.m?js$/.test(id.replaceAll('\\', '/')))
        return null;
      const fonts =
        /`\$\{[^}]+\} \$\{[^}]+\} \$\{[^}]+\.fontSize[^}]*\}px \$\{[^}]+\.fontFamily\}`/g;
      let replacements = 0;
      const patched = code.replace(fonts, (font) => {
        replacements++;
        return `${font}.trimStart()`;
      });
      // Dependency updates must not silently drop this compatibility fix.
      if (replacements !== 2)
        throw new Error('Unexpected xterm WebGL font templates; review the font fix.');
      return { code: patched, map: null };
    },
  };
}
