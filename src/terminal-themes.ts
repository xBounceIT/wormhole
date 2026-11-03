import type { ITheme } from '@xterm/xterm';
import {
  defaultSshTerminalTheme,
  isSshTerminalTheme,
  type SshTerminalTheme,
} from '../electron/terminal-theme-settings.ts';

export { defaultSshTerminalTheme, isSshTerminalTheme, type SshTerminalTheme };

const ansiKeys = [
  'black',
  'red',
  'green',
  'yellow',
  'blue',
  'magenta',
  'cyan',
  'white',
  'brightBlack',
  'brightRed',
  'brightGreen',
  'brightYellow',
  'brightBlue',
  'brightMagenta',
  'brightCyan',
  'brightWhite',
] as const;

function palette(background: string, foreground: string, colors: string[]): ITheme {
  return {
    background,
    foreground,
    cursor: foreground,
    cursorAccent: background,
    selectionBackground: '#80808066',
    ...Object.fromEntries(ansiKeys.map((key, index) => [key, colors[index]])),
  };
}

export const sshTerminalThemes: ReadonlyArray<{
  id: SshTerminalTheme;
  label: string;
  colors: ITheme;
}> = [
  {
    id: 'wormhole-dark',
    label: 'Wormhole Dark',
    // Blue directory names stay distinct against ANSI green backgrounds (ls ow/tw).
    colors: palette('#10141c', '#e6edf3', [
      '#171c26',
      '#f07882',
      '#285430',
      '#e9c46a',
      '#a6c8ff',
      '#cf9fff',
      '#70d6df',
      '#c4cbd4',
      '#8995a8',
      '#ff9ca5',
      '#8fdb99',
      '#ffe09a',
      '#c2daff',
      '#e0baff',
      '#a1eef4',
      '#ffffff',
    ]),
  },
  {
    id: 'dracula',
    label: 'Dracula',
    colors: palette('#282a36', '#f8f8f2', [
      '#21222c',
      '#ff5555',
      '#50fa7b',
      '#f1fa8c',
      '#bd93f9',
      '#ff79c6',
      '#8be9fd',
      '#f8f8f2',
      '#6272a4',
      '#ff6e6e',
      '#69ff94',
      '#ffffa5',
      '#d6acff',
      '#ff92df',
      '#a4ffff',
      '#ffffff',
    ]),
  },
  {
    id: 'tango',
    label: 'Tango (default)',
    colors: palette('#1c1c1c', '#eeeeec', [
      '#2e3436',
      '#cc0000',
      '#4e9a06',
      '#c4a000',
      '#3465a4',
      '#75507b',
      '#06989a',
      '#d3d7cf',
      '#555753',
      '#ef2929',
      '#8ae234',
      '#fce94f',
      '#729fcf',
      '#ad7fa8',
      '#34e2e2',
      '#eeeeec',
    ]),
  },
  {
    id: 'light',
    label: 'Wormhole Light',
    colors: palette('#f8fafc', '#182230', [
      '#182230',
      '#a51d32',
      '#28643a',
      '#805600',
      '#174ea6',
      '#783a9c',
      '#006975',
      '#d1d7df',
      '#556274',
      '#bd263e',
      '#357849',
      '#926400',
      '#2865bf',
      '#9050af',
      '#087e8b',
      '#ffffff',
    ]),
  },
];

export function sshTerminalColors(value: unknown): ITheme {
  const id = isSshTerminalTheme(value) ? value : defaultSshTerminalTheme;
  return {
    ...sshTerminalThemes.find((theme) => theme.id === id)!.colors,
  };
}
