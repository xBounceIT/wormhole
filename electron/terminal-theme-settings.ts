export const sshTerminalThemeIds = ['wormhole-dark', 'dracula', 'tango', 'light'] as const;
export type SshTerminalTheme = (typeof sshTerminalThemeIds)[number];
export const defaultSshTerminalTheme: SshTerminalTheme = 'tango';

export function isSshTerminalTheme(value: unknown): value is SshTerminalTheme {
  return typeof value === 'string' && sshTerminalThemeIds.some((id) => id === value);
}
