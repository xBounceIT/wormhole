export type WorkspaceRdpSettings = {
  domain: string;
  screenSize: string;
  fullScreen: boolean;
  colorDepth: number;
  useAllMonitors: boolean;
  audioMode: number;
  audioCaptureMode: number;
  keyboardHookMode: number;
  redirectClipboard: boolean;
  redirectPrinters: boolean;
  redirectSmartCards: boolean;
  redirectPorts: boolean;
  redirectDevices: boolean;
  redirectDrives: string;
  connectionSpeed: number;
  desktopBackground: boolean;
  fontSmoothing: boolean;
  desktopComposition: boolean;
  windowDrag: boolean;
  menuAnimation: boolean;
  visualStyles: boolean;
  bitmapCaching: boolean;
  autoReconnect: boolean;
  serverAuthentication: number;
  gatewayUsageMethod: number;
  gatewayHostname: string;
  gatewayCredentialId: string;
  gatewayBypassLocal: boolean;
  gatewayUseSameCreds: boolean;
  useExternalClient: boolean;
};

const uuidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const customSizePattern = /^(\d{3,5})[xX](\d{3,5})$/;

export function parseWorkspaceRdpSettings(value: unknown): WorkspaceRdpSettings {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('RDP settings are invalid.');
  }
  const record = value as Record<string, unknown>;
  const text = (key: string, maximum: number) => {
    const candidate = record[key];
    if (typeof candidate !== 'string' || candidate.length > maximum || /[\r\n\0]/.test(candidate)) {
      throw new Error('RDP settings are invalid.');
    }
    return candidate.trim();
  };
  const integer = (key: string, allowed: readonly number[]) => {
    const candidate = record[key];
    if (
      typeof candidate !== 'number' ||
      !Number.isSafeInteger(candidate) ||
      !allowed.includes(candidate)
    ) {
      throw new Error('RDP settings are invalid.');
    }
    return candidate;
  };
  const boolean = (key: string) => {
    const candidate = record[key];
    if (typeof candidate !== 'boolean') throw new Error('RDP settings are invalid.');
    return candidate;
  };
  const screenSize = text('screenSize', 32);
  if (!['fitToWindow', 'Full connection content', 'Full screen'].includes(screenSize)) {
    const match = customSizePattern.exec(screenSize);
    const width = match ? Number(match[1]) : 0;
    const height = match ? Number(match[2]) : 0;
    if (!match || width < 640 || width > 16384 || height < 480 || height > 16384) {
      throw new Error('RDP screen size is invalid.');
    }
  }
  const redirectDrives = text('redirectDrives', 128);
  if (
    redirectDrives &&
    redirectDrives.toLowerCase() !== 'all' &&
    !/^[A-Za-z](?:\s*,\s*[A-Za-z])*$/.test(redirectDrives)
  ) {
    throw new Error('RDP drive redirection is invalid.');
  }
  const gatewayUsageMethod = integer('gatewayUsageMethod', [0, 1, 2, 3]);
  const gatewayHostname = text('gatewayHostname', 253);
  const gatewayCredentialId = text('gatewayCredentialId', 128);
  if (gatewayUsageMethod === 1 && !gatewayHostname) {
    throw new Error('RDP Gateway hostname is required.');
  }
  if (/\s/.test(gatewayHostname)) throw new Error('RDP Gateway hostname is invalid.');
  if (gatewayCredentialId && !uuidPattern.test(gatewayCredentialId)) {
    throw new Error('RDP Gateway credential is invalid.');
  }
  return {
    domain: text('domain', 512),
    screenSize,
    fullScreen: boolean('fullScreen'),
    colorDepth: integer('colorDepth', [15, 16, 24, 32]),
    useAllMonitors: boolean('useAllMonitors'),
    audioMode: integer('audioMode', [0, 1, 2]),
    audioCaptureMode: integer('audioCaptureMode', [0, 1]),
    keyboardHookMode: integer('keyboardHookMode', [0, 1, 2]),
    redirectClipboard: boolean('redirectClipboard'),
    redirectPrinters: boolean('redirectPrinters'),
    redirectSmartCards: boolean('redirectSmartCards'),
    redirectPorts: boolean('redirectPorts'),
    redirectDevices: boolean('redirectDevices'),
    redirectDrives,
    connectionSpeed: integer('connectionSpeed', [1, 2, 3, 4, 5, 6, 7]),
    desktopBackground: boolean('desktopBackground'),
    fontSmoothing: boolean('fontSmoothing'),
    desktopComposition: boolean('desktopComposition'),
    windowDrag: boolean('windowDrag'),
    menuAnimation: boolean('menuAnimation'),
    visualStyles: boolean('visualStyles'),
    bitmapCaching: boolean('bitmapCaching'),
    autoReconnect: boolean('autoReconnect'),
    serverAuthentication: integer('serverAuthentication', [0, 1, 2]),
    gatewayUsageMethod,
    gatewayHostname,
    gatewayCredentialId,
    gatewayBypassLocal: boolean('gatewayBypassLocal'),
    gatewayUseSameCreds: boolean('gatewayUseSameCreds'),
    useExternalClient: boolean('useExternalClient'),
  };
}
