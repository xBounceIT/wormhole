export type RdpSurfaceRect = {
  x: number;
  y: number;
  width: number;
  height: number;
};

export type RdpProfile = {
  nodeId?: string;
  name?: string;
  host: string;
  port?: number;
  username?: string;
  domain?: string;
  password?: string;
  gatewayHostname?: string;
  gatewayUsername?: string;
  gatewayPassword?: string;
  screenSize?: string;
  fullScreen?: boolean;
  colorDepth?: number;
  useAllMonitors?: boolean;
  audioMode?: number;
  audioCaptureMode?: number;
  keyboardHookMode?: number;
  redirectClipboard?: boolean;
  redirectPrinters?: boolean;
  redirectSmartCards?: boolean;
  redirectPorts?: boolean;
  redirectDevices?: boolean;
  redirectDrives?: string;
  connectionSpeed?: number;
  desktopBackground?: boolean;
  fontSmoothing?: boolean;
  desktopComposition?: boolean;
  windowDrag?: boolean;
  menuAnimation?: boolean;
  visualStyles?: boolean;
  bitmapCaching?: boolean;
  autoReconnect?: boolean;
  serverAuthentication?: number;
  gatewayUsageMethod?: number;
  gatewayBypassLocal?: boolean;
  gatewayUseSameCreds?: boolean;
  useExternalClient?: boolean;
  /** Main-process-only loopback endpoint supplied by the shared Go tunnel broker. */
  socksEndpoint?: string;
  /** Main-process-only override: when false, the Go supervisor skips the VPN tunnel entirely. */
  tunnelEnabled?: boolean;
};

export type RdpStartRequest = {
  sessionId: string;
  profile: RdpProfile;
  bounds?: RdpSurfaceRect;
};

export type RdpCommandRequest = {
  sessionId: string;
  bounds?: RdpSurfaceRect;
};

export type RdpBackendEvent = {
  type:
    | 'started'
    | 'ready'
    | 'connected'
    | 'loginComplete'
    | 'disconnected'
    | 'fatalError'
    | 'logonError'
    | 'autoReconnecting'
    | 'autoReconnected'
    | 'exited'
    | 'ack'
    | 'error';
  requestId?: string;
  sessionId?: string;
  backend?: 'activex' | 'freerdp';
  code?: number;
  attempt?: number;
  max?: number;
  message?: string;
};
