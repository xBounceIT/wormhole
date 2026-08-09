export type RdpSurfaceRect = {
  x: number;
  y: number;
  width: number;
  height: number;
};

export const rdpMaxSurfaceCoordinate = 1_000_000;
export const rdpMaxSurfaceDimension = 16_384;

export function isRdpSurfaceRectWithinNativeBounds(rect: RdpSurfaceRect): boolean {
  return (
    Number.isFinite(rect.x) &&
    Number.isFinite(rect.y) &&
    Number.isFinite(rect.width) &&
    Number.isFinite(rect.height) &&
    Math.abs(rect.x) <= rdpMaxSurfaceCoordinate &&
    Math.abs(rect.y) <= rdpMaxSurfaceCoordinate &&
    rect.width >= 1 &&
    rect.height >= 1 &&
    rect.width <= rdpMaxSurfaceDimension &&
    rect.height <= rdpMaxSurfaceDimension
  );
}

export type RdpProfile = {
  nodeId?: string;
  /** Main-process credential resolution for an unsaved Quick Connect target. */
  credentialId?: string;
  /** Transient credential override for a saved connection; never persisted by this contract. */
  credentialIdOverride?: string;
  gatewayCredentialId?: string;
  tunnelConfigId?: string;
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
  /** Renderer supplied transient credentials; skip saved/Bitwarden resolution for this attempt. */
  manualCredentials?: boolean;
};

export type RdpExternalClientRequirementRequest = {
  username: string;
  domain: string;
  credentialId?: string;
  inheritedFromNodeId?: string;
};

const rdpWorkspaceIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseRdpExternalClientRequirementRequest(
  value: unknown,
): RdpExternalClientRequirementRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('RDP external-client requirement is invalid.');
  }
  const candidate = value as Record<string, unknown>;
  const username = candidate.username;
  const domain = candidate.domain;
  const credentialId = candidate.credentialId;
  const inheritedFromNodeId = candidate.inheritedFromNodeId;
  if (
    typeof username !== 'string' ||
    username.length > 512 ||
    /[\r\n\0]/.test(username) ||
    typeof domain !== 'string' ||
    domain.length > 512 ||
    /[\r\n\0]/.test(domain) ||
    (credentialId !== undefined &&
      (typeof credentialId !== 'string' || !rdpWorkspaceIdPattern.test(credentialId.trim()))) ||
    (inheritedFromNodeId !== undefined &&
      (typeof inheritedFromNodeId !== 'string' ||
        !rdpWorkspaceIdPattern.test(inheritedFromNodeId.trim()))) ||
    (credentialId !== undefined && inheritedFromNodeId !== undefined)
  ) {
    throw new Error('RDP external-client requirement is invalid.');
  }
  return {
    username,
    domain,
    credentialId: typeof credentialId === 'string' ? credentialId.trim() : undefined,
    inheritedFromNodeId:
      typeof inheritedFromNodeId === 'string' ? inheritedFromNodeId.trim() : undefined,
  };
}

export function rdpGatewayCredentialIdForResolution(profile: RdpProfile): string | undefined {
  if (!profile.gatewayUsageMethod || profile.gatewayUseSameCreds) return undefined;
  return profile.gatewayCredentialId;
}

export function rdpGatewayUsername(
  username: string | undefined,
  domain: string | undefined,
): string | undefined {
  if (!username || !domain || username.includes('\\')) return username;
  return `${domain}\\${username}`;
}

export function rdpTunnelEnabledForNative(
  profile: Pick<RdpProfile, 'nodeId' | 'tunnelConfigId' | 'tunnelEnabled'>,
  socksEndpoint: string,
): boolean | undefined {
  if (socksEndpoint) return true;
  if (profile.nodeId || profile.tunnelConfigId) return false;
  return profile.tunnelEnabled;
}

export function canProceedWithRdpTunnelRoute(
  profile: Pick<RdpProfile, 'nodeId' | 'tunnelConfigId'>,
  route: { active: boolean; socksEndpoint: string },
): boolean {
  if (route.active) return route.socksEndpoint.length > 0;
  if (route.socksEndpoint) return false;
  // Only Go can authorize a saved connection to proceed directly (disabled tunnel or an explicit
  // route prompt decision). A Quick Connect tunnel selection must always produce a live endpoint.
  return Boolean(profile.nodeId) || !profile.tunnelConfigId;
}

export type RdpCommandRequest = {
  sessionId: string;
  bounds?: RdpSurfaceRect;
};

export type RdpSystemClientCapabilityRequest = {
  nodeId: string;
};

export type RdpSystemClientOpenRequest = RdpSystemClientCapabilityRequest & {
  sessionId: string;
};

export type RdpSystemClientOpenResult =
  | { ok: true; event: RdpBackendEvent }
  | { ok: false; lifecycleCommitted: boolean; error: string };

export type RdpSystemClientCapability = {
  supported: boolean;
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
  /** Main/controller lifecycle token used to discard events from a superseded native process. */
  lifecycleId?: string;
  backend?: 'activex' | 'freerdp';
  external?: boolean;
  lifecycleGeneration?: number;
  code?: number;
  attempt?: number;
  max?: number;
  message?: string;
  /** Go-classified ActiveX logon failure for which transient credentials can help. */
  credentialFailure?: boolean;
};

export function isRdpLifecycleEvent(event: Pick<RdpBackendEvent, 'requestId'>): boolean {
  return !event.requestId;
}
