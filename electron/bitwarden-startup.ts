type BitwardenStartupCliState = {
  enabled: boolean;
  installed: object | null;
  serverRegion: 'UnitedStates' | 'Europe' | 'Current';
};

type BitwardenStartupCliStatus = {
  status: 'Unauthenticated' | 'Locked' | 'Unlocked' | 'Unknown';
  serverUrl: string | null;
  hasSessionKey?: boolean;
};

export async function readBitwardenStartupState(backend: {
  readState: () => Promise<BitwardenStartupCliState>;
  ensureInstalled: () => Promise<BitwardenStartupCliState>;
  readStatus: () => Promise<BitwardenStartupCliStatus>;
  requireAuthorization: () => void;
}): Promise<{
  serverRegion: BitwardenStartupCliState['serverRegion'];
  status: BitwardenStartupCliStatus;
} | null> {
  let state = await backend.readState();
  backend.requireAuthorization();
  if (!state.enabled) return null;
  if (!state.installed) {
    state = await backend.ensureInstalled();
    backend.requireAuthorization();
    if (!state.enabled || !state.installed) return null;
  }
  const status = await backend.readStatus();
  backend.requireAuthorization();
  return { serverRegion: state.serverRegion, status };
}
