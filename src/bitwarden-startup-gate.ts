type BitwardenStartupApi = Pick<NonNullable<Window['wormhole']>, 'readBitwardenStartupState'>;

export async function prepareWorkspaceStartup<TWorkspace>(
  api: BitwardenStartupApi,
  workspace: TWorkspace,
): Promise<{
  workspace: TWorkspace;
  bitwarden: WormholeBitwardenStartupState | null;
}> {
  // Start the optional vault check as soon as Wormhole grants workspace access. Waiting for it
  // here keeps the workspace from becoming interactive before a required login/unlock dialog.
  try {
    return { workspace, bitwarden: await api.readBitwardenStartupState() };
  } catch (error) {
    // Optional CLI failures must not block Wormhole, but an authorization failure invalidates the
    // workspace snapshot too and must remain fail-closed.
    if (
      error instanceof Error &&
      error.message.includes('Authentication is required before accessing the Wormhole workspace.')
    ) {
      throw error;
    }
    return { workspace, bitwarden: null };
  }
}
