namespace Wormhole.Models;

public enum CredentialBindingMode
{
    Inherit,
    None,
    Saved,
}

public static class CredentialBindingSentinelIds
{
    public static readonly Guid Inherit = new("00000000-0000-0000-0000-000000000001");
    public static readonly Guid ConnectionNone = Guid.Empty;
    public static readonly Guid FolderNone = new("ffffffff-ffff-ffff-ffff-fffffffffffe");

    public static bool IsSentinel(Guid id) =>
        id == Inherit || id == ConnectionNone || id == FolderNone;
}
