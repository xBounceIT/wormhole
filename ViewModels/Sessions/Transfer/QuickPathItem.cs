namespace Wormhole.ViewModels.Sessions.Transfer;

/// <summary>
/// One entry in the local pane's WinSCP-style quick-path dropdown.
/// Separators have <see cref="IsSeparator"/> set and empty name/path.
/// </summary>
public sealed class QuickPathItem
{
    public static QuickPathItem Separator { get; } = new(string.Empty, string.Empty, isSeparator: true);

    public string DisplayName { get; }
    public string Path { get; }
    public bool IsSeparator { get; }

    public QuickPathItem(string displayName, string path)
        : this(displayName, path, isSeparator: false)
    {
    }

    private QuickPathItem(string displayName, string path, bool isSeparator)
    {
        DisplayName = displayName;
        Path = path;
        IsSeparator = isSeparator;
    }
}
