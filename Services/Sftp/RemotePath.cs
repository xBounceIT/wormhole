namespace Wormhole.Services.Sftp;

/// <summary>
/// POSIX path helpers for SFTP. <see cref="System.IO.Path"/> uses '\' on Windows and will
/// silently corrupt remote paths if used. Always route remote paths through this helper.
/// </summary>
public static class RemotePath
{
    public const char Separator = '/';

    /// <summary>Joins a parent path and a single child segment, normalizing separators.
    /// Treats <paramref name="parent"/>="/" as "no extra separator needed" so a join of
    /// "/" and "foo" yields "/foo" rather than "//foo".</summary>
    public static string Join(string parent, string child)
    {
        if (string.IsNullOrEmpty(parent)) return child;
        if (string.IsNullOrEmpty(child)) return parent;
        if (parent.EndsWith('/')) return parent + child;
        return parent + "/" + child;
    }

    /// <summary>Returns the parent directory of <paramref name="path"/>, or "/" if the
    /// path is at the root. The returned value never has a trailing slash unless it is
    /// the root itself.</summary>
    public static string Parent(string path)
    {
        if (string.IsNullOrEmpty(path) || path == "/") return "/";
        var trimmed = path.TrimEnd('/');
        var idx = trimmed.LastIndexOf('/');
        if (idx <= 0) return "/";
        return trimmed.Substring(0, idx);
    }

    /// <summary>Returns the final segment (filename) of <paramref name="path"/>, or an
    /// empty string for the root.</summary>
    public static string Leaf(string path)
    {
        if (string.IsNullOrEmpty(path) || path == "/") return string.Empty;
        var trimmed = path.TrimEnd('/');
        var idx = trimmed.LastIndexOf('/');
        return idx < 0 ? trimmed : trimmed.Substring(idx + 1);
    }

    /// <summary>True if the path is well-formed absolute POSIX (starts with '/') and
    /// contains no NUL or backslash characters.</summary>
    public static bool IsAbsolute(string path) =>
        !string.IsNullOrEmpty(path) && path[0] == '/'
            && path.IndexOf('\0') < 0 && path.IndexOf('\\') < 0;
}
