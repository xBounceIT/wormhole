using Wormhole.Models;

namespace Wormhole.ViewModels;

/// <summary>Shared search and commit semantics for saved-credential pickers.</summary>
internal static class CredentialPickerSearch
{
    public static IReadOnlyList<CredentialProfile> Filter(
        IReadOnlyList<CredentialProfile> credentials,
        string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return credentials.ToList();
        }

        var trimmedQuery = query.Trim();
        var matches = new List<CredentialProfile>(credentials.Count);
        foreach (var credential in credentials)
        {
            if (Matches(credential, trimmedQuery))
            {
                matches.Add(credential);
            }
        }

        return matches;
    }

    public static CredentialProfile? ResolveExact(
        IReadOnlyList<CredentialProfile> credentials,
        string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        var trimmedText = text.Trim();
        foreach (var credential in credentials)
        {
            if (string.Equals(credential.Name, trimmedText, StringComparison.OrdinalIgnoreCase))
            {
                return credential;
            }
        }

        return null;
    }

    public static CredentialProfile? ResolveForCommit(
        IReadOnlyList<CredentialProfile> credentials,
        string? text)
    {
        if (ResolveExact(credentials, text) is { } exact) return exact;
        if (string.IsNullOrWhiteSpace(text)) return null;

        var trimmedText = text.Trim();
        CredentialProfile? single = null;
        foreach (var credential in credentials)
        {
            if (CredentialBindingSentinelIds.IsSentinel(credential.Id) ||
                !Matches(credential, trimmedText))
            {
                continue;
            }

            if (single is not null) return null;
            single = credential;
        }

        return single;
    }

    private static bool Matches(CredentialProfile credential, string query) =>
        Contains(credential.Name, query) ||
        Contains(credential.Username, query) ||
        Contains(credential.Domain, query);

    private static bool Contains(string? value, string query) =>
        value is not null && value.Contains(query, StringComparison.OrdinalIgnoreCase);
}
