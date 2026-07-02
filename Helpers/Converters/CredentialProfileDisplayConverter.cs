using Microsoft.UI.Xaml.Data;
using Wormhole.Models;

namespace Wormhole.Helpers.Converters;

public sealed class CredentialProfileDisplayConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not CredentialProfile credential) return string.Empty;
        var name = credential.Name ?? string.Empty;
        if (CredentialBindingSentinelIds.IsSentinel(credential.Id) ||
            name.StartsWith("(missing credential ", StringComparison.OrdinalIgnoreCase))
        {
            return name;
        }
        var protocol = credential.Protocol.ToString().ToUpperInvariant();
        return credential.IsVirtualBitwarden
            ? $"{name} (BITWARDEN {protocol})"
            : $"{name} ({protocol})";
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
