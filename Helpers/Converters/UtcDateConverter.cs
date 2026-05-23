using Microsoft.UI.Xaml.Data;
namespace Wormhole.Helpers.Converters;

public sealed class UtcDateConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is DateTime dt)
        {
            // Show local time so users in the file browser see what their filesystem
            // would show; preserves DateTimeKind.Utc semantics on the model side.
            var local = dt.Kind == DateTimeKind.Utc ? dt.ToLocalTime() : dt;
            if (local == default) return string.Empty;
            return local.ToString("yyyy-MM-dd HH:mm");
        }
        return string.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
