using Microsoft.UI.Xaml.Data;
namespace Wormhole.Helpers.Converters;

/// <summary>Maps a 0..1 fraction to a 0..100 ProgressBar value.</summary>
public sealed class ProgressFractionConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is double d) return Math.Clamp(d * 100.0, 0.0, 100.0);
        return 0.0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
