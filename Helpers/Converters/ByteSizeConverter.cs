using Microsoft.UI.Xaml.Data;
namespace Wormhole.Helpers.Converters;

public sealed class ByteSizeConverter : IValueConverter
{
    private static readonly string[] Units = { "B", "KB", "MB", "GB", "TB" };

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        long bytes = value switch
        {
            long l => l,
            int i => i,
            _ => 0,
        };
        if (bytes <= 0) return string.Empty;
        double v = bytes;
        int unit = 0;
        while (v >= 1024 && unit < Units.Length - 1)
        {
            v /= 1024;
            unit++;
        }
        // Show 0 decimals for B/KB (the values are small enough to read raw), one
        // decimal for everything bigger so "1.2 MB" reads better than "1 MB".
        return unit <= 1 ? $"{v:0} {Units[unit]}" : $"{v:0.#} {Units[unit]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
