using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
namespace Wormhole.Helpers.Converters;

/// <summary>Integer count → Visibility. Returns Visible iff count > 0. Used to hide
/// the transfer queue strip when there are no transfers in flight.</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        int count = value switch { int i => i, long l => (int)l, _ => 0 };
        return count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
