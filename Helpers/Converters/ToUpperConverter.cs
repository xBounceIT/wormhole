using System;
using Microsoft.UI.Xaml.Data;

namespace Wormhole.Helpers.Converters;

public sealed class ToUpperConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
        => value?.ToString()?.ToUpperInvariant() ?? string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
