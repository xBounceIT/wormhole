using System;
using Microsoft.UI.Xaml.Data;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Two-way binds a string value to a bool, where the bool is true when the value equals
/// the ConverterParameter (ordinal, case-insensitive). On ConvertBack, returns the parameter
/// when the input is true, otherwise unchanged (used by RadioButton groups bound to a single
/// string field — only the "checked" radio's back-binding fires).
/// </summary>
public sealed class StringEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var s = value as string ?? string.Empty;
        var p = parameter as string ?? string.Empty;
        return string.Equals(s, p, StringComparison.OrdinalIgnoreCase);
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        if (value is bool b && b && parameter is string p) return p;
        return Microsoft.UI.Xaml.DependencyProperty.UnsetValue;
    }
}
