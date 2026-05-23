using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Maps a <see cref="TransferState"/> to a theme brush for tinting the status glyph
/// in the transfer queue strip. Pulls from Application resources rather than embedding
/// hex colors so the result respects the active theme (light/dark, high-contrast).
/// </summary>
public sealed class TransferStateBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var key = value is TransferState s ? s switch
        {
            TransferState.Completed => "SystemFillColorSuccessBrush",
            TransferState.Failed => "SystemFillColorCriticalBrush",
            TransferState.Cancelled => "SystemFillColorCautionBrush",
            _ => "TextFillColorPrimaryBrush",
        } : "TextFillColorPrimaryBrush";

        if (Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b)
            return b;
        return Application.Current.Resources["TextFillColorPrimaryBrush"] as Brush
            ?? new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
