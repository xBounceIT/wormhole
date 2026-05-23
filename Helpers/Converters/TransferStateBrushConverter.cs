using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Maps a <see cref="TransferState"/> to a SolidColorBrush for tinting the status glyph
/// in the transfer queue strip. Uses fixed colors rather than ThemeResource lookup:
/// Application.Current.Resources doesn't reliably resolve brushes that live in
/// ThemeDictionaries (vs the top-level merged dictionary), so a runtime lookup risks
/// silently returning the fallback. These colors are chosen to read on both light and
/// dark Mica backdrops — they trade theme-perfect fidelity for deterministic rendering.
/// </summary>
public sealed class TransferStateBrushConverter : IValueConverter
{
    // Fluent-aligned status hues. Selected from the Windows 11 system palette so they
    // sit naturally next to other Fluent accents without being garish on either backdrop.
    private static readonly SolidColorBrush SuccessBrush =
        new(ColorHelper.FromArgb(0xFF, 0x6C, 0xCB, 0x5F)); // green
    private static readonly SolidColorBrush CriticalBrush =
        new(ColorHelper.FromArgb(0xFF, 0xFF, 0x99, 0x9A)); // red
    private static readonly SolidColorBrush CautionBrush =
        new(ColorHelper.FromArgb(0xFF, 0xFC, 0xE1, 0x00)); // amber
    private static readonly SolidColorBrush NeutralBrush =
        new(ColorHelper.FromArgb(0xFF, 0xC8, 0xC8, 0xC8)); // gray

    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is TransferState s ? s switch
        {
            TransferState.Completed => SuccessBrush,
            TransferState.Failed => CriticalBrush,
            TransferState.Cancelled => CautionBrush,
            _ => NeutralBrush,
        } : NeutralBrush;

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
