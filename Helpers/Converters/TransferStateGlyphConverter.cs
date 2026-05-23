using Microsoft.UI.Xaml.Data;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Maps a <see cref="TransferState"/> to a Segoe Fluent glyph used in the transfer
/// queue strip to visually confirm terminal status. Without this glyph a fully-filled
/// ProgressBar looks identical to one at 99% — there's no clear "done" affordance.
/// In-progress states return an empty glyph; the companion
/// <see cref="TransferStateTerminalVisibilityConverter"/> collapses the icon's host so
/// nothing renders for those.
/// </summary>
public sealed class TransferStateGlyphConverter : IValueConverter
{
    // Segoe Fluent Icons: Accept (E73E), Cancel (E711), Blocked2 (F140).
    private const string CheckGlyph = "";
    private const string ErrorGlyph = "";
    private const string CancelledGlyph = "";

    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is TransferState s ? s switch
        {
            TransferState.Completed => CheckGlyph,
            TransferState.Failed => ErrorGlyph,
            TransferState.Cancelled => CancelledGlyph,
            _ => string.Empty,
        } : string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
