using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Visible when the transfer is in a terminal state (Completed / Failed / Cancelled),
/// Collapsed while Queued or Running. Used to gate the status glyph in the transfer
/// queue strip — paired with <see cref="TransferStateGlyphConverter"/>.
/// </summary>
public sealed class TransferStateTerminalVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is TransferState s && s is TransferState.Completed or TransferState.Failed or TransferState.Cancelled
            ? Visibility.Visible
            : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
