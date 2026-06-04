using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Helpers.Converters;

/// <summary>
/// Maps a <see cref="ConnectionStepState"/> to a brush for the connecting stepper, selected by a
/// string <c>ConverterParameter</c> role: <c>Fill</c> (circle background), <c>Stroke</c> (circle
/// border) or <c>Connector</c> (the line trailing the step to the next one).
///
/// <para>Uses fixed colors rather than a ThemeResource lookup for the same reason as
/// <see cref="TransferStateBrushConverter"/>: <c>Application.Current.Resources</c> doesn't reliably
/// resolve brushes that live in ThemeDictionaries, so a runtime lookup risks silently returning the
/// fallback. The hues are picked to read on both the dark SSH terminal backdrop and the themed RDP
/// overlay backdrop.</para>
/// </summary>
public sealed class ConnectionStepStateToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush ActiveBrush =
        new(ColorHelper.FromArgb(0xFF, 0x4C, 0xC2, 0xFF)); // accent blue
    private static readonly SolidColorBrush CompletedBrush =
        new(ColorHelper.FromArgb(0xFF, 0x6C, 0xCB, 0x5F)); // green
    private static readonly SolidColorBrush FailedBrush =
        new(ColorHelper.FromArgb(0xFF, 0xFF, 0x6B, 0x6B)); // red
    private static readonly SolidColorBrush PendingStrokeBrush =
        new(ColorHelper.FromArgb(0x80, 0x9A, 0x9A, 0x9A)); // faint gray
    private static readonly SolidColorBrush TransparentBrush =
        new(Colors.Transparent);

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var state = value is ConnectionStepState s ? s : ConnectionStepState.Pending;
        var role = parameter as string ?? "Fill";

        return role switch
        {
            "Fill" => state switch
            {
                ConnectionStepState.Completed => CompletedBrush,
                ConnectionStepState.Failed => FailedBrush,
                _ => TransparentBrush,
            },
            "Stroke" => state switch
            {
                ConnectionStepState.Active => ActiveBrush,
                ConnectionStepState.Completed => CompletedBrush,
                ConnectionStepState.Failed => FailedBrush,
                _ => PendingStrokeBrush,
            },
            // The connector belongs to the step on its left; it reads as "done" only once that
            // step has completed, giving the bar its left-to-right fill.
            "Connector" => state == ConnectionStepState.Completed ? CompletedBrush : PendingStrokeBrush,
            _ => TransparentBrush,
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
