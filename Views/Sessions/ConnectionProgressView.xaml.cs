using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Numbered, phased connecting stepper bound to a <see cref="ViewModels.Sessions.ConnectionProgress"/>
/// (set as the control's DataContext by the host overlay). Pure XAML/binding — the only code-behind
/// is the <see cref="Header"/> dependency property, so the same control can show "Connecting…" in the
/// connecting overlay and no heading when reused inside the failure overlay.
/// </summary>
public sealed partial class ConnectionProgressView : UserControl
{
    public ConnectionProgressView()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Heading shown above the steps. Defaults to "Connecting…"; set to an empty string when the
    /// stepper is hosted in a non-connecting context (e.g. the failure overlay) so it doesn't
    /// contradict the surrounding "Connection failed" message. The heading collapses when empty.
    /// </summary>
    public string Header
    {
        get => (string)GetValue(HeaderProperty);
        set => SetValue(HeaderProperty, value);
    }

    public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
        nameof(Header),
        typeof(string),
        typeof(ConnectionProgressView),
        new PropertyMetadata("Connecting…"));
}
