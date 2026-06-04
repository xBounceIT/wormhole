using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Numbered, phased connecting stepper bound to a <see cref="ViewModels.Sessions.ConnectionProgress"/>
/// (set as the control's DataContext by the host overlay). Pure XAML/binding — no code-behind
/// behavior beyond initialization.
/// </summary>
public sealed partial class ConnectionProgressView : UserControl
{
    public ConnectionProgressView()
    {
        InitializeComponent();
    }
}
