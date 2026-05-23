using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

/// <summary>
/// Multi-tab connection editor backing <see cref="Services.IDialogService.EditConnectionAsync"/>.
/// Hosts a <see cref="ConnectionEditorViewModel"/> resolved from DI; tabs for RDP-specific
/// settings (Display / Local Resources / Experience / Advanced) self-collapse when Protocol
/// is not RDP via x:Bind to <c>ViewModel.IsRdp</c>.
/// </summary>
public sealed partial class NewConnectionDialog : UserControl
{
    public event EventHandler? ValidityChanged;

    public NewConnectionDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<ConnectionEditorViewModel>();
        this.InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    public ConnectionEditorViewModel ViewModel { get; }

    public ProtocolType[] Protocols { get; } = Enum.GetValues<ProtocolType>();

    /// <summary>
    /// Bridge between NumberBox.Value (double, NaN-able) and ConnectionEditorViewModel.Port (int?).
    /// NumberBox uses NaN to mean "empty" — we map NaN ↔ null.
    /// </summary>
    public double PortBindable
    {
        get => ViewModel.Port is { } p ? p : double.NaN;
        set
        {
            int? port = double.IsNaN(value) ? null : (int)value;
            if (ViewModel.Port == port) return;
            ViewModel.Port = port;
        }
    }

    public bool IsValid => ViewModel.IsValid;

    /// <summary>Load credentials and tunnel configs, then copy field values from
    /// <paramref name="initial"/> into the VM. Tunnel configs must populate before LoadFrom
    /// so the SelectedTunnel binding can resolve a saved TunnelConfigId.</summary>
    public async Task LoadAsync(ConnectionNode initial)
    {
        await ViewModel.LoadCredentialsAsync();
        await ViewModel.LoadTunnelConfigsAsync();
        ViewModel.LoadFrom(initial);
    }

    /// <summary>Copy field values back into the supplied node. Caller is responsible for the
    /// Id and parent linkage.</summary>
    public void WriteTo(ConnectionNode node) => ViewModel.WriteTo(node);

    public void FocusNameField()
    {
        NameBox.Focus(Microsoft.UI.Xaml.FocusState.Programmatic);
        NameBox.SelectAll();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ConnectionEditorViewModel.IsValid))
        {
            ValidityChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}
