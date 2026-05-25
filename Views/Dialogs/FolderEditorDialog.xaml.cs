using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

/// <summary>
/// Folder editor backing <see cref="Services.IDialogService.EditFolderAsync"/>. Hosts a
/// <see cref="FolderEditorViewModel"/> resolved from DI and exposes a Name field plus the
/// shared <see cref="TunnelPickerViewModel"/> picker so a folder can hold a tunnel that its
/// descendants inherit via <see cref="Data.InheritanceResolver"/>.
/// </summary>
public sealed partial class FolderEditorDialog : UserControl
{
    public event EventHandler? ValidityChanged;

    public FolderEditorDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<FolderEditorViewModel>();
        this.InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    public FolderEditorViewModel ViewModel { get; }

    public bool IsValid => ViewModel.IsValid;

    /// <summary>Load tunnel configs, then copy field values from <paramref name="initial"/>
    /// into the VM. Tunnel configs must populate before LoadFrom so the SelectedTunnel
    /// binding can resolve a saved TunnelConfigId.</summary>
    public async Task LoadAsync(ConnectionNode initial)
    {
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
        if (e.PropertyName == nameof(FolderEditorViewModel.IsValid))
        {
            ValidityChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}
