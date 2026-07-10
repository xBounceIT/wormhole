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
    private bool _optionsLoaded;

    public event EventHandler? ValidityChanged;

    public FolderEditorDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<FolderEditorViewModel>();
        this.InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    public FolderEditorViewModel ViewModel { get; }

    public bool IsValid => ViewModel.IsValid;
    public bool CanSubmit => _optionsLoaded && IsValid;

    public void Prepare(ConnectionNode initial)
    {
        _optionsLoaded = false;
        OptionsLoadingBar.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
        OptionsLoadError.IsOpen = false;
        ViewModel.LoadFrom(initial);
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task LoadOptionsAsync(CancellationToken cancellationToken = default)
    {
        await ViewModel.LoadOptionsAsync(cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();

        _optionsLoaded = true;
        OptionsLoadingBar.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
        OptionsLoadError.IsOpen = false;
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task LoadAsync(ConnectionNode initial)
    {
        Prepare(initial);
        await LoadOptionsAsync().ConfigureAwait(true);
    }

    public void ShowLoadError(string message)
    {
        _optionsLoaded = false;
        OptionsLoadingBar.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
        OptionsLoadError.Message = message;
        OptionsLoadError.IsOpen = true;
        ValidityChanged?.Invoke(this, EventArgs.Empty);
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
