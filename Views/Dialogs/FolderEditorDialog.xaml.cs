using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
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
        ViewModel.TunnelPicker.PropertyChanged += OnTunnelPickerPropertyChanged;
    }

    public FolderEditorViewModel ViewModel { get; }

    public bool IsValid => ViewModel.IsValid;
    public bool CanSubmit => _optionsLoaded && IsValid;

    public void Prepare(ConnectionNode initial)
    {
        _optionsLoaded = false;
        OptionsLoadingBar.Visibility = Visibility.Visible;
        OptionsLoadError.IsOpen = false;
        ViewModel.LoadFrom(initial);
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task LoadOptionsAsync(CancellationToken cancellationToken = default)
    {
        await ViewModel.LoadOptionsAsync(cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();

        _optionsLoaded = true;
        OptionsLoadingBar.Visibility = Visibility.Collapsed;
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
        OptionsLoadingBar.Visibility = Visibility.Collapsed;
        OptionsLoadError.Message = message;
        OptionsLoadError.IsOpen = true;
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Copy field values back into the supplied node. Caller is responsible for the
    /// Id and parent linkage.</summary>
    public void WriteTo(ConnectionNode node) => ViewModel.WriteTo(node);

    public void FocusNameField()
    {
        NameBox.Focus(FocusState.Programmatic);
        NameBox.SelectAll();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FolderEditorViewModel.IsValid))
        {
            ValidityChanged?.Invoke(this, EventArgs.Empty);
        }
        else if (e.PropertyName == nameof(FolderEditorViewModel.SelectedCredential))
        {
            SyncPickerText(CredentialBox, ViewModel.SelectedCredential?.Name);
        }
    }

    private void OnTunnelPickerPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TunnelPickerViewModel.SelectedTunnel))
        {
            SyncPickerText(TunnelBox, ViewModel.TunnelPicker.SelectedTunnel?.Name);
        }
    }

    private void OnCredentialTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        sender.ItemsSource = ViewModel.FilterCredentials(sender.Text);
    }

    private void OnCredentialQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args) =>
        CommitSelection(
            sender,
            args.ChosenSuggestion,
            credential => ViewModel.SelectedCredential = credential,
            () => ViewModel.SelectedCredential,
            ViewModel.ResolveCredentialForCommit,
            credential => credential.Name);

    private void OnCredentialGotFocus(object sender, RoutedEventArgs e)
    {
        var box = (AutoSuggestBox)sender;
        ClearDefaultSelectionText(box, ViewModel.SelectedCredential, ViewModel.InheritCredential);
        ShowSuggestions(box, ViewModel.FilterCredentials(null));
    }

    private void OnCredentialLostFocus(object sender, RoutedEventArgs e) =>
        CommitSelection(
            (AutoSuggestBox)sender,
            null,
            credential => ViewModel.SelectedCredential = credential,
            () => ViewModel.SelectedCredential,
            ViewModel.ResolveCredentialForCommit,
            credential => credential.Name);

    private void OnTunnelTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        sender.ItemsSource = ViewModel.TunnelPicker.FilterTunnelConfigs(sender.Text);
    }

    private void OnTunnelQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args) =>
        CommitSelection(
            sender,
            args.ChosenSuggestion,
            tunnel => ViewModel.TunnelPicker.SelectedTunnel = tunnel,
            () => ViewModel.TunnelPicker.SelectedTunnel,
            ViewModel.TunnelPicker.ResolveTunnelForCommit,
            tunnel => tunnel.Name);

    private void OnTunnelGotFocus(object sender, RoutedEventArgs e)
    {
        var box = (AutoSuggestBox)sender;
        ClearDefaultSelectionText(box, ViewModel.TunnelPicker.SelectedTunnel, ViewModel.TunnelPicker.InheritTunnel);
        ShowSuggestions(box, ViewModel.TunnelPicker.FilterTunnelConfigs(null));
    }

    private void OnTunnelLostFocus(object sender, RoutedEventArgs e) =>
        CommitSelection(
            (AutoSuggestBox)sender,
            null,
            tunnel => ViewModel.TunnelPicker.SelectedTunnel = tunnel,
            () => ViewModel.TunnelPicker.SelectedTunnel,
            ViewModel.TunnelPicker.ResolveTunnelForCommit,
            tunnel => tunnel.Name);

    private static void ShowSuggestions(AutoSuggestBox box, object suggestions)
    {
        box.ItemsSource = suggestions;
        box.IsSuggestionListOpen = true;
    }

    private static void CommitSelection<T>(
        AutoSuggestBox box,
        object? chosenSuggestion,
        Action<T?> apply,
        Func<T?> current,
        Func<string?, T?> resolve,
        Func<T, string> displayName)
        where T : class
    {
        var committedSuggestion = chosenSuggestion is T;
        if (chosenSuggestion is T chosen)
        {
            apply(chosen);
        }
        // A null getter can encode a valid backing state that has no picker sentinel.
        else if (string.IsNullOrWhiteSpace(box.Text) && current() is not null)
        {
            apply(null);
        }
        else if (resolve(box.Text) is { } resolved)
        {
            apply(resolved);
        }

        SyncPickerText(box, current() is { } selection ? displayName(selection) : null);
        box.IsSuggestionListOpen = false;

        if (committedSuggestion)
        {
            _ = box.DispatcherQueue.TryEnqueue(
                DispatcherQueuePriority.Low,
                () => box.IsSuggestionListOpen = false);
        }
    }

    private static void ClearDefaultSelectionText<T>(AutoSuggestBox box, T? selection, T defaultSelection)
        where T : class
    {
        if (!ReferenceEquals(selection, defaultSelection)) return;
        box.Text = string.Empty;
    }

    private static void SyncPickerText(AutoSuggestBox? box, string? selectionName)
    {
        if (box is null) return;
        var text = selectionName ?? string.Empty;
        if (box.Text != text) box.Text = text;
    }
}
