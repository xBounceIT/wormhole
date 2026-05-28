using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
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
        var credentials = ViewModel.LoadCredentialsAsync();
        var tunnels = ViewModel.TunnelPicker.LoadAsync();
        await Task.WhenAll(credentials, tunnels);
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
        switch (e.PropertyName)
        {
            case nameof(ConnectionEditorViewModel.IsValid):
                ValidityChanged?.Invoke(this, EventArgs.Empty);
                break;
            // Keep the searchable pickers' text in sync when the VM drives selection externally
            // (LoadFrom, protocol switch clearing an incompatible pick, the AAD auto-flow).
            case nameof(ConnectionEditorViewModel.SelectedCredential):
                SyncCredentialText(CredentialBox, ViewModel.SelectedCredential);
                break;
            case nameof(ConnectionEditorViewModel.SelectedGatewayCredential):
                SyncCredentialText(GatewayCredentialBox, ViewModel.SelectedGatewayCredential);
                break;
        }
    }

    // --- Searchable credential pickers (AutoSuggestBox) ---------------------------------------
    // Selection lives in the VM (CredentialId / RdpGatewayCredentialId); the suggestion list is
    // ephemeral, so filtering can never clear the bound selection. The box text shows the selected
    // item's Name — including the "(None — prompt every time)" sentinel, which is displayed like
    // any other row so a pick never rewrites Text mid-selection (that wedged the dropdown open).
    // An untouched field stays empty so PlaceholderText shows; only a real selection sets text.

    private void OnCredentialTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) =>
        FilterSuggestions(sender, args);

    private void OnCredentialQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args) =>
        CommitCredential(sender, args.ChosenSuggestion, c => ViewModel.SelectedCredential = c, () => ViewModel.SelectedCredential);

    private void OnCredentialGotFocus(object sender, RoutedEventArgs e) =>
        ShowAllSuggestions((AutoSuggestBox)sender);

    private void OnCredentialLostFocus(object sender, RoutedEventArgs e) =>
        CommitCredential((AutoSuggestBox)sender, null, c => ViewModel.SelectedCredential = c, () => ViewModel.SelectedCredential);

    private void OnGatewayCredentialTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) =>
        FilterSuggestions(sender, args);

    private void OnGatewayCredentialQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args) =>
        CommitCredential(sender, args.ChosenSuggestion, c => ViewModel.SelectedGatewayCredential = c, () => ViewModel.SelectedGatewayCredential);

    private void OnGatewayCredentialGotFocus(object sender, RoutedEventArgs e) =>
        ShowAllSuggestions((AutoSuggestBox)sender);

    private void OnGatewayCredentialLostFocus(object sender, RoutedEventArgs e) =>
        CommitCredential((AutoSuggestBox)sender, null, c => ViewModel.SelectedGatewayCredential = c, () => ViewModel.SelectedGatewayCredential);

    private void FilterSuggestions(AutoSuggestBox box, AutoSuggestBoxTextChangedEventArgs args)
    {
        // Only react to typing — programmatic Text updates (selection sync) must not re-filter.
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        box.ItemsSource = ViewModel.FilterCredentials(box.Text);
    }

    private void ShowAllSuggestions(AutoSuggestBox box)
    {
        box.ItemsSource = ViewModel.FilterCredentials(null);
        box.IsSuggestionListOpen = true;
    }

    /// <summary>
    /// Resolve the picker's current input to a selection and apply it. Selection is committed on
    /// BOTH submit (Enter / tap / arrow+Enter) and focus loss, so a typed or arrow-highlighted
    /// credential isn't silently dropped when the user tabs or clicks away without pressing Enter.
    /// A chosen suggestion wins; empty text clears back to "(None — prompt every time)"; otherwise
    /// the text is resolved to an exact-or-unique match (ambiguous/no match keeps the current
    /// selection). <paramref name="apply"/> accepts null to clear via the VM's sentinel mapping.
    /// </summary>
    private void CommitCredential(
        AutoSuggestBox box,
        object? chosenSuggestion,
        Action<CredentialProfile?> apply,
        Func<CredentialProfile?> current)
    {
        if (chosenSuggestion is CredentialProfile chosen)
        {
            apply(chosen);
        }
        else if (string.IsNullOrWhiteSpace(box.Text))
        {
            apply(null); // empty input means "no saved credential — prompt every time"
        }
        else if (ViewModel.ResolveCredentialForCommit(box.Text) is { } resolved)
        {
            apply(resolved);
        }
        // else: text matched nothing unambiguous — keep the current selection and revert below.

        SyncCredentialText(box, current());
        box.IsSuggestionListOpen = false;
    }

    private static void SyncCredentialText(AutoSuggestBox? box, CredentialProfile? selection)
    {
        if (box is null) return;
        // Show the selection's Name for every item, including the None sentinel — never blank it
        // mid-pick. Empty only for a null (unresolved) selection, which lets PlaceholderText show
        // on an untouched field.
        var text = selection?.Name ?? string.Empty;
        if (box.Text != text) box.Text = text;
    }
}
