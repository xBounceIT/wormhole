using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Views.Dialogs;

public sealed partial class FileTransferDialog : UserControl
{
    public FileTransferViewModel? ViewModel { get; private set; }

    /// <summary>Raised when the user clicks the in-content Close button. The hosting
    /// service subscribes and calls <c>ContentDialog.Hide()</c> on the wrapping dialog.</summary>
    public event EventHandler? CloseRequested;

    public FileTransferDialog()
    {
        this.InitializeComponent();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) =>
        CloseRequested?.Invoke(this, EventArgs.Empty);

    public async Task InitializeAsync(FileTransferViewModel vm)
    {
        ViewModel = vm;
        Bindings.Update();

        LocalPaneControl.SetViewModel(vm.LocalPane);
        RemotePaneControl.SetViewModel(vm.RemotePane);

        // Wire drop-handler callbacks: each pane forwards a TransferRequest to the
        // orchestrator. The remote pane also exposes drag-out staging so OS drag of
        // remote files materializes them to a temp dir first.
        LocalPaneControl.OnTransferRequested = HandleTransferAsync;
        RemotePaneControl.OnTransferRequested = HandleTransferAsync;
        RemotePaneControl.OnStageForExport = vm.StageForExportAsync;

        await vm.LoadInitialAsync().ConfigureAwait(true);
    }

    private Task HandleTransferAsync(TransferRequest request)
    {
        if (ViewModel is null) return Task.CompletedTask;
        // The conflict resolver is captured as a closure over the dialog so each prompt
        // runs against this XamlRoot. The orchestrator owns the apply-to-all sticky
        // logic — we just answer one prompt at a time.
        return ViewModel.EnqueueAsync(request, PromptConflictAsync, CancellationToken.None);
    }

    private async Task<(ConflictDecision Decision, bool ApplyToAll)> PromptConflictAsync(ConflictContext ctx, CancellationToken ct)
    {
        // Default decision if the dialog is dismissed: Skip. Safer than overwriting on
        // accidental Escape/click-out.
        var check = new CheckBox { Content = "Apply to remaining conflicts", IsChecked = false };
        var panel = new StackPanel { Spacing = 8, MinWidth = 360 };
        panel.Children.Add(new TextBlock
        {
            Text = $"\"{ctx.ItemName}\" already exists at the destination.",
            TextWrapping = TextWrapping.Wrap,
        });
        if (ctx.IncomingSize is { } incoming || ctx.ExistingSize is { } existing)
        {
            panel.Children.Add(new TextBlock
            {
                Text = $"Existing size: {ctx.ExistingSize?.ToString() ?? "?"} bytes — Incoming size: {ctx.IncomingSize?.ToString() ?? "?"} bytes",
                Opacity = 0.7,
                FontSize = 12,
            });
        }
        panel.Children.Add(check);

        var dialog = new ContentDialog
        {
            Title = "File exists",
            Content = panel,
            PrimaryButtonText = "Overwrite",
            SecondaryButtonText = "Skip",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Secondary,
            XamlRoot = this.XamlRoot,
        };
        var result = await dialog.ShowAsync();
        bool applyAll = check.IsChecked == true;
        return result switch
        {
            ContentDialogResult.Primary => (ConflictDecision.Overwrite, applyAll),
            ContentDialogResult.Secondary => (ConflictDecision.Skip, applyAll),
            _ => (ConflictDecision.Skip, applyAll),
        };
    }
}
