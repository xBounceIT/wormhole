using System;
using System.Collections.Specialized;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

public sealed partial class TunnelTestDialog : UserControl
{
    public TunnelTestDialogViewModel ViewModel { get; }

    /// <summary>Raised when the user clicks Close. The host (DialogService) tears down the overlay;
    /// the button is only enabled once the test has finished (CanClose = !IsBusy).</summary>
    public event Action? CloseRequested;

    public TunnelTestDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<TunnelTestDialogViewModel>();
        this.InitializeComponent();
        // The log streams in on the UI thread (the VM marshals progress there), so keep the newest
        // line in view as it grows.
        ViewModel.Log.CollectionChanged += OnLogChanged;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => CloseRequested?.Invoke();

    /// <summary>x:Bind helper — map the outcome to the result InfoBar's severity. Only consulted once
    /// a result exists (IsOpen = HasResult), so the running-state value is never shown. A user cancel
    /// is informational rather than an alarming error.</summary>
    public static InfoBarSeverity ResultSeverity(bool isSuccess, bool wasCancelled) =>
        isSuccess ? InfoBarSeverity.Success
        : wasCancelled ? InfoBarSeverity.Informational
        : InfoBarSeverity.Error;

    private void OnLogChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        var count = ViewModel.Log.Count;
        if (count == 0) return;
        LogList.ScrollIntoView(ViewModel.Log[count - 1]);
    }
}
