using System;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.Views.Pages;

namespace Wormhole;

public sealed partial class MainWindow : Window
{
    // ConnectionTreeView's horizontal Margin "8,4,8,8" (8 left + 8 right = 16)
    // plus NavigationView's empirically-observed PaneCustomContent padding (~12).
    private const double PaneCustomContentInset = 28;

    private readonly INavigationService _navigationService;

    private bool _isResizingSidebar;
    private double _resizeStartWidth;
    private double _resizeStartPointerX;
    private bool _minSidebarMeasured;

    public ShellViewModel ViewModel { get; }

    public MainWindow(ShellViewModel viewModel, INavigationService navigationService)
    {
        ViewModel = viewModel;
        _navigationService = navigationService;

        this.InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        SystemBackdrop = new MicaBackdrop { Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base };

        _navigationService.Initialize(ContentFrame);
        _navigationService.Navigate(typeof(SessionsPage));

        Activated += OnFirstActivated;

        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await ViewModel.Update.RunStartupCheckAsync().ConfigureAwait(false);
        });
    }

    private void OnFirstActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated) return;
        Activated -= OnFirstActivated;
        InitialFocusSink.Focus(FocusState.Programmatic);
    }

    private void UpdateInfoBar_CloseButtonClick(InfoBar sender, object args)
    {
        ViewModel.Update.DismissCommand.Execute(null);
    }

    private void NavView_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        if (args.InvokedItemContainer is not NavigationViewItem item) return;
        switch (item.Tag as string)
        {
            case "Sessions":
                _navigationService.Navigate(typeof(SessionsPage));
                break;
            case "Settings":
                _navigationService.Navigate(typeof(SettingsPage));
                break;
        }
    }

    private void NavView_Loaded(object sender, RoutedEventArgs e)
    {
        if (_minSidebarMeasured) return;
        _minSidebarMeasured = true;
        // Defer until after the footer items have applied their templates so DesiredSize
        // reflects icon + text + internal padding rather than zero.
        NavView.DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, ComputeMinSidebarWidth);
    }

    private void ComputeMinSidebarWidth()
    {
        double maxItemWidth = 0;
        foreach (var item in new[] { SessionsItem, SettingsItem })
        {
            if (item is null) continue;
            item.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            if (item.DesiredSize.Width > maxItemWidth)
            {
                maxItemWidth = item.DesiredSize.Width;
            }
        }

        var headerWidth = ConnectionsTree.MeasureHeaderDesiredWidth() + PaneCustomContentInset;
        ViewModel.ApplyMeasuredMinSidebarWidth(Math.Max(maxItemWidth, headerWidth));
    }

    private void SidebarResizer_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not UIElement element) return;
        // Mouse: only the primary (left) button starts a resize so right/middle
        // clicks don't capture the pointer and accidentally shift the pane.
        // Touch/pen presses are inherently primary — no button to gate on.
        var point = e.GetCurrentPoint(element);
        if (e.Pointer.PointerDeviceType == PointerDeviceType.Mouse
            && !point.Properties.IsLeftButtonPressed)
        {
            return;
        }
        if (!element.CapturePointer(e.Pointer)) return;
        _isResizingSidebar = true;
        _resizeStartWidth = ViewModel.SidebarWidth;
        _resizeStartPointerX = e.GetCurrentPoint(null).Position.X;
        e.Handled = true;
    }

    private void SidebarResizer_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_isResizingSidebar) return;
        var currentX = e.GetCurrentPoint(null).Position.X;
        ViewModel.SidebarWidth = _resizeStartWidth + (currentX - _resizeStartPointerX);
        e.Handled = true;
    }

    private void SidebarResizer_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!_isResizingSidebar) return;
        // Clear before releasing capture: ReleasePointerCapture fires PointerCaptureLost
        // synchronously, and the handler must short-circuit so it doesn't undo the resize.
        _isResizingSidebar = false;
        if (sender is UIElement element)
        {
            element.ReleasePointerCapture(e.Pointer);
        }
        ViewModel.PersistSidebarWidth();
        e.Handled = true;
    }

    private void SidebarResizer_PointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        _isResizingSidebar = false;
    }
}
