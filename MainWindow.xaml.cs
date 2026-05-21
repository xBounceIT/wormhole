using System;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
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

    private OverlappedPresenter? _windowPresenter;
    private OverlappedPresenterState _currentWindowState;

    public ShellViewModel ViewModel { get; }

    public MainWindow(ShellViewModel viewModel, INavigationService navigationService)
    {
        ViewModel = viewModel;
        _navigationService = navigationService;

        this.InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        // The native TitleBar control renders at ~48 px; match the AppWindow's
        // caption-button strip so they don't draw at different heights and leave
        // a visible seam.
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

        // Workaround for WinUI issue #9934 (microsoft/microsoft-ui-xaml): even
        // with PreferredHeightOption.Tall, a 1-2 px gap remains between the
        // system caption buttons and the content below the title bar. Pull
        // the content up by a small negative margin to close it, and re-apply
        // on window-state changes since the inset differs when maximized.
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            _windowPresenter = presenter;
            _currentWindowState = presenter.State;
            AdjustContentMargin(force: true);
            AppWindow.Changed += (_, _) => AdjustContentMargin();
        }

        SystemBackdrop = new MicaBackdrop { Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base };

        _navigationService.Initialize(ContentFrame);
        _navigationService.Navigate(typeof(SessionsPage));

        // Keep the VM informed of the window's content width so the sidebar can
        // re-clamp on window shrink and the resizer stays reachable on-screen.
        RootGrid.SizeChanged += (_, args) =>
        {
            ViewModel.MaxAvailableWidth = args.NewSize.Width;
        };

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
        // Focus the content Frame so the QuickConnect ComboBox (first focusable
        // element in the title-bar row) doesn't keep default launch focus and
        // draw a focus ring. Frame is a Control with IsTabStop=true and a
        // template that draws no focus visual, so this absorbs focus silently.
        // (An IsTabStop=false sink wouldn't work — programmatic Focus returns
        // false in that state in WinUI 3.)
        // Deferred to a low-priority dispatcher tick because the framework's
        // initial-focus pass runs after Activated and would otherwise overwrite
        // our override back onto the ComboBox.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => ContentFrame.Focus(FocusState.Programmatic));
    }

    private void AdjustContentMargin(bool? force = null)
    {
        if (_windowPresenter is null ||
            (_windowPresenter.State == _currentWindowState && force is not true))
        {
            return;
        }

        var top = _windowPresenter.State == OverlappedPresenterState.Maximized ? -1d : -2d;
        var infoBarMargin = UpdateInfoBar.Margin;
        UpdateInfoBar.Margin = new Thickness(infoBarMargin.Left, top, infoBarMargin.Right, infoBarMargin.Bottom);
        ContentArea.Margin = new Thickness(0, top, 0, 0);
        _currentWindowState = _windowPresenter.State;
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
        // Cancel paths (capture stolen, window deactivated, etc.) reach here without
        // a prior PointerReleased, so persist the in-memory width so the resize
        // isn't lost. Normal release short-circuits: PointerReleased clears the
        // flag before ReleasePointerCapture, so this fires with flag=false.
        if (!_isResizingSidebar) return;
        _isResizingSidebar = false;
        ViewModel.PersistSidebarWidth();
    }
}
