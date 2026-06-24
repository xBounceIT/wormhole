using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;

namespace Wormhole.Views.Controls;

public sealed partial class UpdateChangelogView : UserControl
{
    public static readonly DependencyProperty HtmlDocumentProperty =
        DependencyProperty.Register(
            nameof(HtmlDocument),
            typeof(string),
            typeof(UpdateChangelogView),
            new PropertyMetadata(string.Empty, OnHtmlDocumentChanged));

    private static CoreWebView2Environment? s_environment;

    private bool _isInitialized;
    private bool _isLoaded;
    private string? _pendingHtmlDocument;
    private int _navigationGeneration;
    private int _activeNavigationGeneration;

    public string HtmlDocument
    {
        get => (string)GetValue(HtmlDocumentProperty);
        set => SetValue(HtmlDocumentProperty, value);
    }

    public UpdateChangelogView()
    {
        InitializeComponent();
        ActualThemeChanged += OnActualThemeChanged;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private static void OnHtmlDocumentChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UpdateChangelogView view) return;
        _ = view.NavigateToHtmlAsync(e.NewValue as string);
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _isLoaded = true;
        _ = NavigateToHtmlAsync(_pendingHtmlDocument ?? HtmlDocument);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _isLoaded = false;
        LoadingHost.Visibility = Visibility.Collapsed;
        ChangelogWebView.Visibility = Visibility.Collapsed;
    }

    private async Task EnsureInitializedAsync()
    {
        if (_isInitialized) return;

        var environment = await GetOrCreateEnvironmentAsync().ConfigureAwait(true);
        await ChangelogWebView.EnsureCoreWebView2Async(environment);

        var core = ChangelogWebView.CoreWebView2
            ?? throw new InvalidOperationException("WebView2 initialization completed without a CoreWebView2 instance.");

        core.Settings.IsScriptEnabled = false;
        core.Settings.AreDefaultScriptDialogsEnabled = false;
        core.Settings.AreDevToolsEnabled = Debugger.IsAttached;
        core.Settings.AreDefaultContextMenusEnabled = true;
        core.Settings.AreHostObjectsAllowed = false;
        core.Settings.IsWebMessageEnabled = false;
        core.NavigationCompleted -= OnNavigationCompleted;
        core.NavigationCompleted += OnNavigationCompleted;
        core.NavigationStarting -= OnNavigationStarting;
        core.NavigationStarting += OnNavigationStarting;
        ApplyThemeToWebView(core);
        core.NewWindowRequested -= OnNewWindowRequested;
        core.NewWindowRequested += OnNewWindowRequested;

        _isInitialized = true;
        ErrorHost.Visibility = Visibility.Collapsed;
    }

    private static async Task<CoreWebView2Environment> GetOrCreateEnvironmentAsync()
    {
        var existing = Volatile.Read(ref s_environment);
        if (existing is not null) return existing;

        WebViewBrowserArguments.SweepStaleKeyedFolders(AppPaths.GetUpdateChangelogWebView2UserDataRoot());
        var folder = AppPaths.GetUpdateChangelogWebView2UserDataDirectory();
        Directory.CreateDirectory(folder);

        var created = await CoreWebView2Environment.CreateWithOptionsAsync(
            browserExecutableFolder: null,
            userDataFolder: folder,
            options: new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = WebViewBrowserArguments.Build(socks5Proxy: null),
            });
        var winner = Interlocked.CompareExchange(ref s_environment, created, null);
        return winner ?? created;
    }

    private async Task NavigateToHtmlAsync(string? html)
    {
        _pendingHtmlDocument = html;
        var generation = ++_navigationGeneration;

        if (string.IsNullOrWhiteSpace(html))
        {
            _pendingHtmlDocument = null;
            ClearSurface();
            return;
        }

        if (!_isLoaded) return;

        ShowLoading();

        try
        {
            await EnsureInitializedAsync().ConfigureAwait(true);
            if (!_isLoaded || generation != _navigationGeneration) return;

            ApplyThemeToWebView(ChangelogWebView.CoreWebView2);
            _activeNavigationGeneration = generation;
            ChangelogWebView.CoreWebView2.NavigateToString(html);
            _pendingHtmlDocument = null;
        }
        catch (Exception ex)
        {
            if (generation == _navigationGeneration)
                ShowError("Could not render the changelog: " + ex.Message);
        }
    }

    private void OnNavigationCompleted(CoreWebView2 sender, CoreWebView2NavigationCompletedEventArgs args)
    {
        if (!_isLoaded || _activeNavigationGeneration != _navigationGeneration) return;
        if (!args.IsSuccess)
        {
            if (ChangelogWebView.Visibility == Visibility.Visible
                && args.WebErrorStatus == CoreWebView2WebErrorStatus.OperationCanceled)
            {
                return;
            }

            ShowError("Could not render the changelog: " + args.WebErrorStatus);
            return;
        }

        LoadingHost.Visibility = Visibility.Collapsed;
        ErrorHost.Visibility = Visibility.Collapsed;
        ChangelogWebView.Visibility = Visibility.Visible;
    }

    private void OnNavigationStarting(CoreWebView2 sender, CoreWebView2NavigationStartingEventArgs args)
    {
        if (string.IsNullOrWhiteSpace(args.Uri))
        {
            return;
        }

        if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri))
        {
            args.Cancel = true;
            return;
        }

        if (uri.Scheme is "about" or "data")
            return;

        args.Cancel = true;
        OpenExternalHttpLink(uri.ToString());
    }

    private void OnNewWindowRequested(CoreWebView2 sender, CoreWebView2NewWindowRequestedEventArgs args)
    {
        args.Handled = true;
        OpenExternalHttpLink(args.Uri);
    }

    private static void OpenExternalHttpLink(string? uriText)
    {
        if (!Uri.TryCreate(uriText, UriKind.Absolute, out var uri)) return;
        if (uri.Scheme is not ("http" or "https")) return;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = uri.ToString(),
                UseShellExecute = true,
            });
        }
        catch
        {
            // Link opening is best-effort; the changelog itself should remain readable.
        }
    }

    private void OnActualThemeChanged(FrameworkElement sender, object args)
    {
        if (ChangelogWebView.CoreWebView2 is { } core)
            ApplyThemeToWebView(core);
    }

    private void ApplyThemeToWebView(CoreWebView2? core)
    {
        var dark = ActualTheme == ElementTheme.Dark;
        try
        {
            ChangelogWebView.DefaultBackgroundColor = dark
                ? Windows.UI.Color.FromArgb(0xFF, 0x1E, 0x1F, 0x22)
                : Windows.UI.Color.FromArgb(0xFF, 0xFF, 0xFF, 0xFF);
        }
        catch
        {
            // Cosmetic only; the HTML document still carries explicit colors.
        }

        if (core is null) return;

        try
        {
            core.Profile.PreferredColorScheme = dark
                ? CoreWebView2PreferredColorScheme.Dark
                : CoreWebView2PreferredColorScheme.Light;
        }
        catch
        {
            // Some older runtimes may ignore profile color scheme; explicit CSS remains the fallback.
        }
    }

    private void ClearSurface()
    {
        LoadingHost.Visibility = Visibility.Collapsed;
        ErrorHost.Visibility = Visibility.Collapsed;
        ChangelogWebView.Visibility = Visibility.Collapsed;
    }

    private void ShowLoading()
    {
        ErrorHost.Visibility = Visibility.Collapsed;
        ChangelogWebView.Visibility = Visibility.Collapsed;
        LoadingHost.Visibility = Visibility.Visible;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorHost.Visibility = Visibility.Visible;
        LoadingHost.Visibility = Visibility.Collapsed;
        ChangelogWebView.Visibility = Visibility.Collapsed;
    }
}
