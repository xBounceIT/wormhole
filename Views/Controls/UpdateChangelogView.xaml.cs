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

    public string HtmlDocument
    {
        get => (string)GetValue(HtmlDocumentProperty);
        set => SetValue(HtmlDocumentProperty, value);
    }

    public UpdateChangelogView()
    {
        InitializeComponent();
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
        ChangelogWebView.Visibility = Visibility.Visible;
        _ = NavigateToHtmlAsync(_pendingHtmlDocument ?? HtmlDocument);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _isLoaded = false;
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
        core.NavigationStarting -= OnNavigationStarting;
        core.NavigationStarting += OnNavigationStarting;
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
        if (!_isLoaded || string.IsNullOrWhiteSpace(html)) return;

        try
        {
            await EnsureInitializedAsync().ConfigureAwait(true);
            ChangelogWebView.CoreWebView2.NavigateToString(html);
            _pendingHtmlDocument = null;
            ErrorHost.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            ShowError("Could not render the changelog: " + ex.Message);
        }
    }

    private void OnNavigationStarting(CoreWebView2 sender, CoreWebView2NavigationStartingEventArgs args)
    {
        if (string.IsNullOrWhiteSpace(args.Uri)
            || args.Uri.StartsWith("about:blank", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        args.Cancel = true;
        OpenExternalHttpLink(args.Uri);
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

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorHost.Visibility = Visibility.Visible;
    }
}
