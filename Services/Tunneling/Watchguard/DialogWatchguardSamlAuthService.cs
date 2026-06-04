using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

public sealed class DialogWatchguardSamlAuthService : IWatchguardSamlAuthService, IDisposable
{
    private readonly SemaphoreSlim _dialogGate = new(1, 1);
    private readonly CancellationTokenSource _shutdownCts = new();
    private int _disposed;

    public async Task<WatchguardSamlAuthResult> AuthenticateAsync(
        WatchguardSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _disposed) != 0)
            throw new OperationCanceledException("Watchguard SAML prompt service is shutting down.");

        var window = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window to host Watchguard SAML login.");
        var dispatcher = window.DispatcherQueue
            ?? throw new InvalidOperationException("Main window has no DispatcherQueue.");

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownCts.Token);
        await _dialogGate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            var tcs = new TaskCompletionSource<WatchguardSamlAuthResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    var result = await ShowDialogAsync(window, settings, configName, linked.Token).ConfigureAwait(true);
                    tcs.TrySetResult(result);
                }
                catch (OperationCanceledException) when (linked.Token.IsCancellationRequested)
                {
                    tcs.TrySetCanceled(linked.Token);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }))
            {
                tcs.TrySetException(new InvalidOperationException("Could not enqueue Watchguard SAML login on UI thread."));
            }
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            try { _dialogGate.Release(); } catch (ObjectDisposedException) { }
        }
    }

    private static async Task<WatchguardSamlAuthResult> ShowDialogAsync(
        Window window,
        WatchguardSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var xamlRoot = window.Content?.XamlRoot
            ?? throw new InvalidOperationException("Main window content has no XamlRoot.");

        var webView = new WebView2
        {
            MinWidth = 760,
            MinHeight = 560,
        };
        var dialog = new ContentDialog
        {
            Title = $"Watchguard SAML — {configName}",
            Content = webView,
            CloseButtonText = "Cancel",
            XamlRoot = xamlRoot,
        };

        var completion = new TaskCompletionSource<WatchguardSamlAuthResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var ctReg = cancellationToken.Register(() =>
        {
            window.DispatcherQueue.TryEnqueue(() =>
            {
                try { dialog.Hide(); } catch { }
                completion.TrySetCanceled(cancellationToken);
            });
        });

        var environment = await CoreWebView2Environment.CreateWithOptionsAsync(
            browserExecutableFolder: null,
            userDataFolder: AppPaths.GetWatchguardSamlWebView2UserDataDirectory(),
            options: new CoreWebView2EnvironmentOptions());
        await webView.EnsureCoreWebView2Async(environment);

        if (webView.CoreWebView2 is null)
            throw new InvalidOperationException("WebView2 initialization completed without a CoreWebView2 instance.");

        webView.CoreWebView2.Settings.AreDevToolsEnabled = false;
        webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        var baseUri = WatchguardConfigClient.BuildUri(settings.Server, settings.Port, "/");
        if (settings.TrustServerCertificate)
        {
            webView.CoreWebView2.ServerCertificateErrorDetected += (_, args) =>
            {
                if (WatchguardConfigClient.IsConfiguredFireboxHttpsUri(baseUri, args.RequestUri))
                {
                    args.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
                }
            };
        }

        var loginUris = WatchguardConfigClient.BuildSamlLoginUris(settings.Server, settings.Port);
        var loginUriIndex = 0;

        async Task TryCompleteAsync(string? rawUri)
        {
            if (completion.Task.IsCompleted || string.IsNullOrWhiteSpace(rawUri)) return;
            if (!Uri.TryCreate(rawUri, UriKind.Absolute, out var uri)) return;

            var values = ParseQuery(uri.Query);
            if (!values.TryGetValue("user", out var user) || !values.TryGetValue("token", out var token)
                || string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(token))
            {
                return;
            }

            var cookies = await ReadCookiesAsync(webView.CoreWebView2, baseUri).ConfigureAwait(true);
            completion.TrySetResult(new WatchguardSamlAuthResult(user, token, cookies));
            try { dialog.Hide(); } catch { }
        }

        webView.CoreWebView2.NavigationCompleted += async (_, args) =>
        {
            await TryCompleteAsync(webView.Source?.AbsoluteUri).ConfigureAwait(true);
            if (!args.IsSuccess && loginUriIndex < loginUris.Length - 1)
            {
                loginUriIndex++;
                webView.CoreWebView2.Navigate(loginUris[loginUriIndex].ToString());
            }
        };

        dialog.Opened += (_, _) => webView.CoreWebView2.Navigate(loginUris[loginUriIndex].ToString());

        ContentDialogResult dialogResult;
        using (RdpOverlayCoordinator.Suppress())
        {
            dialogResult = await dialog.ShowAsync();
        }

        if (completion.Task.IsCompleted)
            return await completion.Task.ConfigureAwait(true);

        cancellationToken.ThrowIfCancellationRequested();
        if (dialogResult == ContentDialogResult.None)
            throw new InvalidOperationException("Watchguard SAML login was cancelled by the user.");
        throw new InvalidOperationException("Watchguard SAML login closed before authentication completed.");
    }

    private static async Task<IReadOnlyList<Cookie>> ReadCookiesAsync(CoreWebView2 webView, Uri baseUri)
    {
        var source = await webView.CookieManager.GetCookiesAsync(baseUri.ToString());
        var cookies = new List<Cookie>(source.Count);
        foreach (var cookie in source)
        {
            if (string.IsNullOrEmpty(cookie.Name)) continue;
            var domain = string.IsNullOrWhiteSpace(cookie.Domain)
                ? baseUri.Host
                : cookie.Domain.TrimStart('.');
            var path = string.IsNullOrWhiteSpace(cookie.Path) ? "/" : cookie.Path;
            cookies.Add(new Cookie(cookie.Name, cookie.Value, path, domain));
        }
        return cookies;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        var value = query[0] == '?' ? query[1..] : query;
        foreach (var part in value.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = part.Split('=', 2);
            var name = Uri.UnescapeDataString(pieces[0].Replace('+', ' '));
            var val = pieces.Length == 2 ? Uri.UnescapeDataString(pieces[1].Replace('+', ' ')) : string.Empty;
            result[name] = val;
        }
        return result;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _shutdownCts.Cancel(); } catch { }
        try { _shutdownCts.Dispose(); } catch { }
        try { _dialogGate.Dispose(); } catch { }
    }
}
