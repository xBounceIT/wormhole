using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Windows.Graphics;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Interactive Microsoft Entra ID sign-in for Azure VPN tunnels: a separate top-level window
/// hosting a WebView2 on the Microsoft login page — the same standalone Office 365 popup the
/// native Azure VPN Client shows. Runs the OAuth2 authorization-code + PKCE flow; the redirect to
/// <see cref="AzureVpnSettings.RedirectUri"/> is intercepted inside the WebView (the navigation is
/// cancelled before it leaves the machine — nothing listens on the port), then the code is
/// exchanged at the token endpoint.
///
/// <para>A dedicated <see cref="Window"/> rather than a ContentDialog for two reasons: it matches
/// the native client's UX, and WinUI 3 allows only one ContentDialog per XamlRoot — tunnel
/// establish can run while other dialogs (e.g. the tunnel test dialog) are open. The WebView2 uses
/// its own persistent user-data folder so Entra session cookies survive and subsequent interactive
/// sign-ins are usually a single click (the silent refresh-token path normally avoids the popup
/// entirely).</para>
/// </summary>
public sealed class DialogAzureVpnAuthService : IAzureVpnAuthService, IDisposable
{
    private readonly SemaphoreSlim _windowGate = new(1, 1);
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly AzureVpnOAuthClient _oauth;
    private int _disposed;

    public DialogAzureVpnAuthService(AzureVpnOAuthClient oauth)
    {
        _oauth = oauth;
    }

    public async Task<AzureVpnTokenResult> AuthenticateInteractiveAsync(
        AzureVpnSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _disposed) != 0)
            throw new OperationCanceledException("Azure VPN sign-in service is shutting down.");

        var window = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window to anchor the Microsoft sign-in popup.");
        var dispatcher = window.DispatcherQueue
            ?? throw new InvalidOperationException("Main window has no DispatcherQueue.");

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownCts.Token);
        await _windowGate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            var tcs = new TaskCompletionSource<AzureVpnTokenResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    var result = await ShowPopupAsync(window, settings, configName, linked.Token).ConfigureAwait(true);
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
                tcs.TrySetException(new InvalidOperationException("Could not enqueue the Microsoft sign-in popup on the UI thread."));
            }
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            try { _windowGate.Release(); } catch (ObjectDisposedException) { }
        }
    }

    private async Task<AzureVpnTokenResult> ShowPopupAsync(
        Window owner,
        AzureVpnSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var (codeVerifier, codeChallenge) = AzureVpnOAuthClient.CreatePkcePair();
        var expectedState = AzureVpnOAuthClient.CreateState();
        var authorizeUri = AzureVpnOAuthClient.BuildAuthorizeUri(settings, codeChallenge, expectedState);

        var webView = new WebView2();
        var popup = new Window
        {
            Title = $"Sign in to Microsoft — {configName}",
            Content = webView,
        };

        // Completes with the authorization code once the WebView hits the redirect URI; faulted on
        // an Entra-reported error or when the user closes the window first.
        var codeCompletion = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = false;

        // Idempotent close that swallows the post-disposal race (the window may already be tearing
        // down on another path). Captures `closed`/`popup` by reference so it sees later updates.
        void CloseIfOpen()
        {
            try { if (!closed) popup.Close(); } catch { }
        }

        popup.Closed += (_, _) =>
        {
            closed = true;
            codeCompletion.TrySetException(
                new InvalidOperationException("Microsoft sign-in was cancelled before authentication completed."));
        };

        using var ctReg = cancellationToken.Register(() =>
        {
            owner.DispatcherQueue.TryEnqueue(() =>
            {
                codeCompletion.TrySetCanceled(cancellationToken);
                CloseIfOpen();
            });
        });

        try
        {
            SizeAndCenterOver(owner, popup);
            popup.Activate();

            var environment = await CoreWebView2Environment.CreateWithOptionsAsync(
                browserExecutableFolder: null,
                userDataFolder: AppPaths.GetAzureVpnWebView2UserDataDirectory(),
                options: new CoreWebView2EnvironmentOptions());
            await webView.EnsureCoreWebView2Async(environment);

            if (closed || codeCompletion.Task.IsFaulted || codeCompletion.Task.IsCanceled)
            {
                // The user closed the window (or the connect was cancelled) while WebView2 was
                // still starting up — surface that instead of using the dead control. The await
                // rethrows the close/cancel recorded on the completion source.
                await codeCompletion.Task.ConfigureAwait(true);
                throw new InvalidOperationException("Microsoft sign-in ended before it started.");
            }
            if (webView.CoreWebView2 is null)
                throw new InvalidOperationException("WebView2 initialization completed without a CoreWebView2 instance.");

            webView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;

            webView.CoreWebView2.NavigationStarting += (_, args) =>
            {
                if (!args.Uri.StartsWith(AzureVpnSettings.RedirectUri, StringComparison.OrdinalIgnoreCase))
                    return;

                // Never let the loopback redirect actually connect — the code travels in its
                // query string and nothing is listening.
                args.Cancel = true;
                HandleRedirect(args.Uri, expectedState, codeCompletion);
                CloseIfOpen();
            };

            webView.CoreWebView2.Navigate(authorizeUri);

            var code = await codeCompletion.Task.ConfigureAwait(true);

            // The window is gone; redeem the code off the popup. Still cancellable — a token
            // cancel here aborts the HTTP call.
            return await _oauth.ExchangeCodeAsync(settings, code, codeVerifier, cancellationToken).ConfigureAwait(true);
        }
        finally
        {
            CloseIfOpen();
        }
    }

    private static void HandleRedirect(string rawUri, string expectedState, TaskCompletionSource<string> completion)
    {
        if (!Uri.TryCreate(rawUri, UriKind.Absolute, out var uri))
        {
            completion.TrySetException(new InvalidOperationException("Microsoft sign-in returned an unreadable redirect."));
            return;
        }

        var values = ParseQuery(uri.Query);
        if (values.TryGetValue("error", out var error))
        {
            values.TryGetValue("error_description", out var description);
            var detail = string.IsNullOrWhiteSpace(description) ? error : $"{error}: {description.Split('\n')[0]}";
            completion.TrySetException(new InvalidOperationException($"Microsoft sign-in failed: {detail}"));
            return;
        }

        if (!values.TryGetValue("state", out var state) || !string.Equals(state, expectedState, StringComparison.Ordinal))
        {
            completion.TrySetException(new InvalidOperationException(
                "Microsoft sign-in returned a mismatched state value; discarding the response."));
            return;
        }

        if (!values.TryGetValue("code", out var code) || string.IsNullOrWhiteSpace(code))
        {
            completion.TrySetException(new InvalidOperationException(
                "Microsoft sign-in completed without an authorization code."));
            return;
        }

        completion.TrySetResult(code);
    }

    // Microsoft's own sign-in popups are ~480 px wide; size in physical pixels via the owner's
    // rasterization scale and center over the owner window.
    private static void SizeAndCenterOver(Window owner, Window popup)
    {
        try
        {
            var scale = owner.Content?.XamlRoot?.RasterizationScale ?? 1.0;
            var width = (int)(480 * scale);
            var height = (int)(680 * scale);

            if (popup.AppWindow.Presenter is OverlappedPresenter presenter)
            {
                presenter.IsMinimizable = false;
                presenter.IsMaximizable = false;
            }

            var ownerPos = owner.AppWindow.Position;
            var ownerSize = owner.AppWindow.Size;
            var x = ownerPos.X + Math.Max(0, (ownerSize.Width - width) / 2);
            var y = ownerPos.Y + Math.Max(0, (ownerSize.Height - height) / 2);
            popup.AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
        }
        catch
        {
            // Best-effort cosmetics: a default-placed window still completes the sign-in.
        }
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
        try { _windowGate.Dispose(); } catch { }
    }
}
