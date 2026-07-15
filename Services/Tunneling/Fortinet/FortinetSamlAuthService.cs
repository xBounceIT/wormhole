using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Services.Tunneling.Fortinet;

public sealed class SystemFortinetExternalBrowserLauncher : IFortinetExternalBrowserLauncher
{
    public void Open(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = uri.AbsoluteUri,
            UseShellExecute = true,
        });
        if (process is null)
            throw new InvalidOperationException("Windows did not open the default browser for Fortinet SAML authentication.");
    }
}

public sealed class FortinetSamlAuthService : IFortinetSamlAuthService, IDisposable
{
    private static readonly TimeSpan AuthenticationTimeout = TimeSpan.FromMinutes(5);
    private readonly IFortinetExternalBrowserLauncher _browserLauncher;
    private readonly SemaphoreSlim _authGate = new(1, 1);
    private readonly CancellationTokenSource _shutdownCts = new();
    private int _disposed;

    public FortinetSamlAuthService(IFortinetExternalBrowserLauncher browserLauncher)
    {
        _browserLauncher = browserLauncher;
    }

    public async Task<FortinetSamlAuthResult> AuthenticateAsync(
        FortinetSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.UseSingleSignOn)
            throw new InvalidOperationException("Fortinet SAML authentication was requested for a non-SSO tunnel.");
        if (Volatile.Read(ref _disposed) != 0)
            throw new OperationCanceledException("Fortinet SAML authentication service is shutting down.");

        using var timeoutCts = new CancellationTokenSource(AuthenticationTimeout);
        CancellationTokenSource linked;
        try
        {
            linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, _shutdownCts.Token, timeoutCts.Token);
        }
        catch (ObjectDisposedException)
        {
            throw new OperationCanceledException("Fortinet SAML authentication service was disposed during setup.");
        }
        using var linkedCts = linked;
        try
        {
            await _authGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                FortinetSamlAuthResult result;
                if (settings.UseExternalBrowser)
                {
                    result = await new FortinetExternalSamlAuthClient(_browserLauncher)
                        .AuthenticateAsync(settings, linked.Token)
                        .ConfigureAwait(false);
                }
                else
                {
                    result = await AuthenticateEmbeddedAsync(settings, configName, linked.Token)
                        .ConfigureAwait(false);
                }

                if (!result.HasExactlyOneCredential)
                    throw new InvalidOperationException("Fortinet SAML authentication returned an invalid result.");
                return result;
            }
            finally
            {
                _authGate.Release();
            }
        }
        catch (OperationCanceledException) when (
            timeoutCts.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested
            && !_shutdownCts.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Fortinet SAML authentication did not complete within {AuthenticationTimeout.TotalMinutes:F0} minutes.");
        }
    }

    private static async Task<FortinetSamlAuthResult> AuthenticateEmbeddedAsync(
        FortinetSettings settings,
        string configName,
        CancellationToken cancellationToken)
    {
        var window = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window is available for Fortinet SAML authentication.");
        var dispatcher = window.DispatcherQueue
            ?? throw new InvalidOperationException("The main window has no DispatcherQueue.");

        await ContentDialogGate.Shared.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var completion = new TaskCompletionSource<FortinetSamlAuthResult>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            if (!dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    completion.TrySetResult(
                        await ShowEmbeddedDialogAsync(window, settings, configName, cancellationToken)
                            .ConfigureAwait(true));
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    completion.TrySetCanceled(cancellationToken);
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
            }))
            {
                throw new InvalidOperationException("Could not enqueue Fortinet SAML authentication on the UI thread.");
            }

            return await completion.Task.ConfigureAwait(false);
        }
        finally
        {
            ContentDialogGate.Shared.Release();
        }
    }

    private static async Task<FortinetSamlAuthResult> ShowEmbeddedDialogAsync(
        Window window,
        FortinetSettings settings,
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
            Title = $"Fortinet SAML — {configName}",
            Content = webView,
            CloseButtonText = "Cancel",
            XamlRoot = xamlRoot,
        };

        WebViewBrowserArguments.SweepStaleKeyedFolders(AppPaths.GetFortinetSamlWebView2UserDataRoot());
        var environment = await CoreWebView2Environment.CreateWithOptionsAsync(
            browserExecutableFolder: null,
            userDataFolder: AppPaths.GetFortinetSamlWebView2UserDataDirectory(),
            options: new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = WebViewBrowserArguments.Build(socks5Proxy: null),
            });
        await webView.EnsureCoreWebView2Async(environment);
        var core = webView.CoreWebView2
            ?? throw new InvalidOperationException("WebView2 initialization completed without a CoreWebView2 instance.");

        core.Settings.AreDevToolsEnabled = false;
        core.Settings.AreDefaultContextMenusEnabled = false;
        if (settings.TrustServerCertificate)
        {
            core.ServerCertificateErrorDetected += (_, args) =>
            {
                if (FortinetSamlProtocol.IsConfiguredGatewayUri(settings, args.RequestUri))
                    args.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
            };
        }

        core.NewWindowRequested += (_, args) =>
        {
            // Keep every IdP popup in the dedicated profile. Letting WebView2 create an
            // unmanaged window could move the login into the system browser and strand the
            // SVPNCOOKIE outside the cookie jar polled below.
            args.Handled = true;
            var target = WebViewNewWindowNavigation.GetInSessionNavigationUri(args.Uri);
            if (target is null) return;
            core.Navigate(target);
        };

        var startUri = FortinetSamlProtocol.BuildStartUri(settings);
        var cookieManager = core.CookieManager;

        async Task DeleteSvpnCookiesAsync()
        {
            var cookies = await cookieManager.GetCookiesAsync(startUri.AbsoluteUri);
            foreach (var cookie in cookies.Where(c => FortinetSamlProtocol.IsSvpnCookieName(c.Name)))
                cookieManager.DeleteCookie(cookie);
        }

        await DeleteSvpnCookiesAsync().ConfigureAwait(true);

        using var pollingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var completion = new TaskCompletionSource<FortinetSamlAuthResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellationRegistration = cancellationToken.Register(() =>
        {
            window.DispatcherQueue.TryEnqueue(() =>
            {
                try { dialog.Hide(); } catch { }
                completion.TrySetCanceled(cancellationToken);
            });
        });

        async Task PollForCookieAsync()
        {
            try
            {
                while (!completion.Task.IsCompleted)
                {
                    pollingCts.Token.ThrowIfCancellationRequested();
                    var cookies = await cookieManager.GetCookiesAsync(startUri.AbsoluteUri);
                    var value = FortinetSamlProtocol.SelectSvpnCookieValue(
                        cookies.Select(c => (c.Name, c.Value, c.IsHttpOnly)));
                    if (value is not null)
                    {
                        foreach (var cookie in cookies.Where(c => FortinetSamlProtocol.IsSvpnCookieName(c.Name)))
                            cookieManager.DeleteCookie(cookie);
                        completion.TrySetResult(FortinetSamlAuthResult.FromSvpnCookie(value));
                        try { dialog.Hide(); } catch { }
                        return;
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(250), pollingCts.Token).ConfigureAwait(true);
                }
            }
            catch (OperationCanceledException) when (pollingCts.IsCancellationRequested)
            {
                if (cancellationToken.IsCancellationRequested)
                    completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
                try { dialog.Hide(); } catch { }
            }
        }

        Task? pollingTask = null;
        dialog.Opened += (_, _) =>
        {
            core.Navigate(startUri.AbsoluteUri);
            pollingTask = PollForCookieAsync();
        };

        ContentDialogResult dialogResult;
        try
        {
            using (RdpOverlayCoordinator.Suppress())
            {
                dialogResult = await ContentDialogTracker.ShowAsync(dialog, cancellationToken);
            }
        }
        finally
        {
            pollingCts.Cancel();
            if (pollingTask is not null)
            {
                try { await pollingTask.ConfigureAwait(true); }
                catch (OperationCanceledException) { }
            }
            await DeleteSvpnCookiesAsync().ConfigureAwait(true);
        }

        if (completion.Task.IsCompleted)
            return await completion.Task.ConfigureAwait(true);

        cancellationToken.ThrowIfCancellationRequested();
        if (dialogResult == ContentDialogResult.None)
            throw new UserInteractionCancelledException("Fortinet SAML authentication was cancelled by the user.");
        throw new UserInteractionCancelledException("Fortinet SAML authentication closed before login completed.");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _shutdownCts.Cancel(); } catch { }
        try { _shutdownCts.Dispose(); } catch { }
        // _authGate is process-lived with this singleton. Do not dispose it while an
        // in-flight authentication may still need to release it during app shutdown.
    }
}
