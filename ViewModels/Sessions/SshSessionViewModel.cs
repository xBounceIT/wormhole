using System;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.Web.WebView2.Core;
using Renci.SshNet.Common;
using Wormhole.Data.Repositories;
using Wormhole.Interop.Terminal;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class SshSessionViewModel : SessionTabViewModel
{
    private readonly ISshSessionService _sshService;
    private readonly ISshCredentialResolver _credentialResolver;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SshSessionViewModel> _logger;

    private ISshSession? _session;
    private TerminalBridge? _bridge;
    private CancellationTokenSource? _cts;
    private CoreWebView2? _webView;
    private XamlRoot? _xamlRoot;
    private string? _initialKnownFingerprint;

    public SshSessionViewModel(
        ISshSessionService sshService,
        ISshCredentialResolver credentialResolver,
        IConnectionRepository connectionRepo,
        ILoggerFactory loggerFactory)
    {
        _sshService = sshService;
        _credentialResolver = credentialResolver;
        _connectionRepo = connectionRepo;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SshSessionViewModel>();
        PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Status))
            {
                OnPropertyChanged(nameof(IsConnecting));
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsFailed));
            }
        };
    }

    public override ProtocolType Protocol => ProtocolType.Ssh;

    [ObservableProperty]
    private string? errorMessage;

    public bool IsConnecting => Status == SessionStatus.Connecting;
    public bool IsConnected => Status == SessionStatus.Connected;
    public bool IsFailed => Status == SessionStatus.Failed;

    public void Initialize(ConnectionProfile profile)
    {
        Profile = profile;
        Title = string.IsNullOrEmpty(profile.Name) ? profile.Host : profile.Name;
        Status = SessionStatus.Disconnected;
        _initialKnownFingerprint = profile.SshKnownHostFingerprint;
    }

    public async Task AttachAsync(CoreWebView2 webView, XamlRoot xamlRoot)
    {
        if (Profile is null)
            throw new InvalidOperationException("Initialize must be called before AttachAsync.");
        if (_session is not null) return;

        _webView = webView;
        _xamlRoot = xamlRoot;
        await ConnectAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    public async Task RetryAsync()
    {
        if (_webView is null || _xamlRoot is null) return;
        await DetachAsync().ConfigureAwait(true);
        ErrorMessage = null;
        await ConnectAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    public Task DisconnectAsync() => DetachAsync();

    public async Task DetachAsync()
    {
        var cts = _cts;
        _cts = null;
        try { cts?.Cancel(); } catch { /* already disposed */ }

        var bridge = _bridge;
        _bridge = null;
        bridge?.Dispose();

        var session = _session;
        _session = null;
        if (session is not null)
        {
            try { await session.DisposeAsync().ConfigureAwait(true); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error disposing SSH session."); }
        }

        cts?.Dispose();
        Status = SessionStatus.Disconnected;
    }

    public void ReportFailure(string message)
    {
        ErrorMessage = message;
        Status = SessionStatus.Failed;
    }

    private async Task ConnectAsync()
    {
        if (Profile is null || _webView is null || _xamlRoot is null) return;

        Status = SessionStatus.Connecting;
        ErrorMessage = null;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            var creds = await _credentialResolver.ResolveAsync(Profile, _xamlRoot, token).ConfigureAwait(true);
            if (!creds.HasAny)
            {
                ReportFailure("No credentials provided.");
                return;
            }

            _session = await _sshService.ConnectAsync(Profile, creds.Password, creds.PrivateKey, token).ConfigureAwait(true);
            _bridge = new TerminalBridge(_webView, _session, _loggerFactory.CreateLogger<TerminalBridge>());

            if (_initialKnownFingerprint is null && _session is SshSession concrete && !string.IsNullOrEmpty(concrete.HostFingerprint))
            {
                try
                {
                    await _connectionRepo.UpdateHostFingerprintAsync(Profile.NodeId, concrete.HostFingerprint, token).ConfigureAwait(true);
                    _initialKnownFingerprint = concrete.HostFingerprint;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not persist host fingerprint for {Host}.", Profile.Host);
                }
            }

            Status = SessionStatus.Connected;
        }
        catch (OperationCanceledException)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            Status = SessionStatus.Disconnected;
        }
        catch (SshHostKeyMismatchException ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogWarning("Host key mismatch for {Host}.", Profile.Host);
        }
        catch (SshAuthenticationException ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure("Authentication failed: " + ex.Message);
        }
        catch (Exception ex)
        {
            await SafeDisposeSessionAsync().ConfigureAwait(true);
            ReportFailure(ex.Message);
            _logger.LogError(ex, "SSH connect failed for {Host}.", Profile.Host);
        }
    }

    private async Task SafeDisposeSessionAsync()
    {
        var bridge = _bridge;
        _bridge = null;
        bridge?.Dispose();

        var session = _session;
        _session = null;
        if (session is not null)
        {
            try { await session.DisposeAsync().ConfigureAwait(true); } catch { /* best effort */ }
        }
    }
}
