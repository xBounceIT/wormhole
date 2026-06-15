using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

/// <inheritdoc cref="ITunnelRoutePrompter"/>
public sealed class TunnelRoutePrompter : ITunnelRoutePrompter
{
    private const string FallbackTunnelName = "the configured VPN tunnel";

    private readonly IAppSettingsService _settings;
    private readonly IDialogService _dialog;
    private readonly ITunnelConfigRepository _configs;
    private readonly ILogger<TunnelRoutePrompter> _logger;

    public TunnelRoutePrompter(
        IAppSettingsService settings,
        IDialogService dialog,
        ITunnelConfigRepository configs,
        ILogger<TunnelRoutePrompter> logger)
    {
        _settings = settings;
        _dialog = dialog;
        _configs = configs;
        _logger = logger;
    }

    public async Task<ConnectionProfile?> ResolveRouteAsync(ConnectionProfile profile, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);

        // Nothing to choose: the profile isn't tunneled, or the user hasn't opted in to being
        // asked. Both return synchronously so the connect path is unchanged when the feature
        // is off — no extra dialog, no behavior difference for existing connections.
        if (!profile.TunnelEnabled) return profile;
        if (!_settings.Current.PromptBeforeTunnelConnect) return profile;

        var tunnelName = await ResolveTunnelNameAsync(profile, cancellationToken).ConfigureAwait(true);

        // A Disconnect during the (token-aware) name lookup, or in the window just before the
        // prompt opens, must abort the attempt rather than pop a stale route dialog for a connect
        // the user already cancelled. ResolveTunnelNameAsync lets cancellation propagate; this also
        // covers the no-config-id fast path, which doesn't await.
        cancellationToken.ThrowIfCancellationRequested();

        var choice = await _dialog.PromptTunnelRouteAsync(profile.Name, tunnelName, cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        return choice switch
        {
            // Force the tunnel off for this attempt; downstream EstablishAsync sees
            // TunnelEnabled=false and returns null → a direct connection.
            TunnelRouteChoice.Direct => profile with { TunnelEnabled = false },
            TunnelRouteChoice.Cancel => null,
            _ => profile,
        };
    }

    private async Task<string> ResolveTunnelNameAsync(ConnectionProfile profile, CancellationToken cancellationToken)
    {
        if (profile.TunnelConfigId is not { } configId) return FallbackTunnelName;
        try
        {
            var config = await _configs.GetByIdAsync(configId, cancellationToken).ConfigureAwait(true);
            return string.IsNullOrWhiteSpace(config?.Name) ? FallbackTunnelName : config!.Name;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The name is cosmetic — a real lookup failure must not block the routing decision.
            // Cancellation is deliberately NOT swallowed: it propagates so the connect aborts
            // (e.g. SSH's ConnectAsync OperationCanceledException handler) instead of showing a
            // stale prompt for an attempt the user already cancelled via Disconnect.
            _logger.LogWarning(ex, "Could not load tunnel config name for the routing prompt; using a generic label.");
            return FallbackTunnelName;
        }
    }
}
