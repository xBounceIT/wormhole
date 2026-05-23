using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Resolves a <see cref="ConnectionProfile"/>'s tunnel config and dispatches to the matching
/// <see cref="ITunnelProvider"/>. The returned <see cref="ITunnelInstance"/> is owned by the
/// caller (typically a session view-model), which disposes it when the session ends.
/// </summary>
public sealed class TunnelManager
{
    private readonly Dictionary<TunnelKind, ITunnelProvider> _providers;
    private readonly ITunnelConfigRepository _configs;
    private readonly ICredentialService _credentials;
    private readonly ILogger<TunnelManager> _logger;

    public TunnelManager(
        IEnumerable<ITunnelProvider> providers,
        ITunnelConfigRepository configs,
        ICredentialService credentials,
        ILogger<TunnelManager> logger)
    {
        // Group rather than ToDictionary so a duplicate registration (two providers claiming
        // the same TunnelKind) surfaces an actionable message instead of the raw
        // "An item with the same key has already been added." from ToDictionary.
        var byKind = new Dictionary<TunnelKind, ITunnelProvider>();
        foreach (var provider in providers)
        {
            if (byKind.TryGetValue(provider.Kind, out var existing))
            {
                throw new InvalidOperationException(
                    $"Multiple ITunnelProvider implementations registered for {provider.Kind}: " +
                    $"'{existing.GetType().FullName}' and '{provider.GetType().FullName}'. Register exactly one per kind.");
            }
            byKind[provider.Kind] = provider;
        }
        _providers = byKind;
        _configs = configs;
        _credentials = credentials;
        _logger = logger;
    }

    /// <summary>
    /// Establishes a tunnel for the given profile, or returns <c>null</c> when the profile is
    /// not configured to use one. The caller owns the returned instance and must dispose it.
    /// </summary>
    public async Task<ITunnelInstance?> EstablishAsync(ConnectionProfile profile, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!profile.TunnelEnabled) return null;
        if (profile.TunnelConfigId is null)
        {
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has TunnelEnabled=true but no TunnelConfigId set on itself or any ancestor.");
        }

        var configId = profile.TunnelConfigId.Value;
        var config = await _configs.GetByIdAsync(configId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Tunnel config {configId} for connection '{profile.Name}' was not found.");

        if (!_providers.TryGetValue(config.Kind, out var provider))
        {
            throw new InvalidOperationException(
                $"No tunnel provider is registered for kind '{config.Kind}'.");
        }

        var secret = await _credentials.ReadTunnelConfigAsync(configId).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Tunnel secret blob for config {configId} is missing on disk.");

        _logger.LogInformation("Establishing {Kind} tunnel '{Name}'.", config.Kind, config.Name);

        return await provider.EstablishAsync(config, secret, cancellationToken).ConfigureAwait(false);
    }
}
