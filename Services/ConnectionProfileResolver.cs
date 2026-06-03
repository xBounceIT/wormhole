using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services;

/// <summary>
/// Resolves a connection node id to its effective <see cref="ConnectionProfile"/> by reading the
/// current repository state and running it through <see cref="InheritanceResolver"/> — the same
/// path <c>ConnectionTreeViewModel.OpenConnectionAsync</c> uses when first opening a tab.
/// </summary>
public sealed class ConnectionProfileResolver : IConnectionProfileResolver
{
    private readonly IConnectionRepository _repository;
    private readonly InheritanceResolver _inheritanceResolver;
    private readonly ILogger<ConnectionProfileResolver> _logger;

    public ConnectionProfileResolver(
        IConnectionRepository repository,
        InheritanceResolver inheritanceResolver,
        ILogger<ConnectionProfileResolver> logger)
    {
        _repository = repository;
        _inheritanceResolver = inheritanceResolver;
        _logger = logger;
    }

    public async Task<ConnectionProfile?> ResolveAsync(Guid nodeId, CancellationToken cancellationToken = default)
    {
        try
        {
            var all = await _repository.GetAllAsync(cancellationToken).ConfigureAwait(false);
            ConnectionNode? node = null;
            var byId = new Dictionary<Guid, ConnectionNode>(all.Count);
            foreach (var n in all)
            {
                byId[n.Id] = n;
                if (n.Id == nodeId) node = n;
            }

            // Node deleted since the tab opened (or it somehow points at a folder): let the
            // caller keep the profile it already has so a reconnect still does something sane.
            if (node is null || node.Kind != NodeKind.Connection) return null;

            return _inheritanceResolver.Resolve(node, byId);
        }
        catch (Exception ex)
        {
            // Resolve throws when host/protocol was cleared on the node and every ancestor; a
            // repository hiccup throws too. Neither should break reconnect — fall back to the
            // caller's cached profile, which is exactly the pre-existing behavior.
            _logger.LogWarning(ex, "Could not re-resolve connection profile for node {NodeId}; keeping the cached profile.", nodeId);
            return null;
        }
    }
}
