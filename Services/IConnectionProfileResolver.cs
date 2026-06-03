using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services;

/// <summary>
/// Re-resolves a saved connection node into its effective <see cref="ConnectionProfile"/>
/// through folder inheritance, reading the current persisted state. Session tabs use this on
/// reconnect to pick up edits made after the tab was opened — most importantly a per-connection
/// VPN tunnel being disabled — instead of reusing the snapshot captured at open time.
/// </summary>
public interface IConnectionProfileResolver
{
    /// <summary>
    /// Returns the freshly-resolved profile for the connection node <paramref name="nodeId"/>,
    /// or <c>null</c> when the node no longer exists, is not a connection, or can't be resolved
    /// (e.g. its host/protocol was cleared on itself and every ancestor folder). Callers fall
    /// back to their cached profile when this returns <c>null</c>.
    /// </summary>
    Task<ConnectionProfile?> ResolveAsync(Guid nodeId, CancellationToken cancellationToken = default);
}
