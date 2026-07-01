using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class ConnectionCredentialBindingService : IConnectionCredentialBindingService
{
    private readonly IConnectionRepository _connections;
    private readonly ICredentialService _credentials;
    private readonly IConnectionNodeChangeNotifier? _connectionNodeChanges;
    private readonly ILogger<ConnectionCredentialBindingService> _logger;

    public ConnectionCredentialBindingService(
        IConnectionRepository connections,
        ICredentialService credentials,
        ILogger<ConnectionCredentialBindingService> logger,
        IConnectionNodeChangeNotifier? connectionNodeChanges = null)
    {
        _connections = connections;
        _credentials = credentials;
        _connectionNodeChanges = connectionNodeChanges;
        _logger = logger;
    }

    public async Task SaveCredentialBindingAsync(
        Guid nodeId,
        CredentialProfile credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        try
        {
            var node = await _connections.GetByIdAsync(nodeId, cancellationToken).ConfigureAwait(false);
            if (node is null)
            {
                _logger.LogWarning("Could not save credential binding for missing connection node {NodeId}.", nodeId);
                return;
            }

            if (node.Kind != NodeKind.Connection)
            {
                _logger.LogWarning(
                    "Could not save credential binding for node {NodeId} because it is a {Kind}.",
                    nodeId,
                    node.Kind);
                return;
            }

            node.CredentialId = credential.Id;
            node.CredentialMode = CredentialBindingMode.Saved;
            node.UseInlinePassword = false;
            node.PendingInlinePassword = null;

            if (!string.IsNullOrWhiteSpace(credential.Username))
            {
                node.Username = credential.Username.Trim();
            }

            if (credential.Protocol == ProtocolType.Rdp)
            {
                node.RdpDomain = string.IsNullOrWhiteSpace(credential.Domain)
                    ? null
                    : credential.Domain.Trim();
            }

            await _connections.UpdateAsync(node, cancellationToken).ConfigureAwait(false);
            _connectionNodeChanges?.PublishConnectionNodeUpdated(node);
            await _credentials.DeletePasswordAsync(nodeId).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save credential binding for connection node {NodeId}.", nodeId);
        }
    }
}
