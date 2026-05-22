using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

public interface ITunnelProvider
{
    TunnelKind Kind { get; }
    Task<ITunnelInstance> EstablishAsync(TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken);
}
