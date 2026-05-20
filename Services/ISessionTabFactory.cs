using Wormhole.Models;

namespace Wormhole.Services;

public interface ISessionTabFactory
{
    void Open(ConnectionProfile profile);
}
