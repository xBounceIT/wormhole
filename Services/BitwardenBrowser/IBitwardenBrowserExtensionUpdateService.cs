namespace Wormhole.Services.BitwardenBrowser;

public interface IBitwardenBrowserExtensionUpdateService
{
    Task UpdateIfStaleAsync(CancellationToken cancellationToken = default);
}
