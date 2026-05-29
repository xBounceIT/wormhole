namespace Wormhole.Services.Mcp;

/// <summary>
/// Owns the in-process MCP server (Kestrel, Streamable HTTP, bound to loopback). Started/stopped
/// from the Settings toggle and app lifecycle. The bearer token is stored in Windows Credential
/// Manager, never in settings.json.
/// </summary>
public interface IMcpServerHost
{
    bool IsRunning { get; }

    /// <summary>TCP port the server listens on (or would listen on, from settings, when stopped).</summary>
    int Port { get; }

    /// <summary>The loopback endpoint URL an MCP client connects to.</summary>
    string EndpointUrl { get; }

    Task StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>Read the existing token, generating and persisting one if none exists.</summary>
    Task<string> GetOrCreateTokenAsync();

    /// <summary>Read the existing token without creating one (null if none).</summary>
    Task<string?> PeekTokenAsync();

    /// <summary>Generate, persist, and activate a fresh token (revokes the old one immediately).</summary>
    Task<string> RegenerateTokenAsync();
}
