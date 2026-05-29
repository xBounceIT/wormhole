using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Wormhole.Services.Mcp;

/// <inheritdoc />
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Microsoft.Reliability", "CA1001:Types that own disposable fields should be disposable",
    Justification = "The SemaphoreSlim gates (_lifecycleGate, _tokenGate) hold no OS handle unless " +
        "AvailableWaitHandle is touched (never), so GC reclaims them harmlessly. This is an app-lifetime " +
        "singleton; disposing them at shutdown is pointless. Mirrors the SshSession/SshSessionViewModel gate convention.")]
public sealed class McpServerHost : IMcpServerHost
{
    public const int DefaultPort = 8765;

    // Fixed Credential Manager key for the MCP bearer token (stored as "Wormhole:<guid>" by
    // CredentialService). A constant guid so the token round-trips across restarts.
    private static readonly Guid TokenCredentialId = new("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91");

    private readonly IAppSettingsService _settings;
    private readonly IMcpSessionRegistry _registry;
    private readonly ICredentialService _credentials;
    private readonly ILogger<McpServerHost> _logger;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    // Serializes the token read/generate/store path so concurrent first-time callers can't each
    // mint a different token (one caller would get a token that never becomes the active one).
    private readonly SemaphoreSlim _tokenGate = new(1, 1);

    private WebApplication? _app;
    private volatile string? _token;
    private int? _runningPort;

    public McpServerHost(
        IAppSettingsService settings,
        IMcpSessionRegistry registry,
        ICredentialService credentials,
        ILogger<McpServerHost> logger)
    {
        _settings = settings;
        _registry = registry;
        _credentials = credentials;
        _logger = logger;
    }

    public bool IsRunning => _app is not null;

    public int Port =>
        _runningPort
        ?? (_settings.Current.McpServerPort > 0 ? _settings.Current.McpServerPort : DefaultPort);

    public string EndpointUrl => $"http://127.0.0.1:{Port}";

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_app is not null) return;

            await GetOrCreateTokenAsync().ConfigureAwait(false);
            var port = _settings.Current.McpServerPort > 0 ? _settings.Current.McpServerPort : DefaultPort;

            var builder = WebApplication.CreateBuilder();
            // Bind loopback only — never expose the SSH-control surface beyond this machine.
            builder.WebHost.UseUrls($"http://{IPAddress.Loopback}:{port}");
            // Route Kestrel/ASP.NET logs into Wormhole's existing Serilog sink.
            builder.Logging.ClearProviders();
            builder.Logging.AddSerilog(Log.Logger, dispose: false);

            // Bridge the WinUI singleton into the Kestrel container so the tool type can depend on it.
            builder.Services.AddSingleton(_registry);
            builder.Services
                .AddMcpServer()
                .WithHttpTransport(options => options.Stateless = true)
                .WithTools<McpSshTools>();

            var app = builder.Build();
            try
            {
                app.Use(BearerAuthMiddleware);
                app.MapMcp();
                await app.StartAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Don't leak the half-built host (Kestrel listener, DI container) when binding
                // fails — e.g. the port is already in use. The caller logs and reverts the toggle.
                await app.DisposeAsync().ConfigureAwait(false);
                throw;
            }

            _app = app;
            _runningPort = port;
            _logger.LogInformation("MCP server listening on {Endpoint}.", EndpointUrl);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var app = _app;
            if (app is null) return;
            _app = null;
            _runningPort = null;
            try
            {
                await app.StopAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await app.DisposeAsync().ConfigureAwait(false);
            }
            _logger.LogInformation("MCP server stopped.");
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task<string> GetOrCreateTokenAsync()
    {
        // Fast path: a token already exists.
        var existing = await _credentials.ReadPasswordAsync(TokenCredentialId).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(existing))
        {
            _token = existing;
            return existing;
        }

        // Create-if-missing under the gate so racing callers (e.g. StartAsync + a Settings
        // copy/reveal) all observe the same token instead of each minting one.
        await _tokenGate.WaitAsync().ConfigureAwait(false);
        try
        {
            // Re-check: another caller may have created the token while we waited.
            existing = await _credentials.ReadPasswordAsync(TokenCredentialId).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(existing))
            {
                _token = existing;
                return existing;
            }
            return await GenerateAndStoreTokenAsync().ConfigureAwait(false);
        }
        finally
        {
            _tokenGate.Release();
        }
    }

    public Task<string?> PeekTokenAsync() => _credentials.ReadPasswordAsync(TokenCredentialId);

    public async Task<string> RegenerateTokenAsync()
    {
        // Serialized against GetOrCreateTokenAsync so an explicit regenerate and a concurrent
        // create-if-missing don't interleave and leave the active/persisted token inconsistent.
        await _tokenGate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await GenerateAndStoreTokenAsync().ConfigureAwait(false);
        }
        finally
        {
            _tokenGate.Release();
        }
    }

    // Caller must hold _tokenGate.
    private async Task<string> GenerateAndStoreTokenAsync()
    {
        var token = GenerateToken();
        await _credentials.StorePasswordAsync(TokenCredentialId, token).ConfigureAwait(false);
        _token = token; // takes effect immediately for the running server
        return token;
    }

    private async Task BearerAuthMiddleware(HttpContext context, RequestDelegate next)
    {
        var expected = _token;
        if (string.IsNullOrEmpty(expected) || !IsAuthorized(context.Request.Headers.Authorization.ToString(), expected))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: missing or invalid bearer token.").ConfigureAwait(false);
            return;
        }
        await next(context).ConfigureAwait(false);
    }

    private static bool IsAuthorized(string? header, string expected)
    {
        const string prefix = "Bearer ";
        if (string.IsNullOrEmpty(header) || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var presented = header[prefix.Length..].Trim();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presented),
            Encoding.UTF8.GetBytes(expected));
    }

    private static string GenerateToken()
    {
        Span<byte> buf = stackalloc byte[32];
        RandomNumberGenerator.Fill(buf);
        // URL-safe, unpadded so it's easy to paste into a client header / CLI flag.
        return Convert.ToBase64String(buf).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
