using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public sealed class BitwardenCliVaultClient : IBitwardenVaultClient
{
    private const string PasswordEnvVar = "WORMHOLE_BW_PASSWORD";
    private const string SessionEnvVar = "BW_SESSION";
    private static readonly Regex SessionArgumentRegex = new(@"(?i)(--session(?:\s+|=))\S+", RegexOptions.Compiled);
    private static readonly Regex SessionEnvRegex = new(@"(?i)(BW_SESSION(?:\s*=\s*))\S+", RegexOptions.Compiled);
    private static readonly Regex PasswordEnvRegex = new(@"(?i)(WORMHOLE_BW_PASSWORD(?:\s*=\s*))\S+", RegexOptions.Compiled);
    private static readonly Regex TwoFactorCodeArgumentRegex = new(@"(?i)(--code(?:\s+|=))\S+", RegexOptions.Compiled);

    private readonly IBitwardenProcessRunner _runner;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<BitwardenCliVaultClient> _logger;

    public BitwardenCliVaultClient(
        IBitwardenProcessRunner runner,
        IAppSettingsService settings,
        ILogger<BitwardenCliVaultClient> logger)
    {
        _runner = runner;
        _settings = settings;
        _logger = logger;
    }

    public async Task<BitwardenStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var result = await RunAsync(["status"], null, cancellationToken).ConfigureAwait(false);
        using var document = ParseJsonDocument(result.StandardOutput, "Bitwarden status output was not valid JSON.");
        var root = document.RootElement;
        var status = ReadString(root, "status")?.ToLowerInvariant() switch
        {
            "unauthenticated" => BitwardenVaultStatus.Unauthenticated,
            "locked" => BitwardenVaultStatus.Locked,
            "unlocked" => BitwardenVaultStatus.Unlocked,
            _ => BitwardenVaultStatus.Unknown,
        };
        var lastSync = TryReadDateTimeOffset(root, "lastSync");
        return new BitwardenStatus(
            status,
            ReadString(root, "userEmail"),
            ReadString(root, "serverUrl"),
            lastSync);
    }

    public async Task<string> UnlockAsync(string masterPassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(masterPassword);
        var result = await RunAsync(
            ["unlock", "--passwordenv", PasswordEnvVar, "--raw"],
            new Dictionary<string, string?> { [PasswordEnvVar] = masterPassword },
            cancellationToken).ConfigureAwait(false);
        return ReadSessionKey(result.StandardOutput);
    }

    public async Task<string> LoginAsync(
        string email,
        string masterPassword,
        string? authenticatorCode = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentNullException.ThrowIfNull(masterPassword);

        var args = new List<string>
        {
            "login",
            email.Trim(),
            "--passwordenv",
            PasswordEnvVar,
            "--raw",
            "--nointeraction",
        };
        if (!string.IsNullOrWhiteSpace(authenticatorCode))
        {
            args.Add("--method");
            args.Add("0");
            args.Add("--code");
            args.Add(authenticatorCode.Trim().Replace(" ", string.Empty, StringComparison.Ordinal));
        }

        var result = await RunAsync(
            args,
            new Dictionary<string, string?> { [PasswordEnvVar] = masterPassword },
            cancellationToken).ConfigureAwait(false);
        return ReadSessionKey(result.StandardOutput);
    }

    public Task<IReadOnlyList<BitwardenLoginItem>> ListLoginItemsAsync(
        string? sessionKey,
        CancellationToken cancellationToken = default) =>
        ListLoginItemsCoreAsync(null, sessionKey, cancellationToken);

    public async Task<IReadOnlyList<BitwardenLoginItem>> SearchLoginItemsAsync(
        string query,
        string? sessionKey,
        CancellationToken cancellationToken = default)
    {
        await SyncAsync(sessionKey, cancellationToken).ConfigureAwait(false);
        return await ListLoginItemsCoreAsync(query, sessionKey, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<BitwardenLoginItem>> ListLoginItemsCoreAsync(
        string? query,
        string? sessionKey,
        CancellationToken cancellationToken)
    {
        var args = new List<string> { "list", "items" };
        if (!string.IsNullOrWhiteSpace(query))
        {
            args.Add("--search");
            args.Add(query.Trim());
        }
        var result = await RunAsync(args, BuildSessionEnvironment(sessionKey), cancellationToken).ConfigureAwait(false);
        using var document = ParseJsonDocument(result.StandardOutput, "Bitwarden item list output was not valid JSON.");
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new BitwardenVaultException("Bitwarden item list output was not a JSON array.");
        }

        var items = new List<BitwardenLoginItem>();
        foreach (var element in document.RootElement.EnumerateArray())
        {
            if (!IsLoginItem(element)) continue;
            if (MapLoginItem(element) is { } item) items.Add(item);
        }
        return items;
    }
    public async Task<BitwardenLoginItem?> GetLoginItemAsync(
        string itemId,
        string? sessionKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        var args = new List<string> { "get", "item", itemId };
        var result = await TryRunAsync(args, BuildSessionEnvironment(sessionKey), cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            if (IsNotFound(result.StandardError)) return null;
            ThrowProcessFailure(result);
        }

        using var document = ParseJsonDocument(result.StandardOutput, "Bitwarden item output was not valid JSON.");
        return IsLoginItem(document.RootElement) ? MapLoginItem(document.RootElement) : null;
    }

    public async Task SyncAsync(string? sessionKey, CancellationToken cancellationToken = default)
    {
        var args = new List<string> { "sync" };
        await RunAsync(args, BuildSessionEnvironment(sessionKey), cancellationToken).ConfigureAwait(false);
    }

    private async Task<BitwardenProcessResult> RunAsync(
        IReadOnlyList<string> args,
        IReadOnlyDictionary<string, string?>? environment,
        CancellationToken cancellationToken)
    {
        var result = await TryRunAsync(args, environment, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0) ThrowProcessFailure(result);
        return result;
    }

    private Task<BitwardenProcessResult> TryRunAsync(
        IReadOnlyList<string> args,
        IReadOnlyDictionary<string, string?>? environment,
        CancellationToken cancellationToken) =>
        _runner.RunAsync(ResolveCliPath(), args, environment, cancellationToken);

    private string ResolveCliPath() =>
        string.IsNullOrWhiteSpace(_settings.Current.BitwardenCliPath)
            ? "bw"
            : _settings.Current.BitwardenCliPath.Trim();

    private static Dictionary<string, string?>? BuildSessionEnvironment(string? sessionKey) =>
        string.IsNullOrWhiteSpace(sessionKey)
            ? null
            : new Dictionary<string, string?> { [SessionEnvVar] = sessionKey };

    private static string ReadSessionKey(string standardOutput)
    {
        var sessionKey = standardOutput.Trim();
        if (string.IsNullOrWhiteSpace(sessionKey))
        {
            throw new BitwardenVaultException("Bitwarden CLI did not return a session key.", isAuthenticationError: true);
        }
        return sessionKey;
    }

    private void ThrowProcessFailure(BitwardenProcessResult result)
    {
        var sanitized = SanitizeError(result.StandardError);
        var authError = IsAuthenticationError(result.StandardError) || IsAuthenticationError(result.StandardOutput);
        _logger.LogWarning("Bitwarden CLI command failed with exit code {ExitCode}: {Error}", result.ExitCode, sanitized);
        throw new BitwardenVaultException(
            string.IsNullOrWhiteSpace(sanitized) ? "Bitwarden CLI command failed." : sanitized,
            authError);
    }

    private static string SanitizeError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var trimmed = value.Trim();
        var redacted = SessionArgumentRegex.Replace(trimmed, "$1[redacted]");
        redacted = SessionEnvRegex.Replace(redacted, "$1[redacted]");
        redacted = TwoFactorCodeArgumentRegex.Replace(redacted, "$1[redacted]");
        redacted = PasswordEnvRegex.Replace(redacted, "$1[redacted]");
        return redacted.Length <= 500 ? redacted : redacted[..500];
    }

    private static bool IsAuthenticationError(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return value.Contains("locked", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("unauth", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("log in", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("login", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("session", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("two-step", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("two factor", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("two-factor", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNotFound(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        (value.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
         value.Contains("not exist", StringComparison.OrdinalIgnoreCase));

    private static JsonDocument ParseJsonDocument(string json, string errorMessage)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new BitwardenVaultException(errorMessage, ex);
        }
    }

    private static bool IsLoginItem(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty("login", out var login) &&
        login.ValueKind == JsonValueKind.Object &&
        (!element.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.Number || type.GetInt32() == 1);

    private static BitwardenLoginItem? MapLoginItem(JsonElement element)
    {
        var id = ReadString(element, "id");
        if (string.IsNullOrWhiteSpace(id)) return null;
        var name = ReadString(element, "name") ?? id;
        var revisionDate = ReadString(element, "revisionDate");
        string? username = null;
        string? password = null;
        if (element.TryGetProperty("login", out var login) && login.ValueKind == JsonValueKind.Object)
        {
            username = ReadString(login, "username");
            password = ReadString(login, "password");
        }
        return new BitwardenLoginItem(id, name, username, password, revisionDate);
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static DateTimeOffset? TryReadDateTimeOffset(JsonElement element, string propertyName) =>
        DateTimeOffset.TryParse(ReadString(element, propertyName), out var parsed) ? parsed : null;
}
