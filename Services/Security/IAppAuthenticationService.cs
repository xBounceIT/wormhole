using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed record AppAuthenticationSecretStatus(bool HasPin, bool HasPassword, bool IsCorrupted);

public sealed record AppAuthenticationSecretValidation(bool IsValid, string? Error);

public interface IAppAuthenticationService
{
    AppAuthenticationSecretValidation ValidateSecret(AppAuthenticationFallbackMethod method, string secret);

    Task<AppAuthenticationSecretStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    Task<bool> IsConfiguredForModeAsync(
        AppAuthenticationMode mode,
        AppAuthenticationFallbackMethod fallback,
        CancellationToken cancellationToken = default);

    Task SetSecretAsync(
        AppAuthenticationFallbackMethod method,
        string secret,
        CancellationToken cancellationToken = default);

    Task<bool> VerifySecretAsync(
        AppAuthenticationFallbackMethod method,
        string secret,
        CancellationToken cancellationToken = default);

    Task DeleteAllAsync(CancellationToken cancellationToken = default);
}
