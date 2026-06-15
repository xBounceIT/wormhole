using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed record AppAuthenticationVerificationResult(bool Succeeded, string? Message);

public interface IAppAuthenticationVerifier
{
    Task<AppAuthenticationVerificationResult> VerifyAsync(
        AppAuthenticationMode mode,
        AppAuthenticationFallbackMethod fallback,
        IntPtr ownerHwnd,
        string windowsHelloMessage,
        Func<AppAuthenticationFallbackMethod, Task<string?>> promptSecretAsync,
        CancellationToken cancellationToken = default);
}
