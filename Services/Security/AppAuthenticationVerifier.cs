using System.Runtime.InteropServices;
using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed class AppAuthenticationVerifier : IAppAuthenticationVerifier
{
    private readonly IAppAuthenticationService _auth;
    private readonly IWindowsHelloService _hello;

    public AppAuthenticationVerifier(IAppAuthenticationService auth, IWindowsHelloService hello)
    {
        _auth = auth;
        _hello = hello;
    }

    public async Task<AppAuthenticationVerificationResult> VerifyAsync(
        AppAuthenticationMode mode,
        AppAuthenticationFallbackMethod fallback,
        IntPtr ownerHwnd,
        string windowsHelloMessage,
        Func<AppAuthenticationFallbackMethod, Task<string?>> promptSecretAsync,
        CancellationToken cancellationToken = default)
    {
        if (mode == AppAuthenticationMode.Disabled)
        {
            return new AppAuthenticationVerificationResult(true, null);
        }

        var secretMethod = mode switch
        {
            AppAuthenticationMode.Pin => AppAuthenticationFallbackMethod.Pin,
            AppAuthenticationMode.Password => AppAuthenticationFallbackMethod.Password,
            AppAuthenticationMode.WindowsHello => fallback,
            _ => fallback,
        };

        if (mode == AppAuthenticationMode.WindowsHello)
        {
            try
            {
                var availability = await _hello.CheckAvailabilityAsync(cancellationToken).ConfigureAwait(false);
                if (availability.IsAvailable)
                {
                    var hello = await _hello.RequestVerificationAsync(ownerHwnd, windowsHelloMessage, cancellationToken).ConfigureAwait(false);
                    if (hello.IsVerified)
                    {
                        return new AppAuthenticationVerificationResult(true, null);
                    }
                }
            }
            catch (Exception ex) when (ShouldUseFallbackForWindowsHelloFailure(ex))
            {
                // Fall through to the configured Wormhole PIN/password fallback.
            }
        }

        var secret = await promptSecretAsync(secretMethod).ConfigureAwait(false);
        if (secret is null)
        {
            return new AppAuthenticationVerificationResult(false, "Authentication was canceled.");
        }

        var verified = await _auth.VerifySecretAsync(secretMethod, secret, cancellationToken).ConfigureAwait(false);
        return verified
            ? new AppAuthenticationVerificationResult(true, null)
            : new AppAuthenticationVerificationResult(false, secretMethod == AppAuthenticationFallbackMethod.Pin
                ? "Invalid PIN."
                : "Invalid password.");
    }

    private static bool ShouldUseFallbackForWindowsHelloFailure(Exception ex) =>
        ex is UnauthorizedAccessException
            or InvalidOperationException
            or NotSupportedException
            or COMException
            or InvalidCastException;
}
