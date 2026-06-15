using System.Runtime.InteropServices;
using Windows.Security.Credentials.UI;

namespace Wormhole.Services.Security;

public sealed class WindowsHelloService : IWindowsHelloService
{
    public async Task<WindowsHelloAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync().AsTask(cancellationToken).ConfigureAwait(false);
            return availability switch
            {
                UserConsentVerifierAvailability.Available =>
                    new WindowsHelloAvailability(true, "Windows Hello is available."),
                UserConsentVerifierAvailability.DeviceBusy =>
                    new WindowsHelloAvailability(false, "Windows Hello is busy."),
                UserConsentVerifierAvailability.DeviceNotPresent =>
                    new WindowsHelloAvailability(false, "No Windows Hello device is present."),
                UserConsentVerifierAvailability.DisabledByPolicy =>
                    new WindowsHelloAvailability(false, "Windows Hello is disabled by policy."),
                UserConsentVerifierAvailability.NotConfiguredForUser =>
                    new WindowsHelloAvailability(false, "Windows Hello is not configured for this Windows user."),
                _ =>
                    new WindowsHelloAvailability(false, "Windows Hello is unavailable."),
            };
        }
        catch (Exception ex) when (IsExpectedWindowsHelloFailure(ex))
        {
            return new WindowsHelloAvailability(false, "Windows Hello is unavailable.");
        }
    }

    public async Task<WindowsHelloVerification> RequestVerificationAsync(
        IntPtr ownerHwnd,
        string message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var result = ownerHwnd == IntPtr.Zero
                ? await UserConsentVerifier.RequestVerificationAsync(message).AsTask(cancellationToken).ConfigureAwait(false)
                : await UserConsentVerifierInterop.RequestVerificationForWindowAsync(ownerHwnd, message).AsTask(cancellationToken).ConfigureAwait(false);

            return result switch
            {
                UserConsentVerificationResult.Verified =>
                    new WindowsHelloVerification(true, "Verified."),
                UserConsentVerificationResult.Canceled =>
                    new WindowsHelloVerification(false, "Windows Hello was canceled."),
                UserConsentVerificationResult.DeviceBusy =>
                    new WindowsHelloVerification(false, "Windows Hello is busy."),
                UserConsentVerificationResult.DeviceNotPresent =>
                    new WindowsHelloVerification(false, "No Windows Hello device is present."),
                UserConsentVerificationResult.DisabledByPolicy =>
                    new WindowsHelloVerification(false, "Windows Hello is disabled by policy."),
                UserConsentVerificationResult.NotConfiguredForUser =>
                    new WindowsHelloVerification(false, "Windows Hello is not configured for this Windows user."),
                UserConsentVerificationResult.RetriesExhausted =>
                    new WindowsHelloVerification(false, "Windows Hello retries were exhausted."),
                _ =>
                    new WindowsHelloVerification(false, "Windows Hello verification failed."),
            };
        }
        catch (Exception ex) when (IsExpectedWindowsHelloFailure(ex))
        {
            return new WindowsHelloVerification(false, "Windows Hello is unavailable.");
        }
    }

    private static bool IsExpectedWindowsHelloFailure(Exception ex) =>
        ex is UnauthorizedAccessException
            or InvalidOperationException
            or NotSupportedException
            or COMException
            or InvalidCastException;
}
