namespace Wormhole.Services.Security;

public sealed record WindowsHelloAvailability(bool IsAvailable, string Message);

public sealed record WindowsHelloVerification(bool IsVerified, string Message);

public interface IWindowsHelloService
{
    Task<WindowsHelloAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default);

    Task<WindowsHelloVerification> RequestVerificationAsync(
        IntPtr ownerHwnd,
        string message,
        CancellationToken cancellationToken = default);
}
