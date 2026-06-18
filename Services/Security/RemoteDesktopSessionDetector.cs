using Wormhole.Helpers;

namespace Wormhole.Services.Security;

public sealed class RemoteDesktopSessionDetector : IRemoteDesktopSessionDetector
{
    private readonly Func<int, int> _getSystemMetrics;
    private readonly Func<string, string?> _getEnvironmentVariable;

    public RemoteDesktopSessionDetector()
        : this(Win32Interop.GetSystemMetrics, Environment.GetEnvironmentVariable)
    {
    }

    internal RemoteDesktopSessionDetector(
        Func<int, int> getSystemMetrics,
        Func<string, string?> getEnvironmentVariable)
    {
        _getSystemMetrics = getSystemMetrics;
        _getEnvironmentVariable = getEnvironmentVariable;
    }

    public bool IsRemoteDesktopSession()
    {
        if (_getSystemMetrics(Win32Interop.SM_REMOTESESSION) != 0)
        {
            return true;
        }

        var sessionName = _getEnvironmentVariable("SESSIONNAME");
        return sessionName?.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase) == true;
    }
}
