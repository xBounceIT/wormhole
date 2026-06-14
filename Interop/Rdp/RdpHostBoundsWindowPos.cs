using Wormhole.Helpers;

namespace Wormhole.Interop.Rdp;

internal static class RdpHostBoundsWindowPos
{
    internal static uint BuildFlags(bool sizeChanged, bool reveal)
    {
        var flags = Win32Interop.SWP_NOACTIVATE;
        if (reveal)
        {
            flags |= Win32Interop.SWP_SHOWWINDOW;
        }

        if (!sizeChanged)
        {
            flags |= Win32Interop.SWP_NOZORDER;
        }

        return flags;
    }
}
