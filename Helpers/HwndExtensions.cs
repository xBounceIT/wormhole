using Microsoft.UI.Xaml;
using WinRT.Interop;
namespace Wormhole.Helpers;

internal static class HwndExtensions
{
    public static IntPtr GetHwnd(this Window window)
    {
        return WindowNative.GetWindowHandle(window);
    }
}
