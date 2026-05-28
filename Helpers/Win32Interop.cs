using System.Runtime.InteropServices;

namespace Wormhole.Helpers;

internal static class Win32Interop
{
    public static readonly IntPtr HWND_TOP = IntPtr.Zero;

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

    [DllImport("user32.dll")]
    public static extern uint GetDpiForWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowPos(
        IntPtr hWnd,
        IntPtr hWndInsertAfter,
        int X,
        int Y,
        int cx,
        int cy,
        uint uFlags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool RedrawWindow(IntPtr hWnd, IntPtr lprcUpdate, IntPtr hrgnUpdate, uint flags);

    // SetLastError = true so a NULL return can be diagnosed via Marshal.GetLastWin32Error.
    // SetFocus returns the previously-focused HWND (or IntPtr.Zero) and indicates failure
    // via NULL + nonzero GetLastError (NULL + zero error means the window had no prior
    // focus, which is a normal post-launch state). The native call itself does NOT throw.
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetFocus(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    // Maps a point in a window's client area to screen coordinates. Used to position the
    // owned RDP overlay (a top-level window) over the tab, which lives in the WinUI window's
    // client area.
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ClientToScreen(IntPtr hWnd, ref POINT lpPoint);

    // The *LongPtr accessors are required for HWND-sized values (GWLP_HWNDPARENT) and to be
    // safe on 64-bit; the app is x64/arm64 only, so the W entry points always exist.
    [DllImport("user32.dll", SetLastError = true, EntryPoint = "GetWindowLongPtrW")]
    public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true, EntryPoint = "SetWindowLongPtrW")]
    public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int left;
        public int top;
        public int right;
        public int bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int x;
        public int y;
    }

    public const uint WM_SIZE = 0x0005;
    public const uint WM_DPICHANGED = 0x02E0;

    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public const int SW_SHOWNA = 8; // Show without activating

    public const int GWL_STYLE = -16;
    public const int GWL_EXSTYLE = -20;
    public const int GWLP_HWNDPARENT = -8; // Owner HWND for a top-level window
    public const int WS_VISIBLE = 0x10000000;
    public const int WS_CHILD = 0x40000000;
    public const int WS_CLIPCHILDREN = 0x02000000;
    public const int WS_CLIPSIBLINGS = 0x04000000;
    public const int WS_POPUP = unchecked((int)0x80000000);

    public const int WS_EX_TOOLWINDOW = 0x00000080;  // No taskbar button / Alt-Tab entry

    public const uint SWP_NOSIZE = 0x0001;
    public const uint SWP_NOMOVE = 0x0002;
    public const uint SWP_NOZORDER = 0x0004;
    public const uint SWP_NOACTIVATE = 0x0010;
    public const uint SWP_FRAMECHANGED = 0x0020;
    public const uint SWP_SHOWWINDOW = 0x0040;

    public const uint RDW_INVALIDATE = 0x0001;
    public const uint RDW_ALLCHILDREN = 0x0080;
    public const uint RDW_UPDATENOW = 0x0100;
}
