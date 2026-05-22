namespace Wormhole.Interop.Rdp;

public sealed class RdpHostForm : IDisposable
{
    public IntPtr Hwnd { get; private set; } = IntPtr.Zero;

    public void Connect(string host, int port, string? username, string? domain, string? password)
    {
        // TODO: wire up AxMsRdpClient9NotSafeForScripting from a WinForms host.
        // Reference impl: https://github.com/castorix/WinUI3_ActiveX_MSRDP
        // Steps:
        //  1. Create a System.Windows.Forms.Form on STA.
        //  2. Add an AxMsRdpClient9NotSafeForScripting to it (requires AxImp-generated wrappers).
        //  3. Set Server, UserName, AdvancedSettings.ClearTextPassword, then Connect().
        //  4. Reparent the form's HWND into the WinUI placeholder via Win32 SetParent.
        //  5. Forward WM_SIZE to keep the child sized.
        throw new NotImplementedException(
            "RdpHostForm.Connect is a scaffold placeholder. Implement ActiveX host in the RDP feature PR.");
    }

#pragma warning disable CA1822 // stub — RDP feature PR will access ActiveX instance state
    public void Disconnect()
    {
    }
#pragma warning restore CA1822

    public void Dispose()
    {
    }
}
