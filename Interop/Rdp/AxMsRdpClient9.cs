using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Wormhole.Interop.Rdp;

/// <summary>
/// Hand-rolled <see cref="AxHost"/> subclass for the <c>MsRdpClient9NotSafeForScripting</c>
/// ActiveX control (CLSID <c>{8B918B82-7985-4C24-89DF-C33AD2BBFBCD}</c>). We don't ship
/// AxImp-generated wrappers — Windows SDK NETFX Tools aren't always installed and the COM
/// surface we need is small. Property access is dynamic via <see cref="AxHost.GetOcx"/>;
/// events are wired in <see cref="RdpHostForm"/> through IConnectionPointContainer rather
/// than the AxHost CreateSink path.
/// </summary>
[DesignerCategory("")]
public sealed class AxMsRdpClient9NotSafeForScripting : AxHost
{
    /// <summary>CLSID for MsRdpClient9NotSafeForScripting (mstscax.dll). Documented in
    /// the MSDN Remote Desktop ActiveX reference; ProgID MsTscAxNotSafeForScripting.9.</summary>
    public const string ClsidString = "8B918B82-7985-4C24-89DF-C33AD2BBFBCD";

    public AxMsRdpClient9NotSafeForScripting() : base(ClsidString)
    {
    }

    /// <summary>Strongly typed access to the underlying OCX, cast to <see cref="object"/> so
    /// callers can use <c>dynamic</c> at the call site. Null until the OCX is realised
    /// (Handle creation triggers <see cref="AxHost.AttachInterfaces"/>).</summary>
    public object? Ocx => GetOcx();

    protected override void AttachInterfaces()
    {
        // No-op: callers reach properties through dynamic dispatch on Ocx. AxHost still
        // bootstraps the OCX during InPlaceActivate, which is all we need.
    }
}
