using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Wormhole.Interop.Rdp;

/// <summary>
/// Hand-rolled <see cref="AxHost"/> subclass for the Remote Desktop
/// <c>MsRdpClient*NotSafeForScripting</c> ActiveX controls. We prefer the newest
/// registered mstscax class so the embedded host tracks the local mstsc.exe client more
/// closely, while falling back to the v9 class already used by older Wormhole builds.
/// Property access is dynamic via <see cref="AxHost.GetOcx"/>; events are wired in
/// <see cref="RdpHostForm"/> through IConnectionPointContainer rather than the AxHost
/// CreateSink path.
/// </summary>
[DesignerCategory("")]
internal sealed class AxMsRdpClient9NotSafeForScripting : AxHost
{
    /// <summary>CLSID for MsRdpClient9NotSafeForScripting (mstscax.dll). Kept as the
    /// fallback because every supported Wormhole install that previously worked has this
    /// class registered.</summary>
    private const string ClsidString = "8B918B82-7985-4C24-89DF-C33AD2BBFBCD";

    private static readonly RdpActiveXClass[] PreferredClasses =
    [
        new("MsRdpClient11NotSafeForScripting", "1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8"),
        new("MsRdpClient10NotSafeForScripting", "A0C63C30-F08D-4AB4-907C-34905D770C7D"),
        new("MsRdpClient9NotSafeForScripting", ClsidString),
    ];

    internal AxMsRdpClient9NotSafeForScripting(RdpActiveXClass activeXClass) : base(activeXClass.ClsidString)
    {
    }

    /// <summary>Strongly typed access to the underlying OCX, cast to <see cref="object"/> so
    /// callers can use <c>dynamic</c> at the call site. Null until the OCX is realised
    /// (Handle creation triggers <see cref="AxHost.AttachInterfaces"/>).</summary>
    internal object? Ocx => GetOcx();

    internal static IReadOnlyList<RdpActiveXClass> GetRegisteredClasses()
    {
        var registered = new List<RdpActiveXClass>();

        foreach (var candidate in PreferredClasses)
        {
            try
            {
                using var key = Registry.ClassesRoot.OpenSubKey($@"CLSID\{{{candidate.ClsidString}}}");
                if (key is not null) registered.Add(candidate);
            }
            catch
            {
                // Registry probing is best-effort. If access is denied or registry
                // virtualization behaves unexpectedly, the v9 fallback below still lets
                // AxHost surface the real COM activation error.
            }
        }

        if (registered.Count == 0)
        {
            registered.Add(PreferredClasses[^1]);
        }

        return registered;
    }

    protected override void AttachInterfaces()
    {
        // No-op: callers reach properties through dynamic dispatch on Ocx. AxHost still
        // bootstraps the OCX during InPlaceActivate, which is all we need.
    }

    internal sealed record RdpActiveXClass(string Name, string ClsidString);
}
