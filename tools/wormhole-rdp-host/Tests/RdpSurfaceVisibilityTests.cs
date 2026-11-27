using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpSurfaceVisibilityTests
{
    [Fact]
    public void PublicVisibilityContractPreservesExplicitFalseAndLegacyDefault()
    {
        Assert.Null(new RdpHostCommand().Visible);
        var options = (System.Text.Json.JsonSerializerOptions)typeof(RdpHostApplicationContext)
            .GetField("JsonOptions", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        var command = System.Text.Json.JsonSerializer.Deserialize<RdpHostCommand>(
            "{\"visible\":false,\"op\":\"start\"}", options);
        Assert.NotNull(command);
        Assert.False(command.Visible);
    }

    [Fact]
    public void CaptureExclusionRejectsAnInvalidWindow()
    {
        Assert.Throws<InvalidOperationException>(() => Win32Interop.RequireCaptureExclusion(IntPtr.Zero));
    }

    [Fact]
    public void CrashReportingSuppressionPreservesTheOtherProcessFlags()
    {
        var original = Win32Interop.GetErrorMode();
        try
        {
            const uint failCriticalErrors = 0x0001;
            var baseline = (original | failCriticalErrors) & ~Win32Interop.SEM_NOGPFAULTERRORBOX;
            _ = SetErrorMode(baseline);
            Win32Interop.RequireCrashReportingSuppression();
            Assert.Equal(baseline | Win32Interop.SEM_NOGPFAULTERRORBOX, Win32Interop.GetErrorMode());
        }
        finally { _ = SetErrorMode(original); }
    }

    // Exercise real native HWND effects and the production event subscriptions,
    // without a remote account or server. No credential capability is exported.
    [NativeRdpIntegrationFact]
    public void NativeSurfacePreservesVisibilityAndCapturePolicyAcrossCallbacksAndHandles()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var originalErrorMode = Win32Interop.GetErrorMode();
            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                using var owner = new Form();
                _ = owner.Handle;
                foreach (var (visible, requireProtection) in new (bool?, bool)[]
                    { (null, false), (true, false), (false, false), (false, true) })
                {
                    using var context = new RdpHostApplicationContext(readCommands: false);
                    const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
                    var handle = typeof(RdpHostApplicationContext).GetMethod("HandleCommand", flags)!;
                    void Command(string operation) => handle.Invoke(context,
                        [new RdpHostCommand { Op = operation, RequestId = "public-visibility-control" }]);
                    try
                    {
                        handle.Invoke(context, [new RdpHostCommand
                        {
                            Op = requireProtection ? "startProtected" : "start",
                            RequestId = "public-visibility-start", Visible = visible,
                            OwnerWindow = owner.Handle.ToInt64().ToString(CultureInfo.InvariantCulture),
                            Bounds = new RdpHostBounds(-50000, -50000, 320, 240),
                            Profile = new RdpHostProfile
                            {
                                Host = "127.0.0.1", Port = ((IPEndPoint)listener.LocalEndpoint).Port,
                                Username = "synthetic", CredentialsProvided = true,
                            },
                        }]);
                        var form = (RdpHostForm?)typeof(RdpHostApplicationContext).GetField("_form", flags)!.GetValue(context);
                        Assert.NotNull(form);
                        void Raise(string name) => ((Action?)typeof(RdpHostForm).GetField(name, flags)!.GetValue(form))!();
                        void AssertProtected()
                        {
                            if (!requireProtection) return;
                            Assert.NotEqual(0u, Win32Interop.GetErrorMode() & Win32Interop.SEM_NOGPFAULTERRORBOX);
                            Assert.True(Win32Interop.GetWindowDisplayAffinity(form.Hwnd, out var affinity));
                            Assert.Equal(Win32Interop.WDA_EXCLUDEFROMCAPTURE, affinity);
                        }

                        AssertProtected();
                        Raise("Connected");
                        Assert.Equal(visible ?? true, IsWindowVisible(form.Hwnd));
                        Command("hide");
                        Raise("LoginComplete");
                        Assert.False(IsWindowVisible(form.Hwnd));
                        Raise("AutoReconnected");
                        Assert.False(IsWindowVisible(form.Hwnd));
                        Command("show");
                        Assert.True(IsWindowVisible(form.Hwnd));
                        AssertProtected();
                        Raise("AutoReconnected");
                        Assert.True(IsWindowVisible(form.Hwnd));
                        Command("hide");
                        Assert.False(IsWindowVisible(form.Hwnd));
                    }
                    finally { Command("disconnect"); }
                }

                var createForm = typeof(RdpHostApplicationContext).GetMethod("CreateRealizedHostForm",
                    BindingFlags.Static | BindingFlags.NonPublic)!;
                using var recreated = (RdpHostForm)createForm.Invoke(null, null)!;
                recreated.RequireContentProtection();
                var originalHandle = recreated.Hwnd;
                typeof(Control).GetMethod("RecreateHandle", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(recreated, null);
                Assert.NotEqual(originalHandle, recreated.Hwnd);
                Assert.True(Win32Interop.GetWindowDisplayAffinity(recreated.Hwnd, out var recreatedAffinity));
                Assert.Equal(Win32Interop.WDA_EXCLUDEFROMCAPTURE, recreatedAffinity);
            }
            catch (Exception error) { failure = error; }
            finally { _ = SetErrorMode(originalErrorMode); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "Native visibility test did not terminate");
        Assert.Null(failure);
    }

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint SetErrorMode(uint mode);
}
