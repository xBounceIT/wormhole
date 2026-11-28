using System.Diagnostics;
using System.Runtime.InteropServices;
using Wormhole.Interop.Rdp;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpNativeControlReferenceTests
{
    [Fact]
    public void LocalReferenceOwnsItsMarshalTableAndIsReleasedIdempotently()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var reference = new NativeControlReference(new PublicControlFixture());
                Assert.InRange(reference.Data.Length, 68, 32768);
                Assert.Equal(0x574f454du, BitConverter.ToUInt32(reference.Data));
                Assert.Equal(1u, BitConverter.ToUInt32(reference.Data, 4));
                reference.Dispose();
                reference.Dispose();
                Assert.All(reference.Data, value => Assert.Equal((byte)0, value));
                Assert.ThrowsAny<Exception>(() => new NativeControlReference(null!));
            }
            catch (Exception error) { failure = error; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)));
        Assert.Null(failure);
    }

    [Fact]
    public void AdapterProfileHasNoPrimaryOrGatewaySecretProperties()
    {
        Assert.Null(typeof(RdpHostProfile).GetProperty("Password"));
        Assert.Null(typeof(RdpHostProfile).GetProperty("GatewayPassword"));
        Assert.NotNull(typeof(RdpHostProfile).GetProperty("CredentialsProvided"));
    }

    // Set the probe to a compiled Go test binary to verify the actual parent/child
    // boundary and collect the helper's coverage as a child of this test process.
    [NativeRdpIntegrationFact]
    public async Task NativeParentExercisesActualActiveXHandoff()
    {
        var probe = Environment.GetEnvironmentVariable("WORMHOLE_TEST_RDP_GO_PROBE");
        Assert.True(probe is not null && Path.IsPathFullyQualified(probe) && File.Exists(probe));
        var host = Environment.GetEnvironmentVariable("WORMHOLE_TEST_RDP_HOST");
        Assert.True(host is not null && Path.IsPathFullyQualified(host) && File.Exists(host));
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(probe!)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { "-test.run=^TestNativeRdpCOM", "-test.v", "-test.timeout=60s" },
            },
        };
        Assert.True(process.Start());
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(70));
            await process.WaitForExitAsync(timeout.Token);
            var result = await output;
            Assert.True(process.ExitCode == 0, result + await errors);
            Assert.Contains("--- PASS: TestNativeRdpCOMCredentialBridge", result);
            Assert.Contains("--- PASS: TestNativeRdpCOMRejectsUnownedConnect", result);
            Assert.DoesNotContain("SKIP", result);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
        }
    }

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    public sealed class PublicControlFixture
    {
        public string Metadata { get; set; } = "synthetic public control";
    }
}

internal sealed class NativeRdpIntegrationFactAttribute : FactAttribute
{
    public NativeRdpIntegrationFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WORMHOLE_TEST_RDP_GO_PROBE")))
            Skip = "Set WORMHOLE_TEST_RDP_GO_PROBE and WORMHOLE_TEST_RDP_HOST for actual ActiveX verification";
    }
}
