using System;
using System.Text;
using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services;

public class SshHostKeyValidatorTests
{
    [Fact]
    public void ComputeFingerprint_ProducesOpenSshSha256Format()
    {
        var fp = SshHostKeyValidator.ComputeFingerprint(Encoding.UTF8.GetBytes("test"));
        Assert.StartsWith("SHA256:", fp);
        Assert.DoesNotContain("=", fp);
        Assert.True(fp.Length > "SHA256:".Length);
    }

    [Fact]
    public void ComputeFingerprint_DeterministicForSameInput()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        Assert.Equal(
            SshHostKeyValidator.ComputeFingerprint(bytes),
            SshHostKeyValidator.ComputeFingerprint(bytes));
    }

    [Fact]
    public void ComputeFingerprint_DiffersAcrossInputs()
    {
        var a = SshHostKeyValidator.ComputeFingerprint(new byte[] { 1, 2, 3 });
        var b = SshHostKeyValidator.ComputeFingerprint(new byte[] { 1, 2, 4 });
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeFingerprint_NullInputThrows()
    {
        Assert.Throws<ArgumentNullException>(() => SshHostKeyValidator.ComputeFingerprint(null!));
    }

    [Fact]
    public void Decide_NullKnown_ReturnsTofuAccept()
    {
        Assert.Equal(HostKeyDecision.TofuAccept,
            SshHostKeyValidator.Decide(null, "SHA256:abc"));
    }

    [Fact]
    public void Decide_EmptyKnown_ReturnsTofuAccept()
    {
        Assert.Equal(HostKeyDecision.TofuAccept,
            SshHostKeyValidator.Decide(string.Empty, "SHA256:abc"));
    }

    [Fact]
    public void Decide_EqualFingerprints_ReturnsTrust()
    {
        Assert.Equal(HostKeyDecision.Trust,
            SshHostKeyValidator.Decide("SHA256:abc", "SHA256:abc"));
    }

    [Fact]
    public void Decide_DifferentFingerprints_ReturnsMismatch()
    {
        Assert.Equal(HostKeyDecision.Mismatch,
            SshHostKeyValidator.Decide("SHA256:abc", "SHA256:xyz"));
    }

    [Fact]
    public void Decide_CaseSensitive()
    {
        Assert.Equal(HostKeyDecision.Mismatch,
            SshHostKeyValidator.Decide("SHA256:ABC", "SHA256:abc"));
    }

    [Fact]
    public void Decide_EmptyCaptured_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            SshHostKeyValidator.Decide("SHA256:abc", string.Empty));
    }
}
