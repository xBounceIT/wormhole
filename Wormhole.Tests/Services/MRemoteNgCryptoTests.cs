using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Wormhole.Services.MRemoteNg;
using Xunit;

namespace Wormhole.Tests.Services;

public class MRemoteNgCryptoTests
{
    private const string DefaultPassword = "mR3m";
    private const int DefaultIterations = 10000;

    [Fact]
    public void TryDecryptUtf8_Roundtrip_RecoversPlaintext()
    {
        var encrypted = Encrypt("ThisIsProtected", DefaultPassword, DefaultIterations);

        var ok = MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, DefaultIterations, out var plain);

        Assert.True(ok);
        Assert.Equal("ThisIsProtected", plain);
    }

    [Fact]
    public void TryDecryptUtf8_WrongPassword_ReturnsFalseWithoutThrowing()
    {
        var encrypted = Encrypt("hunter2", DefaultPassword, DefaultIterations);

        var ok = MRemoteNgCrypto.TryDecryptUtf8(encrypted, "notTheRightPassword", DefaultIterations, out var plain);

        Assert.False(ok);
        Assert.Equal(string.Empty, plain);
    }

    [Fact]
    public void TryDecryptUtf8_WrongIterations_ReturnsFalse()
    {
        var encrypted = Encrypt("hunter2", DefaultPassword, DefaultIterations);

        // Different iteration count derives a different key — should fail the GCM tag check.
        var ok = MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, 1000, out _);

        Assert.False(ok);
    }

    [Fact]
    public void TryDecryptUtf8_MalformedBase64_ReturnsFalse()
    {
        var ok = MRemoteNgCrypto.TryDecryptUtf8("not!valid!base64!!", DefaultPassword, DefaultIterations, out var plain);

        Assert.False(ok);
        Assert.Equal(string.Empty, plain);
    }

    [Fact]
    public void TryDecryptUtf8_EmptyInput_ReturnsFalse()
    {
        Assert.False(MRemoteNgCrypto.TryDecryptUtf8(string.Empty, DefaultPassword, DefaultIterations, out _));
        Assert.False(MRemoteNgCrypto.TryDecryptUtf8(null!, DefaultPassword, DefaultIterations, out _));
    }

    [Fact]
    public void TryDecryptUtf8_TooShortBlob_ReturnsFalse()
    {
        // Less than salt(16)+nonce(16)+tag(16) = 48 bytes.
        var bytes = new byte[20];
        Assert.False(MRemoteNgCrypto.TryDecryptUtf8(Convert.ToBase64String(bytes), DefaultPassword, DefaultIterations, out _));
    }

    [Fact]
    public void TryDecryptUtf8_ZeroIterations_ReturnsFalse()
    {
        var encrypted = Encrypt("hunter2", DefaultPassword, DefaultIterations);
        Assert.False(MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, 0, out _));
        Assert.False(MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, -1, out _));
    }

    [Fact]
    public void TryDecryptUtf8_InvalidUtf8Payload_ReturnsFalseInsteadOfSubstituting()
    {
        // Construct a blob whose ciphertext decrypts to a byte sequence that is NOT valid UTF-8.
        // A lone 0x80 byte is a continuation byte with no leading byte — invalid in UTF-8.
        // The function should return false rather than silently substituting U+FFFD.
        var encrypted = EncryptRawBytes(new byte[] { 0x80, 0x80, 0x80 }, DefaultPassword, DefaultIterations);

        var ok = MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, DefaultIterations, out var plain);

        Assert.False(ok);
        Assert.Equal(string.Empty, plain);
    }

    [Fact]
    public void TryDecryptUtf8_PreservesUnicode()
    {
        // mRemoteNG stores UTF-8 plaintext — surrogate pairs, non-ASCII, etc. should round-trip.
        var input = "P@ssw0rd—ünì©öđé 🚀";
        var encrypted = Encrypt(input, DefaultPassword, DefaultIterations);

        var ok = MRemoteNgCrypto.TryDecryptUtf8(encrypted, DefaultPassword, DefaultIterations, out var plain);

        Assert.True(ok);
        Assert.Equal(input, plain);
    }

    // mRemoteNG-shaped GCM encrypt for tests. Mirrors MRemoteNgCrypto in reverse: 16-byte salt,
    // 16-byte nonce, AES-256-GCM with 16-byte tag, associated data = salt. Lives in the test
    // assembly so the production crypto file stays decrypt-only — we never need to encrypt
    // in production.
    internal static string Encrypt(string plaintext, string password, int iterations) =>
        EncryptRawBytes(Encoding.UTF8.GetBytes(plaintext), password, iterations);

    private static string EncryptRawBytes(byte[] plain, string password, int iterations)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA1, 32);

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(forEncryption: true, new AeadParameters(new KeyParameter(key), 128, nonce, salt));
        var outBuf = new byte[cipher.GetOutputSize(plain.Length)];
        var len = cipher.ProcessBytes(plain, 0, plain.Length, outBuf, 0);
        cipher.DoFinal(outBuf, len);
        // outBuf now contains ciphertext || tag.

        var blob = new byte[salt.Length + nonce.Length + outBuf.Length];
        Buffer.BlockCopy(salt, 0, blob, 0, salt.Length);
        Buffer.BlockCopy(nonce, 0, blob, salt.Length, nonce.Length);
        Buffer.BlockCopy(outBuf, 0, blob, salt.Length + nonce.Length, outBuf.Length);
        return Convert.ToBase64String(blob);
    }
}
