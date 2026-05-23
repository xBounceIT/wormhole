using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Wormhole.Services.MRemoteNg;

// Mirrors mRemoteNG's AeadCryptographyProvider for ConfVersion 2.7 exports:
// EncryptionEngine="AES", BlockCipherMode="GCM", KDF=PBKDF2-HMAC-SHA1, key=256 bits.
// Layout of the base64 blob: salt(16) | nonce(16) | ciphertext | tag(16).
// Associated data = salt.
// .NET's System.Security.Cryptography.AesGcm rejects nonces other than 12 bytes, so we
// drive the GCM cipher through BouncyCastle which accepts mRemoteNG's 16-byte nonce.
internal static class MRemoteNgCrypto
{
    private const int SaltLength = 16;
    private const int NonceLength = 16;
    private const int TagLength = 16;
    private const int KeyLength = 32;

    // Strict UTF-8 decoder — throws DecoderFallbackException on invalid sequences instead of
    // silently substituting U+FFFD. Without this, a corrupt or forged payload that happens to
    // pass the GCM tag check would surface as a string of replacement characters and we'd
    // store that as a "password" that can never authenticate.
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static bool TryDecryptUtf8(string base64, string password, int kdfIterations, out string plaintext)
    {
        plaintext = string.Empty;
        if (string.IsNullOrEmpty(base64)) return false;
        if (kdfIterations <= 0) return false;

        byte[] blob;
        try { blob = Convert.FromBase64String(base64); }
        catch (FormatException) { return false; }

        if (blob.Length < SaltLength + NonceLength + TagLength) return false;

        var salt = new byte[SaltLength];
        Buffer.BlockCopy(blob, 0, salt, 0, SaltLength);
        var nonce = new byte[NonceLength];
        Buffer.BlockCopy(blob, SaltLength, nonce, 0, NonceLength);
        var cipherLength = blob.Length - SaltLength - NonceLength - TagLength;
        var ciphertextWithTag = new byte[cipherLength + TagLength];
        Buffer.BlockCopy(blob, SaltLength + NonceLength, ciphertextWithTag, 0, ciphertextWithTag.Length);

        byte[] key;
        try
        {
            // PBKDF2 with HMAC-SHA1 is what mRemoteNG uses; CA5379's "SHA1 is weak" advice
            // doesn't apply when we're matching a fixed external format we don't control.
#pragma warning disable CA5379
            key = Rfc2898DeriveBytes.Pbkdf2(password, salt, kdfIterations, HashAlgorithmName.SHA1, KeyLength);
#pragma warning restore CA5379
        }
        catch (Exception)
        {
            return false;
        }

        byte[] plain;
        try
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            // macSize is in bits; mRemoteNG uses a 128-bit GCM tag.
            var parameters = new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, salt);
            cipher.Init(forEncryption: false, parameters);
            plain = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
            var len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, plain, 0);
            cipher.DoFinal(plain, len);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        try
        {
            plaintext = StrictUtf8.GetString(plain);
        }
        catch (DecoderFallbackException)
        {
            // Tag verified but the payload isn't valid UTF-8 — treat as a decryption failure
            // rather than passing replacement characters off as a password.
            return false;
        }
        return true;
    }
}
