using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Security;

public sealed class AppAuthenticationService : IAppAuthenticationService, IDisposable
{
    public const int DefaultPbkdf2Iterations = 600_000;

    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int PinMinLength = 4;
    private const int PinMaxLength = 12;
    private const int PasswordMinLength = 8;
    private const int PasswordMaxLength = 128;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private readonly string _storePath;
    private readonly int _pbkdf2Iterations;
    private readonly IAppAuthenticationDataProtector _protector;
    private readonly ILogger<AppAuthenticationService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AppAuthenticationService(ILogger<AppAuthenticationService> logger)
        : this(
            AppPaths.GetAppAuthenticationFilePath(),
            DefaultPbkdf2Iterations,
            logger,
            new DpapiAppAuthenticationDataProtector())
    {
    }

    public AppAuthenticationService(
        string storePath,
        int pbkdf2Iterations,
        ILogger<AppAuthenticationService> logger,
        IAppAuthenticationDataProtector? protector = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storePath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pbkdf2Iterations);

        _storePath = storePath;
        _pbkdf2Iterations = pbkdf2Iterations;
        _logger = logger;
        _protector = protector ?? new DpapiAppAuthenticationDataProtector();
    }

    public void Dispose() => _gate.Dispose();

    public AppAuthenticationSecretValidation ValidateSecret(AppAuthenticationFallbackMethod method, string secret)
    {
        secret ??= string.Empty;
        return method switch
        {
            AppAuthenticationFallbackMethod.Pin => ValidatePin(secret),
            AppAuthenticationFallbackMethod.Password => ValidatePassword(secret),
            _ => new AppAuthenticationSecretValidation(false, "Unsupported authentication method."),
        };
    }

    public async Task<AppAuthenticationSecretStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (doc, corrupted) = await ReadDocumentAsync(cancellationToken).ConfigureAwait(false);
            return new AppAuthenticationSecretStatus(
                doc.Pin is not null,
                doc.Password is not null,
                corrupted);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> IsConfiguredForModeAsync(
        AppAuthenticationMode mode,
        AppAuthenticationFallbackMethod fallback,
        CancellationToken cancellationToken = default)
    {
        if (mode == AppAuthenticationMode.Disabled) return false;
        var status = await GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status.IsCorrupted) return false;

        return mode switch
        {
            AppAuthenticationMode.Pin => status.HasPin,
            AppAuthenticationMode.Password => status.HasPassword,
            AppAuthenticationMode.WindowsHello => fallback == AppAuthenticationFallbackMethod.Pin
                ? status.HasPin
                : status.HasPassword,
            _ => false,
        };
    }

    public async Task SetSecretAsync(
        AppAuthenticationFallbackMethod method,
        string secret,
        CancellationToken cancellationToken = default)
    {
        var validation = ValidateSecret(method, secret);
        if (!validation.IsValid)
        {
            throw new ArgumentException(validation.Error, nameof(secret));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (doc, _) = await ReadDocumentAsync(cancellationToken).ConfigureAwait(false);
            var verifier = CreateVerifier(secret);
            switch (method)
            {
                case AppAuthenticationFallbackMethod.Pin:
                    doc.Pin = verifier;
                    break;
                case AppAuthenticationFallbackMethod.Password:
                    doc.Password = verifier;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(method), method, null);
            }
            await WriteDocumentAsync(doc, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> VerifySecretAsync(
        AppAuthenticationFallbackMethod method,
        string secret,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (doc, corrupted) = await ReadDocumentAsync(cancellationToken).ConfigureAwait(false);
            if (corrupted) return false;

            var verifier = method switch
            {
                AppAuthenticationFallbackMethod.Pin => doc.Pin,
                AppAuthenticationFallbackMethod.Password => doc.Password,
                _ => null,
            };
            if (verifier is null) return false;
            return Verify(secret, verifier);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAllAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                File.Delete(_storePath);
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static AppAuthenticationSecretValidation ValidatePin(string pin)
    {
        if (pin.Length is < PinMinLength or > PinMaxLength)
        {
            return new AppAuthenticationSecretValidation(false, "PIN must be 4 to 12 digits.");
        }
        foreach (var ch in pin)
        {
            if (!char.IsDigit(ch))
            {
                return new AppAuthenticationSecretValidation(false, "PIN can contain digits only.");
            }
        }
        return new AppAuthenticationSecretValidation(true, null);
    }

    private static AppAuthenticationSecretValidation ValidatePassword(string password)
    {
        if (password.Length is < PasswordMinLength or > PasswordMaxLength)
        {
            return new AppAuthenticationSecretValidation(false, "Password must be 8 to 128 characters.");
        }
        return new AppAuthenticationSecretValidation(true, null);
    }

    private AppAuthenticationVerifier CreateVerifier(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        try
        {
            return new AppAuthenticationVerifier
            {
                Salt = salt,
                Hash = Derive(secret, salt, _pbkdf2Iterations),
                Iterations = _pbkdf2Iterations,
            };
        }
        catch
        {
            CryptographicOperations.ZeroMemory(salt);
            throw;
        }
    }

    private static bool Verify(string secret, AppAuthenticationVerifier verifier)
    {
        if (verifier.Iterations <= 0 || verifier.Salt.Length == 0 || verifier.Hash.Length == 0)
        {
            return false;
        }

        var hash = Derive(secret, verifier.Salt, verifier.Iterations);
        try
        {
            return CryptographicOperations.FixedTimeEquals(hash, verifier.Hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static byte[] Derive(string secret, byte[] salt, int iterations)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                bytes,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                HashLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<(AppAuthenticationDocument Document, bool Corrupted)> ReadDocumentAsync(CancellationToken cancellationToken)
    {
        byte[] protectedBlob;
        try
        {
            protectedBlob = await File.ReadAllBytesAsync(_storePath, cancellationToken).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            return (new AppAuthenticationDocument(), false);
        }
        catch (DirectoryNotFoundException)
        {
            return (new AppAuthenticationDocument(), false);
        }

        byte[] plaintext;
        try
        {
            plaintext = _protector.Unprotect(protectedBlob);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            _logger.LogWarning(ex, "App authentication verifier store could not be unprotected.");
            return (new AppAuthenticationDocument(), true);
        }

        try
        {
            var doc = JsonSerializer.Deserialize<AppAuthenticationDocument>(plaintext, JsonOptions);
            if (doc is null || doc.Version != 1)
            {
                return (new AppAuthenticationDocument(), true);
            }
            if (!IsValidVerifierShape(doc.Pin) || !IsValidVerifierShape(doc.Password))
            {
                return (new AppAuthenticationDocument(), true);
            }
            return (doc, false);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "App authentication verifier store is not valid JSON.");
            return (new AppAuthenticationDocument(), true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task WriteDocumentAsync(AppAuthenticationDocument doc, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(doc, JsonOptions);
        try
        {
            var protectedBlob = _protector.Protect(plaintext);
            var tempPath = _storePath + ".tmp";
            await File.WriteAllBytesAsync(tempPath, protectedBlob, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, _storePath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private sealed class AppAuthenticationDocument
    {
        public int Version { get; set; } = 1;
        public AppAuthenticationVerifier? Pin { get; set; }
        public AppAuthenticationVerifier? Password { get; set; }
    }

    private sealed class AppAuthenticationVerifier
    {
        public byte[] Salt { get; set; } = Array.Empty<byte>();
        public byte[] Hash { get; set; } = Array.Empty<byte>();
        public int Iterations { get; set; }
    }

    private static bool IsValidVerifierShape(AppAuthenticationVerifier? verifier) =>
        verifier is null ||
        (verifier.Iterations > 0 &&
         verifier.Salt is { Length: SaltLength } &&
         verifier.Hash is { Length: HashLength });
}
