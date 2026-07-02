namespace Wormhole.Services.Bitwarden;

public enum BitwardenVaultStatus
{
    Unknown,
    Unauthenticated,
    Locked,
    Unlocked,
}

public sealed record BitwardenStatus(
    BitwardenVaultStatus Status,
    string? UserEmail = null,
    string? ServerUrl = null,
    DateTimeOffset? LastSync = null);

public sealed record BitwardenLoginItem(
    string Id,
    string Name,
    string? Username,
    string? Password,
    string? RevisionDate = null);

public sealed class BitwardenVaultException : Exception
{
    public BitwardenVaultException(string message, bool isAuthenticationError = false)
        : base(message)
    {
        IsAuthenticationError = isAuthenticationError;
    }

    public BitwardenVaultException(string message, Exception innerException, bool isAuthenticationError = false)
        : base(message, innerException)
    {
        IsAuthenticationError = isAuthenticationError;
    }

    public bool IsAuthenticationError { get; }
}

public sealed class BitwardenUnlockCancelledException : OperationCanceledException
{
    public BitwardenUnlockCancelledException()
        : base("Bitwarden vault unlock was cancelled.")
    {
    }
}
