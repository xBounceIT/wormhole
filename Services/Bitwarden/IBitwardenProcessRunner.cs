namespace Wormhole.Services.Bitwarden;

public sealed record BitwardenProcessResult(int ExitCode, string StandardOutput, string StandardError);

public interface IBitwardenProcessRunner
{
    Task<BitwardenProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string?>? environment = null,
        CancellationToken cancellationToken = default);
}
