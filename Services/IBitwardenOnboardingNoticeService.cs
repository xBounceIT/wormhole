namespace Wormhole.Services;

public interface IBitwardenOnboardingNoticeService
{
    Task ShowIfNeededAsync(CancellationToken cancellationToken = default);
}
