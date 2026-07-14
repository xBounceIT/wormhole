using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

public sealed class FakeCredentialPasswordResolver : ICredentialPasswordResolver
{
    private readonly ICredentialService _credentials;

    public FakeCredentialPasswordResolver(ICredentialService credentials)
    {
        _credentials = credentials;
    }

    public Task<string?> ReadPasswordAsync(
        CredentialProfile credential,
        BitwardenUnlockPrompt? unlockPrompt = null,
        CancellationToken cancellationToken = default) =>
        _credentials.ReadPasswordAsync(credential.Id);
}
