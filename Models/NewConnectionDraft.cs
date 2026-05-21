using System;

namespace Wormhole.Models;

public sealed record NewConnectionDraft(
    string Name,
    ProtocolType Protocol,
    string Host,
    int? Port,
    string? Username,
    Guid? CredentialId = null);
