using System;
using Wormhole.Models;

namespace Wormhole.Services;

public interface IAppSettingsService
{
    AppSettings Current { get; }
    event EventHandler? SettingsChanged;
    void Save();
}
