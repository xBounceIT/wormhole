namespace Wormhole.Models;

public enum AppAuthenticationMode
{
    Disabled,
    Pin,
    Password,
    WindowsHello,
}

public enum AppAuthenticationFallbackMethod
{
    Pin,
    Password,
}
