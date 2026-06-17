using Windows.Foundation;

namespace Wormhole.Helpers;

public readonly record struct ModalOverlaySizing(
    double WidthRatio,
    double HeightRatio,
    double MinWidth,
    double MinHeight,
    double MaxWidth,
    double MaxHeight)
{
    public Size Calculate(Size hostSize, double margin) =>
        Calculate(hostSize, horizontalMargin: margin * 2, verticalMargin: margin * 2);

    public Size Calculate(Size hostSize, double horizontalMargin, double verticalMargin)
    {
        var availableWidth = Math.Max(0, hostSize.Width - horizontalMargin);
        var availableHeight = Math.Max(0, hostSize.Height - verticalMargin);

        var targetWidth = Math.Clamp(hostSize.Width * WidthRatio, MinWidth, MaxWidth);
        var targetHeight = Math.Clamp(hostSize.Height * HeightRatio, MinHeight, MaxHeight);

        if (availableWidth > 0)
        {
            targetWidth = Math.Min(targetWidth, availableWidth);
        }

        if (availableHeight > 0)
        {
            targetHeight = Math.Min(targetHeight, availableHeight);
        }

        return new Size(targetWidth, targetHeight);
    }
}
