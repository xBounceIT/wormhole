using Microsoft.UI.Xaml.Data;
namespace Wormhole.Helpers.Converters;

/// <summary>True (directory) -> folder glyph; false (file) -> document glyph. Used by
/// the file transfer pane to label entries without a separate icon column per type.</summary>
public sealed class DirectoryGlyphConverter : IValueConverter
{
    // Segoe Fluent Icons: Folder (E8B7), Document (E8A5).
    private const string FolderGlyph = "";
    private const string FileGlyph = "";

    public object Convert(object value, Type targetType, object parameter, string language)
        => value is bool b && b ? FolderGlyph : FileGlyph;

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotImplementedException();
}
