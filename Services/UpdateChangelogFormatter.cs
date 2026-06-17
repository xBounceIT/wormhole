using Markdig;

namespace Wormhole.Services;

internal static class UpdateChangelogFormatter
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UseAdvancedExtensions()
        .DisableHtml()
        .Build();

    public static string ToHtmlDocument(string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return string.Empty;

        var body = Markdown.ToHtml(markdown.Trim(), Pipeline);
        return BuildDocument(body);
    }

    private static string BuildDocument(string body) =>
        """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
        :root {
          color-scheme: light dark;
          font-family: "Segoe UI", Arial, sans-serif;
          font-size: 14px;
          line-height: 1.45;
        }
        body {
          box-sizing: border-box;
          margin: 0;
          padding: 14px 16px;
          background: Canvas;
          color: CanvasText;
        }
        :first-child { margin-top: 0; }
        :last-child { margin-bottom: 0; }
        h1, h2, h3, h4 {
          margin: 18px 0 8px;
          font-weight: 600;
          line-height: 1.25;
        }
        h1 { font-size: 22px; }
        h2 { font-size: 18px; }
        h3 { font-size: 16px; }
        p, ul, ol, pre, blockquote, table { margin: 0 0 12px; }
        ul, ol { padding-left: 22px; }
        li + li { margin-top: 4px; }
        a { color: LinkText; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
          font-family: Consolas, "Cascadia Mono", monospace;
          font-size: 0.92em;
          padding: 1px 4px;
          border-radius: 4px;
          background: color-mix(in srgb, CanvasText 10%, Canvas);
        }
        pre {
          overflow-x: auto;
          padding: 10px 12px;
          border-radius: 6px;
          background: color-mix(in srgb, CanvasText 10%, Canvas);
        }
        pre code {
          padding: 0;
          background: transparent;
        }
        blockquote {
          padding-left: 12px;
          border-left: 3px solid color-mix(in srgb, CanvasText 30%, Canvas);
          color: color-mix(in srgb, CanvasText 75%, Canvas);
        }
        table {
          width: 100%;
          border-collapse: collapse;
        }
        th, td {
          padding: 6px 8px;
          border: 1px solid color-mix(in srgb, CanvasText 20%, Canvas);
          text-align: left;
        }
        </style>
        </head>
        <body>
        """ + body + """
        </body>
        </html>
        """;
}
