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
          color-scheme: light;
          --wh-bg: #ffffff;
          --wh-text: #1f242b;
          --wh-muted: #5f6875;
          --wh-link: #005fb8;
          --wh-code-bg: #eef1f5;
          --wh-border: #d8dee8;
          font-family: "Segoe UI", Arial, sans-serif;
          font-size: 14px;
          line-height: 1.45;
        }
        @media (prefers-color-scheme: dark) {
          :root {
            color-scheme: dark;
            --wh-bg: #1e1f22;
            --wh-text: #f2f5f9;
            --wh-muted: #b5beca;
            --wh-link: #8ec5ff;
            --wh-code-bg: #2b2d31;
            --wh-border: #444b57;
          }
        }
        html {
          min-height: 100%;
          background: var(--wh-bg);
        }
        body {
          box-sizing: border-box;
          min-height: 100vh;
          margin: 0;
          padding: 14px 16px;
          background: var(--wh-bg);
          color: var(--wh-text);
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
        a { color: var(--wh-link); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
          font-family: Consolas, "Cascadia Mono", monospace;
          font-size: 0.92em;
          padding: 1px 4px;
          border-radius: 4px;
          background: var(--wh-code-bg);
        }
        pre {
          overflow-x: auto;
          padding: 10px 12px;
          border-radius: 6px;
          background: var(--wh-code-bg);
        }
        pre code {
          padding: 0;
          background: transparent;
        }
        blockquote {
          padding-left: 12px;
          border-left: 3px solid var(--wh-border);
          color: var(--wh-muted);
        }
        table {
          width: 100%;
          border-collapse: collapse;
        }
        th, td {
          padding: 6px 8px;
          border: 1px solid var(--wh-border);
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
