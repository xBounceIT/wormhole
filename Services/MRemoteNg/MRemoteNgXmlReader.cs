using System.Xml.Linq;

namespace Wormhole.Services.MRemoteNg;

// Parses an mRemoteNG `<mrng:Connections>` XML document into a raw, string-attribute
// tree. Pure transform — no decryption, no persistence. The importer service decides
// what to do with each node afterwards.
internal sealed class MRemoteNgXmlReader
{
    private static readonly XNamespace Mrng = "http://mremoteng.org";

    public MRemoteNgRoot Parse(Stream xml, out IReadOnlyList<MRemoteNgRawNode> roots)
    {
        if (xml is null) throw new ArgumentNullException(nameof(xml));

        XDocument doc;
        try { doc = XDocument.Load(xml); }
        catch (System.Xml.XmlException ex)
        {
            throw new InvalidDataException("File is not valid XML.", ex);
        }

        var rootElement = doc.Root
            ?? throw new InvalidDataException("XML document has no root element.");
        if (rootElement.Name != Mrng + "Connections")
        {
            throw new InvalidDataException(
                "Root element is not <mrng:Connections>. This does not look like an mRemoteNG export.");
        }

        var root = new MRemoteNgRoot(
            ConfVersion: Attr(rootElement, "ConfVersion"),
            EncryptionEngine: Attr(rootElement, "EncryptionEngine"),
            BlockCipherMode: Attr(rootElement, "BlockCipherMode"),
            Protected: Attr(rootElement, "Protected"),
            FullFileEncryption: string.Equals(Attr(rootElement, "FullFileEncryption"), "true", StringComparison.OrdinalIgnoreCase),
            KdfIterations: ParseInt(Attr(rootElement, "KdfIterations"), fallback: 1000));

        // Despite the root being in the mrng namespace, mRemoteNG emits child <Node> elements
        // with no namespace declaration of their own — they live in the empty namespace. Look
        // for elements by LocalName so we don't miss them.
        var collected = new List<MRemoteNgRawNode>();
        foreach (var nodeElement in rootElement.Elements().Where(IsNodeElement))
        {
            collected.Add(ReadNode(nodeElement));
        }
        roots = collected;
        return root;
    }

    private static bool IsNodeElement(XElement element) => element.Name.LocalName == "Node";

    private static MRemoteNgRawNode ReadNode(XElement element)
    {
        var children = new List<MRemoteNgRawNode>();
        foreach (var child in element.Elements().Where(IsNodeElement))
        {
            children.Add(ReadNode(child));
        }

        return new MRemoteNgRawNode(
            Type: Attr(element, "Type"),
            Name: Attr(element, "Name"),
            Description: Attr(element, "Descr"),
            Protocol: Attr(element, "Protocol"),
            Hostname: Attr(element, "Hostname"),
            Port: Attr(element, "Port"),
            Username: Attr(element, "Username"),
            Domain: Attr(element, "Domain"),
            PasswordCipher: Attr(element, "Password"),
            Resolution: Attr(element, "Resolution"),
            // Inherit* attributes only present on older exports; modern mRemoteNG
            // collapses inheritance into per-leaf duplication. We honor either form.
            InheritUsername: AttrBool(element, "InheritUsername"),
            InheritDomain: AttrBool(element, "InheritDomain"),
            InheritPassword: AttrBool(element, "InheritPassword"),
            InheritHostname: AttrBool(element, "InheritHostname"),
            InheritPort: AttrBool(element, "InheritPort"),
            InheritProtocol: AttrBool(element, "InheritProtocol"),
            InheritResolution: AttrBool(element, "InheritResolution"),
            Children: children);
    }

    private static string Attr(XElement element, string name)
        => element.Attribute(name)?.Value ?? string.Empty;

    private static bool AttrBool(XElement element, string name)
    {
        var raw = element.Attribute(name)?.Value;
        return string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase);
    }

    private static int ParseInt(string raw, int fallback)
        => int.TryParse(raw, out var n) && n > 0 ? n : fallback;
}

internal sealed record MRemoteNgRoot(
    string ConfVersion,
    string EncryptionEngine,
    string BlockCipherMode,
    string Protected,
    bool FullFileEncryption,
    int KdfIterations);

internal sealed record MRemoteNgRawNode(
    string Type,
    string Name,
    string Description,
    string Protocol,
    string Hostname,
    string Port,
    string Username,
    string Domain,
    string PasswordCipher,
    string Resolution,
    bool InheritUsername,
    bool InheritDomain,
    bool InheritPassword,
    bool InheritHostname,
    bool InheritPort,
    bool InheritProtocol,
    bool InheritResolution,
    IReadOnlyList<MRemoteNgRawNode> Children);
