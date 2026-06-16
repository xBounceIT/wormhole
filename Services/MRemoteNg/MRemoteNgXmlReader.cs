using System.Xml.Linq;

namespace Wormhole.Services.MRemoteNg;

// Parses an mRemoteNG `<mrng:Connections>` XML document into a raw, string-attribute
// tree. Pure transform — no decryption, no persistence. The importer service decides
// what to do with each node afterwards.
internal static class MRemoteNgXmlReader
{
    internal const int MaxNestingDepth = 4096;

    private static readonly XNamespace Mrng = "http://mremoteng.org";

    public static MRemoteNgRoot Parse(Stream xml, out IReadOnlyList<MRemoteNgRawNode> roots)
        => Parse(xml, out roots, out _);

    public static MRemoteNgRoot Parse(
        Stream xml,
        out IReadOnlyList<MRemoteNgRawNode> roots,
        out bool hasPasswordPayloads)
    {
        ArgumentNullException.ThrowIfNull(xml);

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
        hasPasswordPayloads = false;
        var stack = new Stack<NodeReadStackEntry>();
        PushNodeElementsReverse(stack, rootElement.Elements(), parent: null, depth: 1);

        while (stack.Count > 0)
        {
            var entry = stack.Pop();
            var frame = entry.Frame;
            if (frame.Depth > MaxNestingDepth)
            {
                throw new InvalidDataException(
                    $"mRemoteNG nesting depth exceeds {MaxNestingDepth}; refusing to import.");
            }

            if (entry.Exiting)
            {
                var raw = BuildNode(frame, out var nodeHasPasswordPayload);
                if (frame.Parent is null)
                {
                    collected.Add(raw);
                    hasPasswordPayloads |= nodeHasPasswordPayload;
                }
                else
                {
                    frame.Parent.Children.Add(raw);
                    frame.Parent.HasPasswordPayload |= nodeHasPasswordPayload;
                }
                continue;
            }

            stack.Push(new NodeReadStackEntry(frame, Exiting: true));
            PushNodeElementsReverse(stack, frame.Element.Elements(), frame, frame.Depth + 1);
        }

        roots = collected;
        return root;
    }

    private static bool IsNodeElement(XElement element) =>
        string.Equals(element.Name.LocalName, "Node", StringComparison.Ordinal);

    private static MRemoteNgRawNode BuildNode(NodeReadFrame frame, out bool hasPasswordPayload)
    {
        var element = frame.Element;
        var passwordCipher = Attr(element, "Password");
        var inheritPassword = AttrBool(element, "InheritPassword");
        hasPasswordPayload = frame.HasPasswordPayload ||
                             (!inheritPassword && !string.IsNullOrWhiteSpace(passwordCipher));

        return new MRemoteNgRawNode(
            Type: Attr(element, "Type"),
            Name: Attr(element, "Name"),
            Description: Attr(element, "Descr"),
            Protocol: Attr(element, "Protocol"),
            Hostname: Attr(element, "Hostname"),
            Port: Attr(element, "Port"),
            Username: Attr(element, "Username"),
            Domain: Attr(element, "Domain"),
            PasswordCipher: passwordCipher,
            Resolution: Attr(element, "Resolution"),
            // Inherit* attributes only present on older exports; modern mRemoteNG
            // collapses inheritance into per-leaf duplication. We honor either form.
            InheritUsername: AttrBool(element, "InheritUsername"),
            InheritDomain: AttrBool(element, "InheritDomain"),
            InheritPassword: inheritPassword,
            InheritHostname: AttrBool(element, "InheritHostname"),
            InheritPort: AttrBool(element, "InheritPort"),
            InheritProtocol: AttrBool(element, "InheritProtocol"),
            InheritResolution: AttrBool(element, "InheritResolution"),
            Children: frame.Children);
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

    private static void PushNodeElementsReverse(
        Stack<NodeReadStackEntry> stack,
        IEnumerable<XElement> elements,
        NodeReadFrame? parent,
        int depth)
    {
        var nodes = elements.Where(IsNodeElement).ToList();
        for (var i = nodes.Count - 1; i >= 0; i--)
        {
            stack.Push(new NodeReadStackEntry(
                new NodeReadFrame(nodes[i], parent, depth),
                Exiting: false));
        }
    }

    private readonly record struct NodeReadStackEntry(NodeReadFrame Frame, bool Exiting);

    private sealed class NodeReadFrame
    {
        public NodeReadFrame(XElement element, NodeReadFrame? parent, int depth)
        {
            Element = element;
            Parent = parent;
            Depth = depth;
        }

        public XElement Element { get; }
        public NodeReadFrame? Parent { get; }
        public int Depth { get; }
        public List<MRemoteNgRawNode> Children { get; } = new();
        public bool HasPasswordPayload { get; set; }
    }
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
