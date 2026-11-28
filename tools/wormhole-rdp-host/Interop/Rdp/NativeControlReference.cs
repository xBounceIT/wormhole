using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace Wormhole.Interop.Rdp;

// A local COM capability, never an authentication payload. Only the native Go
// parent consumes it; the adapter retains no passwords or cryptographic keys.
internal sealed class NativeControlReference : IDisposable
{
    private IStream? _stream;
    internal byte[] Data { get; }

    internal NativeControlReference(object control)
    {
        var iid = new Guid("00020400-0000-0000-C000-000000000046");
        Marshal.ThrowExceptionForHR(CreateStreamOnHGlobal(IntPtr.Zero, true, out var stream));
        var pointer = IntPtr.Zero;
        var marshaled = false;
        try
        {
            pointer = Marshal.GetIDispatchForObject(control);
            Marshal.ThrowExceptionForHR(CoMarshalInterface(stream, ref iid, pointer, 0, IntPtr.Zero, 1));
            marshaled = true;
            stream.Stat(out var stat, 1);
            if (stat.cbSize is < 1 or > 32768) throw new InvalidOperationException("native control reference exceeds limit");
            Data = new byte[(int)stat.cbSize];
            stream.Seek(0, 0, IntPtr.Zero);
            var read = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                stream.Read(Data, Data.Length, read);
                if (Marshal.ReadInt32(read) != Data.Length) throw new InvalidOperationException("native control reference is incomplete");
            }
            finally { Marshal.FreeHGlobal(read); }
            _stream = stream;
        }
        catch
        {
            if (marshaled) ReleaseReference(stream);
            Marshal.ReleaseComObject(stream);
            throw;
        }
        finally { if (pointer != IntPtr.Zero) Marshal.Release(pointer); }
    }

    public void Dispose()
    {
        var stream = _stream;
        _stream = null;
        if (stream is null) return;
        try { ReleaseReference(stream); }
        finally { Array.Clear(Data); Marshal.ReleaseComObject(stream); }
    }

    private static void ReleaseReference(IStream stream)
    {
        stream.Seek(0, 0, IntPtr.Zero);
        Marshal.ThrowExceptionForHR(CoReleaseMarshalData(stream));
    }

    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CreateStreamOnHGlobal(IntPtr memory, [MarshalAs(UnmanagedType.Bool)] bool deleteOnRelease, out IStream stream);
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoMarshalInterface(IStream stream, ref Guid iid, IntPtr control, uint context, IntPtr reserved, uint flags);
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoReleaseMarshalData(IStream stream);
}
