using System.Runtime.InteropServices;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NtHeaders32
    {
        public uint Signature;
        public FileHeader FileHeader;
        public OptionalHeaders32 OptionalHeader;
    }
}