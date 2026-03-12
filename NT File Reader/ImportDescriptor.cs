using System.Runtime.InteropServices;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Explicit)]
    public struct ImportDescriptor
    {
        [FieldOffset(0)]
        public uint Characteristics;

        [FieldOffset(0)]
        public uint OriginalFirstThunk;

        [FieldOffset(4)]
        public uint TimeDateStamp;

        [FieldOffset(8)]
        public uint ForwarderChain;

        [FieldOffset(12)]
        public uint Name;

        [FieldOffset(16)]
        public uint FirstThunk;
    }
}
