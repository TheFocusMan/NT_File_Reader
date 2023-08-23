using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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
