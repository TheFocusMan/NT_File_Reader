using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Explicit)]
    public struct ThunkData32
    {
        [FieldOffset(0)]
        public uint ForwarderString;

        [FieldOffset(0)]
        public uint Function;

        [FieldOffset(0)]
        public uint Ordinal;

        [FieldOffset(0)]
        public uint AddressOfData;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ThunkData64
    {
        [FieldOffset(0)]
        public ulong ForwarderString;

        [FieldOffset(0)]
        public ulong Function;

        [FieldOffset(0)]
        public ulong Ordinal;

        [FieldOffset(0)]
        public ulong AddressOfData;
    }
}
