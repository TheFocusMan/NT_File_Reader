using System.Runtime.InteropServices;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FileHeader
    {
        public Machine Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
}