using System.Runtime.InteropServices;

namespace NT_File_Reader
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SectionHeader
    {
        public fixed byte Name[8];
        public uint PhysicalAddress_VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLineNumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLineNumbers;
        public uint Characteristics;
    }
}
