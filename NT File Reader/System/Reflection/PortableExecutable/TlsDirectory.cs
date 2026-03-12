using System.Runtime.InteropServices;

namespace System.Reflection.PortableExecutable
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TlsDirectory32
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;         // כתובת שבה המערכת תשמור את ה-TLS Index
        public uint AddressOfCallBacks;     // מצביע למערך של פונקציות Callback
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TlsDirectory64
    {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;         // כתובת שבה המערכת תשמור את ה-TLS Index
        public ulong AddressOfCallBacks;     // מצביע למערך של פונקציות Callback
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }
}
