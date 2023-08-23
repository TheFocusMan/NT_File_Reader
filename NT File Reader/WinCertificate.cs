using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NT_File_Reader
{
    [StructLayout(LayoutKind.Sequential,Pack = 1)]
    public unsafe struct WinCertificate
    {
        public uint dwLength;
        public ushort wRevision;
        public ushort wCertificateType;
        public fixed byte bCertificate[1];
    }
}
