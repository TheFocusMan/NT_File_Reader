using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
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
        public byte bCertificate;
    }
    public static class SignedDataExtentions
    {
        public static ref byte GetAsn1Header(ref byte data, out byte tag, out int length)
        {
            tag = data;
            data = ref Unsafe.Add(ref data, 1);
            byte lenByte = data;

            if ((lenByte & 0x80) == 0)
            {
                // Short form: 1 byte length (0-127)
                length = lenByte;
                data = ref Unsafe.Add(ref data, 1);
            }
            else
            {
                // Long form: lenByte's low 7 bits say how many bytes the length takes
                int numOctets = lenByte & 0x7F;
                length = 0;
                for (int i = 0; i < numOctets; i++)
                {
                    data = ref Unsafe.Add(ref data, 1);
                    length = (length << 8) | data;
                }
                data = ref Unsafe.Add(ref data, 1);
            }
            return ref data;
        }
    }
}
