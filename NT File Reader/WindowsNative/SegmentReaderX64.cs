using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NT_File_Reader.WindowsNative
{
    public class SegmentReaderX64
    {
        /// <summary>
        /// Reads the TEB address from GS:[0x30] on x64 systems.
        /// </summary>
        public static IntPtr GetTebAddressX64()
        {
            // קוד מכונה ב-x64 (Opcode):
            // 65 48 8b 04 25 30 00 00 00 : mov rax, gs:[30h]
            // c3                         : ret
            ReadOnlySpan<byte> code = [0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xC3];

            return ExecuteNativeCode(code);
        }

        private unsafe static IntPtr ExecuteNativeCode(ReadOnlySpan<byte> code)
        {

            // חובה בשנת 2026: שינוי הרשאות ל-Execute (PAGE_EXECUTE_READWRITE = 0x40)
            // בגלל מנגנוני DEP ו-Control Flow Guard ב-Windows 11/12
            if (!VirtualProtect(ref MemoryMarshal.GetReference(code), (UIntPtr)code.Length, 0x40, out uint oldProtect))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return ((delegate*<nint>)Unsafe.AsPointer(ref MemoryMarshal.GetReference(code)))();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(scoped ref readonly byte lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
}
