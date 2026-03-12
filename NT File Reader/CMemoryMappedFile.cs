using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NT_File_Reader
{
    public readonly ref struct MemoryMappedView(ref byte handle)
    {
        public readonly ref byte handle = ref handle;

        public SafePointer<T> AsPointer<T>() => new SafePointer<T>(ref Unsafe.As<byte, T>(ref handle));

        public ref T As<T>() => ref Unsafe.As<byte, T>(ref handle);
        public ref T As<T>(nuint offset) => ref Unsafe.As<byte, T>(ref this[offset]);

        public ref byte this[nuint index] => ref Unsafe.AddByteOffset(ref handle, index);

        public unsafe void Dispose()
        {
            Win32API.UnmapViewOfFile((nint)Unsafe.AsPointer(ref handle));
        }
    }
    /// <summary>
    /// A managed version of Memory mapped file
    /// By SHG at mail@Toolsbox.dk
    /// </summary>
    public class CMemoryMappedFile : IDisposable
    {
        IntPtr _hMMF = IntPtr.Zero;
        readonly nint _fs;
        public uint _AllocationGranularity;

        /// <summary>
        /// Creates a FileMapping handel
        /// </summary>
        /// <param name="FileName"></param>
        /// <param name="Name"></param>
        public CMemoryMappedFile(string FileName, string Name)
        {
            _hMMF = Win32API.OpenFileMapping(FileMapAccess.FileMapAllAccess, false, Name);
            if (_hMMF == IntPtr.Zero)
            {
                _fs = Win32API.CreateFileW(FileName, Win32API.GENERIC_READ, FileShare.Read, 0, FileMode.Open, FileAttributes.Normal, 0);
                _hMMF = Win32API.CreateFileMappingW(_fs, 0, Win32API.FileMapProtection.PageReadonly, 0, 0, Name);
                if (_hMMF == IntPtr.Zero)
                    throw new Win32Exception();
            }

            Win32API.SYSTEM_INFO sysinfo = new();
            Win32API.GetSystemInfo(ref sysinfo);
            _AllocationGranularity = sysinfo.dwAllocationGranularity;
        }

        /// <summary>
        /// Writes a sequence of bytes
        /// </summary>
        /// <param name="Buffer"></param>
        /// <param name="BytesToWrite"></param>
        /// <param name="AtOffset"></param>
        unsafe public void Write(byte[] Buffer, int BytesToWrite, Int64 AtOffset)
        {
            IntPtr hMVF = IntPtr.Zero;
            try
            {
                Int64 FileMapStart = (AtOffset / _AllocationGranularity) * _AllocationGranularity;
                Int64 MapViewSize = (AtOffset % _AllocationGranularity) + _AllocationGranularity;
                Int64 iViewDelta = AtOffset - FileMapStart;

                hMVF = Win32API.MapViewOfFile(_hMMF, FileMapAccess.FileMapWrite, FileMapStart, (uint)MapViewSize);
                if (hMVF == IntPtr.Zero)
                    throw new Win32Exception();
                byte* p = (byte*)hMVF.ToPointer() + iViewDelta;
                UnmanagedMemoryStream ums = new UnmanagedMemoryStream(p, MapViewSize, MapViewSize, FileAccess.Write);
                ums.Write(Buffer, 0, BytesToWrite);
                Win32API.FlushViewOfFile(hMVF, (Int32)MapViewSize);
            }
            finally
            {
                if (hMVF != IntPtr.Zero)
                    Win32API.UnmapViewOfFile(hMVF);
            }
        }

        /// <summary>
        /// Read sequence of bytes
        /// </summary>
        /// <param name="Buffer"></param>
        /// <param name="BytesToRead"></param>
        /// <param name="AtOffset"></param>
        /// <returns>Num bytes read</returns>
        unsafe public int Read(byte[] Buffer, int BytesToRead, Int64 AtOffset)
        {
            IntPtr hMVF = IntPtr.Zero;
            try
            {
                Int64 FileMapStart = (AtOffset / _AllocationGranularity) * _AllocationGranularity;
                Int64 MapViewSize = (AtOffset % _AllocationGranularity) + _AllocationGranularity;
                Int64 iViewDelta = AtOffset - FileMapStart;

                hMVF = Win32API.MapViewOfFile(_hMMF, FileMapAccess.FileMapRead, FileMapStart, (uint)MapViewSize);
                if (hMVF == IntPtr.Zero)
                    throw new Win32Exception();
                byte* p = (byte*)hMVF.ToPointer() + iViewDelta;
                UnmanagedMemoryStream ums = new UnmanagedMemoryStream(p, MapViewSize, MapViewSize, FileAccess.Read);
                return ums.Read(Buffer, 0, BytesToRead);
            }
            finally
            {
                if (hMVF != IntPtr.Zero)
                    Win32API.UnmapViewOfFile(hMVF);
            }
        }

        public unsafe MemoryMappedView GetView(FileMapAccess access) =>
            new(ref Unsafe.AsRef<byte>((void*)Win32API.MapViewOfFile(_hMMF, access, 0, 0, 0)));

        public void Dispose()
        {
            if (_hMMF != IntPtr.Zero)
                Win32API.CloseHandle(_hMMF);
            _hMMF = IntPtr.Zero;
            if (_fs != 0)
                Win32API.CloseHandle(_fs);
        }
    }
    [Flags]
    public enum FileMapAccess : uint
    {
        FileMapCopy = 0x0001,
        FileMapWrite = 0x0002,
        FileMapRead = 0x0004,
        FileMapAllAccess = 0x001f,
        fileMapExecute = 0x0020,
    }

    internal sealed partial class Win32API
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool RtlAddFunctionTable(nint functionTable, uint entryCount, nuint baseAddress);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, FileShare dwShareMode, IntPtr lpSecurityAttributes, FileMode dwCreationDisposition, FileAttributes dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("Kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileMappingW(IntPtr hFile, IntPtr lpAttributes, FileMapProtection flProtect, uint dwMaxSizeHi, uint dwMaxSizeLow, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenFileMapping(FileMapAccess DesiredAccess, bool bInheritHandle, string lpName);
        [Flags]
        public enum PAGE_PROTECTION_FLAGS : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [DllImport("ntdll.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern unsafe int NtProtectVirtualMemory(nint ProcessHandle, ref nint BaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, out uint OldAccessProtection);

        public static bool NT_SUCCESS(int status) => status >= 0;
        [Flags]
        internal enum FileMapProtection : uint
        {
            PageReadonly = 0x02,
            PageReadWrite = 0x04,
            PageWriteCopy = 0x08,
            PageExecuteRead = 0x20,
            PageExecuteReadWrite = 0x40,
            SectionCommit = 0x8000000,
            SectionImage = 0x1000000,
            SectionNoCache = 0x10000000,
            SectionReserve = 0x4000000,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(IntPtr hFileMapping, FileMapAccess dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);
        internal static IntPtr MapViewOfFile(IntPtr hFileMapping, FileMapAccess dwDesiredAccess, long ddFileOffset, uint dwNumberOfBytesToMap)
        {
            int Hi = (Int32)(ddFileOffset >> 32);
            uint Lo = unchecked((uint)(ddFileOffset));
            return MapViewOfFile(hFileMapping, dwDesiredAccess, (uint)Hi, Lo, dwNumberOfBytesToMap);
        }

        [DllImport("kernel32.dll")]
        internal static extern bool FlushViewOfFile(IntPtr lpBaseAddress,
           Int32 dwNumberOfBytesToFlush);

        [DllImport("kernel32.dll")]
        internal static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hFile);

        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_INFO
        {
            internal _PROCESSOR_INFO_UNION uProcessorInfo;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort dwProcessorLevel;
            public ushort dwProcessorRevision;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct _PROCESSOR_INFO_UNION
        {
            [FieldOffset(0)]
            internal uint dwOemId;
            [FieldOffset(0)]
            internal ushort wProcessorArchitecture;
            [FieldOffset(2)]
            internal ushort wReserved;
        }
    }
}
