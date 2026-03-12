using NT_File_Reader.WindowsNative;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;

namespace NT_File_Reader
{
    public static unsafe partial class Extentions
    {
        public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; //MZ
        public const ushort IMAGE_OS2_SIGNATURE = 0x454E;     // NE
        public const ushort IMAGE_OS2_SIGNATURE_LE = 0x454C;   // LE
        public const ushort IMAGE_VXD_SIGNATURE = 0x454C;   // LE
        public const ushort IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        #region Ldr
        /// <summary>
        /// Works like the function Win32 LoadLibary
        /// </summary>
        /// <param name="path">File Path</param>
        /// <returns>Load Handle</returns>
        public static AllocatedPointer LdrpLoadDllInternal(string path, uint flags)
        {
            LdrLockLoaderLock(0, out _, out nint cookie1);
            CMemoryMappedFile memoryMapped = new(Path.GetFullPath(path), "MapNT");
            MemoryMappedView memoryMappedView = memoryMapped.GetView(FileMapAccess.FileMapRead);

            var header = memoryMappedView.AsPointer<DOSHeader>();
            var pnt_header = (SafePointer<NtHeaders32>)((nuint)header + header.Value.e_lfanew);
            ValidateImage(ref header.Value);

            ref TEB teb = ref SegmentReaderX64.GetTebAddressX64().AsRef<TEB>();
            ref LDR_DATA_TABLE_ENTRY newEntry = ref Marshal.AllocHGlobal(Unsafe.SizeOf<LDR_DATA_TABLE_ENTRY>()).AsRef<LDR_DATA_TABLE_ENTRY>();
            Unsafe.InitBlock(ref Unsafe.As<LDR_DATA_TABLE_ENTRY, byte>(ref newEntry), 0, (uint)Unsafe.SizeOf<LDR_DATA_TABLE_ENTRY>());
            LIST_ENTRY* head = &teb.ProcessEnvironmentBlock.Ldr->InLoadOrderModuleList;
            string str1 = Path.GetFileName(path);
            uint sizeOfImage = pnt_header.Value.OptionalHeader.SizeOfImage;
            AllocatedPointer pointer = new(sizeOfImage);

            {
                Unsafe.InitBlockUnaligned(ref pointer[0], 0, sizeOfImage);
                Unsafe.CopyBlockUnaligned(ref pointer[0], ref memoryMappedView.handle, pnt_header.Value.OptionalHeader.SizeOfHeaders);
                for (int i = 0; i < pnt_header.Value.FileHeader.NumberOfSections; i++)
                {
                    ref SectionHeader section = ref pointer.As<SectionHeader>((nuint)(header.Value.e_lfanew + Unsafe.SizeOf<uint>() + Unsafe.SizeOf<FileHeader>() +
                        pnt_header.Value.FileHeader.SizeOfOptionalHeader + i * Unsafe.SizeOf<SectionHeader>()));
                    Unsafe.CopyBlockUnaligned(ref pointer[section.VirtualAddress], ref memoryMappedView[section.PointerToRawData], section.SizeOfRawData);
                }
                // למנוע בעיות עתידיות
                memoryMappedView.Dispose();
                memoryMapped.Dispose();
            }

            newEntry.SizeOfImage = sizeOfImage;
            newEntry.DllBase = pointer;
            newEntry.BaseDllName = AllocateUnicodeString(str1);
            newEntry.FullDllName = AllocateUnicodeString(path);
            header = pointer.AsPointer<DOSHeader>();
            pnt_header = (SafePointer<NtHeaders32>)((nuint)header + header.Value.e_lfanew);
            ref NtHeaders32 nt_header = ref pnt_header.Value;

            ApplyRelocations(pointer);
            // הוספה למטמון ומניעת עומס יתר על החסנית ודלפית זיכרון
            LibraryLoader.AddToCache(path, pointer);
            Console.WriteLine("Library: {0} is loaded", path); //LdrpLogNewDll
            if ((flags & 1) == 0)
                LdrpSnapModule(header);

            ref DataDirectory loadConfigTable = ref GetDirectoryTableEntry(ref pointer.As<DOSHeader>(), 10);
            if (!Unsafe.IsNullRef(ref loadConfigTable) && loadConfigTable.Size > 0)
            {
                do
                {
                    if (nt_header.OptionalHeader.Magic == PEMagic.PE32Plus)
                    {
                        ref LoadConfigDirectory64 loadConfig = ref pointer.As<LoadConfigDirectory64>(loadConfigTable.VirtualAddress);
                        if (loadConfig.Size < 112)
                            break;

                        if (loadConfig.SecurityCookie != 0)
                        {
                            // יצירת עוגייה אקראית (בדיקה פשוטה, במציאות עדיף משהו מורכב יותר)
                            ulong cookie = (ulong)Environment.TickCount64;
                            if (cookie == 0x2B992DDFA232ul) cookie++; // אסור שהעוגייה תהיה ערך ברירת המחדל
                            Unsafe.WriteUnaligned((void*)loadConfig.SecurityCookie, cookie);
                        }

                        if ((nt_header.OptionalHeader.DllCharacteristics & DllCharacteristics.ControlFlowGuard) != 0)                 // ניהול פונקציה Control Flow Gaurd
                        {
                            //scoped ref DOSHeader ntdll = ref ((SafePointer<DOSHeader>)LibraryLoader.LoadLibrary("ntdll.dll")).Value;
                            nint validTargetFunc = (nint)(delegate*<nuint, void>)&LdrpValidateUserCallTarget;
                            if ((loadConfig.GuardFlags & (uint)GuardFlags.CFInstrumented) != 0)
                            {
                                //nint dispatchTargetFunc = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpDispatchUserCallTarget"u8)));

                                if (loadConfig.GuardCFCheckFunctionPointer != 0)
                                    ((SafePointer<nint>)loadConfig.GuardCFCheckFunctionPointer).Value = validTargetFunc;

                                //if (loadConfig.GuardCFDispatchFunctionPointer != 0)
                                //    ((SafePointer<nint>)loadConfig.GuardCFDispatchFunctionPointer).Value = dispatchTargetFunc;
                            }
                            if ((loadConfig.GuardFlags & (uint)GuardFlags.CFExportSuppressionInfoPresent) != 0)
                            {
                                ((SafePointer<nint>)loadConfig.GuardXFGCheckFunctionPointer).Value = validTargetFunc;
                                //((SafePointer<nint>)loadConfig.GuardXFGDispatchFunctionPointer).Value = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpDispatchUserCallTargetXFG"u8)));
                                //((SafePointer<nint>)loadConfig.GuardXFGTableDispatchFunctionPointer).Value = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpXfgTableDispatch"u8)));
                            }
                        }
                    }
                    else if (nt_header.OptionalHeader.Magic == PEMagic.PE32)
                    {
                        ref LoadConfigDirectory32 loadConfig = ref pointer.As<LoadConfigDirectory32>(loadConfigTable.VirtualAddress);

                        if (loadConfig.SecurityCookie != 0)
                        {
                            // יצירת עוגייה אקראית (בדיקה פשוטה, במציאות עדיף משהו מורכב יותר)
                            uint cookie = (uint)Environment.TickCount;
                            if (cookie == 0xBB40E64Eu) cookie++; // אסור שהעוגייה תהיה ערך ברירת המחדל
                            Unsafe.WriteUnaligned((void*)loadConfig.SecurityCookie, cookie);
                        }

                        if ((nt_header.OptionalHeader.DllCharacteristics & DllCharacteristics.ControlFlowGuard) != 0)                 // ניהול פונקציה Control Flow Gaurd
                        {
                            //scoped ref DOSHeader ntdll = ref ((SafePointer<DOSHeader>)LibraryLoader.LoadLibrary("ntdll.dll")).Value;
                            nint validTargetFunc = (nint)(delegate*<nuint, void>)&LdrpValidateUserCallTarget;
                            if ((loadConfig.GuardFlags & (uint)GuardFlags.CFInstrumented) != 0)
                            {
                                //nint dispatchTargetFunc = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpDispatchUserCallTarget"u8)));

                                if (loadConfig.GuardCFCheckFunctionPointer != 0)
                                    ((SafePointer<nint>)loadConfig.GuardCFCheckFunctionPointer).Value = validTargetFunc;

                                //if (loadConfig.GuardCFDispatchFunctionPointer != 0)
                                //    ((SafePointer<nint>)loadConfig.GuardCFDispatchFunctionPointer).Value = dispatchTargetFunc;
                            }
                            if ((loadConfig.GuardFlags & (uint)GuardFlags.CFExportSuppressionInfoPresent) != 0)
                            {
                                ((SafePointer<nint>)loadConfig.GuardXFGCheckFunctionPointer).Value = validTargetFunc;
                                //((SafePointer<nint>)loadConfig.GuardXFGDispatchFunctionPointer).Value = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpDispatchUserCallTargetXFG"u8)));
                                //((SafePointer<nint>)loadConfig.GuardXFGTableDispatchFunctionPointer).Value = GetProcAddress(ref ntdll,
                                //    ByRef.ToUPointer(ref MemoryMarshal.GetReference("LdrpXfgTableDispatch"u8)));
                            }
                        }
                    }
                } while (false);
            }
            if ((flags & 2) == 0)
            {
                // Paging
                MapSections(pointer);
                HandleStaticTLS(pointer);
                // Add this inside LdrLoadDllInternal
                ref DataDirectory exceptionTable = ref GetDirectoryTableEntry(ref header.Value, 3);
                if (!Unsafe.IsNullRef<DataDirectory>(ref exceptionTable) && exceptionTable.Size > 0)
                {
                    // The number of entries is the total size divided by the size of a RUNTIME_FUNCTION struct (12 bytes)
                    uint entryCount = exceptionTable.Size / 12; // sizeof(RUNTIME_FUNCTION)

                    // Get the absolute address of the Exception Table in your allocated memory
                    IntPtr functionTableAddr = (IntPtr)(pointer + exceptionTable.VirtualAddress);

                    bool success = RtlAddFunctionTable(
                        functionTableAddr,
                        entryCount,
                        (nuint)pointer // The base address where the DLL is mapped
                    );

                    if (!success)
                    {
                        Console.WriteLine("Failed to register Exception Table.");
                    }
                }

                if (nt_header.OptionalHeader.AddressOfEntryPoint != 0 && (nt_header.FileHeader.Characteristics & 0x2000) != 0)
                {
                    delegate* managed<nuint, uint, IntPtr, int> dllMain =
                        (delegate* managed<nuint, uint, IntPtr, int>)(Unsafe.AsPointer(ref pointer[nt_header.OptionalHeader.AddressOfEntryPoint]));

                    // Call DLL_PROCESS_ATTACH
                    int ret = dllMain(pointer, 1 /*DLL_PROCESS_ATTACH*/, IntPtr.Zero);
                    if (ret == 0)
                    {
                        Console.Write("Dll Init Fail ");
                    }
                }
            }
            newEntry.Flags = 0x00000004 | 0x00004000;
            newEntry.LoadCount = 0xffff;
            newEntry.HashLinks.Flink = SafePointerExtentions.ToPointer(ref newEntry.HashLinks);
            newEntry.HashLinks.Blink = SafePointerExtentions.ToPointer(ref newEntry.HashLinks);
            InsertModule(ref teb.ProcessEnvironmentBlock.Ldr->InLoadOrderModuleList, ref newEntry.InLoadOrderLinks);
            InsertModule(ref teb.ProcessEnvironmentBlock.Ldr->InMemoryOrderModuleList, ref newEntry.InMemoryOrderLinks);
            InsertModule(ref teb.ProcessEnvironmentBlock.Ldr->InInitializationOrderModuleList, ref newEntry.InInitializationOrderLinks);
            IntPtr ddagPtr = Marshal.AllocHGlobal(80); // גודל מקורב ל-LDR_DDAG_NODE ב-x64
            Unsafe.InitBlock((void*)ddagPtr, 0, 80);
            newEntry.DdagNode = ddagPtr;
            LdrUnlockLoaderLock(0, cookie1);
            return pointer;
        }

        private static UNICODE_STRING AllocateUnicodeString(string str)
        {
            return new UNICODE_STRING
            {
                Length = (ushort)(str.Length * 2),
                MaximumLength = (ushort)((str.Length * 2) + 2),
                Buffer = Marshal.StringToHGlobalUni(str)
            };
        }

        private static void InsertModule(ref LIST_ENTRY head, ref LIST_ENTRY newEntry)
        {
            newEntry.Flink = SafePointerExtentions.ToPointer(ref head);
            newEntry.Blink = head.Blink;
            head.Blink.Value.Flink = SafePointerExtentions.ToPointer(ref newEntry);
            head.Blink = SafePointerExtentions.ToPointer(ref newEntry);
        }

        private static ulong GetImageBase(ref DOSHeader header)
        {
            ValidateImage(ref header);
            SafePointer<DOSHeader> pointer = new SafePointer<DOSHeader>(ref header);
            var nt_header = pointer.AddByteOffset(header.e_lfanew).Cast<NtHeaders32>();

            if (nt_header.Value.OptionalHeader.Magic == PEMagic.PE32Plus)
                // Version 64 bits Deletes BaseOfData As ImageBaseLow
                return Unsafe.As<uint, ulong>(ref nt_header.Value.OptionalHeader.BaseOfData);

            return nt_header.Value.OptionalHeader.ImageBase;
        }

        private static ref DataDirectory GetDirectoryTableEntry(ref DOSHeader header, int index)
        {
            ValidateImage(ref header);
            SafePointer<DOSHeader> pointer = new(ref header);
            var nt_header = pointer.AddByteOffset(header.e_lfanew).Cast<NtHeaders32>();

            int nativeIntSize = nt_header.Value.OptionalHeader.Magic == PEMagic.PE32Plus ? 108 : 92;
            ref uint NumberOfRvaAndSizes = ref Unsafe.As<OptionalHeaders32, uint>(
                ref Unsafe.AddByteOffset(ref nt_header.Value.OptionalHeader, nativeIntSize)); // השגת כמות השולחנות

            ref DataDirectory baseTableRVA = ref Unsafe.AddByteOffset(
                ref Unsafe.As<uint, DataDirectory>(ref NumberOfRvaAndSizes), 4); // השגת כתובת השולחנות

            if (index >= NumberOfRvaAndSizes)
                return ref Unsafe.NullRef<DataDirectory>();

            return ref Unsafe.Add(ref baseTableRVA, index);
        }

        private static void LdrpSnapModule(SafePointer<DOSHeader> header)
        {
            // השגת כתובת חילוץ ספריות
            ref DataDirectory importEntry = ref GetDirectoryTableEntry(ref header.Value, 1);
            if (Unsafe.IsNullRef(ref importEntry) || importEntry.Size == 0 || importEntry.VirtualAddress == 0)
                return;

            ref ImportDescriptor importImageDescriptor = ref header.AddByteOffset(importEntry.VirtualAddress).Cast<ImportDescriptor>().Value;
            //DLL Imports
            for (; importImageDescriptor.Name != 0; importImageDescriptor = ref Unsafe.Add(ref importImageDescriptor, 1))
            {
                ref byte Imported_DLL = ref header.AddByteOffset(importImageDescriptor.Name).Cast<byte>().Value;
                //Console.WriteLine("\tImported DLLs: {0}", FromAscii(MemoryMarshal.CreateReadOnlySpan(ref Imported_DLL, strlen(ref Imported_DLL))));
                nint libary = CustomApiCalls.LoadLibraryA(ref Imported_DLL);
                // LoadLibary
                uint iltOffset = importImageDescriptor.OriginalFirstThunk == 0 ? importImageDescriptor.FirstThunk : importImageDescriptor.OriginalFirstThunk;
                uint iatOffset = importImageDescriptor.FirstThunk;
                var ntPointer = header.AddByteOffset(header.Value.e_lfanew).Cast<NtHeaders32>();
                if (ntPointer.Value.OptionalHeader.Magic == PEMagic.PE32)
                {
                    var iltEntry = header.AddByteOffset(iltOffset).Cast<ThunkData32>();
                    var iatEntry = header.AddByteOffset(iatOffset).Cast<ThunkData32>();
                    // dll exported functions
                    for (; iltEntry.Value.AddressOfData != 0;
                        iltEntry++,
                        iatEntry++)
                    {
                        iatEntry.Value.Function = (uint)ResolveProcAddress(libary,
                            header.AddByteOffset((nuint)iltEntry.Value.ForwarderString + 2).Cast<byte>(),
                            (ushort)(iltEntry.Value.Ordinal & 0xFFFF),
                            (iltEntry.Value.AddressOfData & (1ul << 31)) != 0);
                    }
                }
                else if (ntPointer.Value.OptionalHeader.Magic == PEMagic.PE32Plus)
                {
                    var iltEntry = header.AddByteOffset(iltOffset).Cast<ThunkData64>();
                    var iatEntry = header.AddByteOffset(iatOffset).Cast<ThunkData64>();
                    // dll exported functions
                    for (; iltEntry.Value.AddressOfData != 0;
                        iltEntry++,
                        iatEntry++)
                    {
                        bool ordianl = (iltEntry.Value.AddressOfData & (1ul << 63)) != 0;
                        iatEntry.Value.Function = (ulong)ResolveProcAddress(libary,
                            header.AddByteOffset((nuint)iltEntry.Value.ForwarderString + 2).Cast<byte>(),
                            (ushort)(iltEntry.Value.Ordinal & 0xFFFF),
                            ordianl);
                    }
                }
            }

            static nint ResolveProcAddress(nint library, SafePointer<byte> print, ushort ordinal, bool isOrdinal)
            {
                nint ret = 0;
                //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
                if (isOrdinal)
                    //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                    ret = GetProcAddress(ref Unsafe.AsRef<DOSHeader>((void*)library), ordinal);
                else
                {
                    //reolve address by name ¯\_(ツ)_/¯
                    ReadOnlySpan<byte> name = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)(nuint)print);
                    //Console.WriteLine(Encoding.ASCII.GetString(name));
                    ret = CustomApiCalls.MatchApiCallsToResolveImport(library, print, name);
                }
                Debug.Assert(ret != 0);
                return ret;
            }
        }

        public static void HandleStaticTLS(AllocatedPointer pointer)
        {
            var header = pointer.AsPointer<DOSHeader>();
            var tlsTable = GetDirectoryTableEntry(ref header.Value, 9);

            var ntPointer = header.AddByteOffset(header.Value.e_lfanew).Cast<NtHeaders32>();
            int sizeOfInt = ntPointer.Value.OptionalHeader.Magic == PEMagic.PE32Plus ? 8 : 4;
            if (tlsTable.Size == 0) return;
            nint callbackPtr = 0;
            ulong addressOfIndex = 0, startOfRawData = 0, endOfRawData = 0;
            if (sizeOfInt == 8)
            {
                ref TlsDirectory64 tlsDir = ref pointer.As<TlsDirectory64>(tlsTable.VirtualAddress);
                addressOfIndex = tlsDir.AddressOfIndex;
                startOfRawData = tlsDir.StartAddressOfRawData;
                endOfRawData = tlsDir.EndAddressOfRawData;
                callbackPtr = (nint)RVA2VA(pointer, tlsDir.AddressOfCallBacks);
            }
            else
            {
                ref TlsDirectory32 tlsDir = ref pointer.As<TlsDirectory32>(tlsTable.VirtualAddress);
                addressOfIndex = tlsDir.AddressOfIndex;
                startOfRawData = tlsDir.StartAddressOfRawData;
                endOfRawData = tlsDir.EndAddressOfRawData;
                callbackPtr = (nint)RVA2VA(pointer, tlsDir.AddressOfCallBacks);
            }

            // Allocate a new TLS Index from the OS
            uint tlsIndex = TlsAlloc();
            if (tlsIndex == uint.MaxValue) // 0xFFFFFFFF
            {
                throw new Win32Exception("Failed to allocate TLS index.");
            }
            // The DLL code looks at this address to know which slot to check in the TEB
            if (addressOfIndex != 0)
            {
                ((SafePointer<uint>)RVA2VA(pointer, addressOfIndex)).Value = tlsIndex;
            }
#if false
            // DllMain is about to run on THIS thread, so it needs its local variables initialized.
            nuint tlsDataSize = (nuint)(endOfRawData - startOfRawData);
            if (tlsDataSize > 0)
            {
                TEB* tls = (TEB*)SegmentReaderX64.GetTebAddressX64();
                // Allocate memory for this specific thread's version of the TLS data
                IntPtr threadTlsData = Marshal.AllocHGlobal((int)tlsDataSize);

                // Copy the template from the DLL to the thread-local memory
                Unsafe.CopyBlockUnaligned(
                    (void*)threadTlsData,
                    (void*)RVA2VA(pointer, startOfRawData),
                    (uint)tlsDataSize
                );
                nint* pointers = ((nint*)tls->ThreadLocalStoragePointer);
                pointers[tlsIndex] = threadTlsData;
            }
#endif
            if (callbackPtr != 0)
            {
                // רץ על מערך הפונקציות עד שמגיעים ל-NULL
                while (true)
                {
                    nint funcAddr = Unsafe.ReadUnaligned<nint>((void*)callbackPtr);
                    if (funcAddr == 0)
                        break;

                    delegate* unmanaged<nuint, uint, IntPtr, void> callback = (delegate* unmanaged<nuint, uint, IntPtr, void>)funcAddr;
                    callback(pointer, 1 /*DLL_PROCESS_ATTACH*/, IntPtr.Zero);
                    callbackPtr += IntPtr.Size;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static nuint RVA2VA(AllocatedPointer pointer, ulong address)
        {
            ref NtHeaders32 headers = ref pointer.As<NtHeaders32>(pointer.As<DOSHeader>().e_lfanew);
            if (address < headers.OptionalHeader.SizeOfImage)
                return pointer + (nuint)address;
            else return (nuint)address;
        }

        private static void LdrpValidateUserCallTarget(nuint address)
        {
            SafePointer<byte> cfgBitmapBase = (SafePointer<byte>)(LibraryLoader.LoadLibrary("ntdll.dll", 0) + 0x1e94f8); // סכנה

            var rdx = (cfgBitmapBase + ((address >> 9) << 3)).Cast<ulong>();

            ulong bitIndex = (ulong)(address >> 3);

            // בדיקה אם הכתובת מיושרת ל-16 בתים (0xf mask)
            if ((address & 0xf) == 0)
            {
                // בדיקת הביט עבור כתובת מיושרת
                if ((rdx.Value & (1UL << (int)(bitIndex & 63))) != 0)
                    return; // תקין!
            }
            else
            {
                // טיפול בכתובות לא מיושרות (הביט הבא בטבלה)
                bitIndex &= 0xFFFFFFFFFFFFFFFE;
                if ((rdx.Value & (1UL << (int)(bitIndex & 63))) != 0)
                {
                    if ((rdx.Value & (1UL << (int)((bitIndex | 1) & 63))) != 0)
                        return; // תקין!
                }
            }
            Debugger.Break();
            return;
        }

        private static void ValidateImage(ref DOSHeader image)
        {
            // בדיקות של הקובץ האם זה להרצה
            if (Unsafe.IsNullRef(ref image))
                throw new Exception("Invliad exe");

            if (!(image.e_magic == Extentions.IMAGE_DOS_SIGNATURE))
                throw new Exception("Invliad exe");

            ref NtHeaders32 nt_header = ref Unsafe.As<DOSHeader, NtHeaders32>(ref Unsafe.AddByteOffset(ref image, image.e_lfanew));
            if (!(nt_header.Signature == Extentions.IMAGE_NT_SIGNATURE))
                throw new Exception("Invliad exe");
        }

        private static void MapSections(AllocatedPointer pointer)
        {
            scoped ref DOSHeader header = ref pointer.As<DOSHeader>();
            scoped ref NtHeaders32 nt_header = ref pointer.As<NtHeaders32>(header.e_lfanew);
            nuint sectionTableOffset = (nuint)(header.e_lfanew + 4 + Unsafe.SizeOf<FileHeader>() + nt_header.FileHeader.SizeOfOptionalHeader);
            scoped ref SectionHeader sections = ref pointer.As<SectionHeader>(sectionTableOffset);
            int status;
            nint baseAddr;
            for (int i = 0; i < nt_header.FileHeader.NumberOfSections; i++)
            {
                ref SectionHeader section = ref Unsafe.Add(ref sections, i);
                if (section.PhysicalAddress_VirtualSize == 0) continue;

                uint currentSectionSize = AlignUp(Math.Max(section.SizeOfRawData, section.PhysicalAddress_VirtualSize), nt_header.OptionalHeader.SectionAlignment);

                // Define paging for sections
                bool r = (section.Characteristics & SectionCharacteristics.MemRead) != 0;
                bool w = (section.Characteristics & SectionCharacteristics.MemWrite) != 0;
                bool x = (section.Characteristics & SectionCharacteristics.MemExecute) != 0;


                Win32API.PAGE_PROTECTION_FLAGS pagingFlags;
                if (x && r && w) pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE;
                else if (x && r) pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ;
                else if (r && w) pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_READWRITE;
                else if (r) pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_READONLY;
                else pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_NOACCESS;

                if (section.Characteristics.HasFlag(SectionCharacteristics.MemNotCached))
                    pagingFlags |= Win32API.PAGE_PROTECTION_FLAGS.PAGE_NOCACHE;

                if (section.Characteristics.HasFlag(SectionCharacteristics.MemNotPaged) ||
                    section.Characteristics.HasFlag(SectionCharacteristics.MemDiscardable))
                    pagingFlags = Win32API.PAGE_PROTECTION_FLAGS.PAGE_NOACCESS;

                baseAddr = (nint)(pointer + section.VirtualAddress);
                status = Win32API.NtProtectVirtualMemory(-1, ref baseAddr, ref currentSectionSize, (uint)pagingFlags, out _);
                Debug.Assert(Win32API.NT_SUCCESS(status));
            }
            baseAddr = pointer;
            uint sizeOfHeaders = nt_header.OptionalHeader.SizeOfHeaders;
            status = Win32API.NtProtectVirtualMemory(-1, ref baseAddr, ref sizeOfHeaders, (uint)Win32API.PAGE_PROTECTION_FLAGS.PAGE_READONLY, out _);
            Debug.Assert(Win32API.NT_SUCCESS(status));

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static uint AlignUp(uint size, uint alignment)
            {
                if (alignment == 0) return size;
                return (size + alignment - 1) & ~(alignment - 1);
            }
        }

        static void ApplyRelocations(AllocatedPointer imageBase)
        {
            // Actual base in memory minus the preferred base from headers
            ref DOSHeader RawImage = ref imageBase.As<DOSHeader>();
            ulong delta = imageBase - GetImageBase(ref RawImage);
            NtHeaders32 ntHeaders = imageBase.As<NtHeaders32>(RawImage.e_lfanew);

            ref DataDirectory relocTable = ref GetDirectoryTableEntry(ref RawImage, 5);

            // If delta is 0, the image is at its preferred address; no relocation needed
            if (delta == 0) return;
            if (relocTable.Size == 0) return;

            ref BaseRelocation relocBlock = ref (imageBase.As<BaseRelocation>(relocTable.VirtualAddress));

            // Track how many bytes we've processed to avoid runaway loops
            uint totalSize = relocTable.Size;
            uint bytesProcessed = 0;

            while (bytesProcessed < totalSize && relocBlock.SizeOfBlock > 0)
            {
                // Calculate number of entries in this block
                // Each entry is a 16-bit WORD
                int entryCount = (int)((relocBlock.SizeOfBlock - Unsafe.SizeOf<BaseRelocation>()) / sizeof(ushort));
                scoped ReadOnlySpan<ushort> entries = MemoryMarshal.CreateReadOnlySpan(
                    ref Unsafe.As<BaseRelocation, ushort>(ref Unsafe.Add(ref relocBlock, 1)),
                    entryCount);

                for (int i = 0; i < entryCount; i++)
                {
                    // High 4 bits = Type, Low 12 bits = Offset within the page
                    ushort type = (ushort)(entries[i] >> 12);
                    ushort offset = (ushort)(entries[i] & 0x0FFF);

                    // Target address to patch
                    scoped ref byte patchAddr = ref imageBase[relocBlock.VirtualAddress + offset];

                    // Apply patch based on architecture/type
                    switch (type)
                    {
                        case 0:
                            // Does Nothing
                            break;
                        case 1:
                            Unsafe.WriteUnaligned(ref patchAddr, Unsafe.ReadUnaligned<ushort>(ref patchAddr) + (ushort)(delta >> 16));
                            break;
                        case 2:
                            Unsafe.WriteUnaligned(ref patchAddr, Unsafe.ReadUnaligned<ushort>(ref patchAddr) + (ushort)(delta & 0xFFFF));
                            break;
                        case 3:
                            Unsafe.WriteUnaligned(ref patchAddr, Unsafe.ReadUnaligned<uint>(ref patchAddr) + (uint)delta);
                            break;
                        case 4: // IMAGE_REL_BASED_HIGHADJ
                            i++;
                            if (i < entryCount)
                            {
                                uint highWord = Unsafe.ReadUnaligned<ushort>(ref patchAddr);
                                short lowWord = (short)entries[i];
                                uint fullVal = (highWord << 16) + (uint)lowWord;
                                fullVal += (uint)delta;
                                ushort newHigh = (ushort)((fullVal + 0x8000) >> 16);
                                Unsafe.WriteUnaligned(ref patchAddr, newHigh);
                            }
                            break;
                        case 5: // MIPS_JMPADDR / ARM_MOV32 / RISCV_HIGH20
                            if (ntHeaders.FileHeader.Machine == Machine.Arm || ntHeaders.FileHeader.Machine == Machine.ArmThumb2)
                            { // ARM / THUMB
                              // ARM MOV32: Patches 32-bit address across MOVW/MOVT pair
                                uint instrW = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint instrT = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref patchAddr, 4));
                                uint currentVal = ((instrT & 0x000F0000) << 12) | ((instrT & 0x00000FFF) << 16) |
                                                  ((instrW & 0x000F0000) >> 4) | (instrW & 0x00000FFF);
                                uint newVal = (uint)(currentVal + delta);
                                Unsafe.WriteUnaligned(ref patchAddr, (instrW & 0xFFF0F000) | ((newVal & 0xF000) << 4) | (newVal & 0xFFF));
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref patchAddr, 4), (instrT & 0xFFF0F000) | ((newVal & 0xF0000000) >> 12) | ((newVal & 0x0FFF0000) >> 16));
                            }
                            else if (ntHeaders.FileHeader.Machine == Machine.RiscV32 || ntHeaders.FileHeader.Machine == Machine.RiscV64)
                            { // RISC-V 32/64
                              // RISCV_HIGH20: Patches the high 20 bits of a U-type instruction (e.g., LUI)
                                uint instr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint imm20 = instr >> 12;
                                uint newImm20 = (uint)((imm20 + ((delta + 0x800) >> 12)) & 0xFFFFF);
                                Unsafe.WriteUnaligned(ref patchAddr, (instr & 0xFFF) | (newImm20 << 12));
                            }
                            else if (ntHeaders.FileHeader.Machine == Machine.WceMipsV2 || ntHeaders.FileHeader.Machine == (Machine)0x166)
                            {
                                uint instr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint currentTarget = (instr & 0x03FFFFFF) << 2;
                                uint newTarget = currentTarget + (uint)delta;
                                uint newInstr = (instr & 0xFC000000) | ((newTarget >> 2) & 0x03FFFFFF);
                                Unsafe.WriteUnaligned(ref patchAddr, newInstr);
                            }
                            break;

                        case 7: // THUMB_MOV32 / RISCV_LOW12I
                            if (ntHeaders.FileHeader.Machine == Machine.ArmThumb2) // IMAGE_FILE_MACHINE_THUMB (ARM Thumb-2)
                            {
                                // Thumb-2 MOVW/MOVT are 32-bit instructions (two 16-bit words)
                                // Usually, MOVW is at patchAddr and MOVT is at patchAddr + 4
                                uint instrW = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint instrT = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref patchAddr, 4));

                                uint currentVal = (getImm(instrT) << 16) | getImm(instrW);
                                uint newVal = (uint)(currentVal + delta);

                                Unsafe.WriteUnaligned(ref patchAddr, setImm(instrW, newVal & 0xFFFF));
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref patchAddr, 4), setImm(instrT, newVal >> 16));

                                // Helper to extract 16-bit imm from Thumb-2 MOVW/MOVT encoding
                                // Bits: imm4: [19:16], i: [26], imm3: [14:12], imm8: [7:0]
                                // Note: In 32-bit read, these positions shift based on endianness.
                                // Format: [15:0] is 1st halfword, [31:16] is 2nd halfword
                                uint getImm(uint ins) =>
                                    ((ins & 0x00000400) << 1) |  // i (bit 10 of first halfword)
                                    ((ins & 0x0000000F) << 12) | // imm4 (bits 0-3 of first halfword)
                                    ((ins & 0x70000000) >> 16) | // imm3 (bits 12-14 of second halfword)
                                    ((ins & 0x00FF0000) >> 16);  // imm8 (bits 0-7 of second halfword)

                                // Helper to re-encode 16-bit imm back into Thumb-2 format
                                uint setImm(uint ins, uint val) =>
                                    (ins & 0x8FF0FBF0) |            // Mask out old imm bits
                                    ((val & 0x0800) >> 1) |         // i
                                    ((val & 0xF000) >> 12) |        // imm4
                                    ((val & 0x0700) << 16) |        // imm3
                                    ((val & 0x00FF) << 16);         // imm8
                            }
                            else if (ntHeaders.FileHeader.Machine == Machine.RiscV32 || ntHeaders.FileHeader.Machine == Machine.RiscV64)
                            { // RISC-V 32/64
                              // RISCV_LOW12I: Patches 12-bit imm in I-type (e.g., ADDI)
                                uint instr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint imm12 = (uint)((int)instr >> 20);
                                uint newImm12 = (uint)((imm12 + (delta & 0xFFF)) & 0xFFF);
                                Unsafe.WriteUnaligned(ref patchAddr, (instr & 0x000FFFFF) | (newImm12 << 20));
                            }
                            break;

                        case 8: // RISCV_LOW12S / LOONGARCH_MARK_LA
                            if (ntHeaders.FileHeader.Machine == Machine.RiscV32 || ntHeaders.FileHeader.Machine == Machine.RiscV64)
                            { // RISC-V 32/64
                              // RISCV_LOW12S: Patches split 12-bit imm in S-type (e.g., SW)
                                uint instr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint imm12 = ((instr >> 25) << 5) | ((instr >> 7) & 0x1F);
                                uint newImm12 = (uint)((imm12 + (delta & 0xFFF)) & 0xFFF);
                                uint newInstr = (instr & 0x01FFF07F) | ((newImm12 & 0xFE0) << 20) | ((newImm12 & 0x1F) << 7);
                                Unsafe.WriteUnaligned(ref patchAddr, newInstr);
                            }
                            else if (ntHeaders.FileHeader.Machine == Machine.LoongArch64 || ntHeaders.FileHeader.Machine == Machine.LoongArch32)
                            {
                                // טעינת צמד ההוראות (PCALAU12I + ADDI.D/LD.D) 32 - ADDI.W/LD.W
                                uint hiInstr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint loInstr = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref patchAddr, 4));

                                // חילוץ ערכים קיימים (Sign-extended)
                                int currentHi = ((int)hiInstr >> 5) & 0xFFFFF;
                                if ((currentHi & 0x80000) != 0) currentHi |= unchecked((int)0xFFF00000);

                                int currentLo = ((int)loInstr >> 10) & 0xFFF;
                                if ((currentLo & 0x800) != 0) currentLo |= unchecked((int)0xFFFFF000);

                                long currentAddr = ((long)currentHi << 12) + currentLo;
                                long newAddr = currentAddr + (long)delta;

                                // חישוב מחדש - התחשבות ב-Sign extension של הוראת ה-LO
                                int newLo = (int)(newAddr & 0xFFF);
                                if (newLo >= 0x800) newLo -= 0x1000;
                                int newHi = (int)((newAddr - newLo) >> 12) & 0xFFFFF;

                                // הזרקת הערכים החדשים לשדות המתאימים
                                Unsafe.WriteUnaligned(ref patchAddr, (hiInstr & 0xFE00001F) | ((uint)newHi << 5));
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref patchAddr, 4), (loInstr & 0xFFC003FF) | ((uint)(newLo & 0xFFF) << 10));
                            }
                            break;

                        case 9: // MIPS_JMPADDR16
                            if (ntHeaders.FileHeader.Machine == Machine.MIPS16)
                            { // MIPS
                                uint instr = Unsafe.ReadUnaligned<uint>(ref patchAddr);
                                uint target = (instr & 0x03FFFFFF) << 2;
                                uint newTarget = (uint)((target + (uint)delta) >> 2);
                                Unsafe.WriteUnaligned(ref patchAddr, (instr & 0xFC000000) | (newTarget & 0x03FFFFFF));
                            }
                            break;
                        case 10:
                            Unsafe.WriteUnaligned(ref patchAddr, Unsafe.ReadUnaligned<ulong>(ref patchAddr) + delta);
                            break;
                    }
                }

                // Move to the next block
                bytesProcessed += relocBlock.SizeOfBlock;
                relocBlock = ref (Unsafe.AddByteOffset(ref relocBlock, (nint)relocBlock.SizeOfBlock));
            }
        }

        public static void LdrFreeDll(AllocatedPointer pointer)
        {
            ref DOSHeader header = ref pointer.As<DOSHeader>();
            ref NtHeaders32 nt_header = ref pointer.As<NtHeaders32>(header.e_lfanew);

            if (nt_header.OptionalHeader.AddressOfEntryPoint != 0 && (nt_header.FileHeader.Characteristics & 0x2000) != 0)
            {
                delegate* unmanaged<nuint, uint, IntPtr, int> dllMain =
                    (delegate* unmanaged<nuint, uint, IntPtr, int>)(pointer + nt_header.OptionalHeader.AddressOfEntryPoint);

                // 0 = DLL_PROCESS_DETACH
                dllMain(pointer, 0, IntPtr.Zero);
            }

            ref DataDirectory exceptionTable = ref GetDirectoryTableEntry(ref header, 3);
            if (exceptionTable.Size > 0)
            {
                IntPtr functionTableAddr = (IntPtr)(pointer + exceptionTable.VirtualAddress);
                RtlDeleteFunctionTable(functionTableAddr);
            }
            pointer.Dispose();
        }
        #endregion

        /// <summary>
        /// Works like the function Win32 GetProcAddress
        /// </summary>
        /// <returns>Load Handle</returns>
        public static nint GetProcAddress(scoped ref DOSHeader image, nuint funcName)
        {
            // בדיקה ראשונית
            int recursionLimit = 32; // הגבלת עומק למניעת לולאות אינסופיות ב-Forwarding
            while (!Unsafe.IsNullRef(ref image) && recursionLimit-- > 0)
            {
                ushort targetOrdinal = funcName < 0x10000u ? (ushort)funcName : (ushort)0;
                ReadOnlySpan<byte> targetProc = targetOrdinal == 0
                    ? MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)funcName)
                    : default;

                ValidateImage(ref image);

                ref DataDirectory exportTable = ref GetDirectoryTableEntry(ref image, 0);

                if (!Unsafe.IsNullRef(ref exportTable) && exportTable.Size > 0 && exportTable.VirtualAddress != 0)
                {
                    ref ExportDirectory exportDir = ref Unsafe.As<DOSHeader, ExportDirectory>(ref Unsafe.AddByteOffset(ref image, exportTable.VirtualAddress));
                    // השגת מצביעים לטבלאות (Address of Functions, Names, Ordinals)
                    ref uint functions = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref Unsafe.As<DOSHeader, byte>(ref image), exportDir.AddressOfFunctions));
                    ref uint names = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref Unsafe.As<DOSHeader, byte>(ref image), exportDir.AddressOfNames));
                    ref ushort ordinals = ref Unsafe.As<byte, ushort>(ref Unsafe.Add(ref Unsafe.As<DOSHeader, byte>(ref image), exportDir.AddressOfNameOrdinals));

                    uint functionRva = 0; // The potential RVA of the function

                    if (targetOrdinal == 0)
                    {
                        for (int i = 0; i < exportDir.NumberOfNames; i++)
                        {
                            // השוואה בין השמות
                            uint nameOffset = Unsafe.Add(ref names, i);
                            byte* pName = (byte*)Unsafe.AsPointer(ref Unsafe.Add(ref Unsafe.As<DOSHeader, byte>(ref image), nameOffset));
                            var currentProcName = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(pName);

                            if (targetProc.SequenceEqual(currentProcName))
                            {
                                //Console.WriteLine(Encoding.ASCII.GetString(targetProc));
                                ushort ordinal = Unsafe.Add(ref ordinals, i);
                                functionRva = Unsafe.Add(ref functions, ordinal);
                                break;
                            }
                        }
                    }
                    else
                    {
                        // ה-Ordinal בטבלה הוא יחסי ל-Base (בדרך כלל 1)
                        int index = (int)(targetOrdinal - exportDir.Base);
                        if (index >= 0 && index < exportDir.NumberOfFunctions)
                        {
                            functionRva = Unsafe.Add(ref functions, index);
                        }
                    }

                    // בדיקה הבאה

                    if (functionRva != 0)
                    {
                        // בדיקת ספריה נתמכת
                        if (functionRva >= exportTable.VirtualAddress && functionRva < (exportTable.VirtualAddress + exportTable.Size))
                        {
                            byte* pForwarder = ((byte*)Unsafe.AsPointer(ref image)) + functionRva;
                            ReadOnlySpan<byte> forwarderName = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(pForwarder);
                            int dotIndex = SplitForwarder(forwarderName); // פיצול המחרוזת

                            if (dotIndex == -1) return 0; // בדיקת שגיאה
                            nuint length = (nuint)(forwarderName.Length + 1);

                            // מניעת עומס יתר על המחסנית
                            Span<byte> dllName = stackalloc byte[dotIndex + 1];
                            dllName[dotIndex] = 0; // Null Terminator
                            forwarderName.Slice(0, dotIndex).CopyTo(dllName);

                            nint addr = (CustomApiCalls.LoadLibraryA(ref MemoryMarshal.GetReference(dllName))); // השגת הכתובת הבאה
                            //Console.WriteLine(Encoding.ASCII.GetString(forwarderName));
                            if (addr == 0)
                                throw new FileNotFoundException();
                            image = ref ((SafePointer<DOSHeader>)addr).Value;
                            ReadOnlySpan<byte> rest = forwarderName.Slice(dotIndex + 1);
                            if (rest.Length > 0 && rest[0] == (byte)'#')
                            {
                                var ordinal = ushort.Parse(rest.Slice(1));
                                funcName = ordinal;
                            }
                            else
                            {
                                // השמת מצביע למחרוזת החדשה בתוך ה-Forwarder המקורי בזיכרון ה-DLL
                                funcName = (nuint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(rest));
                            }
                            continue;
                        }
                        else return (nint)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref image, functionRva));
                    }
                    return 0;
                }
            }
            return 0;


            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static int SplitForwarder(ReadOnlySpan<byte> str)
            {
                for (int i = 0; i < str.Length; i++)
                {
                    if (str[i] == '.')
                        return i;
                }
                return -1;
            }
        }

        #region Resources
        private static ref ResourceDataEntry FindResourceEx(ref DOSHeader header, nint lpType, nint lpName, short lang)
        {
            ref DataDirectory resourceTable = ref GetDirectoryTableEntry(ref header, 2);
            if (resourceTable.Size > 0 && resourceTable.VirtualAddress != 0)
            {
                var rootDirectory = new SafePointer<DOSHeader>(ref header).AddByteOffset(resourceTable.VirtualAddress).Cast<ResourceDirectory>();
                // חישוב מספר הכניסות הכולל (שמיות + מזהי ID)
                int totalEntries = rootDirectory.Value.NumberOfNamedEntries + rootDirectory.Value.NumberOfIdEntries;

                // המצביע לכניסה הראשונה נמצא מיד אחרי המבנה של ה-Directory
                var entryPtr = rootDirectory.AddByteOffset((uint)Unsafe.SizeOf<ResourceDirectory>()).Cast<ResourceDirectoryEntry>();

                for (uint i = 0; i < totalEntries; i++)
                {
                    // בדיקה האם סוג המשאב (RT_TYPE) תואם ל-lpType
                    if (MatchEntry(rootDirectory, ref entryPtr[i], lpType))
                    {
                        if (entryPtr[i].DataIsDirectory)
                        {
                            var nameDir = rootDirectory.AddByteOffset(entryPtr[i].Offset).Cast<ResourceDirectory>();
                            int nameEntries = nameDir.Value.NumberOfNamedEntries + nameDir.Value.NumberOfIdEntries;
                            var nameEntryPtr = nameDir.AddByteOffset((uint)Unsafe.SizeOf<ResourceDirectory>()).Cast<ResourceDirectoryEntry>();
                            for (uint i2 = 0; i2 < nameEntries; i2++)
                            {
                                if (MatchEntry(rootDirectory, ref nameEntryPtr[i2], lpName))
                                {
                                    if (nameEntryPtr[i2].DataIsDirectory)
                                    {
                                        var langDir = rootDirectory.AddByteOffset(nameEntryPtr[i2].Offset).Cast<ResourceDirectory>();
                                        int langEntries = langDir.Value.NumberOfNamedEntries + langDir.Value.NumberOfIdEntries;
                                        var langEntryPtr = langDir.AddByteOffset((uint)Unsafe.SizeOf<ResourceDirectory>()).Cast<ResourceDirectoryEntry>();

                                        for (uint i3 = 0; i3 < langEntries; i3++)
                                        {
                                            // השוואת שפה לפי windows
                                            if (lang == -1 || langEntryPtr[i3].Id == (ushort)lang)
                                            {
                                                var dataEntry = rootDirectory.AddByteOffset(langEntryPtr[i3].OffsetToData).Cast<ResourceDataEntry>();

                                                // מחזיר כתובת אבסולוטית בזיכרון (Base + RVA)
                                                return ref dataEntry.Value;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return ref Unsafe.NullRef<ResourceDataEntry>();
        }

        private static bool MatchEntry(SafePointer<ResourceDirectory> rootDirectory, scoped ref readonly ResourceDirectoryEntry entry, nint value)
        {
            if (value > 0xFFFF)
            {
                if (!entry.NameIsString) return false;

                var stringPtr = rootDirectory.AddByteOffset(entry.NameOffset).Cast<ushort>();

                ReadOnlySpan<char> resourceName = MemoryMarshal.CreateReadOnlySpan(ref stringPtr.AddByteOffset(2).Cast<char>().Value, stringPtr.Value);

                return resourceName.Equals(((ReadOnlySafePointer<char>)value).ToStringWithNullTerminator(), StringComparison.OrdinalIgnoreCase);
            }
            return !entry.NameIsString && entry.Id == (ushort)value;
        }
        #endregion

        #region Exe
        /// <summary>
        /// Run PE Executeable without create process
        /// </summary>
        /// <param name="FileName"></param>
        public static void RunExecuteable(string FileName)
        {
            AllocatedPointer pointer = Unsafe.BitCast<nint, AllocatedPointer>(LibraryLoader.LoadLibrary(FileName, 0));
            ref ResourceDataEntry mainFestID = ref FindResourceEx(ref pointer.As<DOSHeader>(), 24, 1, -1);
            if (!Unsafe.IsNullRef<ResourceDataEntry>(ref mainFestID))
            {
                string str = Encoding.UTF8.GetString(pointer.AsPointer<byte>()
                    .AddByteOffset(mainFestID.OffsetToData)
                    .AsSpan<byte>((int)mainFestID.Size));
                XNamespace ns = "urn:schemas-microsoft-com:asm.v1";
                XDocument xDocument = XDocument.Parse(str);
                foreach (XElement element in xDocument.Descendants(ns + "dependency").Elements(ns + "dependentAssembly"))
                {
                    XElement? assemblyInfo = element.Element(ns + "assemblyIdentity");
                    if (assemblyInfo != null)
                    {
                        string? name = assemblyInfo.Attribute("name")?.Value;
                        string? version = assemblyInfo.Attribute("version")?.Value;
                        string? publicKeyToken = assemblyInfo.Attribute("publicKeyToken")?.Value;
                        string? architecture = assemblyInfo.Attribute("processorArchitecture")?.Value;
                        string? language = assemblyInfo.Attribute("language")?.Value;

                        string culture = string.IsNullOrEmpty(language) || language == "*" ? "none" : language;

                        if (string.IsNullOrEmpty(architecture) || architecture == "*")
                            architecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

                        // בניית תבנית החיפוש: ארכיטקטורה_שם_טוקן_גרסה_שפה_*
                        // הכוכבית בסוף מחליפה את ה-Hash המערכתי שאין צורך לחשב ידנית
                        string searchPattern = $"{architecture}_{name}_{publicKeyToken}_{version}_{culture}_*".ToLower();

                        string winSxS = Path.Join(Environment.GetEnvironmentVariable("windir"), "WinSxS");
                        var matchedDir = Directory.EnumerateDirectories(winSxS, searchPattern).FirstOrDefault();
                        // ניסיון שני: אם לא נמצא, חפש את הגרסה הכי עדכנית באותה סדרה
                        if (matchedDir == null)
                        {
                            ReadOnlySpan<char> versionSpan = version.AsSpan();
                            int firstDot = versionSpan.IndexOf('.');
                            int secondDot = versionSpan.Slice(firstDot + 1).IndexOf('.');
                            int length = (secondDot != -1) ? firstDot + secondDot + 1 : versionSpan.Length;
                            ReadOnlySpan<char> majorMinor = versionSpan.Slice(0, length);

                            string loosePattern = $"{architecture}_{name}_{publicKeyToken}_{majorMinor}.*_{culture}_*".ToLower();

                            CustomApiCalls.CurrentProcess.WinSxSDir = Directory.EnumerateDirectories(winSxS, loosePattern)
                                .OrderByDescending(d => d) // מיון אלפביתי של הגרסאות
                                .FirstOrDefault();
                        }
                    }
                }
            }
            ref NtHeaders32 header = ref pointer.As<NtHeaders32>(pointer.As<DOSHeader>().e_lfanew);
            if ((header.FileHeader.Characteristics & 0x2) != 0)
            {
                IntPtr entryPointAddr = (IntPtr)Unsafe.AsPointer(ref pointer[header.OptionalHeader.AddressOfEntryPoint]);
                nint ptr = pointer;
                Thread th = new((obj) =>
                {
                    try
                    {
                        CustomApiCalls.CurrentProcess.CommandLine = $"\"{FileName}\"";
                        CustomApiCalls.CurrentProcess.Module = ptr;
                        delegate* unmanaged<void> func = (delegate* unmanaged<void>)entryPointAddr;
                        func();
                    }
                    catch
                    {
                    }
                })
                {
                    IsBackground = false
                };
                th.Start();
                th.Join();
            }
            pointer.Dispose();
            Console.WriteLine("Auto Exit Process");
        }
        #endregion

        #region Active Contex
        // קבועים של מערכת ההפעלה
        const uint ACTX_MAGIC = 0x58544341; // "ACTX"
        const uint SXS_DLL_REDIRECTION_SECTION_ID = 2;

        public static nint BuildManualActivationContextData(nint hmodule)
        {
            int sizeData = Marshal.SizeOf<ACTIVATION_CONTEXT_DATA>();
            int sizeTocHeader = Marshal.SizeOf<ACTIVATION_CONTEXT_DATA_TOC_HEADER>();
            int sizeTocEntry = Marshal.SizeOf<ACTIVATION_CONTEXT_DATA_TOC_ENTRY>();
            int totalSize = sizeData + sizeTocHeader + sizeTocEntry;
            // Create block
            nint pBlock = Marshal.AllocHGlobal(totalSize);

            // zero mem
            Unsafe.InitBlock((void*)pBlock, 0, (uint)totalSize);

            uint tocHeaderOffset = (uint)sizeData;
            uint tocEntryOffset = tocHeaderOffset + (uint)sizeTocHeader;

            ACTIVATION_CONTEXT_DATA* header = (ACTIVATION_CONTEXT_DATA*)pBlock;
            header->Magic = ACTX_MAGIC;
            header->HeaderSize = (uint)sizeData;
            header->FormatVersion = 1;
            header->TotalSize = (uint)totalSize;
            header->DefaultTocOffset = tocHeaderOffset; // מצביע ל-TOC
            header->Flags = 0;

            // 4. מילוי ה-TOC Header
            ACTIVATION_CONTEXT_DATA_TOC_HEADER* tocHeader =
                (ACTIVATION_CONTEXT_DATA_TOC_HEADER*)(pBlock + tocHeaderOffset);
            tocHeader->HeaderSize = (uint)sizeTocHeader;
            tocHeader->EntryCount = 1; // אגף אחד בלבד (למשל DLLs)
            tocHeader->FirstEntryOffset = (uint)sizeTocHeader; // יחסי לתחילת ה-TOC Header

            // 5. מילוי ה-TOC Entry (הגדרת האגף עצמו)
            ACTIVATION_CONTEXT_DATA_TOC_ENTRY* tocEntry =
                (ACTIVATION_CONTEXT_DATA_TOC_ENTRY*)(pBlock + tocEntryOffset);
            tocEntry->Id = SXS_DLL_REDIRECTION_SECTION_ID;
            tocEntry->Offset = (uint)totalSize; // כאן היו מתחילים נתוני ה-DLL (כרגע ריק)
            tocEntry->Size = 0;
            tocEntry->Format = 1;

            return pBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public ref struct ACTCTXW
        {
            public int cbSize;
            public uint dwFlags;
            public ref readonly char lpSource;
            public UInt16 wProcessorArchitecture;
            public UInt16 wLangId;
            public ref readonly char lpAssemblyDirectory;
            public ref readonly char lpResourceName;
            public ref readonly char lpApplicationName;
            public IntPtr hModule;
        }

        public static uint RtlCreateActivationContext(uint Flags,
            ref ACTIVATION_CONTEXT ActivationContextData,
            uint ExtraBytes,
            nint NotificationRoutine,
            nint NotificationContext,
            out nint ActivationContext)
        {
            int baseSize = Unsafe.SizeOf<ACTIVATION_CONTEXT>();
            int totalSize = baseSize + (int)ExtraBytes;

            nint pCtx = Marshal.AllocHGlobal(totalSize);

            byte* ptr = (byte*)pCtx;
            Unsafe.InitBlock(ptr, 0, (uint)totalSize); // איפוס כל הבלוק

            ACTIVATION_CONTEXT* ctx = (ACTIVATION_CONTEXT*)ptr;
            ctx->RefCount = 1;
            ctx->Flags = Flags;
            ctx->ActivationContextData = SafePointerExtentions.ToPointer(ref ActivationContextData);
            ctx->NotificationRoutine = NotificationRoutine;
            ctx->NotificationContext = NotificationContext;

            ActivationContext = pCtx;
            return 0;
        }

        private static bool ActivateActCtx(IntPtr ptr, ref nuint coockie)
        {
            TEB* tls = (TEB*)SegmentReaderX64.GetTebAddressX64();
            if (tls->ActivationContextStackPointer == null)
            {
                return false;
            }

            SafePointer<RTL_ACTIVATION_CONTEXT_STACK_FRAME> framePtr = Marshal.AllocHGlobal(Marshal.SizeOf<RTL_ACTIVATION_CONTEXT_STACK_FRAME>());
            // מילוי הנתונים
            framePtr.Value.Previous = tls->ActivationContextStackPointer->ActiveFrame;
            framePtr.Value.ActivationContext = ptr;
            framePtr.Value.Flags = 0;

            // עדכון ה-TEB
            tls->ActivationContextStackPointer->ActiveFrame = (nint)framePtr;
            coockie = (nuint)framePtr;
            return true;
        }

        private static bool DeactivateActCtx(uint flags, nuint cookie)
        {
            if (cookie == 0) return false;

            TEB* tls = (TEB*)SegmentReaderX64.GetTebAddressX64();

            // ה-cookie הוא הפוינטר ל-Frame שהקצנו ב-AllocHGlobal
            RTL_ACTIVATION_CONTEXT_STACK_FRAME* frameToDeactivate = (RTL_ACTIVATION_CONTEXT_STACK_FRAME*)cookie;

            // וידוי בטיחות: ודא שה-Frame שאנחנו מסירים הוא אכן ה-ActiveFrame הנוכחי
            if (tls->ActivationContextStackPointer->ActiveFrame != (nint)frameToDeactivate)
            {
                // אם זה לא ה-Frame העליון, יש כאן הפרה של סדר המחסנית (LIFO)
                return false;
            }

            // שחזור ה-Frame הקודם בשרשרת
            tls->ActivationContextStackPointer->ActiveFrame = (nint)frameToDeactivate->Previous;

            // שחרור הזיכרון הלא-מנוהל שהוקצה ב-ActivateActCtx
            Marshal.FreeHGlobal((IntPtr)frameToDeactivate);

            return true;
        }
        #endregion

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint TlsAlloc();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TlsSetValue(uint dwTlsIndex, IntPtr lpTlsValue);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool RtlAddFunctionTable(IntPtr FunctionTable, uint EntryCount, nuint BaseAddress);

        [DllImport("kernel32.dll")]
        private static extern bool RtlDeleteFunctionTable(IntPtr FunctionTable);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int LdrLockLoaderLock(uint Flags, out uint Disposition, out IntPtr Cookie);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int LdrUnlockLoaderLock(uint Flags, IntPtr Cookie);
    }
}