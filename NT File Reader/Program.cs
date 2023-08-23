using System.IO.MemoryMappedFiles;
using System.Reflection.PortableExecutable;

namespace NT_File_Reader
{
    public static unsafe class Extentions
    {
        public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; //MZ
        public const ushort IMAGE_OS2_SIGNATURE = 0x454E;     // NE
        public const ushort IMAGE_OS2_SIGNATURE_LE = 0x454C;   // LE
        public const ushort IMAGE_VXD_SIGNATURE = 0x454C;   // LE
        public const ushort IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        public static NtHeaders64* GetNtHeader64(byte* ptr)
        {
            DOSHeader* header = (DOSHeader*)ptr;

            if (header->e_magic != IMAGE_DOS_SIGNATURE)
                return null;

            NtHeaders64* nt_header = (NtHeaders64*)(ptr + header->e_lfanew);
            if (nt_header->Signature != IMAGE_NT_SIGNATURE || nt_header->OptionalHeader.Magic != 0x20b)
                return null;

            return nt_header;
        }

        public static NtHeaders32* GetNtHeader32(byte* ptr)
        {
            DOSHeader* header = (DOSHeader*)ptr;

            if (header->e_magic != IMAGE_DOS_SIGNATURE)
                return null;

            NtHeaders32* nt_header = (NtHeaders32*)(ptr + header->e_lfanew);
            if (nt_header->Signature != IMAGE_NT_SIGNATURE || nt_header->OptionalHeader.Magic != 0x10b)
                return null;

            return nt_header;
        }

        public static NtHeaders32* GetNtHeaderNoChecks(byte* ptr)
        {
            DOSHeader* header = (DOSHeader*)ptr;

            if (header->e_magic != IMAGE_DOS_SIGNATURE)
                return null;

            NtHeaders32* nt_header = (NtHeaders32*)(ptr + header->e_lfanew);
            return nt_header;
        }

        public static unsafe SectionHeader* ResolveSectionHeader(SectionHeader* section_header, uint RVA, uint numberofsections)
        {
            for (int i = 1; i <= numberofsections; i++, section_header++)
            {
                //Console.WriteLine("Section Header: Section Name {0}", FromAscii(section_header->Name, 8));

                if (RVA >= section_header->VirtualAddress && RVA < section_header->VirtualAddress + section_header->PhysicalAddress_VirtualSize)
                {
                    return section_header;
                }
                //section_header += (uint)sizeof(PIMAGE_SECTION_HEADER);
            }
            return null;
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter File To read");
            string? path = Console.ReadLine();
            try
            {
                using MemoryMappedFile memoryMapped = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.ReadWrite);
                using var viewstream = memoryMapped.CreateViewStream();
                unsafe
                {
                    byte* ptr = null;
                    Console.WriteLine("******** Begin Of File ********");


                    viewstream.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
                    DOSHeader* header = (DOSHeader*)ptr;
                    // בדיקות של הקובץ האם זה להרצה
                    if (!(header->e_magic == Extentions.IMAGE_DOS_SIGNATURE))
                        throw new Exception("Invliad exe");

                    NtHeaders64* nt_header = (NtHeaders64*)(ptr + header->e_lfanew);
                    if (!(nt_header->Signature == Extentions.IMAGE_NT_SIGNATURE))
                        throw new Exception("Invliad exe");
#pragma warning disable CS0436 // Type conflicts with imported type
                    SectionHeader* section_header = (SectionHeader*)((ulong)nt_header + (ulong)sizeof(NtHeaders64));
                    uint numberofsections = nt_header->FileHeader.NumberOfSections;
                    if (nt_header->OptionalHeader.CertificateTable.Size > 0)
                    {
                        Console.WriteLine("********  Nt Cer File  ********");
                        SectionHeader* CertSection = Extentions.ResolveSectionHeader(section_header, nt_header->OptionalHeader.CertificateTable.VirtualAddress, numberofsections);
                        WinCertificate* cer_table_offset = (WinCertificate*)(ptr + nt_header->OptionalHeader.CertificateTable.VirtualAddress);
                        return;
                    }
                    if (nt_header->OptionalHeader.ImportTable.Size > 0)
                    {
                        Console.WriteLine("********  Nt Imports  ********");
                        SectionHeader* import_section = Extentions.ResolveSectionHeader(section_header, nt_header->OptionalHeader.ImportTable.VirtualAddress, numberofsections);

                        ulong import_table_offset = (ulong)(ptr + import_section->PointerToRawData);
                        //imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress

                        ImportDescriptor* importImageDescriptor = (ImportDescriptor*)(AddIntOrLong(import_table_offset, (int)(nt_header->OptionalHeader.ImportTable.VirtualAddress - import_section->VirtualAddress)));
                        //DLL Imports
                        for (; importImageDescriptor->Name != 0; importImageDescriptor++)
                        {
                            byte* Imported_DLL = (byte*)AddIntOrLong(import_table_offset, (int)(importImageDescriptor->Name - import_section->VirtualAddress));
                            Console.WriteLine("\tImported DLLs: {0}", FromAscii(Imported_DLL, strlen(Imported_DLL)));
                            uint thunk = (importImageDescriptor->OriginalFirstThunk == 0 ? importImageDescriptor->FirstThunk : importImageDescriptor->OriginalFirstThunk);
                            ThunkData64* thunkData = (ThunkData64*)(import_table_offset + (thunk - import_section->VirtualAddress));
                            // dll exported functions
                            for (; thunkData->AddressOfData != 0; thunkData++)
                            {
                                //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
                                if ((thunkData->AddressOfData & (1ul << 63)) != 0)
                                {
                                    //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                                    Console.WriteLine("\t\tOrdinal: {0}", (ushort)thunkData->AddressOfData);
                                }
                                else
                                {
                                    byte* print = (byte*)(import_table_offset + (thunkData->ForwarderString - import_section->VirtualAddress + 2));
                                    Console.WriteLine("\t\t{0}", FromAscii(print, strlen(print)));
                                }
                            }
                        }
                    }
                    if (nt_header->OptionalHeader.ExportTable.Size > 0)
                    {
                        Console.WriteLine("********  Nt Exports  ********");
                        // Dll Exports

                        SectionHeader* exportSection = Extentions.ResolveSectionHeader(section_header, nt_header->OptionalHeader.ExportTable.VirtualAddress, numberofsections);
                        ulong export_table_offset = (ulong)(ptr + exportSection->PointerToRawData);

                        ExportDirectory* imageExportDirectory = (ExportDirectory*)(AddIntOrLong(export_table_offset, (int)(nt_header->OptionalHeader.ExportTable.VirtualAddress - exportSection->VirtualAddress)));
                        uint* exportAddressTable = (uint*)(ptr + imageExportDirectory->AddressOfFunctions);
                        ushort* nameOrdinalsPointer = (ushort*)(ptr + imageExportDirectory->AddressOfNameOrdinals);
                        uint* exportNamePointerTable = (uint*)(ptr + imageExportDirectory->AddressOfNames);

                        for (int nameIndex = 0; nameIndex < imageExportDirectory->NumberOfNames; nameIndex++)
                        {
                            byte* name = ptr + exportNamePointerTable[nameIndex];
                            Console.WriteLine("\t{0}", FromAscii(name, strlen(name)));
                            ushort ordinal = nameOrdinalsPointer[nameIndex];
                            //Console.WriteLine("\tProc Address:0x{0:X}", (ulong)ptr + exportAddressTable[ordinal]);
                        }
                    }

                    Console.WriteLine("********  End Of File  ********");
                    viewstream.SafeMemoryMappedViewHandle.ReleasePointer();
                }

#pragma warning restore CS0436 // Type conflicts with imported type
            }
            catch (Exception e)
            {
                Console.WriteLine("E Efshar To Read File Error:{0}", e.Message);
            }
            Console.WriteLine("Key.....");
            Console.ReadKey();
        }

        private static ushort CharCombine(char left, char right)
        {
            return (ushort)(left | right << 8);
        }

        private static void LoadLibary(string path)
        {

        }

        private static ulong AddIntOrLong(ulong value, long add)
        {
            if (add < 0)
                return value - (ulong)-add;
            else return value + (ulong)add;
        }
        private static unsafe string FromAscii(byte* ascii, int length)
        {
            string str = "";
            for (int i = 0; i < length; i++)
            {
                str += (char)ascii[i];
            }
            return str;
        }
        public static unsafe int strlen(byte* s)
        {
            if (s == null)
            {
                // Handle the error here
            }

            int length = 0;

            byte* pEnd = s;
            while (*pEnd++ != '\0') ;
            length = (int)((pEnd - s) - 1);

            return length;
        }
    }
}