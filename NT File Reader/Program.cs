using System.CommandLine;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
namespace NT_File_Reader
{
    internal class Program
    {
        static int Main(string[] args)
        {
            Argument<FileInfo> Argfile = new Argument<FileInfo>("file")
            {
                Description = "File to read"
            };
            RootCommand rootCommand = new("NT File display details");
            rootCommand.Arguments.Add(Argfile);
            rootCommand.SetAction(parseResult =>
            {
                FileInfo? parsedFile = parseResult.GetValue(Argfile);
                ReadFile(parsedFile!.FullName);
                return 0;
            });
            ParseResult parseResult = rootCommand.Parse(args);
            return parseResult.Invoke();
        }

        static void ReadFile(string file)
        {
            try
            {
                using CMemoryMappedFile memoryMapped = new CMemoryMappedFile(Path.GetFullPath(file), "MapNT");
                using MemoryMappedView memoryMappedView = memoryMapped.GetView(FileMapAccess.FileMapAllAccess);

                Console.WriteLine(CenterText("Begin Of File", 30, '*'));

                ref DOSHeader header = ref memoryMappedView.As<DOSHeader>();
                // בדיקות של הקובץ האם זה להרצה
                if (!(header.e_magic == Extentions.IMAGE_DOS_SIGNATURE))
                    throw new Exception("Invliad exe");

                ref NtHeaders64 nt_header = ref memoryMappedView.As<NtHeaders64>(header.e_lfanew);
                if (!(nt_header.Signature == Extentions.IMAGE_NT_SIGNATURE))
                    throw new Exception("Invliad exe");

                using AllocatedPointer pointer = new(nt_header.OptionalHeader.SizeOfImage);

                Unsafe.CopyBlockUnaligned(ref pointer[0], ref memoryMappedView.handle, nt_header.OptionalHeader.SizeOfHeaders);
                Console.WriteLine("Sections:");
                for (int i = 0; i < nt_header.FileHeader.NumberOfSections; i++)
                {
                    ref SectionHeader section = ref pointer.As<SectionHeader>((nuint)(header.e_lfanew + Unsafe.SizeOf<NtHeaders64>() + i * Unsafe.SizeOf<SectionHeader>()));
                    Console.WriteLine("\t{0}", Encoding.ASCII.GetString(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<SectionHeader, byte>(ref section), 8)));
                    Unsafe.CopyBlockUnaligned(ref pointer[section.VirtualAddress], ref memoryMappedView[section.PointerToRawData], section.SizeOfRawData);
                }
#pragma warning disable CS0436 // Type conflicts with imported type
                if (nt_header.OptionalHeader.ExportTable.Size > 0)
                {
                    Console.WriteLine(CenterText("Nt Exports", 30, '*'));

                    ref ExportDirectory imageExportDirectory = ref pointer.As<ExportDirectory>(nt_header.OptionalHeader.ExportTable.VirtualAddress);
                    ref uint exportAddressTable = ref pointer.As<uint>(imageExportDirectory.AddressOfFunctions);
                    ref ushort nameOrdinalsPointer = ref pointer.As<ushort>(imageExportDirectory.AddressOfNameOrdinals);
                    ref uint exportNamePointerTable = ref pointer.As<uint>(imageExportDirectory.AddressOfNames);

                    for (int nameIndex = 0; nameIndex < imageExportDirectory.NumberOfNames; nameIndex++)
                    {
                        ref byte name = ref pointer[Unsafe.Add(ref exportNamePointerTable, nameIndex)];
                        Console.WriteLine("\t{0}", Encoding.ASCII.GetString(new ReadOnlySafePointer<byte>(ref name).ToStringWithNullTerminator()));
                        ushort ordinal = Unsafe.Add(ref nameOrdinalsPointer, nameIndex);
                        unsafe
                        {
                            Console.WriteLine("\tProc Address:0x{0:X4}", (nuint)Unsafe.AsPointer(ref pointer[Unsafe.Add(ref exportAddressTable, ordinal)]));
                        }
                    }
                }
                if (nt_header.OptionalHeader.ImportTable.Size > 0)
                {
                    Console.WriteLine(CenterText("Nt Imports", 30, '*'));
                    ref ImportDescriptor importImageDescriptor = ref pointer.As<ImportDescriptor>(nt_header.OptionalHeader.ImportTable.VirtualAddress);
                    //DLL Imports
                    for (; importImageDescriptor.Name != 0; importImageDescriptor = ref Unsafe.Add(ref importImageDescriptor, 1))
                    {
                        ref byte Imported_DLL = ref pointer[importImageDescriptor.Name];
                        Console.WriteLine("\tImported DLLs: {0}", Encoding.ASCII.GetString(new ReadOnlySafePointer<byte>(ref Imported_DLL).ToStringWithNullTerminator()));
                        uint thunk = (importImageDescriptor.OriginalFirstThunk == 0 ? importImageDescriptor.FirstThunk : importImageDescriptor.OriginalFirstThunk);
                        ref ThunkData64 thunkData = ref (pointer.As<ThunkData64>(thunk));
                        // dll exported functions
                        for (; thunkData.AddressOfData != 0; thunkData = ref Unsafe.Add(ref thunkData, 1))
                        {
                            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
                            if ((thunkData.AddressOfData & (1ul << 63)) != 0)
                            {
                                //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                                Console.WriteLine("\t\tOrdinal: {0}", (ushort)thunkData.Ordinal);
                            }
                            else
                            {
                                ref byte print = ref pointer[(nuint)thunkData.ForwarderString + 2];
                                Console.WriteLine("\t\t{0}", Encoding.ASCII.GetString(new ReadOnlySafePointer<byte>(ref Imported_DLL).ToStringWithNullTerminator()));
                            }
                            thunkData.Function = 0; // Resolve Function
                        }
                    }
                }
                if (nt_header.OptionalHeader.CertificateTable.Size > 0)
                {
                    Console.WriteLine(CenterText("Nt Certificate File", 30, '*'));
                    ref WinCertificate cer_table_offset = ref pointer.As<WinCertificate>(nt_header.OptionalHeader.CertificateTable.VirtualAddress);
                    Console.WriteLine($"Certificate Type:{cer_table_offset.wCertificateType}");
                    if (cer_table_offset.wCertificateType == 2)
                    {
                        ref byte data = ref cer_table_offset.bCertificate;
                        data = ref SignedDataExtentions.GetAsn1Header(ref data, out byte tag, out int length);
                        Console.WriteLine($"\t {tag:X2}.{length}");
                        data = ref SignedDataExtentions.GetAsn1Header(ref data, out tag, out length);
                        Console.WriteLine($"\t {tag:X2}.{length}");
                    }
                }
                if (nt_header.OptionalHeader.TLSTable.Size > 0)
                {
                    Console.WriteLine(CenterText("Thread Local Storage", 30, '*'));
                }
                Console.WriteLine(CenterText("End Of File", 30, '*'));

#pragma warning restore CS0436 // Type conflicts with imported type
            }
            catch (Exception e)
            {
                Console.WriteLine("Unable To Read File Error:{0}", e);
            }
        }

        public static string CenterText(string text, int width, char padChar)
        {
            if (text.Length >= width) return text;
            string ret = $"  {text}  ";
            width += 4;
            int leftPadding = (width + ret.Length) / 2;
            return ret.PadLeft(leftPadding, padChar).PadRight(width, padChar);
        }
    }
}