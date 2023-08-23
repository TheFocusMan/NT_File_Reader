// See https://aka.ms/new-console-template for more information
using NT_File_Reader;
using System.Reflection.PortableExecutable;

// הקוד הזה מחליף את חתימת הקובץ מקובץ אחד לאחד ללא שימוש בספריות
Console.WriteLine("Enter Image For Read Singnature:");
string? readFrom = Console.ReadLine();
Console.WriteLine("Enter Image For Write Singnature:");
string? wireTo = Console.ReadLine();
unsafe
{
    byte[]? readFile = null;
    byte[]? writeFile = null;
    if (!string.IsNullOrEmpty(readFrom) && File.Exists(readFrom) && !string.IsNullOrEmpty(wireTo) && File.Exists(wireTo))
    {
        readFile = File.ReadAllBytes(readFrom);
        writeFile = File.ReadAllBytes(wireTo);
    }
    else
    {
        Console.WriteLine("One of Files Is Missing");
        return;
    }

    fixed (byte* ptrRead = readFile)
    fixed (byte* ptrWrite = writeFile)
    {
        NtHeaders32* readHeader = Extentions.GetNtHeaderNoChecks(ptrRead);
        NtHeaders32* WriteHeader = Extentions.GetNtHeaderNoChecks(ptrWrite);

        if (readHeader == null || WriteHeader == null)
        {
            Console.WriteLine("One of the files is invalid");
            goto End;
        }

        int readOffset = readHeader->OptionalHeader.Magic == 0x20b ? sizeof(OptionalHeaders64) : sizeof(OptionalHeaders32);
        int writeOffset = WriteHeader->OptionalHeader.Magic == 0x20b ? sizeof(OptionalHeaders64) : sizeof(OptionalHeaders32);

        DataDirectory* securityRead = GetDataDirectories(readHeader) + 4; // קובץ האבטחה
        DataDirectory* securityWrite = GetDataDirectories(WriteHeader) + 4;

        uint* sizeOfImageWrite = GetSizeOfImage(WriteHeader);
        if (securityRead->Size == 0)
        {
            Console.WriteLine("No Singnature Found!");
            goto End;
        }
        using (FileStream stream = new FileStream(wireTo, FileMode.Open))
        {
            DataDirectory* writes = GetDataDirectories(WriteHeader);
            if (securityWrite->Size == securityRead->Size)
            {
                stream.Position = securityWrite->VirtualAddress;
                stream.Write(new ReadOnlySpan<byte>(ptrRead + securityRead->VirtualAddress, (int)securityRead->Size));
                //Buffer.MemoryCopy(ptrRead + securityRead.VirtualAddress, ptrWrite + securityWrite.VirtualAddress,securityRead.Size,securityWrite.Size);
            }
            else if (securityWrite->VirtualAddress == 0)
            {
                uint size = Math.Min(*sizeOfImageWrite, (uint)stream.Length);
                if ((uint)stream.Length >= *sizeOfImageWrite)
                    *sizeOfImageWrite += securityRead->Size;

                DataDirectory* writeToDir = writes + 4;
                writeToDir->VirtualAddress = size;
                writeToDir->Size = securityRead->Size;
                stream.Write(new ReadOnlySpan<byte>(ptrWrite, (int)size));
                stream.Write(new ReadOnlySpan<byte>(ptrRead + securityRead->VirtualAddress, (int)securityRead->Size));
            }
            else
            {
                for (int i = 0; i < 16; i++, writes++)
                {
                    if (writes->VirtualAddress > securityWrite->VirtualAddress)
                    {
                        // לא נתמך
                    }
                }
            }
        }
        Console.WriteLine("File Swap Signature Successes");
    End:;

    }
}

static unsafe DataDirectory* GetDataDirectories(NtHeaders32* header)
{
    int readOffset = header->OptionalHeader.Magic == 0x20b ? 112 : 96;
    return (DataDirectory*)((byte*)&header->OptionalHeader + readOffset);
}

static unsafe uint* GetSizeOfImage(NtHeaders32* header)
{
    return header->OptionalHeader.Magic == 0x20b ? (uint*)(((byte*)&header->OptionalHeader.SizeOfImage) + 4) : &header->OptionalHeader.SizeOfImage;
}