using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CLIENT_ID
{
    public nint UniqueProcess;
    public nint UniqueThread;
}

// Assuming PROCESSOR_NUMBER is defined as follows (standard Windows definition)
[StructLayout(LayoutKind.Sequential)]
public struct PROCESSOR_NUMBER
{
    public ushort Group;
    public byte Number;
    public byte Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct LIST_ENTRY
{
    public SafePointer<LIST_ENTRY> Flink;
    public SafePointer<LIST_ENTRY> Blink;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct ACTIVATION_CONTEXT_STACK
{
    public IntPtr ActiveFrame;
    public LIST_ENTRY FrameListHead;
    public uint Flags;
    public uint NextCookieSequenceNumber;
    public uint StackId;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    public nint Previous;
    public IntPtr ActivationContext;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct GROUP_AFFINITY
{
    public UIntPtr Mask;
    public ushort Group;
    public fixed ushort Reserved[3];
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct LDR_RESLOADER_RET
{
    public nint Module;
    public nint DataEntry;
    public nint TargetModule;
}

/// <summary>
/// Represents a pointer to a TEB_ACTIVE_FRAME structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct TEB_ACTIVE_FRAME
{
    public uint Flags;
    public TEB_ACTIVE_FRAME* Previous; // This is the PTEB_ACTIVE_FRAME
    public TEB_ACTIVE_FRAME_CONTEXT* Context;
}

/// <summary>
/// Represents the context associated with an active frame.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct TEB_ACTIVE_FRAME_CONTEXT
{
    public uint Flags;
    public IntPtr FrameName;
}

/// <summary>
/// The GDI_TEB_BATCH structure is used by the GDI subsystem to batch graphics operations.
/// It is located within the TEB (Thread Environment Block).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct GDI_TEB_BATCH
{
    /// <summary>
    /// Offset to the next command in the buffer.
    /// Bit 0 is a flag indicating if the batch is being flushed.
    /// </summary>
    public uint Offset;
    public nint HDC;
    public fixed uint Buffer[310];
}
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SOleTlsData
{
    public nuint ThreadBase;
    public nuint SmAllocator;
    public uint ApartmentID;
    public uint Flags; // OLETLSFLAGS
    public int TlsMapIndex;
    public nuint* TlsSlot;
    public uint ComInits;
    public uint OleInits;
    public uint Calls;
    public nuint ServerCall; // previously CallInfo (before TH1)
    public nuint CallObjectCache; // previously FreeAsyncCall (before TH1)
    public nuint ContextStack; // previously FreeClientCall (before TH1)
    public nuint ObjServer;
    public uint TIDCaller;
    // ... (other fields are version-dependant)
}

/// <summary>
/// The PEB_LDR_DATA structure contains information about the loaded modules for the process.
/// <see href="https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data"/>
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct PEB_LDR_DATA
{
    public uint Length;
    public bool Initialized;
    public nint SsHandle;
    public LIST_ENTRY InLoadOrderModuleList;
    public LIST_ENTRY InMemoryOrderModuleList;
    public LIST_ENTRY InInitializationOrderModuleList;
    public nuint EntryInProgress;
    public bool ShutdownInProgress;
    public nint ShutdownThreadId;
}

[StructLayout(LayoutKind.Sequential,Pack = 8)]
public struct LDR_DATA_TABLE_ENTRY
{
    // The three primary linked lists
    public LIST_ENTRY InLoadOrderLinks;
    public LIST_ENTRY InMemoryOrderLinks;
    public LIST_ENTRY InInitializationOrderLinks;

    public IntPtr DllBase;
    public IntPtr EntryPoint;
    public uint SizeOfImage;

    public UNICODE_STRING FullDllName;
    public UNICODE_STRING BaseDllName;

    public uint Flags;
    public ushort LoadCount;
    public ushort TlsIndex;

    public LIST_ENTRY HashLinks;
    public uint TimeDateStamp;
    // Windows 8
    public IntPtr EntryPointActivationContext; 
    public IntPtr Lock;                          
    public IntPtr DdagNode;                    
    public LIST_ENTRY NodeModuleLink;           
    public IntPtr LoadContext;                   
    public IntPtr ParentDllBase;               
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct LEAP_SECOND_DATA
{
    public byte Enabled;
    public fixed byte Reserved[3];
    public uint Count;
    public IntPtr Data;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct SLIST_HEADER
{
    [FieldOffset(0)] public ulong Alignment;
#if TARGET_64BIT
        [FieldOffset(8)] public ulong Region;
#endif
}


/// <summary>
/// Contains information about a Code Page Table.
/// Used by ntdll for character encoding and translation.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct CPTABLEINFO
{
    /// <summary>
    /// Code page number (e.g., 1252 for Windows Western).
    /// </summary>
    public ushort CodePage;

    /// <summary>
    /// Maximum bytes per character in this code page.
    /// </summary>
    public ushort MaximumCharacterSize;

    /// <summary>
    /// Default character used for unmappable characters.
    /// </summary>
    public ushort DefaultChar;

    /// <summary>
    /// Unicode character used for unmappable characters.
    /// </summary>
    public ushort UniDefaultChar;

    /// <summary>
    /// Character used to replace invalid sequences.
    /// </summary>
    public ushort TransDefaultChar;

    /// <summary>
    /// Unicode replacement character.
    /// </summary>
    public ushort TransUniDefaultChar;

    /// <summary>
    /// Pointer to the table used for translating to Unicode.
    /// </summary>
    public IntPtr MultiByteTable;

    /// <summary>
    /// Pointer to the table used for translating from Unicode.
    /// </summary>
    public IntPtr WideCharTable;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct NLSTABLEINFO
{
    public CPTABLEINFO OemTableInfo;               // Specifies OEM table.
    public CPTABLEINFO AnsiTableInfo;              // Specifies an ANSI table.
    public ushort* UpperCaseTable;                 // Specifies an 844 format uppercase table.
    public ushort* LowerCaseTable;                 // Specifies an 844 format lowercase table.
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ACTIVATION_CONTEXT
{
    public int RefCount;
    public uint Flags;
    public IntPtr ActivationContextData;
    public IntPtr NotificationRoutine;
    public IntPtr NotificationContext;
    public unsafe fixed uint SentNotifications[8];
    public unsafe fixed uint DisabledNotifications[8];
    public ASSEMBLY_STORAGE_MAP StorageMap;
    public fixed nuint_t InlineStorageMapBitmap[32];
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ASSEMBLY_STORAGE_MAP
{
    public uint Flags;
    public uint AssemblyCount;
    public ASSEMBLY_STORAGE_MAP_ENTRY** AssemblyArray;
}

public struct ASSEMBLY_STORAGE_MAP_ENTRY
{
    public uint Flags;
    public UNICODE_STRING DosPath;
    public nint Handle;
}

[StructLayout(LayoutKind.Sequential)]
public struct ACTIVATION_CONTEXT_DATA
{
    public uint Magic;
    public uint HeaderSize;
    public uint FormatVersion;
    public uint TotalSize;
    public uint DefaultTocOffset;
    public uint ExtendedTocOffset;
    public uint AssemblyRosterOffset;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
public struct ACTIVATION_CONTEXT_DATA_TOC_HEADER
{
    public uint HeaderSize;
    public uint EntryCount;
    public uint FirstEntryOffset;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
public struct ACTIVATION_CONTEXT_DATA_TOC_ENTRY
{
    public uint Id;
    public uint Offset; // Offset מתחילת ה-ACTIVATION_CONTEXT_DATA
    public uint Size;
    public uint Format;
}