using System.Runtime.InteropServices;

namespace System.Reflection.PortableExecutable
{
    public enum SubSystemType : ushort
    {
        Unknown = 0,
        Native = 1,
        WindowsGUI = 2,
        WindowsCUI = 3,
        PosixCUI = 7,
        WindowsCEGui = 9,
        EfiApplication = 10,
        EfiBootServiceDriver = 11,
        EfiRuntimeDriver = 12,
        EfiRom = 13,
        Xbox = 14
    }

    [Flags]
    public enum GuardFlags : uint
    {
        None = 0x00000000,
        CFInstrumented = 0x00000100,
        CFWInstrumented = 0x00000200,
        CFFunctionTablePresent = 0x00000400,
        SecurityCookieUnused = 0x00000800,
        ProtectDelayLoadIAT = 0x00001000,
        DelayLoadIATInITS = 0x00002000,
        CFExportSuppressionInfoPresent = 0x00004000, 
        CFEnableExportSuppression = 0x00008000,
        CFLongjumpTablePresent = 0x00010000,
        XFGEnabled = 0x00000040 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    public struct BaseRelocation
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LoadConfigCodeIntegrity
    {
        public ushort Flags;
        public ushort Catalog;
        public uint CatalogOffset;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LoadConfigDirectory64
    {
        public uint Size;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint GlobalFlagsClear;
        public uint GlobalFlagsSet;
        public uint CriticalSectionDefaultTimeout;
        public ulong DeCommitFreeBlockThreshold;
        public ulong DeCommitTotalFreeThreshold;
        public ulong LockPrefixTable;
        public ulong MaximumAllocationSize;
        public ulong VirtualMemoryThreshold;
        public ulong ProcessAffinityMask;
        public uint ProcessHeapFlags;
        public ushort CSDVersion;
        public ushort DependentLoadFlags;
        public ulong EditList;
        public ulong SecurityCookie; // השדה הקריטי לטיפול ב-MSVC /GS
        public ulong SEHandlerTable;
        public ulong SEHandlerCount;
        public ulong GuardCFCheckFunctionPointer;
        public ulong GuardCFDispatchFunctionPointer;
        public ulong GuardCFFunctionTable;
        public ulong GuardCFFunctionCount;
        public uint GuardFlags;
        public LoadConfigCodeIntegrity CodeIntegrity;
        public ulong GuardAddressTakenIatEntryTable;
        public ulong GuardAddressTakenIatEntryCount;
        public ulong GuardLongJumpTargetTable;
        public ulong GuardLongJumpTargetCount;
        public ulong DynamicValueRelocTable;
        public ulong CHPEMetadataPointer;
        public ulong GuardRFFailureRoutine;
        public ulong GuardRFFailureRoutineFunctionPointer;
        public uint DynamicValueRelocTableOffset;
        public ushort DynamicValueRelocTableSection;
        public ushort Reserved2;
        public ulong GuardRFVerifyStackPointerFunctionPointer;
        public uint HotPatchTableOffset;
        public uint Reserved3;
        public ulong EnclaveConfigurationPointer;
        public ulong VolatileMetadataPointer;
        public ulong GuardEHContinuationTable;
        public ulong GuardEHContinuationCount;
        public ulong GuardXFGCheckFunctionPointer;
        public ulong GuardXFGDispatchFunctionPointer;
        public ulong GuardXFGTableDispatchFunctionPointer;
        public ulong CastGuardOsDeterminedFailureMode;
        public ulong GuardMemcpyFunctionPointer;
        public ulong UmaFunctionPointers; // נוסף בגרסאות חדשות של Windows 11/10
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LoadConfigDirectory32
    {
        public uint Size;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint GlobalFlagsClear;
        public uint GlobalFlagsSet;
        public uint CriticalSectionDefaultTimeout;
        public uint DeCommitFreeBlockThreshold;
        public uint DeCommitTotalFreeThreshold;
        public uint LockPrefixTable;
        public uint MaximumAllocationSize;
        public uint VirtualMemoryThreshold;
        public uint ProcessHeapFlags;
        public uint ProcessAffinityMask;
        public ushort CSDVersion;
        public ushort DependentLoadFlags;
        public uint EditList;
        public uint SecurityCookie;
        public uint SEHandlerTable;
        public uint SEHandlerCount;
        public uint GuardCFCheckFunctionPointer;
        public uint GuardCFDispatchFunctionPointer;
        public uint GuardCFFunctionTable;
        public uint GuardCFFunctionCount;
        public uint GuardFlags;
        public LoadConfigCodeIntegrity CodeIntegrity;
        public uint GuardAddressTakenIatEntryTable;
        public uint GuardAddressTakenIatEntryCount;
        public uint GuardLongJumpTargetTable;
        public uint GuardLongJumpTargetCount;
        public uint DynamicValueRelocTable;
        public uint CHPEMetadataPointer;
        public uint GuardRFFailureRoutine;
        public uint GuardRFFailureRoutineFunctionPointer;
        public uint DynamicValueRelocTableOffset;
        public ushort DynamicValueRelocTableSection;
        public ushort Reserved2;
        public uint GuardRFVerifyStackPointerFunctionPointer;
        public uint HotPatchTableOffset;
        public uint Reserved3;
        public uint EnclaveConfigurationPointer;
        public uint VolatileMetadataPointer;
        public uint GuardEHContinuationTable;
        public uint GuardEHContinuationCount;
        public uint GuardXFGCheckFunctionPointer;
        public uint GuardXFGDispatchFunctionPointer;
        public uint GuardXFGTableDispatchFunctionPointer;
        public uint CastGuardOsDeterminedFailureMode;
        public uint GuardMemcpyFunctionPointer;
        public uint UmaFunctionPointers;
    }
}
