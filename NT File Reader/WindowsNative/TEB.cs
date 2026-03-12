#define TARGET_64BIT

using System.Runtime.InteropServices;

namespace NT_File_Reader.WindowsNative
{
    /// <summary>
    /// Thread Environment Block (TEB) structure.
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb"/>
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct TEB
    {
        public const int TLS_MINIMUM_AVAILABLE = 64;
        public const int STATIC_UNICODE_BUFFER_LENGTH = 261;
        public const int WIN32_CLIENT_INFO_LENGTH = 62;

        /// <summuray>
        /// Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
        /// </summary>
        public NT_TIB NtTib;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t EnvironmentPointer;

        /// <summuray>
        /// Client ID for this thread.
        /// </summary>
        public CLIENT_ID ClientId;

        /// <summuray>
        /// A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
        /// </summary>
        public nuint_t ActiveRpcHandle;

        /// <summuray>
        /// A pointer to the __declspec(thread) local storage array.
        /// </summary>
        public nuint_t ThreadLocalStoragePointer;

        private nuint _ProcessEnvironmentBlock;
        /// <summuray>
        /// A pointer to the Process Environment Block (PEB), which contains information about the process.
        /// </summary>
        public ref PEB ProcessEnvironmentBlock => ref ((SafePointer<PEB>)_ProcessEnvironmentBlock).Value;
        /// <summuray>
        /// The previous Win32 error value for this thread.
        /// </summary>
        public uint LastErrorValue;

        /// <summuray>
        /// The number of critical sections currently owned by this thread.
        /// </summary>
        public uint CountOfOwnedCriticalSections;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t CsrClientThread;

        /// <summuray>
        /// Reserved for win32k.sys
        /// </summary>
        public nuint_t Win32ThreadInfo;

        /// <summuray>
        /// Reserved for user32.dll
        /// </summary>
        public fixed uint User32Reserved[26];

        /// <summuray>
        /// Reserved for winsrv.dll
        /// </summary>
        public fixed uint UserReserved[5];

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t WOW32Reserved;

        /// <summuray>
        /// The LCID of the current thread. (Kernel32!GetThreadLocale)
        /// </summary>
        public uint CurrentLocale;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public uint FpSoftwareStatusRegister;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public fixed nuint_t ReservedForDebuggerInstrumentation[16];

#if TARGET_64BIT
        /// <summuray>
        /// Reserved for floating-point emulation.
        /// </summary>
        public fixed nuint_t SystemReserved1[25];

        /// <summuray>
        /// Per-thread fiber local storage. (Teb->HasFiberData)
        /// </summary>
        public nuint_t HeapFlsData;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public fixed nuint_t RngState[4];
#else
        /// <summuray>
        /// Reserved.
        /// </summary>
        public fixed nuint_t SystemReserved1[26];
#endif

        /// <summuray>
        /// Placeholder compatibility mode. (ProjFs and Cloud Files)
        /// </summary>
        public sbyte PlaceholderCompatibilityMode;

        /// <summuray>
        /// Indicates whether placeholder hydration is always explicit.
        /// </summary>
        public bool PlaceholderHydrationAlwaysExplicit;

        /// <summuray>
        /// ProjFs and Cloud Files (reparse point) file virtualization.
        /// </summary>
        public fixed sbyte PlaceholderReserved[10];

        /// <summuray>
        /// The process ID (PID) that the current COM server thread is acting on behalf of.
        /// </summary>
        public uint ProxiedProcessId;

        /// <summuray>
        /// Pointer to the activation context stack for the current thread.
        /// </summary>
        public ACTIVATION_CONTEXT_STACK ActivationStack;

        /// <summuray>
        /// Opaque operation on behalf of another user or process.
        /// </summary>
        public fixed byte WorkingOnBehalfTicket[8];

        /// <summuray>
        /// The last exception status for the current thread.
        /// </summary>
        public uint ExceptionCode;

        /// <summuray>
        /// Pointer to the activation context stack for the current thread.
        /// </summary>
        public ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;

        /// <summuray>
        /// The stack pointer (SP) of the current system call or exception during instrumentation.
        /// </summary>
        public nuint_t InstrumentationCallbackSp;

        /// <summuray>
        /// The program counter (PC) of the previous system call or exception during instrumentation.
        /// </summary>
        public nuint_t InstrumentationCallbackPreviousPc;

        /// <summuray>
        /// The stack pointer (SP) of the previous system call or exception during instrumentation.
        /// </summary>
        public nuint_t InstrumentationCallbackPreviousSp;

#if TARGET_64BIT
        /// <summuray>
        /// The miniversion ID of the current transacted file operation.
        /// </summary>
        public uint TxFsContext;
#endif

        /// <summuray>
        /// Indicates the state of the system call or exception instrumentation callback.
        /// </summary>
        public bool InstrumentationCallbackDisabled;

#if TARGET_64BIT
        /// <summuray>
        /// Indicates the state of alignment exceptions for unaligned load/store operations.
        /// </summary>
        public bool UnalignedLoadStoreExceptions;
#endif

#if !TARGET_64BIT
        /// <summuray>
        /// SpareBytes.
        /// </summary>
        public fixed byte SpareBytes[23];

        /// <summuray>
        /// The miniversion ID of the current transacted file operation.
        /// </summary>
        public uint TxFsContext;
#endif

        /// <summuray>
        /// Reserved for GDI (Win32k).
        /// </summary>
        public GDI_TEB_BATCH GdiTebBatch;
        public CLIENT_ID RealClientId;
        public nint GdiCachedProcessHandle;
        public uint GdiClientPID;
        public uint GdiClientTID;
        public nuint_t GdiThreadLocalInfo;

        /// <summuray>
        /// Reserved for User32 (Win32k).
        /// </summary>
        public fixed nuint_t Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];

        /// <summuray>
        /// Reserved for opengl32.dll
        /// </summary>
        public fixed nuint_t glDispatchTable[233];
        public fixed nuint_t glReserved1[29];
        public nuint_t glReserved2;
        public nuint_t glSectionInfo;
        public nuint_t glSection;
        public nuint_t glTable;
        public nuint_t glCurrentRC;
        public nuint_t glContext;

        /// <summuray>
        /// The previous status value for this thread.
        /// </summary>
        public uint LastStatusValue;

        /// <summuray>
        /// A static string for use by the application.
        /// </summary>
        public UNICODE_STRING StaticUnicodeString;

        /// <summuray>
        /// A static buffer for use by the application.
        /// </summary>
        public fixed char StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

        /// <summuray>
        /// The maximum stack size and indicates the base of the stack.
        /// </summary>
        public nuint_t DeallocationStack;

        /// <summuray>
        /// Data for Thread Local Storage. (TlsGetValue)
        /// </summary>
        public fixed nuint_t TlsSlots[TLS_MINIMUM_AVAILABLE];

        /// <summuray>
        /// Reserved for TLS.
        /// </summary>
        LIST_ENTRY TlsLinks;

        /// <summuray>
        /// Reserved for NTVDM.
        /// </summary>
        public nuint_t Vdm;

        /// <summuray>
        /// Reserved for RPC. The pointer is XOR'ed with RPC_THREAD_POINTER_KEY.
        /// </summary>
        public nuint_t ReservedForNtRpc;

        /// <summuray>
        /// Reserved for Debugging (DebugActiveProcess).
        /// </summary>
        public fixed nuint_t DbgSsReserved[2];

        /// <summuray>
        /// The error mode for the current thread. (GetThreadErrorMode)
        /// </summary>
        public uint HardErrorMode;

        /// <summuray>
        /// Reserved.
        /// </summary>
#if TARGET_64BIT
        public fixed nuint_t Instrumentation[11];
#else
        public fixed nuint_t Instrumentation[9];
#endif

        /// <summuray>
        /// Reserved.
        /// </summary>
        public Guid ActivityId;

        /// <summuray>
        /// The identifier of the service that created the thread. (svchost)
        /// </summary>
        public nuint_t SubProcessTag;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t PerflibData;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t EtwTraceData;

        /// <summuray>
        /// The address of a socket handle during a blocking socket operation. (WSAStartup)
        /// </summary>
        public nint WinSockData;

        /// <summuray>
        /// The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
        /// </summary>
        public uint GdiBatchCount;

        /// <summuray>
        /// The preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
        /// </summary>
        public ProcessorUnion IdealProcessorUnion;


        [StructLayout(LayoutKind.Explicit)]
        public struct ProcessorUnion
        {
            // First union member: PROCESSOR_NUMBER (typically a 4-byte struct/value)
            [FieldOffset(0)]
            public PROCESSOR_NUMBER CurrentIdealProcessor;

            // Second union member: uint (4 bytes)
            [FieldOffset(0)]
            public uint IdealProcessorValue;

            // Third union member: nested struct (simulated by flattening fields)
            [FieldOffset(0)]
            public byte ReservedPad0; // UCHAR in C is byte in C#
            [FieldOffset(1)]
            public byte ReservedPad1;
            [FieldOffset(2)]
            public byte ReservedPad2;
            [FieldOffset(3)]
            public byte IdealProcessor;
        }


        /// <summuray>
        /// The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
        /// </summary>
        public uint GuaranteedStackBytes;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t ReservedForPerf;

        /// <summuray>
        /// Reserved for Object Linking and Embedding (OLE)
        /// </summary>
        public SOleTlsData* ReservedForOle;

        /// <summuray>
        /// Indicates whether the thread is waiting on the loader lock.
        /// </summary>
        public uint WaitingOnLoaderLock;

        /// <summuray>
        /// The saved priority state for the thread.
        /// </summary>
        public nuint_t SavedPriorityState;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t ReservedForCodeCoverage;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t ThreadPoolData;

        /// <summuray>
        /// Pointer to the TLS (Thread Local Storage) expansion slots for the thread.
        /// </summary>
        public nuint_t* TlsExpansionSlots;

#if TARGET_64BIT
        public nuint_t ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
        public nuint_t Unused; // previously BStoreLimit
#endif

        /// <summuray>
        /// The generation of the MUI (Multilingual User Interface) data.
        /// </summary>
        public uint MuiGeneration;

        /// <summuray>
        /// Indicates whether the thread is impersonating another security context.
        /// </summary>
        public uint IsImpersonating;

        /// <summuray>
        /// Pointer to the NLS (National Language Support) cache.
        /// </summary>
        public nuint_t NlsCache;

        /// <summuray>
        /// Pointer to the AppCompat/Shim Engine data.
        /// </summary>
        public nuint_t pShimData;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public uint HeapData;

        /// <summuray>
        /// Handle to the current transaction associated with the thread.
        /// </summary>
        public nint CurrentTransactionHandle;

        /// <summuray>
        /// Pointer to the active frame for the thread.
        /// </summary>
        public TEB_ACTIVE_FRAME* ActiveFrame;

        /// <summuray>
        /// Reserved for FLS (RtlProcessFlsData).
        /// </summary>
        public nuint_t FlsData;

        /// <summuray>
        /// Pointer to the preferred languages for the current thread. (GetThreadPreferredUILanguages)
        /// </summary>
        public nuint_t PreferredLanguages;

        /// <summuray>
        /// Pointer to the user-preferred languages for the current thread. (GetUserPreferredUILanguages)
        /// </summary>
        public nuint_t UserPrefLanguages;

        /// <summuray>
        /// Pointer to the merged preferred languages for the current thread. (MUI_MERGE_USER_FALLBACK)
        /// </summary>
        public nuint_t MergedPrefLanguages;

        /// <summuray>
        /// Indicates whether the thread is impersonating another user's language settings.
        /// </summary>
        public uint MuiImpersonation;

        /// <summuray>
        /// Reserved.
        /// </summary>
        private ushort union1;

        public ushort CrossTebFlags => union1;
        public ushort SpareCrossTebBits => union1;

        /// <summuray>
        /// SameTebFlags modify the state and behavior of the current thread.
        /// </summary>
        public ushort SameTebFlags;

        // Helper properties to simulate the bit-fields
        public bool SafeThunkCall { get => (SameTebFlags & (1 << 0)) != 0; set => SetBit(0, value); }
        public bool InDebugPrint { get => (SameTebFlags & (1 << 1)) != 0; set => SetBit(1, value); }
        public bool HasFiberData { get => (SameTebFlags & (1 << 2)) != 0; set => SetBit(2, value); }
        public bool SkipThreadAttach { get => (SameTebFlags & (1 << 3)) != 0; set => SetBit(3, value); }
        public bool WerInShipAssertCode { get => (SameTebFlags & (1 << 4)) != 0; set => SetBit(4, value); }
        public bool RanProcessInit { get => (SameTebFlags & (1 << 5)) != 0; set => SetBit(5, value); }
        public bool ClonedThread { get => (SameTebFlags & (1 << 6)) != 0; set => SetBit(6, value); }
        public bool SuppressDebugMsg { get => (SameTebFlags & (1 << 7)) != 0; set => SetBit(7, value); }
        public bool DisableUserStackWalk { get => (SameTebFlags & (1 << 8)) != 0; set => SetBit(8, value); }
        public bool RtlExceptionAttached { get => (SameTebFlags & (1 << 9)) != 0; set => SetBit(9, value); }
        public bool InitialThread { get => (SameTebFlags & (1 << 10)) != 0; set => SetBit(10, value); }
        public bool SessionAware { get => (SameTebFlags & (1 << 11)) != 0; set => SetBit(11, value); }
        public bool LoadOwner { get => (SameTebFlags & (1 << 12)) != 0; set => SetBit(12, value); }
        public bool LoaderWorker { get => (SameTebFlags & (1 << 13)) != 0; set => SetBit(13, value); }
        public bool SkipLoaderInit { get => (SameTebFlags & (1 << 14)) != 0; set => SetBit(14, value); }
        public bool SkipFileAPIBrokering { get => (SameTebFlags & (1 << 15)) != 0; set => SetBit(15, value); }

        private void SetBit(int bitPos, bool value)
        {
            if (value)
                SameTebFlags |= (ushort)(1 << bitPos);
            else
                SameTebFlags &= (ushort)~(1 << bitPos);
        }

        /// <summuray>
        /// Pointer to the callback function that is called when a KTM transaction scope is entered.
        /// </summary>
        public nuint_t TxnScopeEnterCallback;

        /// <summuray>
        /// Pointer to the callback function that is called when a KTM transaction scope is exited.
        /// </summary>/
        public nuint_t TxnScopeExitCallback;

        /// <summuray>
        /// Pointer to optional context data for use by the application when a KTM transaction scope callback is called.
        /// </summary>
        public nuint_t TxnScopeContext;

        /// <summuray>
        /// The lock count of critical sections for the current thread.
        /// </summary>
        public uint LockCount;

        /// <summuray>
        /// The offset to the WOW64 (Windows on Windows) TEB for the current thread.
        /// </summary>
        public int WowTebOffset;

        /// <summuray>
        /// Pointer to the DLL containing the resource (valid after LdrFindResource_U/LdrResFindResource/etc... returns).
        /// </summary>
        LDR_RESLOADER_RET* ResourceRetValue;

        /// <summuray>
        /// Reserved for Windows Driver Framework (WDF).
        /// </summary>
        public nuint_t ReservedForWdf;

        /// <summuray>
        /// Reserved for the Microsoft C runtime (CRT).
        /// </summary>
        public ulong ReservedForCrt;

        /// <summuray>
        /// The Host Compute Service (HCS) container identifier.
        /// </summary>
        public Guid EffectiveContainerId;

        /// <summuray>
        /// Reserved for Kernel32!Sleep (SpinWait).
        /// </summary>
        public ulong LastSleepCounter; // since Win11

        /// <summuray>
        /// Reserved for Kernel32!Sleep (SpinWait).
        /// </summary>
        public uint SpinCallCount;

        /// <summuray>
        /// Extended feature disable mask (AVX).
        /// </summary>
        public ulong ExtendedFeatureDisableMask;

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t SchedulerSharedDataSlot; // since 24H2

        /// <summuray>
        /// Reserved.
        /// </summary>
        public nuint_t HeapWalkContext;

        /// <summuray>
        /// The primary processor group affinity of the thread.
        /// </summary>
        public GROUP_AFFINITY PrimaryGroupAffinity;

        /// <summuray>
        /// Read-copy-update (RCU) synchronization context.
        /// </summary>
        public fixed uint Rcu[2];
    }
}
