#define TARGET_64BIT

using System.Runtime.CompilerServices;

namespace NT_File_Reader.WindowsNative
{
    /// <summary>
    /// Process Environment Block (PEB) structure.
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb"/>
    /// </summary>
    public unsafe struct PEB
    {
        /// <summary>
        /// The process was cloned with an inherited address space.
        /// </summary>
        public bool InheritedAddressSpace;

        /// <summary>
        /// The process has image file execution options (IFEO).
        /// </summary>
        public bool ReadImageFileExecOptions;

        /// <summary>
        /// The process has a debugger attached.
        /// </summary>
        public bool BeingDebugged;

        public byte BitField;

        // מאפיינים המדמים את ה-Bit-fields של ה-C struct
        public bool ImageUsesLargePages { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 0); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 0, value); }
        public bool IsProtectedProcess { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 1); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 1, value); }
        public bool IsImageDynamicallyRelocated { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 2); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 2, value); }
        public bool SkipPatchingUser32Forwarders { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 3); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 3, value); }
        public bool IsPackagedProcess { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 4); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 4, value); }
        public bool IsAppContainerProcess { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 5); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 5, value); }
        public bool IsProtectedProcessLight { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 6); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 6, value); }
        public bool IsLongPathAwareProcess { get => GetBit(ref Unsafe.As<byte, uint>(ref BitField), 7); set => SetBit(ref Unsafe.As<byte, uint>(ref BitField), 7, value); }

        // פונקציות עזר לניהול הביטים
        private bool GetBit(ref uint value, int bitPos) => (value & (1 << bitPos)) != 0;

        private void SetBit(ref uint value1, int bitPos, bool value)
        {
            if (value)
                value1 |= (byte)(1 << bitPos);
            else
                value1 &= (byte)~(1 << bitPos);
        }

        /// <summary>
        /// Handle to a mutex for synchronization.
        /// </summary>
        public nint Mutant;

        /// <summary>
        /// Pointer to the base address of the process image.
        /// </summary>
        public nuint_t ImageBaseAddress;

        /// <summary>
        /// Pointer to the process loader data.
        /// </summary>
        public PEB_LDR_DATA* Ldr;

        /// <summary>
        /// Pointer to the process parameters.
        /// </summary>
        public nint ProcessParameters;

        /// <summary>
        /// Reserved.
        /// </summary>
        public nuint_t SubSystemData;

        /// <summary>
        /// Pointer to the process default heap.
        /// </summary>
        public nuint_t ProcessHeap;

        /// <summary>
        /// Pointer to a critical section used to synchronize access to the PEB.
        /// </summary>
        public nint FastPebLock;

        /// <summary>
        /// Pointer to a singly linked list used by ATL.
        /// </summary>
        public SLIST_HEADER* AtlThunkSListPtr;

        /// <summary>
        /// Handle to the Image File Execution Options key.
        /// </summary>
        public nint IFEOKey;

        /// <summary>
        /// Cross process flags.
        /// </summary>
        public uint CrossProcessFlags;

        // מאפיינים (Properties) לגישה לביטים הבודדים
        public bool ProcessInJob { get => GetBit(ref CrossProcessFlags, 0); set => SetBit(ref CrossProcessFlags, 0, value); }
        public bool ProcessInitializing { get => GetBit(ref CrossProcessFlags, 1); set => SetBit(ref CrossProcessFlags, 1, value); }
        public bool ProcessUsingVEH { get => GetBit(ref CrossProcessFlags, 2); set => SetBit(ref CrossProcessFlags, 2, value); }
        public bool ProcessUsingVCH { get => GetBit(ref CrossProcessFlags, 3); set => SetBit(ref CrossProcessFlags, 3, value); }
        public bool ProcessUsingFTH { get => GetBit(ref CrossProcessFlags, 4); set => SetBit(ref CrossProcessFlags, 4, value); }
        public bool ProcessPreviouslyThrottled { get => GetBit(ref CrossProcessFlags, 5); set => SetBit(ref CrossProcessFlags, 5, value); }
        public bool ProcessCurrentlyThrottled { get => GetBit(ref CrossProcessFlags, 6); set => SetBit(ref CrossProcessFlags, 6, value); }
        public bool ProcessImagesHotPatched { get => GetBit(ref CrossProcessFlags, 7); set => SetBit(ref CrossProcessFlags, 7, value); }

        /// <summary>
        /// User32 KERNEL_CALLBACK_TABLE (ntuser.h)
        /// </summary>
        public nint KernelCallbackTable;
        public nint UserSharedInfoPtr => KernelCallbackTable;

        /// <summary>
        /// Reserved.
        /// </summary>
        public uint SystemReserved;

        /// <summary>
        /// Pointer to the Active Template Library (ATL) singly linked list (32-bit)
        /// </summary>
        public uint AtlThunkSListPtr32;

        /// <summary>
        /// Pointer to the API Set Schema.
        /// </summary>
        public SafePointer<API_SET_NAMESPACE> ApiSetMap;

        /// <summary>
        /// Counter for TLS expansion.
        /// </summary>
        public uint TlsExpansionCounter;

        /// <summary>
        /// Pointer to the TLS bitmap.
        /// </summary>
        public nint TlsBitmap;

        /// <summary>
        /// Bits for the TLS bitmap.
        /// </summary>
        public fixed uint TlsBitmapBits[2];

        /// <summary>
        /// Reserved for CSRSS.
        /// </summary>
        public nuint_t ReadOnlySharedMemoryBase;

        /// <summary>
        /// Pointer to the USER_SHARED_DATA for the current SILO.
        /// </summary>
        public nint SharedData;

        /// <summary>
        /// Reserved for CSRSS.
        /// </summary>
        public nuint_t* ReadOnlyStaticServerData;

        /// <summary>
        /// Pointer to the ANSI code page data.
        /// </summary>
        public CPTABLEINFO* AnsiCodePageData;

        /// <summary>
        /// Pointer to the OEM code page data.
        /// </summary>
        public CPTABLEINFO* OemCodePageData;

        /// <summary>
        /// Pointer to the Unicode case table data.
        /// </summary>
        public NLSTABLEINFO* UnicodeCaseTableData;

        /// <summary>
        /// The total number of system processors.
        /// </summary>
        public uint NumberOfProcessors;

        /// <summary>
        /// Global flags for the system.
        /// </summary>
        public uint NtGlobalFlag;

        // מאפייני ביטים - לפי הסדר המדויק של ה-Windows SDK
        public bool StopOnException { get => GetBit(ref NtGlobalFlag, 0); set => SetBit(ref NtGlobalFlag, 0, value); }  // FLG_STOP_ON_EXCEPTION
        public bool ShowLoaderSnaps { get => GetBit(ref NtGlobalFlag, 1); set => SetBit(ref NtGlobalFlag, 1, value); }  // FLG_SHOW_LDR_SNAPS
        public bool DebugInitialCommand { get => GetBit(ref NtGlobalFlag, 2); set => SetBit(ref NtGlobalFlag, 2, value); }  // FLG_DEBUG_INITIAL_COMMAND
        public bool StopOnHungGUI { get => GetBit(ref NtGlobalFlag, 3); set => SetBit(ref NtGlobalFlag, 3, value); }  // FLG_STOP_ON_HUNG_GUI
        public bool HeapEnableTailCheck { get => GetBit(ref NtGlobalFlag, 4); set => SetBit(ref NtGlobalFlag, 4, value); }  // FLG_HEAP_ENABLE_TAIL_CHECK
        public bool HeapEnableFreeCheck { get => GetBit(ref NtGlobalFlag, 5); set => SetBit(ref NtGlobalFlag, 5, value); }  // FLG_HEAP_ENABLE_FREE_CHECK
        public bool HeapValidateParameters { get => GetBit(ref NtGlobalFlag, 6); set => SetBit(ref NtGlobalFlag, 6, value); }  // FLG_HEAP_VALIDATE_PARAMETERS
        public bool HeapValidateAll { get => GetBit(ref NtGlobalFlag, 7); set => SetBit(ref NtGlobalFlag, 7, value); }  // FLG_HEAP_VALIDATE_ALL
        public bool ApplicationVerifier { get => GetBit(ref NtGlobalFlag, 8); set => SetBit(ref NtGlobalFlag, 8, value); }  // FLG_APPLICATION_VERIFIER
        public bool MonitorSilentProcessExit { get => GetBit(ref NtGlobalFlag, 9); set => SetBit(ref NtGlobalFlag, 9, value); }  // FLG_MONITOR_SILENT_PROCESS_EXIT
        public bool PoolEnableTagging { get => GetBit(ref NtGlobalFlag, 10); set => SetBit(ref NtGlobalFlag, 10, value); } // FLG_POOL_ENABLE_TAGGING
        public bool HeapEnableTagging { get => GetBit(ref NtGlobalFlag, 11); set => SetBit(ref NtGlobalFlag, 11, value); } // FLG_HEAP_ENABLE_TAGGING
        public bool UserStackTraceDb { get => GetBit(ref NtGlobalFlag, 12); set => SetBit(ref NtGlobalFlag, 12, value); } // FLG_USER_STACK_TRACE_DB
        public bool KernelStackTraceDb { get => GetBit(ref NtGlobalFlag, 13); set => SetBit(ref NtGlobalFlag, 13, value); } // FLG_KERNEL_STACK_TRACE_DB
        public bool MaintainObjectTypeList { get => GetBit(ref NtGlobalFlag, 14); set => SetBit(ref NtGlobalFlag, 14, value); } // FLG_MAINTAIN_OBJECT_TYPELIST
        public bool HeapEnableTagByDll { get => GetBit(ref NtGlobalFlag, 15); set => SetBit(ref NtGlobalFlag, 15, value); } // FLG_HEAP_ENABLE_TAG_BY_DLL
        public bool DisableStackExtension { get => GetBit(ref NtGlobalFlag, 16); set => SetBit(ref NtGlobalFlag, 16, value); } // FLG_DISABLE_STACK_EXTENSION
        public bool EnableCsrDebug { get => GetBit(ref NtGlobalFlag, 17); set => SetBit(ref NtGlobalFlag, 17, value); } // FLG_ENABLE_CSRDEBUG
        public bool EnableKDebugSymbolLoad { get => GetBit(ref NtGlobalFlag, 18); set => SetBit(ref NtGlobalFlag, 18, value); } // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
        public bool DisablePageKernelStacks { get => GetBit(ref NtGlobalFlag, 19); set => SetBit(ref NtGlobalFlag, 19, value); } // FLG_DISABLE_PAGE_KERNEL_STACKS
        public bool EnableSystemCritBreaks { get => GetBit(ref NtGlobalFlag, 20); set => SetBit(ref NtGlobalFlag, 20, value); } // FLG_ENABLE_SYSTEM_CRIT_BREAKS
        public bool HeapDisableCoalescing { get => GetBit(ref NtGlobalFlag, 21); set => SetBit(ref NtGlobalFlag, 21, value); } // FLG_HEAP_DISABLE_COALESCING
        public bool EnableCloseExceptions { get => GetBit(ref NtGlobalFlag, 22); set => SetBit(ref NtGlobalFlag, 22, value); } // FLG_ENABLE_CLOSE_EXCEPTIONS
        public bool EnableExceptionLogging { get => GetBit(ref NtGlobalFlag, 23); set => SetBit(ref NtGlobalFlag, 23, value); } // FLG_ENABLE_EXCEPTION_LOGGING
        public bool EnableHandleTypeTagging { get => GetBit(ref NtGlobalFlag, 24); set => SetBit(ref NtGlobalFlag, 24, value); } // FLG_ENABLE_HANDLE_TYPE_TAGGING
        public bool HeapPageAllocs { get => GetBit(ref NtGlobalFlag, 25); set => SetBit(ref NtGlobalFlag, 25, value); } // FLG_HEAP_PAGE_ALLOCS
        public bool DebugInitialCommandEx { get => GetBit(ref NtGlobalFlag, 26); set => SetBit(ref NtGlobalFlag, 26, value); } // FLG_DEBUG_INITIAL_COMMAND_EX
        public bool DisableDbgPrint { get => GetBit(ref NtGlobalFlag, 27); set => SetBit(ref NtGlobalFlag, 27, value); } // FLG_DISABLE_DBGPRINT
        public bool CritSecEventCreation { get => GetBit(ref NtGlobalFlag, 28); set => SetBit(ref NtGlobalFlag, 28, value); } // FLG_CRITSEC_EVENT_CREATION
        public bool LdrTopDown { get => GetBit(ref NtGlobalFlag, 29); set => SetBit(ref NtGlobalFlag, 29, value); } // FLG_LDR_TOP_DOWN
        public bool EnableHandleExceptions { get => GetBit(ref NtGlobalFlag, 30); set => SetBit(ref NtGlobalFlag, 30, value); } // FLG_ENABLE_HANDLE_EXCEPTIONS
        public bool DisableProtDlls { get => GetBit(ref NtGlobalFlag, 31); set => SetBit(ref NtGlobalFlag, 31, value); } // FLG_DISABLE_PROTDLLS

        /// <summary>
        /// Timeout for critical sections.
        /// </summary>
        public long CriticalSectionTimeout;

        /// <summary>
        /// Reserved size for heap segments.
        /// </summary>
        public nint HeapSegmentReserve;

        /// <summary>
        /// Committed size for heap segments.
        /// </summary>
        public nint HeapSegmentCommit;

        /// <summary>
        /// Threshold for decommitting total free heap.
        /// </summary>
        public nint HeapDeCommitTotalFreeThreshold;

        /// <summary>
        /// Threshold for decommitting free heap blocks.
        /// </summary>
        public nint HeapDeCommitFreeBlockThreshold;

        /// <summary>
        /// Number of process heaps.
        /// </summary>
        public uint NumberOfHeaps;

        /// <summary>
        /// Maximum number of process heaps.
        /// </summary>
        public uint MaximumNumberOfHeaps;

        /// <summary>
        /// Pointer to an array of process heaps. ProcessHeaps is initialized
        /// </summary> to point to the first free byte after the PEB and MaximumNumberOfHeaps
        // is computed from the page size used to hold the PEB, less the fixed
        // size of this data structure.
        //
        public nuint_t* ProcessHeaps;

        /// <summary>
        /// Pointer to the system GDI shared handle table.
        /// </summary>
        public nint GdiSharedHandleTable;

        /// <summary>
        /// Pointer to the process starter helper.
        /// </summary>
        public nuint_t ProcessStarterHelper;

        /// <summary>
        /// The maximum number of GDI function calls during batch operations (GdiSetBatchLimit)
        /// </summary>
        public uint GdiDCAttributeList;

        /// <summary>
        /// Pointer to the loader lock critical section.
        /// </summary>
        public nint LoaderLock;

        /// <summary>
        /// Major version of the operating system.
        /// </summary>
        public uint OSMajorVersion;

        /// <summary>
        /// Minor version of the operating system.
        /// </summary>
        public uint OSMinorVersion;

        /// <summary>
        /// Build number of the operating system.
        /// </summary>
        public ushort OSBuildNumber;

        /// <summary>
        /// CSD version of the operating system.
        /// </summary>
        public ushort OSCSDVersion;

        /// <summary>
        /// Platform ID of the operating system.
        /// </summary>
        public uint OSPlatformId;

        /// <summary>
        /// Subsystem version of the current process image (PE Headers).
        /// </summary>
        public uint ImageSubsystem;

        /// <summary>
        /// Major version of the current process image subsystem (PE Headers).
        /// </summary>
        public uint ImageSubsystemMajorVersion;

        /// <summary>
        /// Minor version of the current process image subsystem (PE Headers).
        /// </summary>
        public uint ImageSubsystemMinorVersion;

        /// <summary>
        /// Affinity mask for the current process.
        /// </summary>
        public nint ActiveProcessAffinityMask;

        /// <summary>
        /// Temporary buffer for GDI handles accumulated in the current batch.
        /// </summary>
        public nint GdiHandleBuffer;

        /// <summary>
        /// Pointer to the post-process initialization routine available for use by the application.
        /// </summary>
        public nint PostProcessInitRoutine;

        /// <summary>
        /// Pointer to the TLS expansion bitmap.
        /// </summary>
        public nint TlsExpansionBitmap;

        /// <summary>
        /// Bits for the TLS expansion bitmap. TLS_EXPANSION_SLOTS
        /// </summary>
        public fixed uint TlsExpansionBitmapBits[32];

        /// <summary>
        /// Session ID of the current process.
        /// </summary>
        public uint SessionId;

        /// <summary>
        /// Application compatibility flags. KACF_*
        /// </summary>
        public ulong AppCompatFlags;

        /// <summary>
        /// Application compatibility flags. KACF_*
        /// </summary>
        public ulong AppCompatFlagsUser;

        /// <summary>
        /// Pointer to the Application SwitchBack Compatibility Engine.
        /// </summary>
        public nuint_t pShimData;

        /// <summary>
        /// Pointer to the Application Compatibility Engine.
        /// </summary>
        public nint AppCompatInfo;

        /// <summary>
        /// CSD version string of the operating system.
        /// </summary>
        public UNICODE_STRING CSDVersion;

        /// <summary>
        /// Pointer to the process activation context.
        /// </summary>
        public nint ActivationContextData;

        private nint _ProcessAssemblyStorageMap;

        /// <summary>
        /// Pointer to the process assembly storage map.
        /// </summary>
        public ref ASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ref SafePointerExtentions.AsRef<ASSEMBLY_STORAGE_MAP>(_ProcessAssemblyStorageMap);
        }

        /// <summary>
        /// Pointer to the system default activation context.
        /// </summary>
        public nint SystemDefaultActivationContextData;

        /// <summary>
        /// Pointer to the system assembly storage map.
        /// </summary>
        public nint SystemAssemblyStorageMap;

        /// <summary>
        /// Minimum stack commit size.
        /// </summary>
        public nint MinimumStackCommit;

        /// <summary>
        /// since 19H1 (previously FlsCallback to FlsHighIndex)
        /// </summary>
        public fixed nuint_t SparePointers[2];

        /// <summary>
        /// Pointer to the patch loader data.
        /// </summary>
        public nuint_t PatchLoaderData;

        /// <summary>
        /// Pointer to the CHPE V2 process information. CHPEV2_PROCESS_INFO
        /// </summary>
        public nuint_t ChpeV2ProcessInfo;

        /// <summary>
        /// Packaged process feature state.
        /// </summary>
        public uint AppModelFeatureState;

        /// <summary>
        /// SpareUlongs
        /// </summary>
        public fixed uint SpareUlongs[2];

        /// <summary>
        /// Active code page.
        /// </summary>
        public ushort ActiveCodePage;

        /// <summary>
        /// OEM code page.
        /// </summary>
        public ushort OemCodePage;

        /// <summary>
        /// Code page case mapping.
        /// </summary>
        public ushort UseCaseMapping;

        /// <summary>
        /// Unused NLS field.
        /// </summary>
        public ushort UnusedNlsField;

        /// <summary>
        /// Pointer to the application WER registration data.
        /// </summary>
        public nint WerRegistrationData;

        /// <summary>
        /// Pointer to the application WER assert pointer.
        /// </summary>
        public nuint_t WerShipAssertPtr;

        /// <summary>
        /// Pointer to the EC bitmap on ARM64. (Windows 11 and above)
        /// </summary>
        public nuint_t pContextData;
        public nuint_t EcCodeBitMap => pContextData;

        /// <summary>
        /// Reserved.
        /// </summary>
        public nuint_t ImageHeaderHash;

        /// <summary>
        /// ETW tracing flags.
        /// </summary>
        public uint TracingFlags;

        // מאפיינים לגישה לביטים הספציפיים
        public bool HeapTracingEnabled { get => GetBit(ref TracingFlags, 0); set => SetBit(ref TracingFlags, 0, value); }
        public bool CritSecTracingEnabled { get => GetBit(ref TracingFlags, 1); set => SetBit(ref TracingFlags, 1, value); }
        public bool LibLoaderTracingEnabled { get => GetBit(ref TracingFlags, 2); set => SetBit(ref TracingFlags, 2, value); }

        /// <summary>
        /// Reserved for CSRSS.
        /// </summary>
        public ulong CsrServerReadOnlySharedMemoryBase;

        /// <summary>
        /// Pointer to the thread pool worker list lock.
        /// </summary>
        public nint TppWorkerpListLock;

        /// <summary>
        /// Pointer to the thread pool worker list.
        /// </summary>
        public LIST_ENTRY TppWorkerpList;

        /// <summary>
        /// Wait on address hash table. (RtlWaitOnAddress)
        /// </summary>
        public fixed nuint_t WaitOnAddressHashTable[128];

        /// <summary>
        /// Pointer to the telemetry coverage header. // since RS3
        /// </summary>
        public nint TelemetryCoverageHeader;

        /// <summary>
        /// Cloud file flags. (ProjFs and Cloud Files) // since RS4
        /// </summary>
        public uint CloudFileFlags;

        /// <summary>
        /// Cloud file diagnostic flags.
        /// </summary>
        public uint CloudFileDiagFlags;

        /// <summary>
        /// Placeholder compatibility mode. (ProjFs and Cloud Files)
        /// </summary>
        public sbyte PlaceholderCompatibilityMode;

        /// <summary>
        /// Reserved for placeholder compatibility mode.
        /// </summary>
        public fixed sbyte PlaceholderCompatibilityModeReserved[7];

        /// <summary>
        /// Pointer to leap second data. // since RS5
        /// </summary>
        public LEAP_SECOND_DATA* LeapSecondData;

        /// <summary>
        /// Leap second flags.
        /// </summary>
        public uint LeapSecondFlags;

        /// <summary>
        /// Global flags for the process.
        /// </summary>
        public uint NtGlobalFlag2;

        /// <summary>
        /// Extended feature disable mask (AVX). // since WIN11
        /// </summary>
        public ulong ExtendedFeatureDisableMask;
    }
}
