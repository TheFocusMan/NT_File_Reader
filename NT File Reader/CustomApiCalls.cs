using System;
using System.Drawing;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text;

namespace NT_File_Reader
{
    public unsafe struct ProcessDataNotPEB
    {
        public string CommandLine;
        public byte* CommandLineA;
        public nint Module;
        public string? WinSxSDir;
    }

    public static class CustomApiCalls
    {
        public static unsafe nint LoadLibraryA(ref readonly byte path)
        {
            return LoadLibraryExA(in path, 0, 0);
        }

        public static unsafe nint LoadLibraryW(char* path)
        {
            return LoadLibraryExW(path, 0, 0);
        }

        public static unsafe nint LoadLibraryExA(ref readonly byte path, nint file, uint flags)
        {
            string str = new((sbyte*)Unsafe.AsPointer(in path));
            try
            {
                return LibraryLoader.LoadLibrary(str, flags);
            }
            finally
            {
                GC.SuppressFinalize(str);
            }
        }

        public static unsafe nint LoadLibraryExW(char* path, nint file, uint flags)
        {
            string str = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(path));
            try
            {
                return LibraryLoader.LoadLibrary(str, flags);
            }
            finally
            {
                GC.SuppressFinalize(str);
            }
        }

        public static unsafe nint MatchApiCallsToResolveImport(nint library, SafePointer<byte> print, ReadOnlySpan<byte> name)
        {
            nint ret;
            if (name.StartsWith("GetProcAddress"u8))
            {
                ret = (nint)(delegate*<ref DOSHeader, nuint, nint>)&Extentions.GetProcAddress;
            }
            #region Library Modules
            else if (name.SequenceEqual("LoadLibraryA"u8))
            {
                ret = (nint)(delegate*<ref readonly byte, nint>)&CustomApiCalls.LoadLibraryA;
            }
            else if (name.SequenceEqual("LoadLibraryExA"u8))
            {
                ret = (nint)(delegate*<ref readonly byte, nint, uint, nint>)&CustomApiCalls.LoadLibraryExA;
            }
            else if (name.SequenceEqual("LoadLibraryW"u8))
            {
                ret = (nint)(delegate*<char*, nint>)&CustomApiCalls.LoadLibraryW;
            }
            else if (name.SequenceEqual("LoadLibraryExW"u8))
            {
                ret = (nint)(delegate*<char*, nint, uint, nint>)&CustomApiCalls.LoadLibraryExW;
            }
            else if (name.SequenceEqual("GetModuleHandleA"u8))
            {
                ret = (nint)(delegate*<ref readonly byte, nint>)&GetModuleHandleA;
            }
            else if (name.SequenceEqual("GetModuleHandleW"u8))
            {
                ret = (nint)(delegate*<ref readonly char, nint>)&GetModuleHandleW;
            }
            else if (name.SequenceEqual("GetModuleHandleExA"u8))
            {
                ret = (nint)(delegate*<uint, ref readonly byte, ref nint,bool>)&GetModuleHandleExA;
            }
            else if (name.SequenceEqual("GetModuleHandleExW"u8))
            {
                ret = (nint)(delegate*<uint, ref readonly char, ref nint, bool>)&GetModuleHandleExW;
            }
            else if (name.SequenceEqual("GetModuleFileNameA"u8))
            {
                ret = (nint)(delegate*<nint, ref byte, int, uint>)&GetModuleFileNameA;
            }
            else if (name.SequenceEqual("GetModuleFileNameW"u8))
            {
                ret = (nint)(delegate*<nint, ref char, int, uint>)&GetModuleFileNameW;
            }
            #endregion
            else if (name.SequenceEqual("GetCommandLineA"u8))
            {
                ret = (nint)(delegate*<nint>)&GetCommandLineA;
            }
            else if (name.SequenceEqual("GetCommandLineW"u8))
            {
                ret = (nint)(delegate*<nint>)&GetCommandLineW;
            }
            else if (name.SequenceEqual("GetSysColor"u8))
            {
                ret = (nint)(delegate*<int,uint>)&GetSysColor;
            }
            else if (name.StartsWith("NtQueryInformationProcess"u8))
            {
                ret = (nint)(delegate*<nint, PROCESSINFOCLASS, nint, uint, ref uint, uint>)&MyNtQueryInformationProcess;
            }
            else if (name.StartsWith("LdrGetDllHandleByName"u8))
            {
                ret = (nint)(delegate*<void*, void*, out nuint, uint>)&LdrGetDllHandleByName;
            }
            else if (name.StartsWith("LdrGetDllPath"u8))
            {
                ret = (nint)(delegate*<ref readonly char, uint, char**, char**, uint>)&LdrGetDllPath;
            }
            else ret = Extentions.GetProcAddress(ref Unsafe.AsRef<DOSHeader>((void*)library), (nuint)print);

            return ret;
        }
        // ייבוא הפונקציה מ-ntdll.dll
        [DllImport("ntdll.dll", SetLastError = true,EntryPoint = "NtQueryInformationProcess")]
        private static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            nint processInformation,
            uint processInformationLength,
            ref uint returnLength);

        public enum PROCESSINFOCLASS : int
        {
            ProcessBasicInformation = 0,                     // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
            ProcessQuotaLimits,                              // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
            ProcessIoCounters,                               // q: IO_COUNTERS
            ProcessVmCounters,                               // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
            ProcessTimes,                                    // q: KERNEL_USER_TIMES
            ProcessBasePriority,                             // s: KPRIORITY
            ProcessRaisePriority,                            // s: ULONG
            ProcessDebugPort,                                // q: HANDLE
            ProcessExceptionPort,                            // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
            ProcessAccessToken,                              // s: PROCESS_ACCESS_TOKEN
            ProcessLdtInformation = 10,                      // qs: PROCESS_LDT_INFORMATION
            ProcessLdtSize,                                  // s: PROCESS_LDT_SIZE
            ProcessDefaultHardErrorMode,                     // qs: ULONG
            ProcessIoPortHandlers,                           // s: PROCESS_IO_PORT_HANDLER_INFORMATION (kernel-mode only)
            ProcessPooledUsageAndLimits,                     // q: POOLED_USAGE_AND_LIMITS
            ProcessWorkingSetWatch,                          // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
            ProcessUserModeIOPL,                             // qs: ULONG (requires SeTcbPrivilege)
            ProcessEnableAlignmentFaultFixup,                // s: BOOLEAN
            ProcessPriorityClass,                            // qs: PROCESS_PRIORITY_CLASS
            ProcessWx86Information,                          // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
            ProcessHandleCount = 20,                         // q: ULONG, PROCESS_HANDLE_INFORMATION
            ProcessAffinityMask,                             // qs: KAFFINITY, qs: GROUP_AFFINITY
            ProcessPriorityBoost,                            // qs: ULONG
            ProcessDeviceMap,                                // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
            ProcessSessionInformation,                       // q: PROCESS_SESSION_INFORMATION
            ProcessForegroundInformation,                    // s: PROCESS_FOREGROUND_BACKGROUND
            ProcessWow64Information,                         // q: ULONG_PTR
            ProcessImageFileName,                            // q: UNICODE_STRING
            ProcessLUIDDeviceMapsEnabled,                    // q: ULONG
            ProcessBreakOnTermination,                       // qs: ULONG
            ProcessDebugObjectHandle = 30,                   // q: HANDLE
            ProcessDebugFlags,                               // qs: ULONG
            ProcessHandleTracing,                            // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
            ProcessIoPriority,                               // qs: IO_PRIORITY_HINT
            ProcessExecuteFlags,                             // qs: ULONG (MEM_EXECUTE_OPTION_*)
            ProcessTlsInformation,                           // qs: PROCESS_TLS_INFORMATION // ProcessResourceManagement
            ProcessCookie,                                   // q: ULONG
            ProcessImageInformation,                         // q: SECTION_IMAGE_INFORMATION
            ProcessCycleTime,                                // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
            ProcessPagePriority,                             // qs: PAGE_PRIORITY_INFORMATION
            ProcessInstrumentationCallback = 40,             // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
            ProcessThreadStackAllocation,                    // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
            ProcessWorkingSetWatchEx,                        // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
            ProcessImageFileNameWin32,                       // q: UNICODE_STRING
            ProcessImageFileMapping,                         // q: HANDLE (input)
            ProcessAffinityUpdateMode,                       // qs: PROCESS_AFFINITY_UPDATE_MODE
            ProcessMemoryAllocationMode,                     // qs: PROCESS_MEMORY_ALLOCATION_MODE
            ProcessGroupInformation,                         // q: USHORT[]
            ProcessTokenVirtualizationEnabled,               // s: ULONG
            ProcessConsoleHostProcess,                       // qs: ULONG_PTR // ProcessOwnerInformation
            ProcessWindowInformation = 50,                   // q: PROCESS_WINDOW_INFORMATION
            ProcessHandleInformation,                        // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
            ProcessMitigationPolicy,                         // s: PROCESS_MITIGATION_POLICY_INFORMATION
            ProcessDynamicFunctionTableInformation,          // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
            ProcessHandleCheckingMode,                       // qs: ULONG; s: 0 disables, otherwise enables
            ProcessKeepAliveCount,                           // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
            ProcessRevokeFileHandles,                        // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
            ProcessWorkingSetControl,                        // s: PROCESS_WORKING_SET_CONTROL
            ProcessHandleTable,                              // q: ULONG[] // since WINBLUE
            ProcessCheckStackExtentsMode,                    // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
            ProcessCommandLineInformation = 60,              // q: UNICODE_STRING
            ProcessProtectionInformation,                    // q: PS_PROTECTION
            ProcessMemoryExhaustion,                         // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
            ProcessFaultInformation,                         // s: PROCESS_FAULT_INFORMATION
            ProcessTelemetryIdInformation,                   // q: PROCESS_TELEMETRY_ID_INFORMATION
            ProcessCommitReleaseInformation,                 // qs: PROCESS_COMMIT_RELEASE_INFORMATION
            ProcessDefaultCpuSetsInformation,                // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
            ProcessAllowedCpuSetsInformation,                // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
            ProcessSubsystemProcess,                         // s: void // EPROCESS->SubsystemProcess
            ProcessJobMemoryInformation,                     // q: PROCESS_JOB_MEMORY_INFO
            ProcessInPrivate = 70,                           // q: BOOLEAN; s: void // ETW // since THRESHOLD2
            ProcessRaiseUMExceptionOnInvalidHandleClose,     // qs: ULONG; s: 0 disables, otherwise enables
            ProcessIumChallengeResponse,                     // q: PROCESS_IUM_CHALLENGE_RESPONSE
            ProcessChildProcessInformation,                  // q: PROCESS_CHILD_PROCESS_INFORMATION
            ProcessHighGraphicsPriorityInformation,          // q: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
            ProcessSubsystemInformation,                     // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
            ProcessEnergyValues,                             // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
            ProcessPowerThrottlingState,                     // qs: POWER_THROTTLING_PROCESS_STATE
            ProcessActivityThrottlePolicy,                   // qs: PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
            ProcessWin32kSyscallFilterInformation,           // q: WIN32K_SYSCALL_FILTER
            ProcessDisableSystemAllowedCpuSets = 80,         // s: BOOLEAN
            ProcessWakeInformation,                          // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
            ProcessEnergyTrackingState,                      // qs: PROCESS_ENERGY_TRACKING_STATE
            ProcessManageWritesToExecutableMemory,           // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
            ProcessCaptureTrustletLiveDump,                  // q: ULONG
            ProcessTelemetryCoverage,                        // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
            ProcessEnclaveInformation,
            ProcessEnableReadWriteVmLogging,                 // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
            ProcessUptimeInformation,                        // q: PROCESS_UPTIME_INFORMATION
            ProcessImageSection,                             // q: HANDLE
            ProcessDebugAuthInformation,                     // s: 90
            ProcessSystemResourceManagement,                 // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
            ProcessSequenceNumber,                           // q: ULONGLONG
            ProcessLoaderDetour,                             // qs: Obsolete // since RS5
            ProcessSecurityDomainInformation,                // q: PROCESS_SECURITY_DOMAIN_INFORMATION
            ProcessCombineSecurityDomainsInformation,        // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
            ProcessEnableLogging,                            // qs: PROCESS_LOGGING_INFORMATION
            ProcessLeapSecondInformation,                    // qs: PROCESS_LEAP_SECOND_INFORMATION
            ProcessFiberShadowStackAllocation,               // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
            ProcessFreeFiberShadowStackAllocation,           // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
            ProcessAltSystemCallInformation = 100,           // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1
            ProcessDynamicEHContinuationTargets,             // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
            ProcessDynamicEnforcedCetCompatibleRanges,       // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
            ProcessCreateStateChange,                        // s: Obsolete // since WIN11
            ProcessApplyStateChange,                         // s: Obsolete
            ProcessEnableOptionalXStateFeatures,             // s: ULONG64 // EnableProcessOptionalXStateFeatures
            ProcessAltPrefetchParam,                         // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
            ProcessAssignCpuPartitions,                      // s: HANDLE
            ProcessPriorityClassEx,                          // s: PROCESS_PRIORITY_CLASS_EX
            ProcessMembershipInformation,                    // q: PROCESS_MEMBERSHIP_INFORMATION
            ProcessEffectiveIoPriority = 110,                // q: IO_PRIORITY_HINT
            ProcessEffectivePagePriority,                    // q: ULONG
            ProcessSchedulerSharedData,                      // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
            ProcessSlistRollbackInformation,
            ProcessNetworkIoCounters,                        // q: PROCESS_NETWORK_COUNTERS
            ProcessFindFirstThreadByTebValue,                // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
            ProcessEnclaveAddressSpaceRestriction,           // qs: // since 25H2
            ProcessAvailableCpus,                            // q: PROCESS_AVAILABLE_CPUS_INFORMATION
            MaxProcessInfoClass,
        }

        private static uint MyNtQueryInformationProcess(nint ProcessHandle, PROCESSINFOCLASS processInformationClass,
            nint processInformation, 
            uint processInformationLength,
            ref uint returnLength)
        {
            if (ProcessHandle == -1)
            {
                switch (processInformationClass)
                {
                    case PROCESSINFOCLASS.ProcessWx86Information:
                        if (processInformationLength == 4)
                        {
                            if (!Unsafe.IsNullRef(ref returnLength))
                                returnLength = 4;

                            ((SafePointer<uint>)processInformation).Value = 0;
                            return 0;
                        }
                        break;
                }
                return 0xC0000001;
            }
            else
            {
                return NtQueryInformationProcess(ProcessHandle, (int)processInformationClass,processInformation, processInformationLength,ref returnLength);
            }
        }

        private unsafe static uint LdrGetDllPath(ref readonly char DllName, uint Flags, char** DllPath, char** SearchPaths)
        {
            return 0xC0000001;
        }

        private unsafe static uint LdrGetDllHandleByName(void* BaseDllName, void* FullDllName, out nuint DllHandle)
        {
            DllHandle = 0;
            return 0xC0000001;
        }

        public static ProcessDataNotPEB CurrentProcess;

        private static unsafe uint GetModuleFileNameA(nint module,ref byte fileName,int size)
        {
            Span<byte> output = MemoryMarshal.CreateSpan(ref fileName, size);
            if (module == 0)
            {
                var strT = Path.GetFileName(CurrentProcess.CommandLine.AsSpan().TrimEnd("\""));
                Encoding.ASCII.GetBytes(strT,output);
                output[strT.Length] = 0;
                return (uint)strT.Length;
            }
            else
            {
                var keys = LibraryLoader.Libraries.Keys.ToArray();
                var values = LibraryLoader.Libraries.Values.ToArray();

                for (var i = 0; i < LibraryLoader.Libraries.Count; i++)
                {
                    if (values[i] == module)
                    {
                        GC.SuppressFinalize(keys);
                        GC.SuppressFinalize(values);
                        Encoding.ASCII.GetBytes(keys[i], output);
                        output[keys[i].Length] = 0;
                        return 0;
                    }
                }
                GC.SuppressFinalize(keys);
                GC.SuppressFinalize(values);
                return 0xC0000001;
            }
        }

        private static unsafe uint GetModuleFileNameW(nint module,ref char fileName,int size)
        {
            Span<char> output = MemoryMarshal.CreateSpan(ref fileName, size);
            if (module == 0)
            {
                var strT = Path.GetFileName(CurrentProcess.CommandLine.AsSpan().TrimEnd("\""));
                strT.CopyTo(output);
                output[strT.Length] = '\0';
                return (uint)strT.Length;
            }
            else
            {
                var keys = LibraryLoader.Libraries.Keys.ToArray();
                var values = LibraryLoader.Libraries.Values.ToArray();

                for (var i = 0; i < LibraryLoader.Libraries.Count; i++)
                {
                    if (values[i] == module)
                    {
                        GC.SuppressFinalize(keys);
                        GC.SuppressFinalize(values);
                        keys[i].CopyTo(output);
                        output[keys[i].Length] = '\0';
                        return 0;
                    }
                }
                GC.SuppressFinalize(keys);
                GC.SuppressFinalize(values);
                return 0xC0000001;
            }
        }

        private static unsafe nint GetModuleHandleA(ref readonly byte module)
        {
            nint handle = 0;
            GetModuleHandleExA(0,in module,ref handle);
            return handle;
        }

        private static unsafe bool GetModuleHandleExA(uint flags, ref readonly byte module, ref nint handle)
        {
            if (Unsafe.IsNullRef(in module))
            {
                handle = CurrentProcess.Module;
                return true;
            }
            scoped Span<char> chars = stackalloc char[256];
            Encoding.ASCII.TryGetChars((new ReadOnlySafePointer<byte>(in module)).ToStringWithNullTerminator(), chars, out int charsW);
            return GetModuleHandleExW(flags,ref MemoryMarshal.GetReference(chars),ref handle);
        }

        private static unsafe bool GetModuleHandleExW(uint flags, ref readonly char module, ref nint handle)
        {
            if (flags != 0) return false;

            if (Unsafe.IsNullRef(in module))
            {
                handle = CurrentProcess.Module;
                return true;
            }
            else
            {
                scoped Span<char> chars = stackalloc char[256];
                scoped var moduleCmp = new ReadOnlySafePointer<char>(in module).ToStringWithNullTerminator();
                moduleCmp.CopyTo(chars);
                if (!Path.HasExtension(moduleCmp))
                    ".dll".CopyTo(chars.Slice(moduleCmp.Length)); // הוסף סיומת
                ReadOnlySpan<char> str = chars.TrimNullTerminator();
                var keys = LibraryLoader.Libraries.Keys.ToArray();
                var values = LibraryLoader.Libraries.Values.ToArray();

                nint ret = 0;
                for (var i = 0; i < LibraryLoader.Libraries.Count; i++)
                {
                    if (keys[i].AsSpan().SequenceEqual(str))
                    {
                        ret = values[i];
                        break;
                    }
                }
                GC.SuppressFinalize(keys);
                GC.SuppressFinalize(values);
                //Console.Write("Module Handle:");
                //Console.WriteLine(chars);
                handle = ret == 0 ? LibraryLoader.GetModuleHandleW(in module) : ret;
                return handle != 0;
            }
        }
        private static nint GetModuleHandleW(ref readonly char module)
        {
            nint ret = 0;
            GetModuleHandleExW(0,in module,ref ret);
            return ret;
        }

        private static nint GetCommandLineW()
        {
            return SafePointerExtentions.ToPointer(in Utf16StringMarshaller.GetPinnableReference(CurrentProcess.CommandLine));
        }
        private unsafe static nint GetCommandLineA()
        {
            if (CurrentProcess.CommandLineA == null)
            {
                CurrentProcess.CommandLineA = Utf8StringMarshaller.ConvertToUnmanaged(CurrentProcess.CommandLine);
            }
            return (nint)CurrentProcess.CommandLineA;
        }

        private static uint GetSysColor(int colorId)
        {
            return (uint)Color.Green.ToArgb();
        }
    }
}
