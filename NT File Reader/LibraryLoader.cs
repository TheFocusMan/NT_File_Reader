using NT_File_Reader.WindowsNative;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NT_File_Reader
{

    public static class LibraryLoader
    {
        private static Dictionary<string, nint> _libaries;

        public static Dictionary<string, nint> Libraries
        {
            get { return _libaries; }
        }

        static LibraryLoader()
        {
            _libaries = new Dictionary<string, nint>();
        }


        // Import the GetModuleHandle function from kernel32.dll
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandleW(ref readonly char lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(ref readonly byte lpModuleName);

        // הוסף את ה-Imports הללו למחלקה שלך אם הם לא קיימים
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryExW(ref readonly char lpLibFileName, IntPtr file, uint flags);

        /// <summary>
        /// Add the library for Cache
        /// </summary>
        public static void AddToCache(ReadOnlySpan<char> path, nint address)
        {
            Buffer256Bytes buffer = default;
            Path.GetFileName(path).ToLowerInvariant(buffer);
            string libName = ((ReadOnlySpan<char>)buffer).TrimNullTerminator().ToString();
            _libaries.TryAdd(libName, address);
        }

        // Import the native Windows API function
        [DllImport("shlwapi.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern bool PathFileExistsW(ref readonly char pszPath);

        public unsafe static nint LoadLibrary(string path, uint flags)
        {
            if (!Path.HasExtension(path))
                path = Path.ChangeExtension(path, ".dll");
            Buffer256Bytes buffer = new();
            path.AsSpan().CopyTo(buffer); // אופטימיזציה

            Buffer256Bytes tempnname = default;
            Path.GetFileName(buffer).ToLowerInvariant(tempnname);
            string libName = ((ReadOnlySpan<char>)tempnname)
                .TrimNullTerminator()
                .ToString();
            var fileName = Path.GetFileName(buffer)
                .TrimNullTerminator();

            if (_libaries.TryGetValue(libName, out nint value))
            {
                return value;
            }
            else
            {
                // Api Level
                nint lib = LdrpPreprocessDllName(libName);
                if (lib != 0) return lib;
                do
                {
                    if (!PathFileExistsW(ref MemoryMarshal.GetReference<char>(buffer)))
                    {
                        int chars;
                        // Win SxS
                        if (!string.IsNullOrEmpty(CustomApiCalls.CurrentProcess.WinSxSDir))
                        {
                            Path.TryJoin(CustomApiCalls.CurrentProcess.WinSxSDir, fileName, tempnname, out chars);
                            if (PathFileExistsW(ref MemoryMarshal.GetReference<char>(tempnname)))
                            {
                                ((Span<char>)tempnname).CopyTo(buffer);
                                fileName = Path.GetFileName(buffer).TrimNullTerminator();
                                break;
                            }
                        }
                        // System 32
                        Path.TryJoin(Environment.SystemDirectory.AsSpan(), fileName, tempnname, out chars);
                        ((Span<char>)tempnname).CopyTo(buffer);
                        fileName = Path.GetFileName(buffer).TrimNullTerminator();
                    }
                } while (false);
                if (!libName.AsSpan().StartsWith("api-ms-"))
                {
                    nint moudleHandle = GetModuleHandleW(libName); // מונע תקלות רבות
                    if (moudleHandle != 0)
                    {
                        _libaries.TryAdd(libName, moudleHandle);
                        return moudleHandle;
                    }
                    lib = LdrLoadDll(buffer, flags);
                }
                // Api downlevel
                if (lib == 0)
                {
                    Path.TryJoin(Environment.SystemDirectory.AsSpan(), "downlevel", fileName, tempnname, out int chars);
                    ((Span<char>)tempnname).CopyTo(buffer);
                    fileName = Path.GetFileName(buffer).TrimNullTerminator();
                    if (PathFileExistsW(ref MemoryMarshal.GetReference<char>(buffer)))
                    {
                        lib = LdrLoadDll(buffer, flags);
                    }
                }
                if (lib == 0)
                {
                    lib = LoadLibraryExW(ref MemoryMarshal.GetReference(fileName), 0, 0);
                    _libaries.TryAdd(fileName.ToString(), lib);
                }
                Debug.Assert(lib != 0);
                return lib;
            }

            static nint LdrLoadDll(ReadOnlySpan<char> path, uint flags)
            {
                if (PathFileExistsW(ref MemoryMarshal.GetReference(path)))
                    return Extentions.LdrpLoadDllInternal(path
                        .TrimNullTerminator()
                        .ToString(), flags);
                return 0;
            }
        }

        public static void FreeLibrary(nint module)
        {
            List<string> toRemove = new(16);
            if (_libaries.ContainsValue(module))
            {
                foreach (var lib in _libaries)
                {
                    if (lib.Value == module)
                    {
                        toRemove.Add(lib.Key);
                    }
                }
                for (int i = 0; i < toRemove.Count; i++)
                {
                    _libaries.Remove(toRemove[i]);
                }
                Extentions.LdrFreeDll(Unsafe.BitCast<nint, AllocatedPointer>(module));
            }
        }

        #region Api Set Scema
        private static nint LdrpPreprocessDllName(ReadOnlySpan<char> dllName)
        {
            if (!(dllName.StartsWith("api",StringComparison.OrdinalIgnoreCase) || dllName.StartsWith("ext", StringComparison.OrdinalIgnoreCase)))
                return 0;
            // 1. Remove extension if present (.dll)
            if (dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                dllName = dllName.Slice(0, dllName.Length - 4);
            }
            ref TEB addr = ref SegmentReaderX64.GetTebAddressX64().AsRef<TEB>();
            ref API_SET_NAMESPACE apiSchema = ref addr.ProcessEnvironmentBlock.ApiSetMap.Value;
            nuint apiSchemaBase = (nuint)addr.ProcessEnvironmentBlock.ApiSetMap;

            if (apiSchema.Version != ApiSetScema.API_SET_SCHEMA_VERSION && apiSchema.Version != ApiSetScema.API_SET_SCHEMA_VERSION_V7)
                return 0;
            ref API_SET_VALUE_ENTRY targetVal = ref ApiSetpGetSearchKeyHash(dllName, apiSchemaBase);
            if (Unsafe.IsNullRef(ref targetVal))
            {
                ref API_SET_NAMESPACE_ENTRY entries = ref (apiSchemaBase + apiSchema.EntryOffset).AsRef<API_SET_NAMESPACE_ENTRY>();
                // חיפוש ספרייה לפי שם
                uint low = 0, high = apiSchema.Count - 1;
                while (low <= high)
                {
                    uint mid = low + ((high - low) >> 1);
                    ref API_SET_NAMESPACE_ENTRY entry = ref Unsafe.Add(ref entries, mid);

                    ReadOnlySpan<char> name = MemoryMarshal.CreateReadOnlySpan(
                        ref (apiSchemaBase + entry.NameOffset).AsRef<char>(),
                        (int)(entry.NameLength / sizeof(char))
                    );
                    int cmp = dllName.CompareTo(name,StringComparison.OrdinalIgnoreCase);
                    if (cmp == 0)
                    {
                        ref API_SET_VALUE_ENTRY values = ref (apiSchemaBase + entry.ValueOffset).AsRef<API_SET_VALUE_ENTRY>();

                        for (int j = 0; j < entry.ValueCount; j++)
                        {
                            ref API_SET_VALUE_ENTRY val = ref Unsafe.Add(ref values, j);
                            if (val.NameLength == 0) // This is the default physical DLL
                            {
                                targetVal = ref val;
                                break;
                            }
                        }
                    }
                    if (cmp < 0) high = mid - 1;
                    else low = mid + 1;
                }
            }
            if (!Unsafe.IsNullRef(ref targetVal))
            {
                ReadOnlySpan<char> name1 = MemoryMarshal.CreateReadOnlySpan(
                    ref (apiSchemaBase + targetVal.ValueOffset).AsRef<char>(),
                    (int)(targetVal.ValueLength / sizeof(char))
                );
                string pysycalPath = name1.ToString();
                var ret = LoadLibrary(pysycalPath, 0);
                if (ret != 0)
                    AddToCache(dllName, ret);
                return ret;
            }
#if false
            ref API_SET_NAMESPACE_ENTRY entries1 = ref (apiSchemaBase + apiSchema.EntryOffset).AsRef<API_SET_NAMESPACE_ENTRY>();
            for (int i = 0; i < apiSchema.Count; i++)
            {
                ref API_SET_NAMESPACE_ENTRY entry = ref Unsafe.Add(ref entries1, i);

                ReadOnlySpan<char> name = MemoryMarshal.CreateReadOnlySpan(
                    ref (apiSchemaBase + entry.NameOffset).AsRef<char>(),
                    (int)(entry.NameLength / sizeof(char))
                );
                Console.WriteLine(name);
            }
            Console.WriteLine(dllName);
            Console.Clear();
#endif
            return 0;
        }

        private static ref API_SET_VALUE_ENTRY ApiSetpGetSearchKeyHash(ReadOnlySpan<char> name, nuint apiSchemaBase)
        {
            ref API_SET_NAMESPACE apiSchema = ref apiSchemaBase.AsRef<API_SET_NAMESPACE>();
            ref API_SET_HASH_ENTRY hashes = ref (apiSchemaBase + apiSchema.HashOffset).AsRef<API_SET_HASH_ENTRY>();
            ref API_SET_NAMESPACE_ENTRY entries = ref (apiSchemaBase + apiSchema.EntryOffset).AsRef<API_SET_NAMESPACE_ENTRY>();

            // Get reference to the hash array
            int low = 0;
            int high = (int)apiSchema.Count - 1;
            // Binary search on the hash table
            uint targetHash;
            targetHash = ComputeApiSetHash(name, apiSchema.HashFactor, (uint)name.Length);
            while (low <= high)
            {
                int mid = low + ((high - low) >> 1);
                ref API_SET_HASH_ENTRY hashEntry = ref Unsafe.Add(ref hashes, mid);
                // Found a hash match; now get the actual Namespace Entry
                ref API_SET_NAMESPACE_ENTRY entry = ref Unsafe.Add(ref entries, hashEntry.Index);
                if (hashEntry.Hash == targetHash)
                {
#if false
                    ReadOnlySpan<char> fullName = MemoryMarshal.CreateReadOnlySpan(
                        ref (apiSchemaBase + entry.NameOffset).AsRef<char>(),
                        (int)(entry.HashedLength / sizeof(char))
                    );
                    if (name.StartsWith(fullName, StringComparison.OrdinalIgnoreCase))
                    {
                        ref API_SET_VALUE_ENTRY values = ref (apiSchemaBase + entry.ValueOffset).AsRef<API_SET_VALUE_ENTRY>();
                        for (int j = 0; j < entry.ValueCount; j++)
                        {
                            ref API_SET_VALUE_ENTRY val = ref Unsafe.Add(ref values, j);
                            if (val.NameLength == 0) // This is the default physical DLL
                            {
                                return ref val;
                            }
                        }
                        return ref values;
                    }
#endif
                    // סריקה ליניארית על כל ה-Entries עם אותו Hash (כולל mid עצמו)
                    // נתחיל מ-mid ונרד למטה, ואז מ-mid+1 ונעלה למעלה
                    for (int scanIdx = mid; scanIdx >= low; scanIdx--)
                    {
                        ref var currentHashEntry = ref Unsafe.Add(ref hashes, scanIdx);
                        if (currentHashEntry.Hash != targetHash) break;

                        ref var res = ref TryMatchEntry(currentHashEntry.Index, name, apiSchemaBase, ref entries);
                        if (!Unsafe.IsNullRef(ref res)) return ref res;
                    }

                    for (int scanIdx = mid + 1; scanIdx <= high; scanIdx++)
                    {
                        ref var currentHashEntry = ref Unsafe.Add(ref hashes, scanIdx);
                        if (currentHashEntry.Hash != targetHash) break;

                        ref var res = ref TryMatchEntry(currentHashEntry.Index, name, apiSchemaBase, ref entries);
                        if (!Unsafe.IsNullRef(ref res)) return ref res;
                    }

                    static ref API_SET_VALUE_ENTRY TryMatchEntry(uint index, ReadOnlySpan<char> name, nuint baseAddr, ref API_SET_NAMESPACE_ENTRY entries)
                    {
                        ref var entry = ref Unsafe.Add(ref entries, index);
                        var fullName = MemoryMarshal.CreateReadOnlySpan(ref (baseAddr + entry.NameOffset).AsRef<char>(), (int)entry.HashedLength / 2);

                        if (name.StartsWith(fullName, StringComparison.OrdinalIgnoreCase))
                        {
                            ref var values = ref (baseAddr + entry.ValueOffset).AsRef<API_SET_VALUE_ENTRY>();
                            for (int j = 0; j < entry.ValueCount; j++)
                            {
                                ref var val = ref Unsafe.Add(ref values, j);
                                if (val.NameLength == 0) return ref val; // ברירת מחדל
                            }
                            return ref values;
                        }
                        return ref Unsafe.NullRef<API_SET_VALUE_ENTRY>();
                    }
                }

                if (hashEntry.Hash < targetHash) low = mid + 1;
                else high = mid - 1;
            }
            return ref Unsafe.NullRef<API_SET_VALUE_ENTRY>();
        }

        private static uint ComputeApiSetHash(ReadOnlySpan<char> name, uint hashFactor, uint hashedCharCount)
        {
            uint hash = 0;

            int nameLimit = name.Length > 2 ? name.Length - 2 : 0;
            uint limit = Math.Min((uint)nameLimit, hashedCharCount);
            for (int i = 0; i < (int)limit; i++)
            {
                char c = char.ToLowerInvariant(name[i]);
                hash = (hash * hashFactor) + (uint)c;
            }
            return hash;
        }
#endregion
    }
}
