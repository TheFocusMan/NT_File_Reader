using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NT_File_Reader.WindowsNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct API_SET_NAMESPACE
    {
        public uint Version; // API_SET_SCHEMA_VERSION_V6
        public uint Size;
        public uint Flags; // API_SET_SCHEMA_FLAGS_*
        public uint Count;
        public uint EntryOffset; // to API_SET_NAMESPACE_ENTRY[Count], from this struct base
        public uint HashOffset; // to API_SET_HASH_ENTRY[Count], from this struct base
        public uint HashFactor;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct API_SET_NAMESPACE_ENTRY
    {
        /// <summary>
        /// Flags for the API set (e.g., sealed or extension).
        /// </summary>
        public uint Flags;

        /// <summary>
        /// Offset to the name (WCHAR array) from the base address of the schema.
        /// </summary>
        public uint NameOffset;

        /// <summary>
        /// Length of the name in bytes.
        /// </summary>
        public uint NameLength;

        /// <summary>
        /// Length of the hashed name for optimized lookup.
        /// </summary>
        public uint HashedLength;

        /// <summary>
        /// Offset to an array of API_SET_VALUE_ENTRY structures from the schema base.
        /// </summary>
        public uint ValueOffset;

        /// <summary>
        /// The number of value entries (implementing DLLs) associated with this API set.
        /// </summary>
        public uint ValueCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct API_SET_HASH_ENTRY
    {
        /// <summary>
        /// The computed hash of the API set name (up to its HashedLength).
        /// </summary>
        public uint Hash;

        /// <summary>
        /// The index of the corresponding API_SET_NAMESPACE_ENTRY in the namespace array.
        /// </summary>
        public uint Index;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct API_SET_VALUE_ENTRY
    {
        /// <summary>
        /// Flags (typically 0, used for specific redirection rules).
        /// </summary>
        public uint Flags;

        /// <summary>
        /// Offset to the virtual DLL name (WCHAR array) from the base address of the schema.
        /// This is often the same as the name in the Namespace Entry.
        /// </summary>
        public uint NameOffset;

        /// <summary>
        /// Length of the virtual name in bytes.
        /// </summary>
        public uint NameLength;

        /// <summary>
        /// Offset to the physical DLL name (WCHAR array) from the schema base.
        /// This is the actual DLL on disk (e.g., "kernelbase.dll").
        /// </summary>
        public uint ValueOffset;

        /// <summary>
        /// Length of the physical DLL name in bytes.
        /// </summary>
        public uint ValueLength;
    }

    public static class ApiSetScema
    {
        // private
        public const uint API_SET_SCHEMA_VERSION_V2 = 0x00000002; // WIN7, WIN8
        public const uint API_SET_SCHEMA_VERSION_V4 = 0x00000004; // WINBLUE
        public const uint API_SET_SCHEMA_VERSION_V6 = 0x00000006; // since THRESHOLD
        public const uint API_SET_SCHEMA_VERSION_V7 = 0x00000007; // since WIN11
        public const uint API_SET_SCHEMA_VERSION = API_SET_SCHEMA_VERSION_V6;

        // private
        public const uint API_SET_SCHEMA_FLAGS_SEALED = 0x00000001;
        public const uint API_SET_SCHEMA_FLAGS_HOST_EXTENSION = 0x00000002;

        // private
        public const uint API_SET_SCHEMA_ENTRY_FLAGS_SEALED = 0x00000001;
        public const uint API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION = 0x00000002;
    }

}
