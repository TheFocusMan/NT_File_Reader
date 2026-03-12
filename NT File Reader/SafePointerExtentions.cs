using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    public static class SafePointerExtentions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static nuint ToUPointer<T>(scoped ref readonly T addr) where T : allows ref struct
        {
            scoped Converter<T> converter = new Converter<T>(in addr);
            return Unsafe.BitCast<Converter<T>, nuint>(converter);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static nint ToPointer<T>(scoped ref readonly T addr) where T : allows ref struct
        {
            scoped Converter<T> converter = new Converter<T>(in addr);
            return Unsafe.BitCast<Converter<T>, nint>(converter);
        }

        [StructLayout(LayoutKind.Sequential)]
        private ref struct Converter<T> where T : allows ref struct
        {
            private ref byte _byref;
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public Converter(ref readonly T addr)
            {
                _byref = ref Unsafe.As<T, byte>(ref Unsafe.AsRef(in addr));
            }
            public ref readonly T byref
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => ref Unsafe.As<byte, T>(ref _byref);
            }
        }

        /// <summary>
        /// Convert to Ref By Safe Address
        /// </summary>
        /// <typeparam name="T">Any Type</typeparam>
        /// <param name="addr">Actual address</param>
        /// <returns>pointer</returns>
        public static ref T AsRef<T>(this nint addr)
        {
            return ref Unsafe.AsRef(in Unsafe.BitCast<nint, Converter<T>>(addr).byref);
        }

        /// <summary>
        /// Convert to Ref By Safe Address
        /// </summary>
        /// <typeparam name="T">Any Type</typeparam>
        /// <param name="addr">Actual address</param>
        /// <returns>pointer</returns>
        public static ref T AsRef<T>(this nuint addr) where T : allows ref struct
        {
            return ref Unsafe.AsRef(in Unsafe.BitCast<nuint, Converter<T>>(addr).byref);
        }

        public static Span<T> AsSpan<T>(this SafePointer<T> self, int length)
        {
            return MemoryMarshal.CreateSpan(ref self.Value, length);
        }

        public static Span<T> AsSpan<T>(this nint self, int length)
        {
            return MemoryMarshal.CreateSpan(ref self.AsRef<T>(), length);
        }

        extension(ReadOnlySafePointer<byte> self)
        {
            public ReadOnlySpan<byte> ToStringWithNullTerminator()
            {
                int len = 0;
                ReadOnlySafePointer<byte> pEnd = self;
                while ((pEnd++).Value != '\0') len++;
                return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<byte>(in self.Value), len);
            }
        }

        extension(ReadOnlySafePointer<char> self)
        {
            public ReadOnlySpan<char> ToStringWithNullTerminator()
            {
                int len = 0;
                ReadOnlySafePointer<char> pEnd = self;
                while ((pEnd++).Value != '\0') len++;
                return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<char>(in self.Value), len);
            }
        }

        extension(ReadOnlySpan<char> self)
        {
            public ReadOnlySpan<char> TrimNullTerminator()
            {
                int len = 0;
                ReadOnlySafePointer<char> pEnd = self.AsSafePointer();
                while ((pEnd++).Value != '\0') len++;
                return self.Slice(0, len);
            }
        }

        extension<T>(ReadOnlySpan<T> self)
        {
            public nint ToPointer()
            {
                return (nint)(self.AsSafePointer());
            }

            public nuint ToUPointer()
            {
                return (nuint)(self.AsSafePointer());
            }

            public ReadOnlySafePointer<T> AsSafePointer()
            {
                return new ReadOnlySafePointer<T>(ref MemoryMarshal.GetReference(self));
            }
        }

        extension<T>(Span<T> self)
        {
            public nint ToPointer()
            {
                return (nint)(self.AsSafePointer());
            }

            public nuint ToUPointer()
            {
                return (nuint)(self.AsSafePointer());
            }

            public SafePointer<T> AsSafePointer()
            {
                return new SafePointer<T>(ref MemoryMarshal.GetReference(self));
            }
        }
    }
}
