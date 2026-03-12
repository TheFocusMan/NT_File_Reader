using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NT_File_Reader
{
    public readonly unsafe ref struct AllocatedPointer(nuint length)
    {
        public readonly ref byte handle = ref Unsafe.AsRef<byte>(NativeMemory.AlignedAlloc(length,4096));

        public ref T As<T>() where T : allows ref struct
            => ref Unsafe.As<byte, T>(ref handle);
        public ref T As<T>(nuint offset) where T : allows ref struct
            => ref Unsafe.As<byte, T>(ref this[offset]);

        public SafePointer<T> AsPointer<T>() => new SafePointer<T>((nuint)this);

        public ref byte this[nuint index] => ref Unsafe.AddByteOffset(ref handle, index);

        public static implicit operator nuint(AllocatedPointer pointer) 
            => (nuint)Unsafe.AsPointer(ref pointer.handle);

        public static implicit operator nint(AllocatedPointer pointer)
            => (nint)Unsafe.AsPointer(ref pointer.handle);

        public Span<T> AsSpan<T>(int length)
        {
            return MemoryMarshal.CreateSpan(ref As<T>(), length);
        }
        public void Dispose()
        {
            NativeMemory.AlignedFree(Unsafe.AsPointer(ref handle));
        }
    }
}