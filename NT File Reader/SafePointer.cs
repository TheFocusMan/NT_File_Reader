using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    /// <summary>
    /// Alternative for void*
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct SafePointer<T> : IEquatable<SafePointer<T>> where T : allows ref struct
    {
        private readonly nuint _pointer;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafePointer(nuint addrss)
        {
            this = Unsafe.BitCast<nuint, SafePointer<T>>(addrss);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafePointer(ref T refrence)
        {
            _pointer = SafePointerExtentions.ToUPointer(ref refrence);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator ReadOnlySafePointer<T>(SafePointer<T> pointer)
        {
            return Unsafe.BitCast<SafePointer<T>, ReadOnlySafePointer<T>>(pointer);
        }

        #region Explit Operators
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static explicit operator nint(SafePointer<T> self)
        {
            return Unsafe.BitCast<SafePointer<T>, nint>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator SafePointer<T>(nint self)
        {
            return Unsafe.BitCast<nint, SafePointer<T>>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static explicit operator nuint(SafePointer<T> self)
        {
            return Unsafe.BitCast<SafePointer<T>, nuint>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator SafePointer<T>(nuint self)
        {
            return Unsafe.BitCast<nuint, SafePointer<T>>(self);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafePointer<TTo> Cast<TTo>()
        {
            return Unsafe.BitCast<SafePointer<T>, SafePointer<TTo>>(this);
        }
        #endregion

        #region Function Operators
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafePointer<T> AddByteOffset(nuint value)
        {
            return new SafePointer<T>(_pointer + value);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafePointer<T> SubtractByteOffset(nuint value)
        {
            return new SafePointer<T>(_pointer - value);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ref TTo AsRef<TTo>()
        {
            return ref (_pointer).AsRef<TTo>();
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ref TTo AddByteOffsetAsRef<TTo>(nuint value)
        {
            return ref (_pointer + value).AsRef<TTo>();
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ref TTo SubtractByteOffsetAsRef<TTo>(nuint value)
        {
            return ref (_pointer - value).AsRef<TTo>();
        }

        #endregion

        #region Operators
        public static SafePointer<T> operator +(SafePointer<T> self, nuint value)
        {
            return new SafePointer<T>(self._pointer + (value * (nuint)Unsafe.SizeOf<T>()));
        }

        public static SafePointer<T> operator -(SafePointer<T> self, nuint value)
        {
            return new SafePointer<T>(self._pointer - (value * (nuint)Unsafe.SizeOf<T>()));
        }

        public static SafePointer<T> operator ++(SafePointer<T> self)
        {
            return new SafePointer<T>(self._pointer + (uint)Unsafe.SizeOf<T>());
        }

        public static SafePointer<T> operator --(SafePointer<T> self)
        {
            return new SafePointer<T>(self._pointer - (uint)Unsafe.SizeOf<T>());
        }
        #endregion

        #region Compare Operators
        public static bool operator ==(SafePointer<T> left, SafePointer<T> right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(SafePointer<T> left, SafePointer<T> right)
        {
            return !left.Equals(right);
        }

        public static bool operator >(SafePointer<T> left, SafePointer<T> right)
        {
            return left._pointer > right._pointer;
        }

        public static bool operator >=(SafePointer<T> left, SafePointer<T> right)
        {
            return left._pointer >= right._pointer;
        }

        public static bool operator <(SafePointer<T> left, SafePointer<T> right)
        {
            return left._pointer < right._pointer;
        }

        public static bool operator <=(SafePointer<T> left, SafePointer<T> right)
        {
            return left._pointer <= right._pointer;
        }
        #endregion

        public ref T this[nuint index]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ref Unsafe.Add(ref _pointer.AsRef<T>(), index);
        }

        public ref T Value
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ref _pointer.AsRef<T>();
        }

        public new string? ToString()
        {
            if (_pointer == 0)
                return "<Null>";
            else
                return (_pointer).ToString();
        }

        public bool Equals(SafePointer<T> other)
        {
            return this._pointer == other._pointer;
        }

        public override bool Equals(object? obj)
        {
            return obj is SafePointer<T> pointer1 && Equals(pointer1);
        }

        public override int GetHashCode()
        {
            return _pointer.GetHashCode();
        }
    }
}
