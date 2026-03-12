using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace System
{
    /// <summary>
    /// Alternative for const void*
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    public struct ReadOnlySafePointer<T> : IEquatable<ReadOnlySafePointer<T>> where T : allows ref struct
    {
        private nuint _pointer;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySafePointer(nuint addrss)
        {
            this = Unsafe.BitCast<nuint, ReadOnlySafePointer<T>>(addrss);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySafePointer(ref readonly T refrence)
        {
            _pointer = SafePointerExtentions.ToUPointer(in refrence);
        }

        #region Explit Operators
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static explicit operator nint(ReadOnlySafePointer<T> self)
        {
            return Unsafe.BitCast<ReadOnlySafePointer<T>, nint>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator ReadOnlySafePointer<T>(nint self)
        {
            return Unsafe.BitCast<nint, ReadOnlySafePointer<T>>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static explicit operator nuint(ReadOnlySafePointer<T> self)
        {
            return Unsafe.BitCast<ReadOnlySafePointer<T>, nuint>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator ReadOnlySafePointer<T>(nuint self)
        {
            return Unsafe.BitCast<nuint, ReadOnlySafePointer<T>>(self);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySafePointer<TTo> Cast<TTo>()
        {
            return Unsafe.BitCast<ReadOnlySafePointer<T>, ReadOnlySafePointer<TTo>>(this);
        }
        #endregion

        #region Function Operators
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySafePointer<T> AddByteOffset(nuint value)
        {
            return new ReadOnlySafePointer<T>(_pointer + value);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ReadOnlySafePointer<T> SubtractByteOffset(nuint value)
        {
            return new ReadOnlySafePointer<T>(_pointer - value);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ref TTo AsRef<TTo>()
        {
            return ref _pointer.AsRef<TTo>();
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
        public static ReadOnlySafePointer<T> operator +(ReadOnlySafePointer<T> self, nuint value)
        {
            return new ReadOnlySafePointer<T>(self._pointer + (value * (nuint)Unsafe.SizeOf<T>()));
        }

        public static ReadOnlySafePointer<T> operator -(ReadOnlySafePointer<T> self, nuint value)
        {
            return new ReadOnlySafePointer<T>(self._pointer - (value * (nuint)Unsafe.SizeOf<T>()));
        }

        public static ReadOnlySafePointer<T> operator ++(ReadOnlySafePointer<T> self)
        {
            return new ReadOnlySafePointer<T>(self._pointer + (uint)Unsafe.SizeOf<T>());
        }

        public static ReadOnlySafePointer<T> operator --(ReadOnlySafePointer<T> self)
        {
            return new ReadOnlySafePointer<T>(self._pointer - (uint)Unsafe.SizeOf<T>());
        }
        #endregion

        #region Compare Operators
        public static bool operator ==(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return !left.Equals(right);
        }

        public static bool operator >(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return Unsafe.IsAddressGreaterThan(ref left._pointer, ref right._pointer);
        }

        public static bool operator >=(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return Unsafe.IsAddressLessThanOrEqualTo(ref left._pointer, ref right._pointer);
        }

        public static bool operator <(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return Unsafe.IsAddressLessThan(ref left._pointer, ref right._pointer);
        }

        public static bool operator <=(ReadOnlySafePointer<T> left, ReadOnlySafePointer<T> right)
        {
            return Unsafe.IsAddressLessThanOrEqualTo(ref left._pointer, ref right._pointer);
        }
        #endregion
        public ref readonly T this[nuint index]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ref Unsafe.Add(ref _pointer.AsRef<T>(), index);
        }

        public ref readonly T Value
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

        public bool Equals(ReadOnlySafePointer<T> other)
        {
            return Unsafe.AreSame(ref this._pointer, ref other._pointer);
        }

        public override bool Equals(object? obj)
        {
            return obj is ReadOnlySafePointer<T> pointer1 && Equals(pointer1);
        }

        public override int GetHashCode()
        {
            return _pointer.GetHashCode();
        }
    }
}
