#define TARGET_64BIT
#if TARGET_64BIT
global using nuint_t = System.UInt64;
#else
global using nuint_t = System.UInt32;
#endif