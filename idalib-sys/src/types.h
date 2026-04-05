#pragma once

#include <cstdint>

#if defined(_MSC_VER)
typedef unsigned __int64 ea_t;
typedef __int64 sval_t;
typedef unsigned __int64 uval_t;
typedef unsigned __int64 flags64_t;
#elif defined(__GNUC__)
typedef unsigned long long ea_t;
typedef long long sval_t;
typedef unsigned long long uval_t;
// autocxx cannot resolve the typedef otherwise...
typedef unsigned long long flags64_t;
#endif

typedef unsigned char optype_t;

typedef void c_void;
typedef char c_char;
typedef unsigned char c_uchar;
typedef short c_short;
typedef unsigned short c_ushort;
typedef int c_int;
typedef unsigned int c_uint;
typedef long c_long;
typedef unsigned long c_ulong;
typedef long long c_longlong;
typedef unsigned long long c_ulonglong;
