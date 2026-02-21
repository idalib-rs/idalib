#include <cstddef>

#if defined(_MSC_VER) && defined(__clang__)
#undef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif
