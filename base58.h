#ifndef BASE58_H
#define BASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

    extern bool (*base58_sha256_impl)(void *, const void *, size_t);
    extern bool base58_to_bin(void *, size_t *, const char *, size_t);
    extern int base58_check(const void *, size_t, const char *, size_t);
    extern bool base58_encode(char *, size_t *, const void *, size_t);
    extern bool base58_check_encode(char *, size_t *, uint8_t, const void *, size_t);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // BASE58_H
