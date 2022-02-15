#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif // WIN32

#include <string.h>
#include "base58.h"

bool (*base58_sha256_impl)(void *, const void *, size_t) = NULL;

static const int8_t base58_digits_map[] = {
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    -1,
    17,
    18,
    19,
    20,
    21,
    -1,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    -1,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
    56,
    57,
    -1,
    -1,
    -1,
    -1,
    -1,
};

static const char base58_digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

typedef uint64_t base58_maxint_t;
typedef uint32_t base58_almostmaxint_t;
#define base58_almostmaxint_bits (sizeof(base58_almostmaxint_t) * 8)
static const base58_almostmaxint_t base58_almostmaxint_mask = ((((base58_maxint_t)1) << base58_almostmaxint_bits) - 1);

bool base58_to_bin(void *bin, size_t *bin_len, const char *b58_data, size_t data_len)
{
    size_t binsz = *bin_len;
    const unsigned char *b58u = (void *)b58_data;
    unsigned char *binu = bin;
    size_t outsz = (binsz + sizeof(base58_almostmaxint_t) - 1) / sizeof(base58_almostmaxint_t);
    base58_almostmaxint_t outi[outsz];
    base58_maxint_t t;
    base58_almostmaxint_t c;
    size_t i, j;
    uint8_t bytesleft = binsz % sizeof(base58_almostmaxint_t);
    base58_almostmaxint_t zeromask = bytesleft ? (base58_almostmaxint_mask << (bytesleft * 8)) : 0;
    unsigned int zero_count = 0;

    if (!data_len)
    {
        data_len = strlen(b58_data);
    }

    for (i = 0; i < outsz; ++i)
    {
        outi[i] = 0;
    }

    // Leading zeros, just count
    for (i = 0; i < data_len && b58u[i] == '1'; ++i)
    {
        ++zero_count;
    }

    for (; i < data_len; ++i)
    {
        if (b58u[i] & 0x80)
        {
            // Invalid base58 digit
            return false;
        }

        if (base58_digits_map[b58u[i]] == -1)
        {
            // Invalid base58 digit
            return false;
        }

        c = (unsigned)base58_digits_map[b58u[i]];
        for (j = outsz; j--;)
        {
            t = ((base58_maxint_t)outi[j]) * 58 + c;
            c = t >> base58_almostmaxint_bits;
            outi[j] = t & base58_almostmaxint_mask;
        }

        if (c)
        {
            // Output number too big (carry to the next int32)
            return false;
        }

        if (outi[0] & zeromask)
        {
            // Output number too big (last int32 filled too far)
            return false;
        }
    }

    j = 0;
    if (bytesleft)
    {
        for (i = bytesleft; i > 0; --i)
        {
            *(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
        }
        ++j;
    }

    for (; j < outsz; ++j)
    {
        for (i = sizeof(*outi); i > 0; --i)
        {
            *(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
        }
    }

    // Count canonical base58 byte count
    binu = bin;
    for (i = 0; i < binsz; ++i)
    {
        if (binu[i])
        {
            break;
        }
        --*bin_len;
    }
    *bin_len += zero_count;

    return true;
}

static bool my_dblsha256(void *hash, const void *data, size_t data_len)
{
    uint8_t buffer[0x20];
    return base58_sha256_impl(buffer, data, data_len) && base58_sha256_impl(hash, buffer, sizeof(buffer));
}

int base58_check(const void *bin, size_t binsz, const char *base58str, size_t b58sz)
{
    unsigned char buffer[32];
    const uint8_t *binc = bin;
    unsigned int i;

    if (binsz < 4)
    {
        return -4;
    }

    if (!my_dblsha256(buffer, bin, binsz - 4))
    {
        return -2;
    }

    if (memcmp(&binc[binsz - 4], buffer, 4))
    {
        return -1;
    }

    // Check number of zeros is correct AFTER verifying checksum (to avoid possibility of accessing base58str[-1])
    for (i = 0; binc[i] == '\0' && base58str[i] == '1'; ++i)
    {
        ; // Just finding the end of zeros, nothing to do
    }

    if (binc[i] == '\0' && base58str[i] == '1')
    {
        return -3;
    }

    return binc[0];
}

bool base58_encode(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
    const uint8_t *bin = data;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < binsz && !bin[zcount])
    {
        ++zcount;
    }

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
        {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if (!j)
            {
                // Otherwise j wraps to maxint which is bigger than high
                break;
            }
        }
    }

    for (j = 0; j < size && !buf[j]; ++j)
    {
        ; // Just finding the end of zeros, nothing to do
    }

    if (*b58sz <= zcount + size - j)
    {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount)
    {
        memset(b58, '1', zcount);
    }

    for (i = zcount; j < size; ++i, ++j)
    {
        b58[i] = base58_digits_ordered[buf[j]];
    }
    b58[i] = '\0';
    *b58sz = i + 1;

    return true;
}

bool base58_check_encode(char *b58c, size_t *b58c_sz, uint8_t ver, const void *data, size_t datasz)
{
    uint8_t buf[1 + datasz + 0x20];
    uint8_t *hash = &buf[1 + datasz];

    buf[0] = ver;
    memcpy(&buf[1], data, datasz);
    if (!my_dblsha256(hash, buf, datasz + 1))
    {
        *b58c_sz = 0;
        return false;
    }

    return base58_encode(b58c, b58c_sz, buf, 1 + datasz + 4);
}
