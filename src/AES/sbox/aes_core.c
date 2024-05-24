#include <assert.h>
#include <stdlib.h>
#include <assert.h>
#include "aes.h"

// #  define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define GETU32(p) (*((u32*)(p)))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

//typedef unsigned long long u64;
# ifdef AES_LONG
typedef unsigned long u32;
# else
typedef unsigned int u32;
# endif
typedef unsigned short u16;
typedef unsigned char u8;


const u8 Te4[256] __attribute__ ((aligned(64)))  = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

const uint8_t* sbox_Td4 = Td4_;

const u8 Td4_[256] __attribute__ ((aligned(64)))= {
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U,
    0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U,
    0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU,
    0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U,
    0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U,
    0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU,
    0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU,
    0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U,
    0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU,
    0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U,
    0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U,
    0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U,
    0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U,
    0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU,
    0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U,
    0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U,
    0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU,
};

static const u32 rcon[] = {
    0x00000001U, 0x00000002U, 0x00000004U, 0x00000008U,
    0x00000010U, 0x00000020U, 0x00000040U, 0x00000080U,
    0x0000001bU, 0x00000036U, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};


int AES_set_encrypt_key_sbox(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{
    u32 *rk;
    int i = 0;
    u32 temp;

    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = key->rd_key;

    if (bits==128)
        key->rounds = 10;
    else if (bits==192)
        key->rounds = 12;
    else
        key->rounds = 14;

    rk[0] = GETU32(userKey     );
    rk[1] = GETU32(userKey +  4);
    rk[2] = GETU32(userKey +  8);
    rk[3] = GETU32(userKey + 12);
    if (bits == 128) {
        while (1) {
            temp  = rk[3];
            rk[4] = rk[0] ^
                ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xff] << 24) ^
                rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                return 0;
            }
            rk += 4;
        }
    }
    rk[4] = GETU32(userKey + 16);
    rk[5] = GETU32(userKey + 20);
    if (bits == 192) {
        while (1) {
            temp = rk[ 5];
            rk[ 6] = rk[ 0] ^
                ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xff] << 24) ^
                rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                return 0;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    }
    rk[6] = GETU32(userKey + 24);
    rk[7] = GETU32(userKey + 28);
    if (bits == 256) {
        while (1) {
            temp = rk[ 7];
            rk[ 8] = rk[ 0] ^
                ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xff] << 24) ^
                rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                return 0;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^
                ((u32)Te4[(temp      ) & 0xff]      ) ^
                ((u32)Te4[(temp >>  8) & 0xff] <<  8) ^
                ((u32)Te4[(temp >> 16) & 0xff] << 16) ^
                ((u32)Te4[(temp >> 24)       ] << 24);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
            }
    }
    return 0;
}

int AES_set_decrypt_key_sbox(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{

    u32 *rk;
    int i, j, status;
    u32 temp;

    /* first, start with an encryption schedule */
    status = AES_set_encrypt_key_sbox(userKey, bits, key);
    if (status < 0)
        return status;

    rk = key->rd_key;

    /* invert the order of the round keys: */
    for (i = 0, j = 4*(key->rounds); i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < (key->rounds); i++) {
        rk += 4;

        for (j = 0; j < 4; j++) {
            u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            tp1 = rk[j];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;

            rk[j] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
        }
    }
    return 0;
}

void AES_encrypt_sbox(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{
    const u32 *rk;
    u32 s0, s1, s2, s3, t[4];
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];

    t[0] = (u32)Te4[(s0      ) & 0xff]       ^
           (u32)Te4[(s1 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s2 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s3 >> 24)       ] << 24;
    t[1] = (u32)Te4[(s1      ) & 0xff]       ^
           (u32)Te4[(s2 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s3 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s0 >> 24)       ] << 24;
    t[2] = (u32)Te4[(s2      ) & 0xff]       ^
           (u32)Te4[(s3 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s0 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s1 >> 24)       ] << 24;
    t[3] = (u32)Te4[(s3      ) & 0xff]       ^
           (u32)Te4[(s0 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s1 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s2 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {   int i;
        u32 r0, r1, r2;

        for (i = 0; i < 4; i++) {
            r0 = t[i];
            r1 = r0 & 0x80808080;
            r2 = ((r0 & 0x7f7f7f7f) << 1) ^
                ((r1 - (r1 >> 7)) & 0x1b1b1b1b);

            t[i] = r2 ^ ((r2 ^ r0) << 24) ^ ((r2 ^ r0) >> 8) ^
                (r0 << 16) ^ (r0 >> 16) ^
                (r0 << 8) ^ (r0 >> 24);
            t[i] ^= rk[4+i];
        }
    }

    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
        t[0] = (u32)Te4[(s0      ) & 0xff]       ^
               (u32)Te4[(s1 >>  8) & 0xff] <<  8 ^
               (u32)Te4[(s2 >> 16) & 0xff] << 16 ^
               (u32)Te4[(s3 >> 24)       ] << 24;
        t[1] = (u32)Te4[(s1      ) & 0xff]       ^
               (u32)Te4[(s2 >>  8) & 0xff] <<  8 ^
               (u32)Te4[(s3 >> 16) & 0xff] << 16 ^
               (u32)Te4[(s0 >> 24)       ] << 24;
        t[2] = (u32)Te4[(s2      ) & 0xff]       ^
               (u32)Te4[(s3 >>  8) & 0xff] <<  8 ^
               (u32)Te4[(s0 >> 16) & 0xff] << 16 ^
               (u32)Te4[(s1 >> 24)       ] << 24;
        t[3] = (u32)Te4[(s3      ) & 0xff]       ^
               (u32)Te4[(s0 >>  8) & 0xff] <<  8 ^
               (u32)Te4[(s1 >> 16) & 0xff] << 16 ^
               (u32)Te4[(s2 >> 24)       ] << 24;

        /* now do the linear transform using words */
        {
            int i;
            u32 r0, r1, r2;

            for (i = 0; i < 4; i++) {
                r0 = t[i];
                r1 = r0 & 0x80808080;
                r2 = ((r0 & 0x7f7f7f7f) << 1) ^
                    ((r1 - (r1 >> 7)) & 0x1b1b1b1b);

                t[i] = r2 ^ ((r2 ^ r0) << 24) ^ ((r2 ^ r0) >> 8) ^
                    (r0 << 16) ^ (r0 >> 16) ^
                    (r0 << 8) ^ (r0 >> 24);
                t[i] ^= rk[i];
            }
        }

        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */

    *(u32*)(out+0) =
           (u32)Te4[(s0      ) & 0xff]       ^
           (u32)Te4[(s1 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s2 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s3 >> 24)       ] << 24 ^
        rk[0];
    *(u32*)(out+4) =
           (u32)Te4[(s1      ) & 0xff]       ^
           (u32)Te4[(s2 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s3 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s0 >> 24)       ] << 24 ^
        rk[1];
    *(u32*)(out+8) =
           (u32)Te4[(s2      ) & 0xff]       ^
           (u32)Te4[(s3 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s0 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s1 >> 24)       ] << 24 ^
        rk[2];
    *(u32*)(out+12) =
           (u32)Te4[(s3      ) & 0xff]       ^
           (u32)Te4[(s0 >>  8) & 0xff] <<  8 ^
           (u32)Te4[(s1 >> 16) & 0xff] << 16 ^
           (u32)Te4[(s2 >> 24)       ] << 24 ^
        rk[3];
}

void AES_decrypt_sbox(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{
    const u32 *rk;
    u32 s0, s1, s2, s3, t[4];
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];

    t[0] = (u32)sbox_Td4[(s0      ) & 0xff]       ^
           (u32)sbox_Td4[(s3 >>  8) & 0xff] <<  8 ^
           (u32)sbox_Td4[(s2 >> 16) & 0xff] << 16 ^
           (u32)sbox_Td4[(s1 >> 24)       ] << 24;
    t[1] = (u32)sbox_Td4[(s1      ) & 0xff]       ^
           (u32)sbox_Td4[(s0 >>  8) & 0xff] <<  8 ^
           (u32)sbox_Td4[(s3 >> 16) & 0xff] << 16 ^
           (u32)sbox_Td4[(s2 >> 24)       ] << 24;
    t[2] = (u32)sbox_Td4[(s2      ) & 0xff]       ^
           (u32)sbox_Td4[(s1 >>  8) & 0xff] <<  8 ^
           (u32)sbox_Td4[(s0 >> 16) & 0xff] << 16 ^
           (u32)sbox_Td4[(s3 >> 24)       ] << 24;
    t[3] = (u32)sbox_Td4[(s3      ) & 0xff]       ^
           (u32)sbox_Td4[(s2 >>  8) & 0xff] <<  8 ^
           (u32)sbox_Td4[(s1 >> 16) & 0xff] << 16 ^
           (u32)sbox_Td4[(s0 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;

            t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
            t[i] ^= rk[4+i];
        }
    }

    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
        t[0] = (u32)sbox_Td4[(s0      ) & 0xff]       ^
               (u32)sbox_Td4[(s3 >>  8) & 0xff] <<  8 ^
               (u32)sbox_Td4[(s2 >> 16) & 0xff] << 16 ^
               (u32)sbox_Td4[(s1 >> 24)       ] << 24;
        t[1] = (u32)sbox_Td4[(s1      ) & 0xff]       ^
               (u32)sbox_Td4[(s0 >>  8) & 0xff] <<  8 ^
               (u32)sbox_Td4[(s3 >> 16) & 0xff] << 16 ^
               (u32)sbox_Td4[(s2 >> 24)       ] << 24;
        t[2] = (u32)sbox_Td4[(s2      ) & 0xff]       ^
               (u32)sbox_Td4[(s1 >>  8) & 0xff] <<  8 ^
               (u32)sbox_Td4[(s0 >> 16) & 0xff] << 16 ^
               (u32)sbox_Td4[(s3 >> 24)       ] << 24;
        t[3] = (u32)sbox_Td4[(s3      ) & 0xff]       ^
               (u32)sbox_Td4[(s2 >>  8) & 0xff] <<  8 ^
               (u32)sbox_Td4[(s1 >> 16) & 0xff] << 16 ^
               (u32)sbox_Td4[(s0 >> 24)       ] << 24;
    
        /* now do the linear transform using words */
        {
            int i;
            u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            for (i = 0; i < 4; i++) {
                tp1 = t[i];
                m = tp1 & 0x80808080;
                tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp2 & 0x80808080;
                tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp4 & 0x80808080;
                tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                tp9 = tp8 ^ tp1;
                tpb = tp9 ^ tp2;
                tpd = tp9 ^ tp4;
                tpe = tp8 ^ tp4 ^ tp2;
    
                t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                    (tp9 >> 24) ^ (tp9 << 8) ^
                    (tpb >> 8) ^ (tpb << 24);
                t[i] ^= rk[i];
            }
        }
        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */

    *(u32*)(out+0) =
        ((u32)sbox_Td4[(s0      ) & 0xff])    ^
        ((u32)sbox_Td4[(s3 >>  8) & 0xff] <<  8) ^
        ((u32)sbox_Td4[(s2 >> 16) & 0xff] << 16) ^
        ((u32)sbox_Td4[(s1 >> 24)       ] << 24) ^
        rk[0];
    *(u32*)(out+4) =
        ((u32)sbox_Td4[(s1      ) & 0xff])     ^
        ((u32)sbox_Td4[(s0 >>  8) & 0xff] <<  8) ^
        ((u32)sbox_Td4[(s3 >> 16) & 0xff] << 16) ^
        ((u32)sbox_Td4[(s2 >> 24)       ] << 24) ^
        rk[1];
    *(u32*)(out+8) =
        ((u32)sbox_Td4[(s2      ) & 0xff])     ^
        ((u32)sbox_Td4[(s1 >>  8) & 0xff] <<  8) ^
        ((u32)sbox_Td4[(s0 >> 16) & 0xff] << 16) ^
        ((u32)sbox_Td4[(s3 >> 24)       ] << 24) ^
        rk[2];
    *(u32*)(out+12) =
        ((u32)sbox_Td4[(s3      ) & 0xff])     ^
        ((u32)sbox_Td4[(s2 >>  8) & 0xff] <<  8) ^
        ((u32)sbox_Td4[(s1 >> 16) & 0xff] << 16) ^
        ((u32)sbox_Td4[(s0 >> 24)       ] << 24) ^
        rk[3];
}

void AES_decrypt_sbox_debug(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key, uint8_t* sets)
{
    const u32 *rk;
    u32 s0, s1, s2, s3, t[4];
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];

    int scount = 0;
#define Sidx(x, t) (sets[scount+t] = (x), (x))

    t[0] = (u32)sbox_Td4[Sidx((s0      ) & 0xff, 0x0)]       ^
           (u32)sbox_Td4[Sidx((s3 >>  8) & 0xff, 0x1)] <<  8 ^
           (u32)sbox_Td4[Sidx((s2 >> 16) & 0xff, 0x2)] << 16 ^
           (u32)sbox_Td4[Sidx((s1 >> 24)       , 0x3)] << 24;
    t[1] = (u32)sbox_Td4[Sidx((s1      ) & 0xff, 0x4)]       ^
           (u32)sbox_Td4[Sidx((s0 >>  8) & 0xff, 0x5)] <<  8 ^
           (u32)sbox_Td4[Sidx((s3 >> 16) & 0xff, 0x6)] << 16 ^
           (u32)sbox_Td4[Sidx((s2 >> 24)       , 0x7)] << 24;
    t[2] = (u32)sbox_Td4[Sidx((s2      ) & 0xff, 0x8)]       ^
           (u32)sbox_Td4[Sidx((s1 >>  8) & 0xff, 0x9)] <<  8 ^
           (u32)sbox_Td4[Sidx((s0 >> 16) & 0xff, 0xA)] << 16 ^
           (u32)sbox_Td4[Sidx((s3 >> 24)       , 0xB)] << 24;
    t[3] = (u32)sbox_Td4[Sidx((s3      ) & 0xff, 0xC)]       ^
           (u32)sbox_Td4[Sidx((s2 >>  8) & 0xff, 0xD)] <<  8 ^
           (u32)sbox_Td4[Sidx((s1 >> 16) & 0xff, 0xE)] << 16 ^
           (u32)sbox_Td4[Sidx((s0 >> 24)       , 0xF)] << 24;
    scount += 16;

    /* now do the linear transform using words */
    {
        int i;
        u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;

            t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
            t[i] ^= rk[4+i];
        }
    }

    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
        t[0] = (u32)sbox_Td4[Sidx((s0      ) & 0xff, 0x0)]       ^
               (u32)sbox_Td4[Sidx((s3 >>  8) & 0xff, 0x1)] <<  8 ^
               (u32)sbox_Td4[Sidx((s2 >> 16) & 0xff, 0x2)] << 16 ^
               (u32)sbox_Td4[Sidx((s1 >> 24)       , 0x3)] << 24;
        t[1] = (u32)sbox_Td4[Sidx((s1      ) & 0xff, 0x4)]       ^
               (u32)sbox_Td4[Sidx((s0 >>  8) & 0xff, 0x5)] <<  8 ^
               (u32)sbox_Td4[Sidx((s3 >> 16) & 0xff, 0x6)] << 16 ^
               (u32)sbox_Td4[Sidx((s2 >> 24)       , 0x7)] << 24;
        t[2] = (u32)sbox_Td4[Sidx((s2      ) & 0xff, 0x8)]       ^
               (u32)sbox_Td4[Sidx((s1 >>  8) & 0xff, 0x9)] <<  8 ^
               (u32)sbox_Td4[Sidx((s0 >> 16) & 0xff, 0xA)] << 16 ^
               (u32)sbox_Td4[Sidx((s3 >> 24)       , 0xB)] << 24;
        t[3] = (u32)sbox_Td4[Sidx((s3      ) & 0xff, 0xC)]       ^
               (u32)sbox_Td4[Sidx((s2 >>  8) & 0xff, 0xD)] <<  8 ^
               (u32)sbox_Td4[Sidx((s1 >> 16) & 0xff, 0xE)] << 16 ^
               (u32)sbox_Td4[Sidx((s0 >> 24)       , 0xF)] << 24;
        scount += 16;
    
        /* now do the linear transform using words */
        {
            int i;
            u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            for (i = 0; i < 4; i++) {
                tp1 = t[i];
                m = tp1 & 0x80808080;
                tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp2 & 0x80808080;
                tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp4 & 0x80808080;
                tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                    ((m - (m >> 7)) & 0x1b1b1b1b);
                tp9 = tp8 ^ tp1;
                tpb = tp9 ^ tp2;
                tpd = tp9 ^ tp4;
                tpe = tp8 ^ tp4 ^ tp2;
    
                t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                    (tp9 >> 24) ^ (tp9 << 8) ^
                    (tpb >> 8) ^ (tpb << 24);
                t[i] ^= rk[i];
            }
        }
        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */

    *(u32*)(out+0) =
        ((u32)sbox_Td4[Sidx((s0      ) & 0xff, 0x0)])    ^
        ((u32)sbox_Td4[Sidx((s3 >>  8) & 0xff, 0x1)] <<  8) ^
        ((u32)sbox_Td4[Sidx((s2 >> 16) & 0xff, 0x2)] << 16) ^
        ((u32)sbox_Td4[Sidx((s1 >> 24)       , 0x3)] << 24) ^
        rk[0];
    *(u32*)(out+4) =
        ((u32)sbox_Td4[Sidx((s1      ) & 0xff, 0x4)])     ^
        ((u32)sbox_Td4[Sidx((s0 >>  8) & 0xff, 0x5)] <<  8) ^
        ((u32)sbox_Td4[Sidx((s3 >> 16) & 0xff, 0x6)] << 16) ^
        ((u32)sbox_Td4[Sidx((s2 >> 24)       , 0x7)] << 24) ^
        rk[1];
    *(u32*)(out+8) =
        ((u32)sbox_Td4[Sidx((s2      ) & 0xff, 0x8)])     ^
        ((u32)sbox_Td4[Sidx((s1 >>  8) & 0xff, 0x9)] <<  8) ^
        ((u32)sbox_Td4[Sidx((s0 >> 16) & 0xff, 0xA)] << 16) ^
        ((u32)sbox_Td4[Sidx((s3 >> 24)       , 0xB)] << 24) ^
        rk[2];
    *(u32*)(out+12) =
        ((u32)sbox_Td4[Sidx((s3      ) & 0xff, 0xC)])     ^
        ((u32)sbox_Td4[Sidx((s2 >>  8) & 0xff, 0xD)] <<  8) ^
        ((u32)sbox_Td4[Sidx((s1 >> 16) & 0xff, 0xE)] << 16) ^
        ((u32)sbox_Td4[Sidx((s0 >> 24)       , 0xF)] << 24) ^
        rk[3];
}
