#include "aesblockcipher.h"

// Optimised Java implementation of the Rijndael (AES) block cipher.

// Flag to setup the encryption key schedule.
static const quint32 DIR_ENCRYPT = 1;
// Flag to setup the decryption key schedule.
static const quint32 DIR_DECRYPT = 2;
// Flag to setup both key schedules (encryption/decryption).
static const quint32 DIR_BOTH    = (DIR_ENCRYPT|DIR_DECRYPT);
// AES block size in bits
// (N.B. the Rijndael algorithm itself allows for other sizes).
static const quint32 BLOCK_BITS  = 128;
//AES block size in bytes
// (N.B. the Rijndael algorithm itself allows for other sizes)
static const quint32 BLOCK_SIZE  = (BLOCK_BITS >> 3);

// Substitution table (S-box).
// Forward s-box table
const quint8 SS[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


static quint8 Se[256] = {};

static quint32 Te0[256] = {};
static quint32 Te1[256] = {};
static quint32 Te2[256] = {};
static quint32 Te3[256] = {};

static quint8 Sd[256] = {};

static quint32 Td0[256] = {};
static quint32 Td1[256] = {};
static quint32 Td2[256] = {};
static quint32 Td3[256] = {};

static quint32 rcon[10] = {}; // for 128-bit blocks, Rijndael never uses more than 10 rcon values
quint32 Nr = 0;

quint32 Nk = 0;

quint32 Nw = 0;

/**
     * Encryption key schedule
     */
QVector<int> rek = {};

/**
     * Decryption key schedule
     */
QVector<int> rdk = {};

AESBlockCipher::AESBlockCipher()
{
    quint32 ROOT = 0x11B;
    quint32 s1, s2, s3, i1, i2, i4, i8, i9, ib, id, ie, t;
    for (i1 = 0; i1 < 256; i1++) {
        quint8 c = SS[i1 >> 1];
        s1 = (quint8)((i1 & 1) == 0 ? c >> 8 : c) & 0xff;
        s2 = s1 << 1;
        if (s2 >= 0x100) {
            s2 ^= ROOT;
        }
        s3 = s2 ^ s1;
        i2 = i1 << 1;
        if (i2 >= 0x100) {
            i2 ^= ROOT;
        }
        i4 = i2 << 1;
        if (i4 >= 0x100) {
            i4 ^= ROOT;
        }
        i8 = i4 << 1;
        if (i8 >= 0x100) {
            i8 ^= ROOT;
        }
        i9 = i8 ^ i1;
        ib = i9 ^ i2;
        id = i9 ^ i4;
        ie = i8 ^ i4 ^ i2;

        Se[i1] = (quint8)s1;
        Te0[i1] = t = (s2 << 24) | (s1 << 16) | (s1 << 8) | s3;
        Te1[i1] = (t >>  8) | (t  << 24);
        Te2[i1] = (t >> 16) | (t  << 16);
        Te3[i1] = (t >> 24) | (t  <<  8);

        Sd[s1] = (quint8)i1;
        Td0[s1] = t = (ie << 24) | (i9 << 16) | (id << 8) | ib;
        Td1[s1] = (t >>  8) | (t  << 24);
        Td2[s1] = (t >> 16) | (t  << 16);
        Td3[s1] = (t >> 24) | (t  <<  8);
    }
    /*
         * round constants
         */
    quint32 r = 1;
    rcon[0] = r << 24;
    for (quint32 i = 1; i < 10; i++) {
        r <<= 1;
        if (r >= 0x100) {
            r ^= ROOT;
        }
        rcon[i] = r << 24;
    }
}

/**
     * Expand a cipher key into a full encryption key schedule.
     *
     * @param   cipherKey   the cipher key (128, 192, or 256 bits).
     */
void AESBlockCipher::expandKey(QVector<quint8> cipherKey) {
    quint32 temp, r = 0;
    for (quint32 i = 0, k = 0; i < Nk; i++, k += 4) {
        rek[i] =
            ((cipherKey[k    ]       ) << 24) |
            ((cipherKey[k + 1] & 0xff) << 16) |
            ((cipherKey[k + 2] & 0xff) <<  8) |
            ((cipherKey[k + 3] & 0xff));
    }
    for (quint32 i = Nk, n = 0; i < Nw; i++, n--) {
        temp = rek[i - 1];
        if (n == 0) {
            n = Nk;
            temp =
                ((Se[(temp >> 16) & 0xff]       ) << 24) |
                ((Se[(temp >>  8) & 0xff] & 0xff) << 16) |
                ((Se[(temp       ) & 0xff] & 0xff) <<  8) |
                ((Se[(temp >> 24)       ] & 0xff));
            temp ^= rcon[r++];
        } else if (Nk == 8 && n == 4) {
            temp =
                ((Se[(temp >> 24)       ]       ) << 24) |
                ((Se[(temp >> 16) & 0xff] & 0xff) << 16) |
                ((Se[(temp >> 8) & 0xff] & 0xff) <<  8) |
                ((Se[(temp       ) & 0xff] & 0xff));
        }
        rek[i] = rek[i - Nk] ^ temp;
    }
    temp = 0;
}


/**
     * Compute the decryption schedule from the encryption schedule .
     */
void AESBlockCipher::invertKey() {
    quint32 d = 0, e = 4*Nr, w;
    /*
        * apply the inverse MixColumn transform to all round keys
        * but the first and the last:
        */
    rdk[d    ] = rek[e    ];
    rdk[d + 1] = rek[e + 1];
    rdk[d + 2] = rek[e + 2];
    rdk[d + 3] = rek[e + 3];
    d += 4;
    e -= 4;
    for (quint32 r = 1; r < Nr; r++) {
        w = rek[e    ];
        rdk[d    ] =
            Td0[Se[(w >> 24)       ] & 0xff] ^
            Td1[Se[(w >> 16) & 0xff] & 0xff] ^
            Td2[Se[(w >>  8) & 0xff] & 0xff] ^
            Td3[Se[(w       ) & 0xff] & 0xff];
        w = rek[e + 1];
        rdk[d + 1] =
            Td0[Se[(w >> 24)       ] & 0xff] ^
            Td1[Se[(w >> 16) & 0xff] & 0xff] ^
            Td2[Se[(w >>  8) & 0xff] & 0xff] ^
            Td3[Se[(w       ) & 0xff] & 0xff];
        w = rek[e + 2];
        rdk[d + 2] =
            Td0[Se[(w >> 24)       ] & 0xff] ^
            Td1[Se[(w >> 16) & 0xff] & 0xff] ^
            Td2[Se[(w >>  8) & 0xff] & 0xff] ^
            Td3[Se[(w       ) & 0xff] & 0xff];
        w = rek[e + 3];
        rdk[d + 3] =
            Td0[Se[(w >> 24)       ] & 0xff] ^
            Td1[Se[(w >> 16) & 0xff] & 0xff] ^
            Td2[Se[(w >>  8) & 0xff] & 0xff] ^
            Td3[Se[(w       ) & 0xff] & 0xff];
        d += 4;
        e -= 4;
    }
    rdk[d    ] = rek[e    ];
    rdk[d + 1] = rek[e + 1];
    rdk[d + 2] = rek[e + 2];
    rdk[d + 3] = rek[e + 3];
}

/**
     * Setup the AES key schedule for encryption, decryption, or both.
     *
     * @param   cipherKey   the cipher key (128, 192, or 256 bits).
     * @param   keyBits     size of the cipher key in bits.
     * @param   direction   cipher direction (DIR_ENCRYPT, DIR_DECRYPT, or DIR_BOTH).
     */
void AESBlockCipher::makeKey(QVector<quint8> cipherKey, quint32 keyBits, quint32 direction)
{
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return;
    }
    Nk = keyBits >> 5;
    Nr = Nk + 6;
    Nw = 4*(Nr + 1);
    rek.resize(Nw);
    rdk.resize(Nw);
    if ((direction & DIR_BOTH) != 0) {
        expandKey(cipherKey);
        /*
            for (quint32 r = 0; r <= Nr; r++) {
                System.out.print("RK" + r + "=");
                for (quint32 i = 0; i < 4; i++) {
                    quint32 w = rek[4*r + i];
                    System.out.print(" " + Integer.toHexString(w));
                }
                System.out.println();
            }
            */
        if ((direction & DIR_DECRYPT) != 0) {
            invertKey();
        }
    }
}

/**
     * Setup the AES key schedule (any cipher direction).
     *
     * @param   cipherKey   the cipher key (128, 192, or 256 bits).
     * @param   keyBits     size of the cipher key in bits.
     */
void AESBlockCipher::makeKey(QVector<quint8> cipherKey, quint32 keyBits)
{
    makeKey(cipherKey, keyBits, DIR_BOTH);
}

/**
     * Encrypt exactly one block (BLOCK_SIZE bytes) of plaintext.
     *
     * @param   pt          plaintext block.
     * @param   ct          ciphertext block.
     */
QVector<quint8> AESBlockCipher::encrypt(QVector<quint8> pt) {
    /*
         * map quint8 array block to cipher state
         * and add initial round key:
         */
    QVector<quint8> ct(16);
    quint32 k = 0, v;
    quint32 t0   = ((pt[ 0]       ) << 24 |
              (pt[ 1] & 0xff) << 16 |
              (pt[ 2] & 0xff) <<  8 |
              (pt[ 3] & 0xff)        ) ^ rek[0];
    quint32 t1   = ((pt[ 4]       ) << 24 |
              (pt[ 5] & 0xff) << 16 |
              (pt[ 6] & 0xff) <<  8 |
              (pt[ 7] & 0xff)        ) ^ rek[1];
    quint32 t2   = ((pt[ 8]       ) << 24 |
              (pt[ 9] & 0xff) << 16 |
              (pt[10] & 0xff) <<  8 |
              (pt[11] & 0xff)        ) ^ rek[2];
    quint32 t3   = ((pt[12]       ) << 24 |
              (pt[13] & 0xff) << 16 |
              (pt[14] & 0xff) <<  8 |
              (pt[15] & 0xff)        ) ^ rek[3];
    /*
         * Nr - 1 full rounds:
         */
    for (quint32 r = 1; r < Nr; r++) {
        k += 4;
        quint32 a0 =
            Te0[(t0 >> 24)       ] ^
            Te1[(t1 >> 16) & 0xff] ^
            Te2[(t2 >>  8) & 0xff] ^
            Te3[(t3       ) & 0xff] ^
            rek[k    ];
        quint32 a1 =
            Te0[(t1 >> 24)       ] ^
            Te1[(t2 >> 16) & 0xff] ^
            Te2[(t3 >>  8) & 0xff] ^
            Te3[(t0       ) & 0xff] ^
            rek[k + 1];
        quint32 a2 =
            Te0[(t2 >> 24)       ] ^
            Te1[(t3 >> 16) & 0xff] ^
            Te2[(t0 >>  8) & 0xff] ^
            Te3[(t1       ) & 0xff] ^
            rek[k + 2];
        quint32 a3 =
            Te0[(t3 >> 24)       ] ^
            Te1[(t0 >> 16) & 0xff] ^
            Te2[(t1 >>  8) & 0xff] ^
            Te3[(t2       ) & 0xff] ^
            rek[k + 3];
        t0 = a0; t1 = a1; t2 = a2; t3 = a3;
    }
    /*
         * last round lacks MixColumn:
         */
    k += 4;

    v = rek[k    ];
    ct[ 0] = (quint8)(Se[(t0 >> 24)       ] ^ (v >> 24));
    ct[ 1] = (quint8)(Se[(t1 >> 16) & 0xff] ^ (v >> 16));
    ct[ 2] = (quint8)(Se[(t2 >>  8) & 0xff] ^ (v >>  8));
    ct[ 3] = (quint8)(Se[(t3       ) & 0xff] ^ (v       ));

    v = rek[k + 1];
    ct[ 4] = (quint8)(Se[(t1 >> 24)       ] ^ (v >> 24));
    ct[ 5] = (quint8)(Se[(t2 >> 16) & 0xff] ^ (v >> 16));
    ct[ 6] = (quint8)(Se[(t3 >>  8) & 0xff] ^ (v >>  8));
    ct[ 7] = (quint8)(Se[(t0       ) & 0xff] ^ (v       ));

    v = rek[k + 2];
    ct[ 8] = (quint8)(Se[(t2 >> 24)       ] ^ (v >> 24));
    ct[ 9] = (quint8)(Se[(t3 >> 16) & 0xff] ^ (v >> 16));
    ct[10] = (quint8)(Se[(t0 >>  8) & 0xff] ^ (v >>  8));
    ct[11] = (quint8)(Se[(t1       ) & 0xff] ^ (v       ));

    v = rek[k + 3];
    ct[12] = (quint8)(Se[(t3 >> 24)       ] ^ (v >> 24));
    ct[13] = (quint8)(Se[(t0 >> 16) & 0xff] ^ (v >> 16));
    ct[14] = (quint8)(Se[(t1 >>  8) & 0xff] ^ (v >>  8));
    ct[15] = (quint8)(Se[(t2       ) & 0xff] ^ (v       ));

    return ct;
}

/**
     * Decrypt exactly one block (BLOCK_SIZE bytes) of ciphertext.
     *
     * @param   ct          ciphertext block.
     * @param   pt          plaintext block.
     */
QVector<quint8> AESBlockCipher::decrypt(QVector<quint8> ct) {
    /*
         * map quint8 array block to cipher state
         * and add initial round key:
         */
    QVector<quint8> pt(16);
    quint32 k = 0, v;
    quint32 t0 =   ((ct[ 0]       ) << 24 |
              (ct[ 1] & 0xff) << 16 |
              (ct[ 2] & 0xff) <<  8 |
              (ct[ 3] & 0xff)        ) ^ rdk[0];
    quint32 t1 =   ((ct[ 4]       ) << 24 |
              (ct[ 5] & 0xff) << 16 |
              (ct[ 6] & 0xff) <<  8 |
              (ct[ 7] & 0xff)        ) ^ rdk[1];
    quint32 t2 =   ((ct[ 8]       ) << 24 |
              (ct[ 9] & 0xff) << 16 |
              (ct[10] & 0xff) <<  8 |
              (ct[11] & 0xff)        ) ^ rdk[2];
    quint32 t3 =   ((ct[12]       ) << 24 |
              (ct[13] & 0xff) << 16 |
              (ct[14] & 0xff) <<  8 |
              (ct[15] & 0xff)        ) ^ rdk[3];
    /*
         * Nr - 1 full rounds:
         */
    for (quint32 r = 1; r < Nr; r++) {
        k += 4;
        quint32 a0 =
            Td0[(t0 >> 24)       ] ^
            Td1[(t3 >> 16) & 0xff] ^
            Td2[(t2 >>  8) & 0xff] ^
            Td3[(t1       ) & 0xff] ^
            rdk[k    ];
        quint32 a1 =
            Td0[(t1 >> 24)       ] ^
            Td1[(t0 >> 16) & 0xff] ^
            Td2[(t3 >>  8) & 0xff] ^
            Td3[(t2       ) & 0xff] ^
            rdk[k + 1];
        quint32 a2 =
            Td0[(t2 >> 24)       ] ^
            Td1[(t1 >> 16) & 0xff] ^
            Td2[(t0 >>  8) & 0xff] ^
            Td3[(t3       ) & 0xff] ^
            rdk[k + 2];
        quint32 a3 =
            Td0[(t3 >> 24)       ] ^
            Td1[(t2 >> 16) & 0xff] ^
            Td2[(t1 >>  8) & 0xff] ^
            Td3[(t0       ) & 0xff] ^
            rdk[k + 3];
        t0 = a0; t1 = a1; t2 = a2; t3 = a3;
    }
    /*
         * last round lacks MixColumn:
         */
    k += 4;

    v = rdk[k    ];
    pt[ 0] = (quint8)(Sd[(t0 >> 24)       ] ^ (v >> 24));
    pt[ 1] = (quint8)(Sd[(t3 >> 16) & 0xff] ^ (v >> 16));
    pt[ 2] = (quint8)(Sd[(t2 >>  8) & 0xff] ^ (v >>  8));
    pt[ 3] = (quint8)(Sd[(t1       ) & 0xff] ^ (v       ));

    v = rdk[k + 1];
    pt[ 4] = (quint8)(Sd[(t1 >> 24)       ] ^ (v >> 24));
    pt[ 5] = (quint8)(Sd[(t0 >> 16) & 0xff] ^ (v >> 16));
    pt[ 6] = (quint8)(Sd[(t3 >>  8) & 0xff] ^ (v >>  8));
    pt[ 7] = (quint8)(Sd[(t2       ) & 0xff] ^ (v       ));

    v = rdk[k + 2];
    pt[ 8] = (quint8)(Sd[(t2 >> 24)       ] ^ (v >> 24));
    pt[ 9] = (quint8)(Sd[(t1 >> 16) & 0xff] ^ (v >> 16));
    pt[10] = (quint8)(Sd[(t0 >>  8) & 0xff] ^ (v >>  8));
    pt[11] = (quint8)(Sd[(t3       ) & 0xff] ^ (v       ));

    v = rdk[k + 3];
    pt[12] = (quint8)(Sd[(t3 >> 24)       ] ^ (v >> 24));
    pt[13] = (quint8)(Sd[(t2 >> 16) & 0xff] ^ (v >> 16));
    pt[14] = (quint8)(Sd[(t1 >>  8) & 0xff] ^ (v >>  8));
    pt[15] = (quint8)(Sd[(t0       ) & 0xff] ^ (v       ));

    return pt;
}

/**
     * Destroy all sensitive information in this object.
     */
void AESBlockCipher::finalize() {
    if (!rek.isEmpty()) {
        for (quint32 i = 0; i < rek.size(); i++) {
            rek[i] = 0;
        }
        rek.clear();
    }
    if (!rdk.isEmpty()) {
        for (quint32 i = 0; i < rdk.size(); i++) {
            rdk[i] = 0;
        }
        rek.clear();
    }
}

