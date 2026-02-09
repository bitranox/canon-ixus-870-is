// Tiny JPEG Encoder for CHDK
// Minimal JPEG encoder for embedded ARM targets.
// Based on public domain code by Sergio Gonzalez, adapted for CHDK.
//
// Encodes YUV data directly to JPEG without RGB conversion.
// Uses integer-only arithmetic (no floating point).

#include "tje.h"

// Forward declaration of memcpy/memset (provided by CHDK module system)
extern void *memcpy(void *dest, const void *src, long n);
extern void *memset(void *s, int c, long n);

// Fast bit-length: number of bits needed to represent val (0 returns 0).
// Uses binary search — 5 comparisons vs up to 11 iterations in a while loop.
static inline int bit_length(unsigned int val)
{
    int n = 0;
    if (val >= (1u << 16)) { n += 16; val >>= 16; }
    if (val >= (1u <<  8)) { n +=  8; val >>=  8; }
    if (val >= (1u <<  4)) { n +=  4; val >>=  4; }
    if (val >= (1u <<  2)) { n +=  2; val >>=  2; }
    if (val >= (1u <<  1)) { n +=  1; val >>=  1; }
    n += val;
    return n;
}

// ============================================================
// JPEG constants
// ============================================================

// Zig-zag order: maps natural 2D index to zig-zag scan position
// Used in encode_block to reorder quantized DCT coefficients
static const unsigned char zz_order[64] = {
     0,  1,  5,  6, 14, 15, 27, 28,
     2,  4,  7, 13, 16, 26, 29, 42,
     3,  8, 12, 17, 25, 30, 41, 43,
     9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63
};

// Inverse zig-zag: maps zig-zag scan position to natural 2D index
// Used for DQT header (JPEG spec requires quant values in zig-zag order)
static const unsigned char zz_inv[64] = {
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63
};

// Standard luminance quantization table (quality 50)
static const unsigned char std_lum_quant[64] = {
    16, 11, 10, 16,  24,  40,  51,  61,
    12, 12, 14, 19,  26,  58,  60,  55,
    14, 13, 16, 24,  40,  57,  69,  56,
    14, 17, 22, 29,  51,  87,  80,  62,
    18, 22, 37, 56,  68, 109, 103,  77,
    24, 35, 55, 64,  81, 104, 113,  92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103,  99
};

// Standard chrominance quantization table (quality 50)
static const unsigned char std_chrom_quant[64] = {
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99
};

// DC luminance Huffman table
static const unsigned char dc_lum_bits[17] = {
    0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0
};
static const unsigned char dc_lum_val[12] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
};

// DC chrominance Huffman table
static const unsigned char dc_chrom_bits[17] = {
    0, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0
};
static const unsigned char dc_chrom_val[12] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
};

// AC luminance Huffman table
static const unsigned char ac_lum_bits[17] = {
    0, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d
};
static const unsigned char ac_lum_val[162] = {
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12,
    0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08,
    0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4,
    0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea,
    0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa
};

// AC chrominance Huffman table
static const unsigned char ac_chrom_bits[17] = {
    0, 0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77
};
static const unsigned char ac_chrom_val[162] = {
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21,
    0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
    0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34,
    0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2,
    0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa
};

// ============================================================
// Encoder state
// ============================================================

typedef struct {
    unsigned short code[256];
    unsigned char  len[256];
} huff_table_t;

typedef struct {
    unsigned char *buf;
    int            buf_len;
    int            pos;
    unsigned int   bitbuf;
    int            bitcount;

    // Quantization tables (scaled by quality)
    unsigned char  lum_quant[64];
    unsigned char  chrom_quant[64];

    // Reciprocal tables for fast division: recip[i] = (1 << 16) / quant[i]
    unsigned short lum_recip[64];
    unsigned short chrom_recip[64];

    // Huffman tables
    huff_table_t   dc_lum_ht;
    huff_table_t   ac_lum_ht;
    huff_table_t   dc_chrom_ht;
    huff_table_t   ac_chrom_ht;
} tje_state_t;

// ============================================================
// Bit output
// ============================================================

static inline void tje_write_byte(tje_state_t *s, unsigned char b)
{
    if (s->pos < s->buf_len) {
        s->buf[s->pos++] = b;
    }
}

static void tje_write_bytes(tje_state_t *s, const unsigned char *data, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        tje_write_byte(s, data[i]);
    }
}

static inline void tje_write_word(tje_state_t *s, unsigned short w)
{
    tje_write_byte(s, (unsigned char)(w >> 8));
    tje_write_byte(s, (unsigned char)(w & 0xFF));
}

static inline void tje_flush_bits(tje_state_t *s)
{
    while (s->bitcount >= 8) {
        unsigned char b = (unsigned char)(s->bitbuf >> (s->bitcount - 8));
        tje_write_byte(s, b);
        if (b == 0xFF) {
            tje_write_byte(s, 0x00); // byte stuffing
        }
        s->bitcount -= 8;
    }
}

static inline void tje_put_bits(tje_state_t *s, unsigned int bits, int nbits)
{
    s->bitbuf = (s->bitbuf << nbits) | (bits & ((1u << nbits) - 1));
    s->bitcount += nbits;
    tje_flush_bits(s);
}

// ============================================================
// Huffman table construction
// ============================================================

static void build_huffman_table(huff_table_t *ht, const unsigned char *bits, const unsigned char *vals)
{
    int i, j, k;
    unsigned short code = 0;

    memset(ht, 0, sizeof(huff_table_t));

    k = 0;
    for (i = 1; i <= 16; i++) {
        for (j = 0; j < bits[i]; j++) {
            if (k < 256) {
                ht->code[vals[k]] = code;
                ht->len[vals[k]] = (unsigned char)i;
                k++;
            }
            code++;
        }
        code <<= 1;
    }
}

// ============================================================
// Quantization table generation
// ============================================================

static void make_quant_table(unsigned char *dst, unsigned short *recip, const unsigned char *src, int quality)
{
    int i;
    int scale;

    if (quality < 1) quality = 1;
    if (quality > 100) quality = 100;

    if (quality < 50) {
        scale = 5000 / quality;
    } else {
        scale = 200 - quality * 2;
    }

    for (i = 0; i < 64; i++) {
        int val = (src[i] * scale + 50) / 100;
        if (val < 1) val = 1;
        if (val > 255) val = 255;
        dst[i] = (unsigned char)val;
        recip[i] = (unsigned short)(65536u / (unsigned)val);
    }
}

// ============================================================
// DCT (integer, AAN algorithm)
// ============================================================

// Fixed-point constants for integer DCT (IJG jfdctint.c compatible)
// CONST_BITS = 13: constants scaled by 2^13
// PASS1_BITS = 2: intermediate precision between row and column passes
#define CONST_BITS  13
#define PASS1_BITS  2

#define FIX_0_298631336  2446
#define FIX_0_390180644  3196
#define FIX_0_541196100  4433
#define FIX_0_765366865  6270
#define FIX_0_899976223  7373
#define FIX_1_175875602  9633
#define FIX_1_501321110  12299
#define FIX_1_847759065  15137
#define FIX_1_961570560  16069
#define FIX_2_053119869  16819
#define FIX_2_562915447  20995
#define FIX_3_072711026  25172

#define DESCALE(x, n)  (((x) + (1 << ((n)-1))) >> (n))

static void fdct_int(int *block)
{
    int tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
    int tmp10, tmp11, tmp12, tmp13;
    int z1, z2, z3, z4, z5;
    int *bp;
    int i;

    // Row pass (output scaled by PASS1_BITS for column pass precision)
    bp = block;
    for (i = 0; i < 8; i++, bp += 8) {
        tmp0 = bp[0] + bp[7];
        tmp7 = bp[0] - bp[7];
        tmp1 = bp[1] + bp[6];
        tmp6 = bp[1] - bp[6];
        tmp2 = bp[2] + bp[5];
        tmp5 = bp[2] - bp[5];
        tmp3 = bp[3] + bp[4];
        tmp4 = bp[3] - bp[4];

        tmp10 = tmp0 + tmp3;
        tmp13 = tmp0 - tmp3;
        tmp11 = tmp1 + tmp2;
        tmp12 = tmp1 - tmp2;

        bp[0] = (tmp10 + tmp11) << PASS1_BITS;
        bp[4] = (tmp10 - tmp11) << PASS1_BITS;

        z1 = (tmp12 + tmp13) * FIX_0_541196100;
        bp[2] = DESCALE(z1 + tmp13 * FIX_0_765366865, CONST_BITS - PASS1_BITS);
        bp[6] = DESCALE(z1 - tmp12 * FIX_1_847759065, CONST_BITS - PASS1_BITS);

        z1 = tmp4 + tmp7;
        z2 = tmp5 + tmp6;
        z3 = tmp4 + tmp6;
        z4 = tmp5 + tmp7;
        z5 = (z3 + z4) * FIX_1_175875602;

        tmp4 = tmp4 * FIX_0_298631336;
        tmp5 = tmp5 * FIX_2_053119869;
        tmp6 = tmp6 * FIX_3_072711026;
        tmp7 = tmp7 * FIX_1_501321110;
        z1 = -z1 * FIX_0_899976223;
        z2 = -z2 * FIX_2_562915447;
        z3 = -z3 * FIX_1_961570560;
        z4 = -z4 * FIX_0_390180644;

        z3 += z5;
        z4 += z5;

        bp[7] = DESCALE(tmp4 + z1 + z3, CONST_BITS - PASS1_BITS);
        bp[5] = DESCALE(tmp5 + z2 + z4, CONST_BITS - PASS1_BITS);
        bp[3] = DESCALE(tmp6 + z2 + z3, CONST_BITS - PASS1_BITS);
        bp[1] = DESCALE(tmp7 + z1 + z4, CONST_BITS - PASS1_BITS);
    }

    // Column pass (final output, properly normalized)
    bp = block;
    for (i = 0; i < 8; i++, bp++) {
        tmp0 = bp[0*8] + bp[7*8];
        tmp7 = bp[0*8] - bp[7*8];
        tmp1 = bp[1*8] + bp[6*8];
        tmp6 = bp[1*8] - bp[6*8];
        tmp2 = bp[2*8] + bp[5*8];
        tmp5 = bp[2*8] - bp[5*8];
        tmp3 = bp[3*8] + bp[4*8];
        tmp4 = bp[3*8] - bp[4*8];

        tmp10 = tmp0 + tmp3;
        tmp13 = tmp0 - tmp3;
        tmp11 = tmp1 + tmp2;
        tmp12 = tmp1 - tmp2;

        bp[0*8] = DESCALE(tmp10 + tmp11, PASS1_BITS + 3);
        bp[4*8] = DESCALE(tmp10 - tmp11, PASS1_BITS + 3);

        z1 = (tmp12 + tmp13) * FIX_0_541196100;
        bp[2*8] = DESCALE(z1 + tmp13 * FIX_0_765366865, CONST_BITS + PASS1_BITS + 3);
        bp[6*8] = DESCALE(z1 - tmp12 * FIX_1_847759065, CONST_BITS + PASS1_BITS + 3);

        z1 = tmp4 + tmp7;
        z2 = tmp5 + tmp6;
        z3 = tmp4 + tmp6;
        z4 = tmp5 + tmp7;
        z5 = (z3 + z4) * FIX_1_175875602;

        tmp4 = tmp4 * FIX_0_298631336;
        tmp5 = tmp5 * FIX_2_053119869;
        tmp6 = tmp6 * FIX_3_072711026;
        tmp7 = tmp7 * FIX_1_501321110;
        z1 = -z1 * FIX_0_899976223;
        z2 = -z2 * FIX_2_562915447;
        z3 = -z3 * FIX_1_961570560;
        z4 = -z4 * FIX_0_390180644;

        z3 += z5;
        z4 += z5;

        bp[7*8] = DESCALE(tmp4 + z1 + z3, CONST_BITS + PASS1_BITS + 3);
        bp[5*8] = DESCALE(tmp5 + z2 + z4, CONST_BITS + PASS1_BITS + 3);
        bp[3*8] = DESCALE(tmp6 + z2 + z3, CONST_BITS + PASS1_BITS + 3);
        bp[1*8] = DESCALE(tmp7 + z1 + z4, CONST_BITS + PASS1_BITS + 3);
    }
}

// ============================================================
// Encode a single 8x8 block
// ============================================================

static void encode_block(tje_state_t *s, int *block, const unsigned char *quant,
                         const unsigned short *recip,
                         huff_table_t *dc_ht, huff_table_t *ac_ht, int *last_dc)
{
    int i;
    int temp, temp2;
    int nbits;
    int zz_block[64];

    // Quantize using reciprocal multiplication instead of division
    for (i = 0; i < 64; i++) {
        int q = quant[i];
        int val = block[i];
        unsigned int r = recip[i];
        // Round to nearest with bias toward zero, then multiply by reciprocal
        if (val >= 0) {
            val = (int)(((unsigned int)(val + (q >> 1)) * r) >> 16);
        } else {
            val = -(int)(((unsigned int)(-val + (q >> 1)) * r) >> 16);
        }
        zz_block[zz_order[i]] = val;
    }

    // DC coefficient
    temp = temp2 = zz_block[0] - *last_dc;
    *last_dc = zz_block[0];

    if (temp < 0) {
        temp = -temp;
        temp2--;
    }
    nbits = bit_length((unsigned int)temp);

    tje_put_bits(s, dc_ht->code[nbits], dc_ht->len[nbits]);
    if (nbits) {
        tje_put_bits(s, (unsigned int)temp2 & ((1u << nbits) - 1), nbits);
    }

    // AC coefficients
    {
        int run = 0;
        for (i = 1; i < 64; i++) {
            temp = zz_block[i];
            if (temp == 0) {
                run++;
                continue;
            }
            while (run >= 16) {
                // ZRL (zero run length 16)
                tje_put_bits(s, ac_ht->code[0xF0], ac_ht->len[0xF0]);
                run -= 16;
            }
            temp2 = temp;
            if (temp < 0) {
                temp = -temp;
                temp2--;
            }
            nbits = bit_length((unsigned int)temp);
            {
                int code_idx = (run << 4) | nbits;
                tje_put_bits(s, ac_ht->code[code_idx], ac_ht->len[code_idx]);
            }
            tje_put_bits(s, (unsigned int)temp2 & ((1u << nbits) - 1), nbits);
            run = 0;
        }
        if (run > 0) {
            // EOB
            tje_put_bits(s, ac_ht->code[0x00], ac_ht->len[0x00]);
        }
    }
}

// ============================================================
// Write JPEG headers
// ============================================================

static void write_jpeg_header(tje_state_t *s, int width, int height)
{
    int i;

    // SOI
    tje_write_word(s, 0xFFD8);

    // APP0 (JFIF)
    tje_write_word(s, 0xFFE0);
    tje_write_word(s, 16);          // length
    tje_write_byte(s, 'J');
    tje_write_byte(s, 'F');
    tje_write_byte(s, 'I');
    tje_write_byte(s, 'F');
    tje_write_byte(s, 0);
    tje_write_byte(s, 1);           // version major
    tje_write_byte(s, 1);           // version minor
    tje_write_byte(s, 0);           // no aspect ratio
    tje_write_word(s, 1);           // x density
    tje_write_word(s, 1);           // y density
    tje_write_byte(s, 0);           // no thumbnail
    tje_write_byte(s, 0);

    // DQT (luminance) - write in zig-zag order per JPEG spec using zz_inv lookup
    tje_write_word(s, 0xFFDB);
    tje_write_word(s, 67);          // length = 2 + 1 + 64
    tje_write_byte(s, 0);           // table 0, 8-bit precision
    for (i = 0; i < 64; i++) {
        tje_write_byte(s, s->lum_quant[zz_inv[i]]);
    }

    // DQT (chrominance)
    tje_write_word(s, 0xFFDB);
    tje_write_word(s, 67);
    tje_write_byte(s, 1);           // table 1
    for (i = 0; i < 64; i++) {
        tje_write_byte(s, s->chrom_quant[zz_inv[i]]);
    }

    // SOF0 (Baseline DCT, YCbCr 4:2:2)
    tje_write_word(s, 0xFFC0);
    tje_write_word(s, 17);          // length = 2 + 1 + 2 + 2 + 1 + 3*3
    tje_write_byte(s, 8);           // precision (8 bits)
    tje_write_word(s, (unsigned short)height);
    tje_write_word(s, (unsigned short)width);
    tje_write_byte(s, 3);           // 3 components (Y, Cb, Cr)
    // Y: id=1, sampling 2x1, quant table 0
    tje_write_byte(s, 1);
    tje_write_byte(s, 0x21);        // H=2, V=1 (4:2:2)
    tje_write_byte(s, 0);
    // Cb: id=2, sampling 1x1, quant table 1
    tje_write_byte(s, 2);
    tje_write_byte(s, 0x11);        // H=1, V=1
    tje_write_byte(s, 1);
    // Cr: id=3, sampling 1x1, quant table 1
    tje_write_byte(s, 3);
    tje_write_byte(s, 0x11);
    tje_write_byte(s, 1);

    // DHT (DC luminance)
    tje_write_word(s, 0xFFC4);
    tje_write_word(s, 19 + 12);     // length
    tje_write_byte(s, 0x00);        // class 0 (DC), table 0
    tje_write_bytes(s, dc_lum_bits + 1, 16);
    tje_write_bytes(s, dc_lum_val, 12);

    // DHT (AC luminance)
    tje_write_word(s, 0xFFC4);
    tje_write_word(s, 19 + 162);
    tje_write_byte(s, 0x10);        // class 1 (AC), table 0
    tje_write_bytes(s, ac_lum_bits + 1, 16);
    tje_write_bytes(s, ac_lum_val, 162);

    // DHT (DC chrominance)
    tje_write_word(s, 0xFFC4);
    tje_write_word(s, 19 + 12);
    tje_write_byte(s, 0x01);        // class 0 (DC), table 1
    tje_write_bytes(s, dc_chrom_bits + 1, 16);
    tje_write_bytes(s, dc_chrom_val, 12);

    // DHT (AC chrominance)
    tje_write_word(s, 0xFFC4);
    tje_write_word(s, 19 + 162);
    tje_write_byte(s, 0x11);        // class 1 (AC), table 1
    tje_write_bytes(s, ac_chrom_bits + 1, 16);
    tje_write_bytes(s, ac_chrom_val, 162);

    // SOS
    tje_write_word(s, 0xFFDA);
    tje_write_word(s, 12);          // length = 2 + 1 + 3*2 + 3
    tje_write_byte(s, 3);           // 3 components
    tje_write_byte(s, 1);           // Y  -> DC table 0, AC table 0
    tje_write_byte(s, 0x00);
    tje_write_byte(s, 2);           // Cb -> DC table 1, AC table 1
    tje_write_byte(s, 0x11);
    tje_write_byte(s, 3);           // Cr -> DC table 1, AC table 1
    tje_write_byte(s, 0x11);
    tje_write_byte(s, 0);           // Ss
    tje_write_byte(s, 63);          // Se
    tje_write_byte(s, 0);           // Ah/Al
}

// ============================================================
// YUV411 (UYVYYY) encoder - native CHDK Digic IV format
// ============================================================

// Y offset within 6-byte UYVYYY group: pixel 0->1, 1->3, 2->4, 3->5
static const unsigned char y_offsets[4] = {1, 3, 4, 5};

// Extract an 8x8 Y block from UYVYYY data
// px, py: block position in pixels
static void extract_y_block_yuv411(int *block, const unsigned char *yuv_data,
                                    int yuv_stride, int px, int py,
                                    int img_width, int img_height)
{
    int r, c;
    for (r = 0; r < 8; r++) {
        int y = py + r;
        if (y >= img_height) y = img_height - 1;
        const unsigned char *row = yuv_data + y * yuv_stride;
        for (c = 0; c < 8; c++) {
            int x = px + c;
            if (x >= img_width) x = img_width - 1;
            // In UYVYYY: each group of 4 pixels = 6 bytes
            // group = x/4, sub-pixel index = x%4
            int group = x >> 2;
            int base = (group << 2) + (group << 1); // group * 6
            block[r * 8 + c] = (int)row[base + y_offsets[x & 3]] - 128;
        }
    }
}

// Extract an 8x8 U or V block from UYVYYY data (subsampled)
// For 4:2:2 encoding, we sample Cb/Cr at half horizontal resolution
// px, py: block position in chroma space (px covers 16 luma pixels)
static void extract_chroma_block_yuv411(int *block, const unsigned char *yuv_data,
                                         int yuv_stride, int px, int py,
                                         int img_width, int img_height,
                                         int is_cr)
{
    int r, c;
    for (r = 0; r < 8; r++) {
        int y = py + r;
        if (y >= img_height) y = img_height - 1;
        const unsigned char *row = yuv_data + y * yuv_stride;
        for (c = 0; c < 8; c++) {
            // Each column in chroma block covers 2 luma pixels
            int x = px + c * 2;
            if (x >= img_width) x = img_width - 2;
            if (x < 0) x = 0;
            int group = x >> 2;
            int base = (group << 2) + (group << 1); // group * 6
            // U (Cb) at offset 0, V (Cr) at offset 2 in each 6-byte group
            // Viewport stores chroma as SIGNED bytes centered at 0,
            // not unsigned centered at 128. Cast to signed char directly.
            if (is_cr) {
                block[r * 8 + c] = (int)(signed char)row[base + 2]; // V/Cr
            } else {
                block[r * 8 + c] = (int)(signed char)row[base + 0]; // U/Cb
            }
        }
    }
}

int tje_encode_yuv411(
    unsigned char *dst_buf,
    int dst_buf_len,
    int width,
    int height,
    const unsigned char *yuv_data,
    int yuv_stride,
    int quality)
{
    tje_state_t state;
    int block[64];
    int dc_y = 0, dc_cb = 0, dc_cr = 0;
    int mcux, mcuy;
    int mcu_w, mcu_h;

    if (!dst_buf || dst_buf_len < 1024 || !yuv_data) return 0;
    if (width < 8 || height < 8) return 0;

    memset(&state, 0, sizeof(state));
    state.buf = dst_buf;
    state.buf_len = dst_buf_len;
    state.pos = 0;
    state.bitbuf = 0;
    state.bitcount = 0;

    // Build quantization tables (natural order for encoding) + reciprocals
    make_quant_table(state.lum_quant, state.lum_recip, std_lum_quant, quality);
    make_quant_table(state.chrom_quant, state.chrom_recip, std_chrom_quant, quality);

    // Build Huffman tables
    build_huffman_table(&state.dc_lum_ht, dc_lum_bits, dc_lum_val);
    build_huffman_table(&state.ac_lum_ht, ac_lum_bits, ac_lum_val);
    build_huffman_table(&state.dc_chrom_ht, dc_chrom_bits, dc_chrom_val);
    build_huffman_table(&state.ac_chrom_ht, ac_chrom_bits, ac_chrom_val);

    // Write JPEG header
    write_jpeg_header(&state, width, height);

    // MCU size: 16x8 for 4:2:2 (2 Y blocks + 1 Cb + 1 Cr)
    mcu_w = (width + 15) / 16;
    mcu_h = (height + 7) / 8;

    for (mcuy = 0; mcuy < mcu_h; mcuy++) {
        for (mcux = 0; mcux < mcu_w; mcux++) {
            int px = mcux * 16;
            int py = mcuy * 8;

            // Y block 0 (left 8 pixels)
            extract_y_block_yuv411(block, yuv_data, yuv_stride, px, py, width, height);
            fdct_int(block);
            encode_block(&state, block, state.lum_quant, state.lum_recip,
                        &state.dc_lum_ht, &state.ac_lum_ht, &dc_y);

            // Y block 1 (right 8 pixels)
            extract_y_block_yuv411(block, yuv_data, yuv_stride, px + 8, py, width, height);
            fdct_int(block);
            encode_block(&state, block, state.lum_quant, state.lum_recip,
                        &state.dc_lum_ht, &state.ac_lum_ht, &dc_y);

            // Cb block (subsampled)
            extract_chroma_block_yuv411(block, yuv_data, yuv_stride, px, py,
                                        width, height, 0);
            fdct_int(block);
            encode_block(&state, block, state.chrom_quant, state.chrom_recip,
                        &state.dc_chrom_ht, &state.ac_chrom_ht, &dc_cb);

            // Cr block (subsampled)
            extract_chroma_block_yuv411(block, yuv_data, yuv_stride, px, py,
                                        width, height, 1);
            fdct_int(block);
            encode_block(&state, block, state.chrom_quant, state.chrom_recip,
                        &state.dc_chrom_ht, &state.ac_chrom_ht, &dc_cr);
        }
    }

    // Pad remaining bits with 1s
    if (state.bitcount > 0) {
        tje_put_bits(&state, (1u << (8 - state.bitcount)) - 1, 8 - state.bitcount);
    }

    // EOI
    tje_write_word(&state, 0xFFD9);

    return state.pos;
}

