#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <shared.h>
#include <shutils.h>
#include <stdint.h>
#include <ctype.h>
#include <bcmnvram.h>

extern struct nvram_tuple router_defaults[];
extern struct nvram_tuple router_state_defaults[];

/* MD5 context. */
typedef struct {
    unsigned int state[4];		/* state (ABCD) */
    unsigned int count[2];		/* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];	/* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
void MD5Final(unsigned char[16], MD5_CTX *);

#define MD5_DIGEST_CHARS         16

/*
 * Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform(unsigned int[4], unsigned char[64]);
static void Encode(unsigned char *, unsigned int*, unsigned int);
static void Decode(unsigned int*, unsigned char *, unsigned int);
static void MD5_memcpy(unsigned char *, unsigned char *, unsigned int);
static void MD5_memset(char *, int, unsigned int);

static unsigned char PADDING[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4. Rotation is
 * separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);   }
#define GG(a, b, c, d, x, s, ac) {  (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);   }
#define HH(a, b, c, d, x, s, ac) {  (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);   }
#define II(a, b, c, d, x, s, ac) {  (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);   }

/*
 * MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void
MD5Init(MD5_CTX * context)
{
    context->count[0] = context->count[1] = 0;
    /*
     * Load magic initialization constants.
     */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/*
 * MD5 block update operation. Continues an MD5 message-digest operation,
 * processing another message block, and updating the context.
 */
void
MD5Update(MD5_CTX * context, unsigned char *input, unsigned int inputLen)
{
    unsigned int i, index, partLen;

    /* Compute number of bytes mod 64 */
    index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if ((context->count[0] += ((unsigned int) inputLen << 3))
	< ((unsigned int) inputLen << 3))
	context->count[1]++;
    context->count[1] += ((unsigned int) inputLen >> 29);

    partLen = 64 - index;

    /*
     * Transform as many times as possible.
     */
    if (inputLen >= partLen) {
	MD5_memcpy(&context->buffer[index], input, partLen);
	MD5Transform(context->state, context->buffer);

	for (i = partLen; i + 63 < inputLen; i += 64)
	    MD5Transform(context->state, &input[i]);

	index = 0;
    } else
	i = 0;

    /* Buffer remaining input */
    MD5_memcpy(&context->buffer[index], &input[i], inputLen - i);
}

/*
 * MD5 finalization. Ends an MD5 message-digest operation, writing the the
 * message digest and zeroizing the context.
 */
void
MD5Final(unsigned char digest[16], MD5_CTX * context)
{
    unsigned char bits[8];
    unsigned int index, padLen;

    /* Save number of bits */
    Encode(bits, context->count, 8);

    /*
     * Pad out to 56 mod 64.
     */
    index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);

    /* Append length (before padding) */
    MD5Update(context, bits, 8);
    /* Store state in digest */
    Encode(digest, context->state, 16);

    /*
     * Zeroize sensitive information.
     */
    MD5_memset((char *) context, 0, sizeof(*context));
}

/*
 * MD5 basic transformation. Transforms state based on block.
 */
static void
MD5Transform(unsigned int state[4], unsigned char block[64])
{
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    Decode(x, block, 64);

    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478);	/* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);	/* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db);	/* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);	/* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);	/* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a);	/* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613);	/* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501);	/* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8);	/* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);	/* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);	/* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be);	/* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122);	/* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193);	/* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e);	/* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821);	/* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);	/* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6);	/* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);	/* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c);	/* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);	/* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);	/* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05);	/* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);	/* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);	/* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7);	/* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);	/* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /*
     * Zeroize sensitive information.
     */
    MD5_memset((char *) x, 0, sizeof(x));
}

/*
 * Encodes input (unsigned int) into output (unsigned char). Assumes len is a
 * multiple of 4.
 */
static void
Encode(unsigned char *output, unsigned int * input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
	output[j] = (unsigned char) (input[i] & 0xff);
	output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);
	output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);
	output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);
    }
}

/*
 * Decodes input (unsigned char) into output (unsigned int). Assumes len is a
 * multiple of 4.
 */
static void
Decode(unsigned int * output, unsigned char *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
	output[i] = ((unsigned int) input[j]) | (((unsigned int) input[j + 1]) << 8) |
	    (((unsigned int) input[j + 2]) << 16) | (((unsigned int) input[j + 3]) << 24);
}

/*
 * Note: Replace "for loop" with standard memcpy if possible.
 */

static void
MD5_memcpy(unsigned char *output, unsigned char *input, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
	output[i] = input[i];
}

/*
 * Note: Replace "for loop" with standard memset if possible.
 */
static void
MD5_memset(char *output, int value, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
	output[i] = (char) value;
}

char *str2md5(const char *string, int length, char *out) {
	int n;
	 MD5_CTX context;
	unsigned char digest[16];

	MD5Init(&context);
	MD5Update(&context, (unsigned char *)string, length);
	MD5Final(digest, &context);

	for (n = 0; n < 16; ++n) {
		snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
	}

	return out;
}


#define ECB 1
#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#define CRC_LEN 8

struct AES_ctx
{
  unsigned char RoundKey[AES_keyExpSize];
};

void AES_ECB_encrypt_buffer(struct AES_ctx *ctx,unsigned char* buf, int length);
void AES_ECB_decrypt_buffer(struct AES_ctx *ctx,unsigned char* buf, int length);

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
#define CEILING_POS(X) ((X-(int)(X)) > 0 ? (int)(X+1) : (int)(X))
#define CEILING_NEG(X) ((X-(int)(X)) < 0 ? (int)(X-1) : (int)(X))
#define CEILING(X) ( ((X) > 0) ? CEILING_POS(X) : CEILING_NEG(X) )

void AES_init_ctx(struct AES_ctx* ctx, const unsigned char* key);
void AES_ECB_encrypt(struct AES_ctx* ctx, const unsigned char* buf);
void AES_ECB_decrypt(struct AES_ctx* ctx, const unsigned char* buf);

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 8
// The number of rounds in AES Cipher.
#define Nr 14

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef unsigned char state_t[4][4];

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const unsigned char sbox[256] =   {
	/* 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F */
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
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const unsigned char rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const unsigned char Rcon[11] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(unsigned char* RoundKey, const unsigned char* Key)
{
	unsigned i, j, k;
	unsigned char tempa[4]; // Used for the column/row operations

	// The first round key is the key itself.
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	// All other round keys are found from the previous round keys.
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
		k = (i - 1) * 4;
		tempa[0]=RoundKey[k + 0];
		tempa[1]=RoundKey[k + 1];
		tempa[2]=RoundKey[k + 2];
		tempa[3]=RoundKey[k + 3];

		}

		if (i % Nk == 0)
		{
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				k = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = k;
			}

			// SubWord() is a function that takes a four-byte input word and
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i/Nk];
		}

		if (i % Nk == 4)
		{
			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
		}

		j = i * 4; k=(i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void AES_init_ctx(struct AES_ctx* ctx, const unsigned char* key)
{
	KeyExpansion(ctx->RoundKey, key);
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(unsigned char round,state_t* state,unsigned char* RoundKey)
{
	unsigned char i,j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
	unsigned char temp;

	// Rotate first row 1 columns to left
	temp           = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// Rotate second row 2 columns to left
	temp           = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp           = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to left
	temp           = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static unsigned char xtime(unsigned char x)
{
	return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
	unsigned char i;
	unsigned char Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{
		t   = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
		Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
	}
}

// Multiply is used to multiply numbers in the field GF(2^8)
#define Multiply(x, y)                                \
(  ((y & 1) * x) ^                              \
((y>>1 & 1) * xtime(x)) ^                       \
((y>>2 & 1) * xtime(xtime(x))) ^                \
((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}

static void InvShiftRows(state_t* state)
{
	unsigned char temp;

	// Rotate first row 1 columns to right
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	// Rotate second row 2 columns to right
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to right
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, unsigned char* RoundKey)
{
	unsigned char round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round = 1; round < Nr; ++round)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(Nr, state, RoundKey);
}

static void InvCipher(state_t* state,unsigned char* RoundKey)
{
	unsigned char round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round = (Nr - 1); round > 0; --round)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		InvMixColumns(state);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(0, state, RoundKey);
}


/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
void AES_ECB_encrypt(struct AES_ctx *ctx,const unsigned char* buf)
{
// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(struct AES_ctx* ctx,const unsigned char* buf)
{
// The next function call decrypts the PlainText with the Key using AES algorithm.
	InvCipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_encrypt_buffer(struct AES_ctx *ctx,unsigned char* buf, int length)
{
	while(length>AES_BLOCKLEN)
	{
		AES_ECB_encrypt(ctx, buf);
		buf += AES_BLOCKLEN;
		length -= AES_BLOCKLEN;
	}

	if(length > 0)
	{
		memset(buf + length, 0, AES_BLOCKLEN - length);
		AES_ECB_encrypt(ctx, buf);
	}
}

void AES_ECB_decrypt_buffer(struct AES_ctx *ctx,unsigned char* buf, int length)
{
	while(length>AES_BLOCKLEN)
	{
		AES_ECB_decrypt(ctx, buf);
		buf += AES_BLOCKLEN;
		length -= AES_BLOCKLEN;
	}

	if(length > 0)
	{
		memset(buf + length, 0, AES_BLOCKLEN - length); /* add 0-padding */
		AES_ECB_decrypt(ctx, buf);
	}
}

int pw_enc_len(const char *input)
{
	int inputLen_count, ret_len;
	float len;
	len = strlen(input)+CRC_LEN;
	inputLen_count = CEILING(len/AES_BLOCKLEN);
	ret_len = inputLen_count*AES_BLOCKLEN;

	return ret_len;
}

int pw_enc_blen(const char *input)
{
	int len, ret_len;
	len = pw_enc_len(input);
	ret_len = base64_encoded_len(len);
	return ret_len;
}

int pw_dec_len(const char *input)
{
	int len, ret_len;
	len = strlen(input);
	ret_len = base64_decoded_len(len);
	return ret_len;
}
static int get_nvram_key(char *key){
	int mac[6] = {0};
	char org_key[128] = {0};
	char *model_name = nvram_get("odmpid"); /* try to get the ODM model id first */
	char *macaddr = get_lan_hwaddr(); /* nvram_safe_get("lan_hwaddr"); */

#if 0 /* zero initialization on declaration */
	memset(org_key, 0, sizeof(org_key));
#endif

	if(!model_name)
		model_name = nvram_safe_get("productid");

	if(strlen(macaddr))
		sscanf(macaddr, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	sprintf(org_key, "%x%x%x%x%x%s%x", mac[3]+mac[0], mac[1]+mac[1], mac[5]+mac[4], mac[2]+mac[5], mac[4]*mac[2], model_name, mac[0]*mac[3]);

	str2md5(org_key, strlen(org_key), key);
	return 0;
}


int pw_enc(const char *input, char *output)
{
	if(!strlen(input)){
		strcpy(output, "");
		return 0;
	}

	struct AES_ctx ctx;
	int n = 0;
	int inputLen, encodedLen, aesencLen;
	char key[33] = {0};
	char crc_str[CRC_LEN] = {0};
	unsigned int crc_key = 0;

	aesencLen = pw_enc_len(input);
	inputLen = strlen(input);
	unsigned char plain_text[aesencLen+1];

	memset(plain_text, 0, sizeof(plain_text));
#if 0 /* zero initialization on declaration */
	memset(crc_str, 0, sizeof(crc_str));
	memset(key, 0, sizeof(key));
#endif

	crc_key = crc_calc(0, input, inputLen);
	sprintf(crc_str, "%.8x", crc_key);

	encodedLen = pw_enc_blen(input);
	char encoded[encodedLen+16];
	memset(encoded, 0, sizeof(encoded));
	memcpy(plain_text, crc_str, CRC_LEN);
	memcpy(plain_text+CRC_LEN, input, inputLen);

	get_nvram_key(key);
	AES_init_ctx(&ctx, (unsigned char *)key);
	AES_ECB_encrypt_buffer(&ctx, plain_text, inputLen+CRC_LEN);

	n = base64_encode(plain_text, encoded, aesencLen);

	strlcpy(output, encoded, n+1);
	return 0;
}

int pw_dec(const char *input, char *output, int len)
{
	if(!strlen(input)){
		strcpy(output, "");
		return 0;
	}

	struct AES_ctx ctx;
	int i, n, ret;
	int crc_isalnum = 0;
	int inputLen = strlen(input);
	char key[33] = {0};
	char crc_str[CRC_LEN+1] = {0};
	char crc_dec_str[CRC_LEN+1] = {0};
	char crc_todec_str[inputLen];
	unsigned int crc_key = 0;
	unsigned char decoded[inputLen];

	memset(decoded, 0, sizeof(decoded));
	memset(crc_todec_str, 0, sizeof(crc_todec_str));
#if 0 /* zero initialization on declaration */
	memset(key, 0, sizeof(key));
	memset(crc_str, 0, sizeof(crc_str));
	memset(crc_dec_str, 0, sizeof(crc_dec_str));
#endif

	get_nvram_key(key);
	AES_init_ctx(&ctx, (unsigned char *)key);
	n = base64_decode(input, decoded, inputLen);

	decoded[n] = '\0';
	unsigned char output_buf[len];
	memset(output_buf, 0, sizeof(output_buf));

	memcpy(output_buf, decoded, n);
	AES_ECB_decrypt_buffer(&ctx, output_buf, n);

	memcpy(crc_str, output_buf, CRC_LEN);
	for (i=0;i<CRC_LEN;i++){
		if (isalnum(crc_str[i]) == 0){
			crc_isalnum = 0;
			break;
		}else{
			crc_isalnum = 1;
		}
	}
	if(crc_isalnum){
		if(strlen((char *)output_buf) > CRC_LEN){
			memcpy(crc_todec_str, output_buf+CRC_LEN, strlen((char *)output_buf)-CRC_LEN);
			crc_key = crc_calc(0, crc_todec_str, strlen((char *)output_buf)-CRC_LEN);
			sprintf(crc_dec_str, "%.8x", crc_key);
		}
	}

	if(crc_str != NULL && crc_dec_str != NULL && !strcmp(crc_str, crc_dec_str)){
		strlcpy(output, (char *)output_buf+CRC_LEN, n+1-CRC_LEN);
		ret = 1;
	}
	else{
		strlcpy(output, input, len);
		ret = 0;
	}
	return ret;
}

int enc_nvram(char *name, char *input, char *output){

	int ret = 0;
	char *nv, *nvp, *b;
	char *username, *passwd;
	char enc_passwd[NVRAM_ENC_LEN];
	char buf[NVRAM_ENC_MAXLEN] = {0}, tmp_buf[NVRAM_ENC_MAXLEN] = {0};

#if 0 /* zero initialization on declaration */
	memset(buf, 0, sizeof(buf));
	memset(tmp_buf, 0, sizeof(tmp_buf));
#endif

	if(strlen(input)){
		if(strcmp(name, "pptpd_clientlist") == 0 || strcmp(name, "vpn_serverx_clientlist") == 0 || strcmp(name, "acc_list") == 0){
			nv = nvp = strdup(input);
			if (nv) {
				while ((b = strsep(&nvp, "<")) != NULL) {
					if ((vstrsep(b, ">", &username, &passwd) != 2))
						continue;
					memset(enc_passwd, 0, sizeof(enc_passwd));
					pw_enc(passwd, enc_passwd);
					sprintf(tmp_buf, "<%s>%s%s", username, enc_passwd, buf);
					strlcpy(buf, tmp_buf, sizeof(buf));
				}
				strlcpy(output, buf, sizeof(buf));
				free(nv);
			}
		}else{
			pw_enc(input, output);
		}
		ret = 1;
	}else{
		strcpy(output, "");
	}
	return ret;
}

int is_same_pass(char *name, char *username, char *passwd){

	int retStatus = 0;
	char *nv, *nvp, *b;
	char *username_org, *passwd_org;

	char *value = nvram_safe_get(name);

	nv = nvp = strdup(value);
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &username_org, &passwd_org) != 2))
				continue;

			if(!strcmp(username, username_org) && !strcmp(passwd, passwd_org)){
				retStatus = 1;
				break;
			}
		}
		free(nv);
	}
	return retStatus;
}

int set_enc_nvram(char *name, char *input, char *output){

	int ret = 0;
	char *nv, *nvp, *b;
	char *username, *passwd;
	char enc_passwd[NVRAM_ENC_MAXLEN];
	char buf[NVRAM_ENC_MAXLEN] = {0}, tmp_buf[NVRAM_ENC_MAXLEN] = {0};

#if 0 /* zero initialization on declaration */
	memset(buf, 0, sizeof(buf));
	memset(tmp_buf, 0, sizeof(tmp_buf));
#endif

	if(strlen(input)){
		if(strcmp(name, "pptpd_clientlist") == 0 || strcmp(name, "vpn_serverx_clientlist") == 0 || strcmp(name, "acc_list") == 0){
			nv = nvp = strdup(input);
			if (nv) {
				while ((b = strsep(&nvp, "<")) != NULL) {
					if ((vstrsep(b, ">", &username, &passwd) != 2))
						continue;
					if(!is_same_pass(name, username, passwd)){
						memset(enc_passwd, 0, sizeof(enc_passwd));
						pw_enc(passwd, enc_passwd);
						passwd = enc_passwd;
					}
					sprintf(tmp_buf, "<%s>%s%s", username, passwd, buf);
					strlcpy(buf, tmp_buf, sizeof(buf));
				}
				strlcpy(output, buf, sizeof(buf));
				free(nv);
			}
		}else{
			pw_enc(input, output);
		}
		ret = 1;
	}else{
		strcpy(output, "");
	}
	return ret;
}

int dec_nvram(char *name, char *input, char *output)
{
	int ret = 0;
	char passwdbuf[NVRAM_ENC_LEN] = {0};
	char buf[NVRAM_ENC_MAXLEN] = {0}, tmp_buf[NVRAM_ENC_MAXLEN] = {0};

#if 0 /* zero initialization on declaration */
	memset(buf, 0, sizeof(buf));
	memset(tmp_buf, 0, sizeof(tmp_buf));
	memset(passwdbuf, 0, sizeof(passwdbuf));
#endif

	if(strcmp(name, "pptpd_clientlist") == 0 || strcmp(name, "acc_list") == 0 || strcmp(name, "vpn_serverx_clientlist") == 0){
		char *nv, *nvp, *b;
		char *username, *passwd;

		nv = nvp = strdup(input);
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &username, &passwd) != 2))
					continue;
				memset(passwdbuf, 0, sizeof(passwdbuf));

				ret = pw_dec(passwd, passwdbuf, sizeof(passwdbuf));
				sprintf(tmp_buf, "<%s>%s%s", username, passwdbuf, buf);

				strlcpy(buf, tmp_buf, sizeof(buf));
			}
			strlcpy(output, buf, sizeof(buf));
			free(nv);
		}
	}else{
		ret = pw_dec(input, passwdbuf, sizeof(passwdbuf));
		strlcpy(output, passwdbuf, sizeof(passwdbuf));
	}

	return ret;
}

int init_enc_nvram(void)
{
	int ret = 0, len = 0;
	char *value = NULL;
	struct nvram_tuple *t;
	char output[NVRAM_ENC_MAXLEN];
	char *nvram_encrypt = nvram_default_get("nvram_encrypt");

	for (t = router_defaults; t->name; t++)
	{
		value = nvram_safe_get(t->name);
		len = strlen(value);

		if(!len) continue;
		//memset(output, 0, sizeof(output));
		if(t->enc == 1){
			if(dec_nvram(t->name, value, output)){
				continue;
			}
			else{
				enc_nvram(t->name, value, output);
			}
			nvram_set(t->name, output);
		}
#if 0 /* do not decode nvram if the enc field is not marked */
		else{
			if(len > 23 && len < NVRAM_ENC_MAXLEN && dec_nvram(t->name, value, output)){
				nvram_set(t->name, output);
			}
		}
#endif
	}

	if(nvram_encrypt != NULL)
		nvram_set("nvram_encrypt", nvram_encrypt);

	nvram_commit();
	return ret;
}

int start_enc_nvram(void)
{
	int ret = 0;
	char *value = NULL;
	struct nvram_tuple *t;
	char output[NVRAM_ENC_MAXLEN];

	for (t = router_defaults; t->name; t++)
	{
		if(t->enc == 1){
			value = nvram_safe_get(t->name);
			ret = enc_nvram(t->name, value, output);

			nvram_set(t->name, output);
		}
	}
	nvram_set("nvram_encrypt", "1");

	nvram_commit();
	return 0;
}

int start_dec_nvram(void)
{
	int ret = 0;
	char *value = NULL;
	struct nvram_tuple *t;
	char output[NVRAM_ENC_MAXLEN] = {0};

#if 0 /* zero initialization on declaration */
	memset(output, 0, sizeof(output));
#endif

	for (t = router_defaults; t->name; t++)
	{
		if(t->enc == 1){
			value = nvram_safe_get(t->name);
			ret = dec_nvram(t->name, value, output);

			nvram_set(t->name, output);
		}
	}
	nvram_set("nvram_encrypt", "0");

	nvram_commit();
	return 0;
}
