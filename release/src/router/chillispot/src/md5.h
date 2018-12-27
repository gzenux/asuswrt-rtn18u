#ifndef MD5_H
#define MD5_H

#ifdef __alpha
typedef unsigned int uint32_c;
#else
typedef unsigned long uint32_c;
#endif

struct MD5Context {
        uint32_c buf[4];
        uint32_c bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32_c buf[4], uint32_c const in[16]);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

/*base64 function*/
char *oauth_encode_base64(int size, const unsigned char *src);

#endif /* !MD5_H */
