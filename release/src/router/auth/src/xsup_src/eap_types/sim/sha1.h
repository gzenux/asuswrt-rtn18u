/* sha1.h */

/* If OpenSSL is in use, then use that version of SHA-1 */
#ifdef OPENSSL
#include <t_sha.h>
#define __SHA1_INCLUDE_
#endif

#ifndef __SHA1_INCLUDE_

#ifndef SHA1_SIGNATURE_SIZE
#ifdef SHA_DIGESTSIZE
#define SHA1_SIGNATURE_SIZE SHA_DIGESTSIZE
#else
#define SHA1_SIGNATURE_SIZE 20
#endif
#endif


#define SHA1Transform		SHA1_Transform

extern void nossl_SHA1_Transform(unsigned long state[5], 
				 const unsigned char buffer[64]);

#define __SHA1_INCLUDE_
#endif /* __SHA1_INCLUDE_ */

