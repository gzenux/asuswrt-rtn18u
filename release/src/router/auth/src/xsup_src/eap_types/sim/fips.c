/* 
 *  FIPS 186-2 Pseudo-Random Number Generator
 *  Copyright (C) 2003 Mondru AB.
 *
 *  Available under GPL or BSD license as described below.
 * 
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 *  As an alternative to the GNU General Public License Version 2 the
 *  content may also be used under the license conditions described
 *  below:
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 
 *  3. The name(s) of the authors of this software must not be used to
 *     endorse or promote products derived from this software without
 *     prior written permission. 

 *  THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 *  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 *  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 *  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 *  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * 
 *  The initial developer of the original code is
 *  Jens Jakobsen <jj@openggsn.org>
 * 
 *  Contributor(s):
 * 
 */

#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include "sha1.h"
#include "fips.h"

/* Pseudo random number generator                                        
 * FIPS 186-2 Appendix 3.1 with change notes: Random Number Generation: 1
 * Uses the SHA1 transform function as G().
 *
 * Based on the initial value XKEY a set of pseudo-random numbers are 
 * generated. The generated numbers are placed in x, which must be allocated
 * prior to calling fips186_2_prng(). On error x is reset to all zero;
 *
 * Currently the implementation has the following restrictions:
 *   XKEY must be 20 bytes long (160 bit).
 *   XSEEDj is not supported.
 *   x must be multiple of 40 bytes (320 bit).
 */
   
void fips186_2_prng(unsigned char *XKEY, int XKEYlen, 
		    unsigned char *XSEEDj, int XSEEDjlen,
		    unsigned char *x, int xlen) {

  int i, j, m;
  unsigned int addresult, carry;

  unsigned long state[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
			    0xc3d2e1f0};
  unsigned long t[5];

  unsigned char xval[64];
  unsigned char w[20];
  
  int n;
  
  /* XSEEDj is not (yet) supported */
  if (XSEEDjlen != 0) {
    memset(x, 0, xlen);
    return;
  }
  
  /* XKEYlen must be 20 */
  if (XKEYlen != 20) {
    memset(x, 0, xlen);
    return;
  }
  
  /* xlen must be multiple of 40 */
  if (xlen % 40) { 
    memset(x, 0, xlen);
    return;
  }
  m = xlen / 40;  /* Number of iterations */
  
  /* Step 3 */
  for (j=0; j<=(m-1); j++)
    {
      /* Step 3.2 */
      for (i=0; i<=1; i++) {

      /* a. XVAL = (XKEY + XSEED_j) mod 2^b */
      for (n=0;n<20;n++)  xval[n] = XKEY[n]; /* FIPS 186-2 Appendix 3.3 */
      for (n=20;n<64;n++) xval[n] = 0;

#ifdef FIPSTEST
      printf("xval: "); 
      for (n=0; n<20; n++) printf("%.2hhx", xval[n]);
      printf("\n");
#endif

      /* b. w_i = G(t, XVAL) */
      memcpy(t, state, 20);
      nossl_SHA1_Transform(t, xval);
      t[0] = htonl(t[0]);
      t[1] = htonl(t[1]);
      t[2] = htonl(t[2]);
      t[3] = htonl(t[3]);
      t[4] = htonl(t[4]);
      memcpy(w, t, 20);

#ifdef FIPSTEST
      printf("w%d:   ", i);
      for (n=0; n<20; n++)
	printf("%.2hhx", w[n]); printf("\n");
#endif

      /* c. XKEY = (1 + XKEY + w_i) mod 2^b */
      carry = 0; 
      for (n=19;n>=0;n--) {
	if (n==19) addresult = 1; else addresult = 0;
	addresult += XKEY[n] + w[n] + carry;
	XKEY[n] = (addresult & 0x00ff);
	carry = ((addresult & 0xff00) >> 8);
      }

#ifdef FIPSTEST
      printf("XKEY: "); 
      for (n=0; n<20; n++) 
	printf("%.2hhx", XKEY[n]); 
      printf("\n");
#endif
      
      /* Step 3.3 xj = (w0 | w1) mod q */
      memcpy(&x[j*40+i*20], w, XKEYlen);
      }
    }

#ifdef FIPSTEST  
  printf("x: \n");
  for (n=0; n<xlen; n++) {
    printf("%.2hhx", x[n]);
    if ((n+1)%20 == 0) printf("\n");
  }
  printf("\n");
#endif

  return;
}


#ifdef FIPSTEST
/*
 *  cc -DFIPSTEST -I . fips.c sha1.c -o fips
 *  ./fips
 */

int main(int argc, char **argv)
{
  int n;
  unsigned char x[40];

  /* Test vector from Multiple Examples of DSA section 2:
     http://csrc.nist.gov/encryption/dss/Examples-1024bit.pdf
     2.2 Computing a public and private key pair.
   */
     
  unsigned char XKEY[] = {0xbd, 0x02, 0x9b, 0xbe,
			  0x7f, 0x51, 0x96, 0x0b,
			  0xcf, 0x9e, 0xdb, 0x2b,
			  0x61, 0xf0, 0x6f, 0x0f,
			  0xeb, 0x5a, 0x38, 0xb6};

  fips186_2_prng(XKEY, sizeof(XKEY), NULL, 0, x, sizeof(x));

  printf("x: \n");
  for (n=0; n<sizeof(x); n++) {
    printf("%.2hhx", x[n]);
    if ((n+1)%20 == 0) printf("\n");
  }
  printf("\n");

}

#endif


