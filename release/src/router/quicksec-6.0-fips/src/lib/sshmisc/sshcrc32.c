/* The implementation here was originally done by Gary S. Brown.  I have
   borrowed the tables directly, and made some minor changes to the
   crc32-function (including changing the interface). //ylo */

#include "sshincludes.h"
#include "sshcrc32.h"

  /* ============================================================= */
  /*  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or       */
  /*  code or tables extracted from it, as desired without restriction.     */
  /*                                                                        */
  /*  First, the polynomial itself and its table of feedback terms.  The    */
  /*  polynomial is                                                         */
  /*  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0   */
  /*                                                                        */
  /*  Note that we take it "backwards" and put the highest-order term in    */
  /*  the lowest-order bit.  The X^32 term is "implied"; the LSB is the     */
  /*  X^31 term, etc.  The X^0 term (usually shown as "+1") results in      */
  /*  the MSB being 1.                                                      */
  /*                                                                        */
  /*  Note that the usual hardware shift register implementation, which     */
  /*  is what we're using (we're merely optimizing it by doing eight-bit    */
  /*  chunks at a time) shifts bits into the lowest-order term.  In our     */
  /*  implementation, that means shifting towards the right.  Why do we     */
  /*  do it this way?  Because the calculated CRC must be transmitted in    */
  /*  order from highest-order term to lowest-order term.  UARTs transmit   */
  /*  characters in order from LSB to MSB.  By storing the CRC this way,    */
  /*  we hand it to the UART in the order low-byte to high-byte; the UART   */
  /*  sends each low-bit to hight-bit; and the result is transmission bit   */
  /*  by bit from highest- to lowest-order term without requiring any bit   */
  /*  shuffling on our part.  Reception works similarly.                    */
  /*                                                                        */
  /*  The feedback terms table consists of 256, 32-bit entries.  Notes:     */
  /*                                                                        */
  /*      The table can be generated at runtime if desired; code to do so   */
  /*      is shown later.  It might not be obvious, but the feedback        */
  /*      terms simply represent the results of eight shift/xor opera-      */
  /*      tions for all combinations of data and CRC register values.       */
  /*                                                                        */
  /*      The values must be right-shifted by eight bits by the "updcrc"    */
  /*      logic; the shift must be unsigned (bring in zeroes).  On some     */
  /*      hardware you could probably optimize the shift in assembler by    */
  /*      using byte-swap instructions.                                     */
  /*      polynomial $edb88320                                              */
  /*                                                                        */
  /*  --------------------------------------------------------------------  */

static const SshUInt32 SSH_CODE_SEGMENT crc32_tab[] = {
      0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
      0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
      0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
      0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
      0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
      0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
      0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
      0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
      0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
      0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
      0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
      0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
      0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
      0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
      0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
      0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
      0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
      0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
      0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
      0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
      0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
      0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
      0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
      0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
      0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
      0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
      0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
      0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
      0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
      0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
      0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
      0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
      0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
      0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
      0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
      0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
      0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
      0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
      0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
      0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
      0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
      0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
      0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
      0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
      0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
      0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
      0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
      0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
      0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
      0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
      0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
      0x2d02ef8dL
   };

/* Return a 32-bit CRC of the contents of the buffer. */

SshUInt32 crc32_buffer(const unsigned char *s, size_t len)
{
  size_t i;
  SshUInt32 crc32val;

  crc32val = 0;
  for (i = 0;  i < len;  i ++)
    {
      crc32val =
        crc32_tab[(crc32val ^ s[i]) & 0xff] ^
          (crc32val >> 8);
    }
  return crc32val;
}

/* Return a 32-bit 'modified' CRC of the contents of the buffer. */

SshUInt32 crc32_buffer_altered(const unsigned char *s, size_t len)
{
  size_t i;
  SshUInt32 crc32val;

  crc32val = len;
  for (i = 0;  i < len;  i ++)
    {
      crc32val =
        crc32_tab[(crc32val ^ s[i]) & 0xff] ^
          (crc32val >> 8);
    }
  return crc32val;
}

/* Generates feedback terms table for crc32. Useful if table must be
   recreated later. */

void crc32_create_table(SshUInt32 *table)
{
  unsigned int i, j;
  SshUInt32 crc;

  for (i = 0; i < 256; i++)
    {
      crc = i;

      for (j = 0; j < 8; j++)
        crc = (crc >> 1) ^ ((crc & 0x1) ? 0xedb88320L : 0);

      table[i] = crc;
    }
}

/* Following routines given are written by Mika Kojo for
   Applied Computing Research, Finland. All code below is

  @copyright
  Copyright (c) 2002 - 2014, INSIDE Secure Oy.  All rights reserved.

   */

/* Our GF(2^n) modulus. */
#define MOD_32BIT 0xedb88320L
#define MASK      0xffffffffL

/* Polynomial arithmetics over GF(2^n).

   That is we are working under the given polynomial, and give
   routines to add, reduce and multiply within GF(2^n) etc. Code here
   is not exactly the fastest around, however, its polynomial time :)
   */

/* We'll give a bit abstraction here with simple polynomial of maximum
   size 32 bits (with some bits for extension due multiplication). */

typedef SshUInt32 GFPoly[2];

/* This is useful to know, however, we have inlined this always. */
void gf_add(GFPoly a, GFPoly b)
{
  a[0] ^= b[0];
  a[1] ^= b[1];
}

void gf_set(GFPoly a, GFPoly b)
{
  a[0] = b[0];
  a[1] = b[1];
}

void gf_set_ui(GFPoly a, SshUInt32 i)
{
  a[0] = i & MASK;
  a[1] = 0;
}

/* General division routine for polynomials. This is rather clumsy so
   for modular reduction use the gf_red instead. */
void gf_div(GFPoly q, GFPoly r, GFPoly a, GFPoly b)
{
  GFPoly t, h;
  unsigned int k, i;
  if (b[0] == 0 && b[1] == 0)
    ssh_fatal("gf_div: division by zero.");

  gf_set(t, a);
  gf_set(h, b);

  if (h[1])
    {
      for (k = 0; k < 32; k++)
        {
          if (h[1] & 0x1)
            break;
          h[1] = (((h[1] & MASK) >> 1) | (h[0] << 31)) & MASK;
          h[0] = (h[0] & MASK) >> 1;
        }
    }
  else
    {
      for (k = 0; k < 32; k++)
        {
          if (h[0] & 0x1)
            break;
          h[0] = (h[0] & MASK) >> 1;
        }
      h[1] = h[0];
      h[0] = 0;
      k += 32;
    }

  /* Shift the highest bit out. It is more implied than needed. */
  h[1] = (((h[1] & MASK) >> 1) | (h[0] << 31)) & MASK;
  h[0] = (h[0] & MASK) >>  1;
  k++;

  gf_set_ui(q, 0);

  for (i = 0; i < k; i++)
    {
      if (t[1] & 0x1)
        {
          t[1] = ((((t[1] & MASK) >> 1) | (t[0] << 31)) ^ h[1]) & MASK;
          t[0] = (((t[0] & MASK) >> 1) ^ h[0]);

          q[1] = (((q[1] & MASK) >> 1) | (q[0] << 31)) & MASK;
          q[0] = ((q[0] & MASK) >> 1) | ((SshUInt32)1 << 31);
        }
      else
        {
          t[1] = (((t[1] & MASK) >> 1) | (t[0] << 31)) & MASK;
          t[0] = (t[0] & MASK) >> 1;

          q[1] = (((q[1] & MASK) >> 1) | (q[0] << 31)) & MASK;
          q[0] = (q[0] & MASK) >> 1;
        }
    }

  /* Set the remainder, which is not as easy as it seems. */
  if (k >= 32)
    {
      r[0] = (t[1] << (k - 32)) & MASK;
      r[1] = 0;
    }
  else
    {
      r[0] = ((t[0] << k) | (t[1] << (31 - k))) & MASK;
      r[1] = (t[1] << k) & MASK;
    }
}

/* Reduce b (mod p) and output a. The p is the our irreducible (or not)
   polynomial in GF(2^n). If one changes the polynomial one should
   change this also. */
void gf_red(GFPoly a, GFPoly b)
{
  GFPoly c;
  int i;

  if (b[1] == 0)
    {
      c[0] = b[0];
      a[0] = c[0];
      a[1] = 0;
      return;
    }

  gf_set(c, b);

  for (i = 0; i < 32; i++)
    {
      if (c[1] & 0x1)
        {
          c[1] = ((((c[1] & MASK) >> 1) | (c[0] << 31)) ^ MOD_32BIT) & MASK;
          c[0] = (c[0] & MASK) >> 1;
        }
      else
        {
          c[1] = (((c[1] & MASK) >> 1) | (c[0] << 31)) & MASK;
          c[0] = (c[0] & MASK) >> 1;
        }
    }

  gf_set_ui(a, c[1]);
}

/* Multiplication of two elements in GF(2^n). That is a*b = out (mod p).
   Must be in reduced form. */
void gf_mul(GFPoly out, GFPoly a, GFPoly b)
{
  SshUInt32 c = b[0];
  GFPoly h, r;

  gf_set(h, a);

  gf_set_ui(r, 0);

  while (c)
    {
      if (c & ((SshUInt32)1 << 31))
        {
          r[0] ^= h[0];
          r[1] ^= h[1];
        }

      c = (c << 1) & MASK;
      h[1] = (((h[1] & MASK) >> 1) | (h[0] << 31)) & MASK;
      h[0] = (h[0] & MASK) >> 1;
    }
  gf_set(out, r);
}

/* Handy functions. One might like to write comparison function too
   but that is too much trouble? */
int gf_zero(GFPoly a)
{
  if (a[0] == 0 && a[1] == 0)
    return 1;
  return 0;
}

int gf_one(GFPoly a)
{
  if (a[0] == ((SshUInt32)1 << 31) && a[1] == 0)
    return 1;
  return 0;
}

/* Simple gcd algorithm for polynomials. Isn't used here, but implemented
   because it is so simple. */
void gf_gcd(GFPoly gcd, GFPoly a, GFPoly b)
{
  GFPoly h, g, r, q;

  gf_set(h, a);
  gf_set(g, b);

  while (!gf_zero(h))
    {
      gf_div(q, r, g, h);
      gf_set(g, h);
      gf_set(h, r);
    }
  gf_set(gcd, g);
}

/* Extended gcd computation for the inversion. We have removed some
   cases, which can be computed outside if neccessary. */
void gf_gcdext(GFPoly gcd, GFPoly sx, GFPoly gx, GFPoly hx)
{
  GFPoly s = { 0 }, q = { 0 }, r = { 0 };
  GFPoly g = { 0 }, h = { 0 }, s1 = { 0 }, s2 = { 0 };

  if (gf_zero(hx))
    {
      gf_set(gcd, g);
      gf_set_ui(sx, 1);
      return;
    }

  gf_set(h, hx);
  gf_set(g, gx);

  gf_set_ui(s2, (((SshUInt32)1) << 31));
  gf_set_ui(s1, 0);
  while (!gf_zero(h))
    {
      gf_div(q, r, g, h);
      gf_mul(s, q, s1);
      gf_add(s, s2);

      gf_set(g, h);
      gf_set(h, r);

      gf_set(s2, s1);
      gf_set(s1, s);
    }

  gf_set(gcd, g);
  gf_set(sx, s2);
}

/* Yet we need an inversion algorithm for polynomials. */
int gf_inv(GFPoly inv, GFPoly a)
{
  GFPoly b, g;

  /* Our modulus polynomial. */
  b[0] = MOD_32BIT;
  b[1] = (((SshUInt32)1) << 31);

  gf_gcdext(g, inv, a, b);
  if (!gf_one(g))
    return 0;
  return 1;
}

/* Exponentiation modulo a irreducible (or not) polynomial. The exponent
   is best to kept as a standard integer. */
void gf_exp(GFPoly r, GFPoly g, size_t n)
{
  GFPoly t, h;

  gf_set(h, g);

  gf_set_ui(t, (((SshUInt32)1) << 31));

  while (n)
    {
      if (n & 0x1)
        {
          gf_mul(t, t, h);
          gf_red(t, t);
        }
      n >>= 1;
      gf_mul(h, h, h);
      gf_red(h, h);
    }
  gf_set(r, t);
}

/* Crc32 computations using the GF(2^n) arithmetic routines. Runs in
   polynomial time, which is quite nice when having to update long
   buffers. */

/* Compute the x^n (mod p) which is needed for crc scam. */
SshUInt32 crc32_blank(SshUInt32 mask_crc, size_t len)
{
  GFPoly t, g;

  gf_set_ui(t, mask_crc & MASK);
  gf_set_ui(g, (1 << (31 - 8)));

  gf_exp(g, g, len);

  gf_mul(t, t, g);
  gf_red(t, t);


  return t[0] & MASK;
}

/* Compute the x^(-n) (mod p) which is need for crc scam 2. */
SshUInt32 crc32_divide(SshUInt32 mask_crc, size_t len)
{
  GFPoly t, g;

  gf_set_ui(t, mask_crc & MASK);
  gf_set_ui(g, (1 << (31 - 8)));
  gf_exp(g, g, len);

  if (gf_inv(g, g) == 0)
    {
      ssh_fatal("crc32_divide: polynomial modulus not irreducible.");
    }

  gf_mul(t, t, g);
  gf_red(t, t);

  return t[0];
}

/* The main function which allows us to keep the crc32 updated even though
   we are not computing it entirely again. This works using GF(2^n)
   arithmetics and actually computes crc32 again only of the mask given.

   This works because given original message m and its crc m_crc we get

     m = m_crc (mod p)

   and yet if have a mask k for m that is m + k = n, where n is the new
   message then,

     m + k = n (mod p)

   and indeed

     k = m + n (mod p)

   and this is indeed equivalent to

     k_crc = m_crc + n_crc (mod p) <=>
     k_crc + m_crc = n_crc (mod p)

   Very trivial indeed. Then we notice that if there is a lot of
   zeros before actual changes we need to compute only from the start
   of the non-zero elements in the mask for k_crc. Also by noting that

     m*x^n = (m_crc)*((x^n)_crc) (mod p)

   we get using our GF(2^n) implementation polynomial time algorithm
   for getting rid of the possible trailing zeros. Thus we can
   update the CRC in polynomial time, after just computing crc32 out of
   the part of the mask k which is non-zero (or mostly non-zero and
   contiguous).

   Function input is the mask buffer of length mask_len. It's offset
   is the place to where to xor it one gets the new message. Total_len
   is the total lenght of the message computed with crc32. Prev_crc32
   is the previously computed crc32.

   Function returns the new crc32 that is indeed same as the one that
   is computed over the full message.

   */
SshUInt32 crc32_mask(const unsigned char *mask, size_t mask_len,
                     size_t offset,
                     size_t total_len,
                     SshUInt32 prev_crc32)
{
  return crc32_blank(crc32_buffer(mask, mask_len),
                     total_len - (offset + mask_len)) ^ prev_crc32;
}

/* Extend the crc32 computed (prev_crc32) to also number of zeroes
   after it. This could be useful with filesystems enlarging a file which
   one has computed crc32 before. Thus with a polynomial time algorithm
   one can compute new correct crc32. */
SshUInt32 crc32_extend(SshUInt32 prev_crc32, size_t len)
{
  return crc32_blank(prev_crc32, len);
}

/* Function to truncate crc32 of a buffer containing atleast len
   trailing zeroes. With this computation one can actually truncate
   the buffer in question by len bytes and keep the crc32 correct. */

SshUInt32 crc32_truncate(SshUInt32 prev_crc32,
                         size_t len)
{
  return crc32_divide(prev_crc32, len);
}
