/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshgetput.h"
#include "sshrotate.h"
#include "des.h"

#define SSH_DEBUG_MODULE "SshDes"

/* Table of weak keys that are checked for. This includes the usual
   weak and semi-weak keys. */
#define SSH_DES_WEAK_KEYS  (4 + 6*2)
static const unsigned char ssh_des_weak_keys[SSH_DES_WEAK_KEYS][8] =
{
  /* The weak keys. */
  { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
  { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
  { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
  { 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },

  /* The semi-weak keys. */
  { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
  { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },

  { 0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1 },
  { 0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e },

  { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
  { 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01 },

  { 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
  { 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e },

  { 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e },
  { 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01 },

  { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
  { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1 }
};

Boolean ssh_des_init_is_weak_key(const unsigned char *key)
{
  int i;

  /* Do weak key checks. */
  for (i = 0; i < SSH_DES_WEAK_KEYS; i++)
    {
      int j, match;

      for (j = 0, match = 0; j < 8; j++)
        {
          if ((key[j] & 0xfe) != (ssh_des_weak_keys[i][j] & 0xfe))
            break;

          match++;
        }

      /* Was a weak key? */
      if (match == 8)
        return TRUE;
    }
  return FALSE;
}

/* X an SshUInt32, this returns bit I of X, I is from 1 to 32. Bit 1
   is MSB of the SshUInt32 */
#define BIT(I, X) (((X) >> (32 - (I))) & 0x1)

/* X an SshUInt32, this returns byte I of X, I is from 1 to 4. Byte 1
   is MSB of the SshUInt32 */
#define BYTE(I, X) (((X) >> 8*(4 - (I))) & 0xff)

/* X an SshUInt32, this returns nibble 'I' of X, 'I' is from 1 to 8 */
#define NIB(I, X) (((X) >> 4*(8 - (I))) & 0xf)

static const SshUInt32 IP_L[16][16] = {
  {0x00000000, 0x00000080, 0x00000000, 0x00000080,
   0x00008000, 0x00008080, 0x00008000, 0x00008080,
   0x00000000, 0x00000080, 0x00000000, 0x00000080,
   0x00008000, 0x00008080, 0x00008000, 0x00008080},
  {0x00000000, 0x00800000, 0x00000000, 0x00800000,
   0x80000000, 0x80800000, 0x80000000, 0x80800000,
   0x00000000, 0x00800000, 0x00000000, 0x00800000,
   0x80000000, 0x80800000, 0x80000000, 0x80800000},
  {0x00000000, 0x00000040, 0x00000000, 0x00000040,
   0x00004000, 0x00004040, 0x00004000, 0x00004040,
   0x00000000, 0x00000040, 0x00000000, 0x00000040,
   0x00004000, 0x00004040, 0x00004000, 0x00004040},
  {0x00000000, 0x00400000, 0x00000000, 0x00400000,
   0x40000000, 0x40400000, 0x40000000, 0x40400000,
   0x00000000, 0x00400000, 0x00000000, 0x00400000,
   0x40000000, 0x40400000, 0x40000000, 0x40400000},
  {0x00000000, 0x00000020, 0x00000000, 0x00000020,
   0x00002000, 0x00002020, 0x00002000, 0x00002020,
   0x00000000, 0x00000020, 0x00000000, 0x00000020,
   0x00002000, 0x00002020, 0x00002000, 0x00002020},
  {0x00000000, 0x00200000, 0x00000000, 0x00200000,
   0x20000000, 0x20200000, 0x20000000, 0x20200000,
   0x00000000, 0x00200000, 0x00000000, 0x00200000,
   0x20000000, 0x20200000, 0x20000000, 0x20200000},
  {0x00000000, 0x00000010, 0x00000000, 0x00000010,
   0x00001000, 0x00001010, 0x00001000, 0x00001010,
   0x00000000, 0x00000010, 0x00000000, 0x00000010,
   0x00001000, 0x00001010, 0x00001000, 0x00001010},
  {0x00000000, 0x00100000, 0x00000000, 0x00100000,
   0x10000000, 0x10100000, 0x10000000, 0x10100000,
   0x00000000, 0x00100000, 0x00000000, 0x00100000,
   0x10000000, 0x10100000, 0x10000000, 0x10100000},
  {0x00000000, 0x00000008, 0x00000000, 0x00000008,
   0x00000800, 0x00000808, 0x00000800, 0x00000808,
   0x00000000, 0x00000008, 0x00000000, 0x00000008,
   0x00000800, 0x00000808, 0x00000800, 0x00000808},
  {0x00000000, 0x00080000, 0x00000000, 0x00080000,
   0x08000000, 0x08080000, 0x08000000, 0x08080000,
   0x00000000, 0x00080000, 0x00000000, 0x00080000,
   0x08000000, 0x08080000, 0x08000000, 0x08080000},
  {0x00000000, 0x00000004, 0x00000000, 0x00000004,
   0x00000400, 0x00000404, 0x00000400, 0x00000404,
   0x00000000, 0x00000004, 0x00000000, 0x00000004,
   0x00000400, 0x00000404, 0x00000400, 0x00000404},
  {0x00000000, 0x00040000, 0x00000000, 0x00040000,
   0x04000000, 0x04040000, 0x04000000, 0x04040000,
   0x00000000, 0x00040000, 0x00000000, 0x00040000,
   0x04000000, 0x04040000, 0x04000000, 0x04040000},
  {0x00000000, 0x00000002, 0x00000000, 0x00000002,
   0x00000200, 0x00000202, 0x00000200, 0x00000202,
   0x00000000, 0x00000002, 0x00000000, 0x00000002,
   0x00000200, 0x00000202, 0x00000200, 0x00000202},
  {0x00000000, 0x00020000, 0x00000000, 0x00020000,
   0x02000000, 0x02020000, 0x02000000, 0x02020000,
   0x00000000, 0x00020000, 0x00000000, 0x00020000,
   0x02000000, 0x02020000, 0x02000000, 0x02020000},
  {0x00000000, 0x00000001, 0x00000000, 0x00000001,
   0x00000100, 0x00000101, 0x00000100, 0x00000101,
   0x00000000, 0x00000001, 0x00000000, 0x00000001,
   0x00000100, 0x00000101, 0x00000100, 0x00000101},
  {0x00000000, 0x00010000, 0x00000000, 0x00010000,
   0x01000000, 0x01010000, 0x01000000, 0x01010000,
   0x00000000, 0x00010000, 0x00000000, 0x00010000,
   0x01000000, 0x01010000, 0x01000000, 0x01010000}
};

static const SshUInt32 IP_R[16][16] = {
  {0x00000000, 0x00000000, 0x00000080, 0x00000080,
   0x00000000, 0x00000000, 0x00000080, 0x00000080,
   0x00008000, 0x00008000, 0x00008080, 0x00008080,
   0x00008000, 0x00008000, 0x00008080, 0x00008080},
  {0x00000000, 0x00000000, 0x00800000, 0x00800000,
   0x00000000, 0x00000000, 0x00800000, 0x00800000,
   0x80000000, 0x80000000, 0x80800000, 0x80800000,
   0x80000000, 0x80000000, 0x80800000, 0x80800000},
  {0x00000000, 0x00000000, 0x00000040, 0x00000040,
   0x00000000, 0x00000000, 0x00000040, 0x00000040,
   0x00004000, 0x00004000, 0x00004040, 0x00004040,
   0x00004000, 0x00004000, 0x00004040, 0x00004040},
  {0x00000000, 0x00000000, 0x00400000, 0x00400000,
   0x00000000, 0x00000000, 0x00400000, 0x00400000,
   0x40000000, 0x40000000, 0x40400000, 0x40400000,
   0x40000000, 0x40000000, 0x40400000, 0x40400000},
  {0x00000000, 0x00000000, 0x00000020, 0x00000020,
   0x00000000, 0x00000000, 0x00000020, 0x00000020,
   0x00002000, 0x00002000, 0x00002020, 0x00002020,
   0x00002000, 0x00002000, 0x00002020, 0x00002020},
  {0x00000000, 0x00000000, 0x00200000, 0x00200000,
   0x00000000, 0x00000000, 0x00200000, 0x00200000,
   0x20000000, 0x20000000, 0x20200000, 0x20200000,
   0x20000000, 0x20000000, 0x20200000, 0x20200000},
  {0x00000000, 0x00000000, 0x00000010, 0x00000010,
   0x00000000, 0x00000000, 0x00000010, 0x00000010,
   0x00001000, 0x00001000, 0x00001010, 0x00001010,
   0x00001000, 0x00001000, 0x00001010, 0x00001010},
  {0x00000000, 0x00000000, 0x00100000, 0x00100000,
   0x00000000, 0x00000000, 0x00100000, 0x00100000,
   0x10000000, 0x10000000, 0x10100000, 0x10100000,
   0x10000000, 0x10000000, 0x10100000, 0x10100000},
  {0x00000000, 0x00000000, 0x00000008, 0x00000008,
   0x00000000, 0x00000000, 0x00000008, 0x00000008,
   0x00000800, 0x00000800, 0x00000808, 0x00000808,
   0x00000800, 0x00000800, 0x00000808, 0x00000808},
  {0x00000000, 0x00000000, 0x00080000, 0x00080000,
   0x00000000, 0x00000000, 0x00080000, 0x00080000,
   0x08000000, 0x08000000, 0x08080000, 0x08080000,
   0x08000000, 0x08000000, 0x08080000, 0x08080000},
  {0x00000000, 0x00000000, 0x00000004, 0x00000004,
   0x00000000, 0x00000000, 0x00000004, 0x00000004,
   0x00000400, 0x00000400, 0x00000404, 0x00000404,
   0x00000400, 0x00000400, 0x00000404, 0x00000404},
  {0x00000000, 0x00000000, 0x00040000, 0x00040000,
   0x00000000, 0x00000000, 0x00040000, 0x00040000,
   0x04000000, 0x04000000, 0x04040000, 0x04040000,
   0x04000000, 0x04000000, 0x04040000, 0x04040000},
  {0x00000000, 0x00000000, 0x00000002, 0x00000002,
   0x00000000, 0x00000000, 0x00000002, 0x00000002,
   0x00000200, 0x00000200, 0x00000202, 0x00000202,
   0x00000200, 0x00000200, 0x00000202, 0x00000202},
  {0x00000000, 0x00000000, 0x00020000, 0x00020000,
   0x00000000, 0x00000000, 0x00020000, 0x00020000,
   0x02000000, 0x02000000, 0x02020000, 0x02020000,
   0x02000000, 0x02000000, 0x02020000, 0x02020000},
  {0x00000000, 0x00000000, 0x00000001, 0x00000001,
   0x00000000, 0x00000000, 0x00000001, 0x00000001,
   0x00000100, 0x00000100, 0x00000101, 0x00000101,
   0x00000100, 0x00000100, 0x00000101, 0x00000101},
  {0x00000000, 0x00000000, 0x00010000, 0x00010000,
   0x00000000, 0x00000000, 0x00010000, 0x00010000,
   0x01000000, 0x01000000, 0x01010000, 0x01010000,
   0x01000000, 0x01000000, 0x01010000, 0x01010000}
};

static const SshUInt32 FP_L[16][16] = {
  {0x00000000, 0x02000000, 0x00020000, 0x02020000,
   0x00000200, 0x02000200, 0x00020200, 0x02020200,
   0x00000002, 0x02000002, 0x00020002, 0x02020002,
   0x00000202, 0x02000202, 0x00020202, 0x02020202},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x08000000, 0x00080000, 0x08080000,
   0x00000800, 0x08000800, 0x00080800, 0x08080800,
   0x00000008, 0x08000008, 0x00080008, 0x08080008,
   0x00000808, 0x08000808, 0x00080808, 0x08080808},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x20000000, 0x00200000, 0x20200000,
   0x00002000, 0x20002000, 0x00202000, 0x20202000,
   0x00000020, 0x20000020, 0x00200020, 0x20200020,
   0x00002020, 0x20002020, 0x00202020, 0x20202020},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x80000000, 0x00800000, 0x80800000,
   0x00008000, 0x80008000, 0x00808000, 0x80808000,
   0x00000080, 0x80000080, 0x00800080, 0x80800080,
   0x00008080, 0x80008080, 0x00808080, 0x80808080},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x01000000, 0x00010000, 0x01010000,
   0x00000100, 0x01000100, 0x00010100, 0x01010100,
   0x00000001, 0x01000001, 0x00010001, 0x01010001,
   0x00000101, 0x01000101, 0x00010101, 0x01010101},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x04000000, 0x00040000, 0x04040000,
   0x00000400, 0x04000400, 0x00040400, 0x04040400,
   0x00000004, 0x04000004, 0x00040004, 0x04040004,
   0x00000404, 0x04000404, 0x00040404, 0x04040404},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x10000000, 0x00100000, 0x10100000,
   0x00001000, 0x10001000, 0x00101000, 0x10101000,
   0x00000010, 0x10000010, 0x00100010, 0x10100010,
   0x00001010, 0x10001010, 0x00101010, 0x10101010},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x40000000, 0x00400000, 0x40400000,
   0x00004000, 0x40004000, 0x00404000, 0x40404000,
   0x00000040, 0x40000040, 0x00400040, 0x40400040,
   0x00004040, 0x40004040, 0x00404040, 0x40404040},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000}
};

static const SshUInt32 FP_R[16][16] = {
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x02000000, 0x00020000, 0x02020000,
   0x00000200, 0x02000200, 0x00020200, 0x02020200,
   0x00000002, 0x02000002, 0x00020002, 0x02020002,
   0x00000202, 0x02000202, 0x00020202, 0x02020202},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x08000000, 0x00080000, 0x08080000,
   0x00000800, 0x08000800, 0x00080800, 0x08080800,
   0x00000008, 0x08000008, 0x00080008, 0x08080008,
   0x00000808, 0x08000808, 0x00080808, 0x08080808},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x20000000, 0x00200000, 0x20200000,
   0x00002000, 0x20002000, 0x00202000, 0x20202000,
   0x00000020, 0x20000020, 0x00200020, 0x20200020,
   0x00002020, 0x20002020, 0x00202020, 0x20202020},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x80000000, 0x00800000, 0x80800000,
   0x00008000, 0x80008000, 0x00808000, 0x80808000,
   0x00000080, 0x80000080, 0x00800080, 0x80800080,
   0x00008080, 0x80008080, 0x00808080, 0x80808080},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x01000000, 0x00010000, 0x01010000,
   0x00000100, 0x01000100, 0x00010100, 0x01010100,
   0x00000001, 0x01000001, 0x00010001, 0x01010001,
   0x00000101, 0x01000101, 0x00010101, 0x01010101},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x04000000, 0x00040000, 0x04040000,
   0x00000400, 0x04000400, 0x00040400, 0x04040400,
   0x00000004, 0x04000004, 0x00040004, 0x04040004,
   0x00000404, 0x04000404, 0x00040404, 0x04040404},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x10000000, 0x00100000, 0x10100000,
   0x00001000, 0x10001000, 0x00101000, 0x10101000,
   0x00000010, 0x10000010, 0x00100010, 0x10100010,
   0x00001010, 0x10001010, 0x00101010, 0x10101010},
  {0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000},
  {0x00000000, 0x40000000, 0x00400000, 0x40400000,
   0x00004000, 0x40004000, 0x00404000, 0x40404000,
   0x00000040, 0x40000040, 0x00400040, 0x40400040,
   0x00004040, 0x40004040, 0x00404040, 0x40404040}
};

static const SshUInt32 SP[8][64] = {
  {0xd8d8dbbc, 0xd0d8db9c, 0xd0dad39c, 0xd8dadbbc,
   0xd8d8d39c, 0xd8d8dbbc, 0xd0d8d3bc, 0xd8d8d39c,
   0xd0dad3bc, 0xd8dad39c, 0xd8dadbbc, 0xd0dadb9c,
   0xd8dadb9c, 0xd0dadbbc, 0xd0d8db9c, 0xd0d8d3bc,
   0xd8dad39c, 0xd8d8d3bc, 0xd8d8db9c, 0xd0d8dbbc,
   0xd0dadb9c, 0xd0dad3bc, 0xd8dad3bc, 0xd8dadb9c,
   0xd0d8dbbc, 0xd0d8d39c, 0xd0d8d39c, 0xd8dad3bc,
   0xd8d8d3bc, 0xd8d8db9c, 0xd0dadbbc, 0xd0dad39c,
   0xd0dadbbc, 0xd0dad39c, 0xd8dadb9c, 0xd0d8db9c,
   0xd0d8d3bc, 0xd8dad3bc, 0xd0d8db9c, 0xd0dadbbc,
   0xd8d8db9c, 0xd0d8d3bc, 0xd8d8d3bc, 0xd8dad39c,
   0xd8dad3bc, 0xd8d8d39c, 0xd0dad39c, 0xd8d8dbbc,
   0xd0d8d39c, 0xd8dadbbc, 0xd0dad3bc, 0xd8d8d3bc,
   0xd8dad39c, 0xd8d8db9c, 0xd8d8dbbc, 0xd0d8d39c,
   0xd8dadbbc, 0xd0dadb9c, 0xd0dadb9c, 0xd0d8dbbc,
   0xd0d8dbbc, 0xd0dad3bc, 0xd8d8d39c, 0xd8dadb9c},

  {0xd8d8dbbc, 0xdad8dbbd, 0xdac8dfbd, 0xd8c8dbbc,
   0xd8c8dfbc, 0xdac8dfbd, 0xd8d8dfbd, 0xdad8dfbc,
   0xdad8dfbd, 0xd8d8dbbc, 0xd8c8dbbc, 0xdac8dbbd,
   0xd8c8dbbd, 0xdac8dbbc, 0xdad8dbbd, 0xd8c8dfbd,
   0xdac8dfbc, 0xd8d8dfbd, 0xd8d8dbbd, 0xdac8dfbc,
   0xdac8dbbd, 0xdad8dbbc, 0xdad8dfbc, 0xd8d8dbbd,
   0xdad8dbbc, 0xd8c8dfbc, 0xd8c8dfbd, 0xdad8dfbd,
   0xd8d8dfbc, 0xd8c8dbbd, 0xdac8dbbc, 0xd8d8dfbc,
   0xdac8dbbc, 0xd8d8dfbc, 0xd8d8dbbc, 0xdac8dfbd,
   0xdac8dfbd, 0xdad8dbbd, 0xdad8dbbd, 0xd8c8dbbd,
   0xd8d8dbbd, 0xdac8dbbc, 0xdac8dfbc, 0xd8d8dbbc,
   0xdad8dfbc, 0xd8c8dfbd, 0xd8d8dfbd, 0xdad8dfbc,
   0xd8c8dfbd, 0xdac8dbbd, 0xdad8dfbd, 0xdad8dbbc,
   0xd8d8dfbc, 0xd8c8dbbc, 0xd8c8dbbd, 0xdad8dfbd,
   0xd8c8dbbc, 0xd8d8dfbd, 0xdad8dbbc, 0xd8c8dfbc,
   0xdac8dbbd, 0xdac8dfbc, 0xd8c8dfbc, 0xd8d8dbbd},

  {0xd8d8dbbc, 0xd8f8dbb4, 0xc8d8fbb4, 0xd8f8fbbc,
   0xd8f8dbb4, 0xc8d8dbbc, 0xd8f8fbbc, 0xc8f8dbb4,
   0xd8d8fbb4, 0xc8f8fbbc, 0xc8f8dbb4, 0xd8d8dbbc,
   0xc8f8dbbc, 0xd8d8fbb4, 0xd8d8dbb4, 0xc8d8fbbc,
   0xc8d8dbb4, 0xc8f8dbbc, 0xd8d8fbbc, 0xc8d8fbb4,
   0xc8f8fbb4, 0xd8d8fbbc, 0xc8d8dbbc, 0xd8f8dbbc,
   0xd8f8dbbc, 0xc8d8dbb4, 0xc8f8fbbc, 0xd8f8fbb4,
   0xc8d8fbbc, 0xc8f8fbb4, 0xd8f8fbb4, 0xd8d8dbb4,
   0xd8d8fbb4, 0xc8d8dbbc, 0xd8f8dbbc, 0xc8f8fbb4,
   0xd8f8fbbc, 0xc8f8dbb4, 0xc8d8fbbc, 0xd8d8dbbc,
   0xc8f8dbb4, 0xd8d8fbb4, 0xd8d8dbb4, 0xc8d8fbbc,
   0xd8d8dbbc, 0xd8f8fbbc, 0xc8f8fbb4, 0xd8f8dbb4,
   0xc8f8fbbc, 0xd8f8fbb4, 0xc8d8dbb4, 0xd8f8dbbc,
   0xc8d8dbbc, 0xc8d8fbb4, 0xd8f8dbb4, 0xc8f8fbbc,
   0xc8d8fbb4, 0xc8f8dbbc, 0xd8d8fbbc, 0xc8d8dbb4,
   0xd8f8fbb4, 0xd8d8dbb4, 0xc8f8dbbc, 0xd8d8fbbc},

  {0xd8d8dbbc, 0xd9dcdbbc, 0xd9dcdb3c, 0xf9d8dbbc,
   0xd8dcdb3c, 0xd8d8dbbc, 0xf8d8db3c, 0xd9dcdb3c,
   0xf8dcdbbc, 0xd8dcdb3c, 0xd9d8dbbc, 0xf8dcdbbc,
   0xf9d8dbbc, 0xf9dcdb3c, 0xd8dcdbbc, 0xf8d8db3c,
   0xd9d8db3c, 0xf8dcdb3c, 0xf8dcdb3c, 0xd8d8db3c,
   0xf8d8dbbc, 0xf9dcdbbc, 0xf9dcdbbc, 0xd9d8dbbc,
   0xf9dcdb3c, 0xf8d8dbbc, 0xd8d8db3c, 0xf9d8db3c,
   0xd9dcdbbc, 0xd9d8db3c, 0xf9d8db3c, 0xd8dcdbbc,
   0xd8dcdb3c, 0xf9d8dbbc, 0xd8d8dbbc, 0xd9d8db3c,
   0xf8d8db3c, 0xd9dcdb3c, 0xf9d8dbbc, 0xf8dcdbbc,
   0xd9d8dbbc, 0xf8d8db3c, 0xf9dcdb3c, 0xd9dcdbbc,
   0xf8dcdbbc, 0xd8d8dbbc, 0xd9d8db3c, 0xf9dcdb3c,
   0xf9dcdbbc, 0xd8dcdbbc, 0xf9d8db3c, 0xf9dcdbbc,
   0xd9dcdb3c, 0xd8d8db3c, 0xf8dcdb3c, 0xf9d8db3c,
   0xd8dcdbbc, 0xd9d8dbbc, 0xf8d8dbbc, 0xd8dcdb3c,
   0xd8d8db3c, 0xf8dcdb3c, 0xd9dcdbbc, 0xf8d8dbbc},

  {0xd8d8dbbc, 0xd898dbfc, 0xd898dbfc, 0x5898cbfc,
   0x58d8dbfc, 0xd8d8cbfc, 0xd8d8cbbc, 0xd898dbbc,
   0x5898cbbc, 0x58d8dbbc, 0x58d8dbbc, 0xd8d8dbfc,
   0xd898cbfc, 0x5898cbbc, 0x58d8cbfc, 0xd8d8cbbc,
   0xd898cbbc, 0x5898dbbc, 0x58d8cbbc, 0xd8d8dbbc,
   0x5898cbfc, 0x58d8cbbc, 0xd898dbbc, 0x5898dbfc,
   0xd8d8cbfc, 0xd898cbbc, 0x5898dbfc, 0x58d8cbfc,
   0x5898dbbc, 0x58d8dbfc, 0xd8d8dbfc, 0xd898cbfc,
   0x58d8cbfc, 0xd8d8cbbc, 0x58d8dbbc, 0xd8d8dbfc,
   0xd898cbfc, 0x5898cbbc, 0x5898cbbc, 0x58d8dbbc,
   0x5898dbfc, 0x58d8cbfc, 0xd8d8cbfc, 0xd898cbbc,
   0xd8d8dbbc, 0xd898dbfc, 0xd898dbfc, 0x5898cbfc,
   0xd8d8dbfc, 0xd898cbfc, 0xd898cbbc, 0x5898dbbc,
   0xd8d8cbbc, 0xd898dbbc, 0x58d8dbfc, 0xd8d8cbfc,
   0xd898dbbc, 0x5898dbfc, 0x58d8cbbc, 0xd8d8dbbc,
   0x5898cbfc, 0x58d8cbbc, 0x5898dbbc, 0x58d8dbfc},

  {0xd8d8dbbc, 0xdcd9dbb8, 0xd8d8dab8, 0xdcd9dabc,
   0xdcd8dbb8, 0xd8d8dab8, 0xd8d9dbbc, 0xdcd8dbb8,
   0xd8d9dabc, 0xdcd8dabc, 0xdcd8dabc, 0xd8d9dab8,
   0xdcd9dbbc, 0xd8d9dabc, 0xdcd9dab8, 0xd8d8dbbc,
   0xdcd8dab8, 0xd8d8dabc, 0xdcd9dbb8, 0xd8d8dbb8,
   0xd8d9dbb8, 0xdcd9dab8, 0xdcd9dabc, 0xd8d9dbbc,
   0xdcd8dbbc, 0xd8d9dbb8, 0xd8d9dab8, 0xdcd8dbbc,
   0xd8d8dabc, 0xdcd9dbbc, 0xd8d8dbb8, 0xdcd8dab8,
   0xdcd9dbb8, 0xdcd8dab8, 0xd8d9dabc, 0xd8d8dbbc,
   0xd8d9dab8, 0xdcd9dbb8, 0xdcd8dbb8, 0xd8d8dab8,
   0xd8d8dbb8, 0xd8d9dabc, 0xdcd9dbbc, 0xdcd8dbb8,
   0xdcd8dabc, 0xd8d8dbb8, 0xd8d8dab8, 0xdcd9dabc,
   0xdcd8dbbc, 0xd8d9dab8, 0xdcd8dab8, 0xdcd9dbbc,
   0xd8d8dabc, 0xd8d9dbbc, 0xd8d9dbb8, 0xdcd8dabc,
   0xdcd9dab8, 0xdcd8dbbc, 0xd8d8dbbc, 0xdcd9dab8,
   0xd8d9dbbc, 0xd8d8dabc, 0xdcd9dabc, 0xd8d9dbb8},

  {0xd8d8dbbc, 0xd8d0dbac, 0x98d0dbac, 0x98d8dbbc,
   0x98d89bac, 0x98d09bbc, 0xd8d89bbc, 0xd8d0dbbc,
   0xd8d09bbc, 0xd8d8dbbc, 0xd8d8dbac, 0xd8d09bac,
   0xd8d0dbac, 0x98d89bac, 0x98d09bbc, 0xd8d89bbc,
   0x98d8dbac, 0x98d89bbc, 0xd8d0dbbc, 0x98d09bac,
   0xd8d09bac, 0x98d0dbac, 0x98d8dbbc, 0xd8d89bac,
   0x98d89bbc, 0xd8d09bbc, 0x98d09bac, 0x98d8dbac,
   0x98d0dbbc, 0xd8d8dbac, 0xd8d89bac, 0x98d0dbbc,
   0x98d09bac, 0x98d8dbbc, 0xd8d89bbc, 0x98d89bac,
   0xd8d0dbbc, 0xd8d89bac, 0xd8d8dbac, 0x98d0dbac,
   0xd8d89bac, 0xd8d0dbac, 0x98d09bbc, 0xd8d8dbbc,
   0x98d8dbbc, 0x98d09bbc, 0x98d0dbac, 0xd8d09bac,
   0x98d0dbbc, 0xd8d8dbac, 0x98d89bac, 0xd8d09bbc,
   0x98d89bbc, 0xd8d0dbbc, 0xd8d09bbc, 0x98d89bbc,
   0x98d8dbac, 0x98d09bac, 0xd8d0dbac, 0x98d0dbbc,
   0xd8d09bac, 0xd8d89bbc, 0xd8d8dbbc, 0x98d8dbac},

  {0xd8d8dbbc, 0xd85859bc, 0xd858d9bc, 0xd8d8dbbe,
   0xd8d8d9be, 0xd858dbbe, 0xd85859be, 0xd858d9bc,
   0xd8585bbc, 0xd8d8dbbc, 0xd8d8dbbe, 0xd8585bbc,
   0xd8d85bbe, 0xd8d8d9be, 0xd8d859bc, 0xd85859be,
   0xd8585bbe, 0xd8d85bbc, 0xd8d85bbc, 0xd858dbbc,
   0xd858dbbc, 0xd8d8d9bc, 0xd8d8d9bc, 0xd8d85bbe,
   0xd858d9be, 0xd8d859be, 0xd8d859be, 0xd858d9be,
   0xd85859bc, 0xd8585bbe, 0xd858dbbe, 0xd8d859bc,
   0xd858d9bc, 0xd8d8dbbe, 0xd85859be, 0xd8d8d9bc,
   0xd8d8dbbc, 0xd8d859bc, 0xd8d859bc, 0xd8585bbc,
   0xd8d8d9be, 0xd858d9bc, 0xd858dbbc, 0xd8d859be,
   0xd8585bbc, 0xd85859be, 0xd8d85bbe, 0xd858dbbe,
   0xd8d8dbbe, 0xd858d9be, 0xd8d8d9bc, 0xd8d85bbe,
   0xd8d859be, 0xd8585bbe, 0xd858dbbe, 0xd8d8dbbc,
   0xd8585bbe, 0xd8d85bbc, 0xd8d85bbc, 0xd85859bc,
   0xd858d9be, 0xd858dbbc, 0xd85859bc, 0xd8d8d9be}
};

SshUInt32 ssh_des_pc1_l(SshUInt32 i1, SshUInt32 i2)
{
  SshUInt32 t;
  t  = BIT(25,i2)<<27 | BIT(17,i2)<<26 | BIT(9,i2)<<25 |  BIT(1,i2)<<24;
  t |= BIT(25,i1)<<23 | BIT(17,i1)<<22 | BIT(9,i1)<<21  | BIT(1,i1)<<20;
  t |= BIT(26,i2)<<19 | BIT(18,i2)<<18 | BIT(10,i2)<<17 | BIT(2,i2)<<16;
  t |= BIT(26,i1)<<15 | BIT(18,i1)<<14 | BIT(10,i1)<<13 | BIT(2,i1)<<12;
  t |= BIT(27,i2)<<11 | BIT(19,i2)<<10 | BIT(11,i2)<<9  | BIT(3,i2)<<8;
  t |= BIT(27,i1)<<7  | BIT(19,i1)<<6  | BIT(11,i1)<<5  | BIT(3,i1)<<4;
  t |= BIT(28,i2)<<3  | BIT(20,i2)<<2  | BIT(12,i2)<<1  | BIT(4,i2)<<0;

  return t;
}

SshUInt32 ssh_des_pc1_r(SshUInt32 i1, SshUInt32 i2)
{
  SshUInt32 t;
  t  = BIT(31,i2)<<27 | BIT(23,i2)<<26 | BIT(15,i2)<<25 | BIT(7,i2)<<24;
  t |= BIT(31,i1)<<23 | BIT(23,i1)<<22 | BIT(15,i1)<<21 | BIT(7,i1)<<20;
  t |= BIT(30,i2)<<19 | BIT(22,i2)<<18 | BIT(14,i2)<<17 | BIT(6,i2)<<16;
  t |= BIT(30,i1)<<15 | BIT(22,i1)<<14 | BIT(14,i1)<<13 | BIT(6,i1)<<12;
  t |= BIT(29,i2)<<11 | BIT(21,i2)<<10 | BIT(13,i2)<<9  | BIT(5,i2)<<8;
  t |= BIT(29,i1)<<7  | BIT(21,i1)<<6  | BIT(13,i1)<<5  | BIT(5,i1)<<4;
  t |= BIT(28,i1)<<3  | BIT(20,i1)<<2  | BIT(12,i1)<<1  | BIT(4,i1)<<0;

  return t;
}

SshUInt32 ssh_des_pc2_l(SshUInt32 x)
{
  SshUInt32 t;

  t  = BIT(18,x)<<31 | BIT(21,x)<<30 | BIT(15,x)<<29 | BIT(28,x)<<28;
  t |= BIT(5,x)<<27  | BIT(9,x)<<26  | BIT(7,x)<<23  | BIT(32,x)<<22;
  t |= BIT(19,x)<<21 | BIT(10,x)<<20 | BIT(25,x)<<19 | BIT(14,x)<<18;
  t |= BIT(27,x)<<15 | BIT(23,x)<<14 | BIT(16,x)<<13 | BIT(8,x)<<12;
  t |= BIT(30,x)<<11 | BIT(12,x)<<10 | BIT(20,x)<<7  | BIT(11,x)<<6;
  t |= BIT(31,x)<<5  | BIT(24,x)<<4  | BIT(17,x)<<3  | BIT(6,x)<<2;
  return t;
}

SshUInt32 ssh_des_pc2_r(SshUInt32 x)
{
  SshUInt32 t;

  t  = BIT(17,x)<<31 | BIT(28,x)<<30 | BIT(7,x)<<29  | BIT(13,x)<<28;
  t |= BIT(23,x)<<27 | BIT(31,x)<<26 | BIT(6,x)<<23  | BIT(16,x)<<22;
  t |= BIT(27,x)<<21 | BIT(21,x)<<20 | BIT(9,x)<<19  | BIT(24,x)<<18;
  t |= BIT(20,x)<<15 | BIT(25,x)<<14 | BIT(15,x)<<13 | BIT(32,x)<<12;
  t |= BIT(10,x)<<11 | BIT(29,x)<<10 | BIT(22,x)<<7  | BIT(18,x)<<6;
  t |= BIT(26,x)<<5  | BIT(12,x)<<4  | BIT(5,x)<<3   | BIT(8,x)<<2;
  return t;
}

#define DES_ROUND(L,R,S)                                \
  t1 = SSH_ROR32(R, 1);                                 \
  t2 = SSH_ROL32(R, 3);                                 \
  t3 = t1;                                              \
  t4 = t2;                                              \
  t3 ^= key_schedule[S];                                \
  t4 ^= key_schedule[S+1];                              \
  t1 = 0xd8d8dbbc;                                      \
  t1 ^= SP[0][BYTE(4,t4)>>2] ^ SP[1][BYTE(4,t3)>>2] ^   \
        SP[2][BYTE(3,t4)>>2] ^ SP[3][BYTE(3,t3)>>2];    \
  t1 ^= SP[4][BYTE(2,t4)>>2] ^ SP[5][BYTE(2,t3)>>2] ^   \
        SP[6][BYTE(1,t4)>>2] ^ SP[7][BYTE(1,t3)>>2];    \
  L ^= t1;

void
ssh_single_des_encrypt(SshUInt32 l, SshUInt32 r, SshUInt32 *output,
                       SshUInt32 *key_schedule, int for_encryption)
{
  SshUInt32 t1, t2, t3, t4;
  int i;

  /* IP transformation */
  t1  = IP_L[0][NIB(8,r)]  | IP_L[1][NIB(7,r)]   |\
        IP_L[2][NIB(6,r)]  | IP_L[3][NIB(5,r)]   |\
        IP_L[4][NIB(4,r)]  | IP_L[5][NIB(3,r)]   |\
        IP_L[6][NIB(2,r)]  | IP_L[7][NIB(1,r)];
  t1 |= IP_L[8][NIB(8,l)]  | IP_L[9][NIB(7,l)]   |\
        IP_L[10][NIB(6,l)] | IP_L[11][NIB(5,l)]  |\
        IP_L[12][NIB(4,l)] | IP_L[13][NIB(3,l)]  |
        IP_L[14][NIB(2,l)] | IP_L[15][NIB(1,l)];
  t2 =  IP_R[0][NIB(8,r)]  | IP_R[1][NIB(7,r)]   |\
        IP_R[2][NIB(6,r)]  | IP_R[3][NIB(5,r)]   |\
        IP_R[4][NIB(4,r)]  | IP_R[5][NIB(3,r)]   |\
        IP_R[6][NIB(2,r)]  | IP_R[7][NIB(1,r)];
  t2 |= IP_R[8][NIB(8,l)]  | IP_R[9][NIB(7,l)]   |\
        IP_R[10][NIB(6,l)] | IP_R[11][NIB(5,l)]  |\
        IP_R[12][NIB(4,l)] | IP_R[13][NIB(3,l)]  |\
        IP_R[14][NIB(2,l)] | IP_R[15][NIB(1,l)];

  l = t1, r = t2;

  /* I don't know if it is worth the effort of loop unrolling the
   * inner loop */
  if (for_encryption)
    {
      for (i=0; i<32; i+=4)
        {
          DES_ROUND(l,r,i+0); /*  1 */
          DES_ROUND(r,l,i+2); /*  2 */
        }
    }
  else
    {
      for (i=30; i>0; i-=4)
        {
          DES_ROUND(l,r,i-0); /* 16 */
          DES_ROUND(r,l,i-2); /* 15 */
        }
    }


  /* IP inverse (FP) transformation */
  t1  = FP_L[0][NIB(8,l)]  | FP_L[1][NIB(7,l)]   |\
        FP_L[2][NIB(6,l)]  | FP_L[3][NIB(5,l)]   |\
        FP_L[4][NIB(4,l)]  | FP_L[5][NIB(3,l)]   |\
        FP_L[6][NIB(2,l)]  | FP_L[7][NIB(1,l)];
  t1 |= FP_L[8][NIB(8,r)]  | FP_L[9][NIB(7,r)]   |\
        FP_L[10][NIB(6,r)] | FP_L[11][NIB(5,r)]  |\
        FP_L[12][NIB(4,r)] | FP_L[13][NIB(3,r)]  |\
        FP_L[14][NIB(2,r)] | FP_L[15][NIB(1,r)];
  t2  = FP_R[0][NIB(8,l)]  | FP_R[1][NIB(7,l)]   |\
        FP_R[2][NIB(6,l)]  | FP_R[3][NIB(5,l)]   |\
        FP_R[4][NIB(4,l)]  | FP_R[5][NIB(3,l)]   |\
        FP_R[6][NIB(2,l)]  | FP_R[7][NIB(1,l)];
  t2 |= FP_R[8][NIB(8,r)]  | FP_R[9][NIB(7,r)]   |\
        FP_R[10][NIB(6,r)] | FP_R[11][NIB(5,r)]  |\
        FP_R[12][NIB(4,r)] | FP_R[13][NIB(3,r)]  |\
        FP_R[14][NIB(2,r)] | FP_R[15][NIB(1,r)];

  output[0] = t1;
  output[1] = t2;
}

/* Triple des encrypt/decrypt/encrypt and decrypt/encrypt/decrypt */
void ssh_triple_des_ede_encrypt(SshUInt32 l, SshUInt32 r, SshUInt32 output[2],
                                SshUInt32 *key_schedule,
                                Boolean for_encryption)
{
    SshUInt32 t1, t2, t3, t4;
    int i;

  /* IP transformation */
  t1  = IP_L[0][NIB(8,r)]  | IP_L[1][NIB(7,r)]  |\
        IP_L[2][NIB(6,r)]  | IP_L[3][NIB(5,r)]  |\
        IP_L[4][NIB(4,r)]  | IP_L[5][NIB(3,r)]  |\
        IP_L[6][NIB(2,r)]  | IP_L[7][NIB(1,r)];
  t1 |= IP_L[8][NIB(8,l)]  | IP_L[9][NIB(7,l)]  |\
        IP_L[10][NIB(6,l)] | IP_L[11][NIB(5,l)] |\
        IP_L[12][NIB(4,l)] | IP_L[13][NIB(3,l)] |\
        IP_L[14][NIB(2,l)] | IP_L[15][NIB(1,l)];
  t2  = IP_R[0][NIB(8,r)]  | IP_R[1][NIB(7,r)]  |\
        IP_R[2][NIB(6,r)]  | IP_R[3][NIB(5,r)]  |\
        IP_R[4][NIB(4,r)]  | IP_R[5][NIB(3,r)]  |\
        IP_R[6][NIB(2,r)]  | IP_R[7][NIB(1,r)];
  t2 |= IP_R[8][NIB(8,l)]  | IP_R[9][NIB(7,l)]  |\
        IP_R[10][NIB(6,l)] | IP_R[11][NIB(5,l)] |\
        IP_R[12][NIB(4,l)] | IP_R[13][NIB(3,l)] |\
        IP_R[14][NIB(2,l)] | IP_R[15][NIB(1,l)];

  l = t1, r = t2;

  /* I don't know if it is worth the effort of loop unrolling the
   * inner loop */
  if (for_encryption)
    {
      for (i=0; i<32; i+=4)
        {
          DES_ROUND(l,r,i+0); /*  1 */
          DES_ROUND(r,l,i+2); /*  2 */
        }
      for (i = 62; i > 32; i-=4)
        {
          DES_ROUND(r,l,i-0);
          DES_ROUND(l,r,i-2);
        }
      for (i = 64; i < 96; i+=4)
        {
          DES_ROUND(l,r,i+0);
          DES_ROUND(r,l,i+2);
        }
    }
  else
    {
      for (i=94; i>64; i-=4)
        {
          DES_ROUND(l,r,i-0); /*  127 */
          DES_ROUND(r,l,i-2); /*  126 */
        }
      for (i = 32; i < 64; i+=4)
        {
          DES_ROUND(r,l,i+0);
          DES_ROUND(l,r,i+2);
        }
      for (i = 30; i > 0; i-=4)
        {
          DES_ROUND(l,r,i-0);
          DES_ROUND(r,l,i-2);
        }
    }

  /* IP inverse (FP) transformation */
  t1  = FP_L[0][NIB(8,l)]  | FP_L[1][NIB(7,l)]  |\
        FP_L[2][NIB(6,l)]  | FP_L[3][NIB(5,l)]  |\
        FP_L[4][NIB(4,l)]  | FP_L[5][NIB(3,l)]  |\
        FP_L[6][NIB(2,l)]  | FP_L[7][NIB(1,l)];
  t1 |= FP_L[8][NIB(8,r)]  | FP_L[9][NIB(7,r)]  |\
        FP_L[10][NIB(6,r)] | FP_L[11][NIB(5,r)] |\
        FP_L[12][NIB(4,r)] | FP_L[13][NIB(3,r)] |\
        FP_L[14][NIB(2,r)] | FP_L[15][NIB(1,r)];
  t2  = FP_R[0][NIB(8,l)]  | FP_R[1][NIB(7,l)]  |\
        FP_R[2][NIB(6,l)]  | FP_R[3][NIB(5,l)]  |\
        FP_R[4][NIB(4,l)]  | FP_R[5][NIB(3,l)]  |\
        FP_R[6][NIB(2,l)]  | FP_R[7][NIB(1,l)];
  t2 |= FP_R[8][NIB(8,r)]  | FP_R[9][NIB(7,r)]  |\
        FP_R[10][NIB(6,r)] | FP_R[11][NIB(5,r)] |\
        FP_R[12][NIB(4,r)] | FP_R[13][NIB(3,r)] |\
        FP_R[14][NIB(2,r)] | FP_R[15][NIB(1,r)];

  output[0] = t1;
  output[1] = t2;
}

void ssh_des_set_key(const unsigned char *key, SshUInt32 *schedule)
{
  SshUInt32 c, d, tmp;
  SshUInt32 t1, t2;
  int i;

  c = SSH_GET_32BIT(key);
  d = SSH_GET_32BIT(key + 4);

  tmp = ssh_des_pc1_l(c, d);
  d = ssh_des_pc1_r(c, d);
  c = tmp;

  for (i = 0; i < 16; i++)
    {
      if (i == 0 || i == 1 || i == 8 || i == 15)
        {
          c = (c << 1) | (c >> 27);
          d = (d << 1) | (d >> 27);
        }
      else
        {
          c = (c << 2) | (c >> 26);
          d = (d << 2) | (d >> 26);
        }

      c &= 0x0fffffff;
      d &= 0x0fffffff;

      /* Swap the bytes of the key schedule here. This saves an expensive
         operation in the DES_ROUND function whereby without doing this
         we would need to perform essentially the same operation as below
         (for each invocation of DES_ROUND). */
      t1 = ssh_des_pc2_l(c);
      t2 = ssh_des_pc2_r(d);

      *schedule++ = (BYTE(1,t1)<<24) | (BYTE(3,t1)<<16) |\
                     (BYTE(1,t2)<<8) | BYTE(3, t2);

      *schedule++ = (BYTE(2,t1)<<24) | (BYTE(4,t1)<<16) |\
                    (BYTE(2,t2)<<8) | BYTE(4, t2);
    }
}


typedef struct
{
  SshUInt32 key_schedule[32];
  unsigned char iv[8];
  Boolean for_encryption;
} SshDESContext;


/* Single des */

size_t ssh_des_ctxsize()
{
  return sizeof(SshDESContext);
}


SshCryptoStatus ssh_des_init(void *ptr,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption)
{
  SshDESContext *ctx = (SshDESContext *)ptr;

  if (keylen < 8)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  ctx->for_encryption = for_encryption;
  ssh_des_set_key(key, ctx->key_schedule);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_des_init_with_key_check(void *ptr,
                            const unsigned char *key, size_t keylen,
                            Boolean for_encryption)
{
  SshDESContext *ctx = (SshDESContext *)ptr;

  if (keylen < 8)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  if (ssh_des_init_is_weak_key(key))
    return SSH_CRYPTO_KEY_WEAK;

  /* Not a weak key continue. */
  ctx->for_encryption = for_encryption;
  ssh_des_set_key(key, ctx->key_schedule);

  return SSH_CRYPTO_OK;
}

void ssh_des_uninit(void *context)
{
  return;
}

SshCryptoStatus ssh_des_start(void *context, const unsigned char *iv)
{
  SshDESContext *ctx = (SshDESContext *)context;

  memcpy(ctx->iv, iv, 8);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des_ecb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len)
{
  SshDESContext *ctx = (SshDESContext *)context;
  SshUInt32 output[2], l, r;
  Boolean for_encryption = ctx->for_encryption;

  while (len)
    {
      l = SSH_GET_32BIT(src);
      r = SSH_GET_32BIT(src + 4);

      ssh_single_des_encrypt(l, r, output, ctx->key_schedule, for_encryption);

      SSH_PUT_32BIT(dest, output[0]);
      SSH_PUT_32BIT(dest + 4, output[1]);

      src += 8;
      dest += 8;
      len -= 8;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des_cbc(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len)
{
  SshDESContext *ctx = (SshDESContext *)context;
  SshUInt32 l, r, iv[2], temp[2];
  Boolean for_encryption = ctx->for_encryption;

  iv[0] = SSH_GET_32BIT(ctx->iv);
  iv[1] = SSH_GET_32BIT(ctx->iv + 4);



  if (for_encryption)
    {
      while (len)
        {
          l = SSH_GET_32BIT(src) ^ iv[0];
          r = SSH_GET_32BIT(src + 4) ^ iv[1];

          ssh_single_des_encrypt(l, r, iv, ctx->key_schedule, for_encryption);

          SSH_PUT_32BIT(dest, iv[0]);
          SSH_PUT_32BIT(dest + 4, iv[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          l = SSH_GET_32BIT(src);
          r = SSH_GET_32BIT(src + 4);

          ssh_single_des_encrypt(l, r, temp,
                                 ctx->key_schedule, for_encryption);

          temp[0] ^= iv[0];
          temp[1] ^= iv[1];

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          iv[0] = l;
          iv[1] = r;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT(ctx->iv, iv[0]);
  SSH_PUT_32BIT(ctx->iv + 4, iv[1]);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des_cfb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len)
{
  SshDESContext *ctx = (SshDESContext *)context;
  SshUInt32 l, r, temp[2];

  l = SSH_GET_32BIT(ctx->iv);
  r = SSH_GET_32BIT(ctx->iv + 4);

  if (ctx->for_encryption)
    {
      while (len)
        {
          ssh_single_des_encrypt(l, r, temp, ctx->key_schedule, TRUE);

          l = SSH_GET_32BIT(src) ^ temp[0];
          r = SSH_GET_32BIT(src + 4) ^ temp[1];

          temp[0] = l;
          temp[1] = r;

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          ssh_single_des_encrypt(l, r, temp, ctx->key_schedule, TRUE);

          l = SSH_GET_32BIT(src);
          r = SSH_GET_32BIT(src + 4);

          temp[0] ^= l;
          temp[1] ^= r;

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT(ctx->iv, l);
  SSH_PUT_32BIT(ctx->iv + 4, r);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des_ofb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len)
{
  SshDESContext *ctx = (SshDESContext *)context;
  SshUInt32 iv[2], l, r;

  iv[0] = SSH_GET_32BIT(ctx->iv);
  iv[1] = SSH_GET_32BIT(ctx->iv + 4);

  while (len)
    {
      l = iv[0];
      r = iv[1];

      ssh_single_des_encrypt(l, r, iv, ctx->key_schedule, TRUE);

      l = SSH_GET_32BIT(src) ^ iv[0];
      r = SSH_GET_32BIT(src + 4) ^ iv[1];

      SSH_PUT_32BIT(dest, l);
      SSH_PUT_32BIT(dest + 4, r);

      src += 8;
      dest += 8;
      len -= 8;
    }

  SSH_PUT_32BIT(ctx->iv, iv[0]);
  SSH_PUT_32BIT(ctx->iv + 4, iv[1]);
  return SSH_CRYPTO_OK;
}

#ifndef HAVE_3DES

/* Triple des */

typedef struct
{
  SshUInt32 key_schedule[96];
  unsigned char iv[8];
  Boolean for_encryption;
} SshTripleDESContext;


size_t ssh_des3_ctxsize()
{
  return sizeof(SshTripleDESContext);
}

SshCryptoStatus
ssh_des3_init(void *ptr,
              const unsigned char *key, size_t keylen,
              Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  ctx->for_encryption = for_encryption;

  ssh_des_set_key(key, &ctx->key_schedule[0]);
  ssh_des_set_key(&key[8], &ctx->key_schedule[1*32]);
  ssh_des_set_key(&key[16], &ctx->key_schedule[2*32]);

  return SSH_CRYPTO_OK;
}

void ssh_des3_uninit(void *context)
{
  return;
}


SshCryptoStatus
ssh_des3_init_with_key_check(void *ptr,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;

  ctx->for_encryption = for_encryption;

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  /* Check des weak keys. Is this really needed? Better put it here. */
  if (ssh_des_init_is_weak_key(key))
    return SSH_CRYPTO_KEY_WEAK;
  if (ssh_des_init_is_weak_key(key + 8))
    return SSH_CRYPTO_KEY_WEAK;
  if (ssh_des_init_is_weak_key(key + 16))
    return SSH_CRYPTO_KEY_WEAK;

  /* Check if K1 is same than K2, or K2 is same than K3. */
  if (memcmp(key, key + 8, 8) == 0 ||
      memcmp(key + 8, key + 16, 8) == 0)
    return SSH_CRYPTO_KEY_INVALID;

  ssh_des_set_key(key, &ctx->key_schedule[0]);
  ssh_des_set_key(&key[8], &ctx->key_schedule[1*32]);
  ssh_des_set_key(&key[16], &ctx->key_schedule[2*32]);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_start(void *context, const unsigned char *iv)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;

  memcpy(ctx->iv, iv, 8);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_ecb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;
  SshUInt32 output[2], l, r;
  Boolean for_encryption = ctx->for_encryption;

  while (len)
    {
      l = SSH_GET_32BIT(src);
      r = SSH_GET_32BIT(src + 4);

      ssh_triple_des_ede_encrypt(l, r, output,
                                 ctx->key_schedule, for_encryption);

      SSH_PUT_32BIT(dest, output[0]);
      SSH_PUT_32BIT(dest + 4, output[1]);

      src += 8;
      dest += 8;
      len -= 8;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_cbc(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;
  SshUInt32 l, r, iv[2], temp[2];
  Boolean for_encryption = ctx->for_encryption;

  iv[0] = SSH_GET_32BIT(ctx->iv);
  iv[1] = SSH_GET_32BIT(ctx->iv + 4);

  if (for_encryption)
    {
      while (len)
        {
          l = SSH_GET_32BIT(src) ^ iv[0];
          r = SSH_GET_32BIT(src + 4) ^ iv[1];

          ssh_triple_des_ede_encrypt(l, r, iv,
                                     ctx->key_schedule, for_encryption);

          SSH_PUT_32BIT(dest, iv[0]);
          SSH_PUT_32BIT(dest + 4, iv[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          l = SSH_GET_32BIT(src);
          r = SSH_GET_32BIT(src + 4);

          ssh_triple_des_ede_encrypt(l, r, temp,
                                     ctx->key_schedule, for_encryption);

          temp[0] ^= iv[0];
          temp[1] ^= iv[1];

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          iv[0] = l;
          iv[1] = r;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT(ctx->iv, iv[0]);
  SSH_PUT_32BIT(ctx->iv + 4, iv[1]);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_cfb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;
  SshUInt32 l, r, temp[2];

  l = SSH_GET_32BIT(ctx->iv);
  r = SSH_GET_32BIT(ctx->iv + 4);

  if (ctx->for_encryption)
    {
      while (len)
        {
          ssh_triple_des_ede_encrypt(l, r, temp, ctx->key_schedule, TRUE);

          l = temp[0] ^= SSH_GET_32BIT(src);
          r = temp[1] ^= SSH_GET_32BIT(src + 4);

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          ssh_triple_des_ede_encrypt(l, r, temp, ctx->key_schedule, TRUE);

          l = SSH_GET_32BIT(src);
          r = SSH_GET_32BIT(src + 4);

          temp[0] ^= l;
          temp[1] ^= r;

          SSH_PUT_32BIT(dest, temp[0]);
          SSH_PUT_32BIT(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT(ctx->iv, l);
  SSH_PUT_32BIT(ctx->iv + 4, r);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_ofb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;
  SshUInt32 iv[2], l, r;

  iv[0] = SSH_GET_32BIT(ctx->iv);
  iv[1] = SSH_GET_32BIT(ctx->iv + 4);

  while (len)
    {
      l = iv[0];
      r = iv[1];

      ssh_triple_des_ede_encrypt(l, r, iv, ctx->key_schedule, TRUE);

      l = SSH_GET_32BIT(src) ^ iv[0];
      r = SSH_GET_32BIT(src + 4) ^ iv[1];

      SSH_PUT_32BIT(dest, l);
      SSH_PUT_32BIT(dest + 4, r);

      src += 8;
      dest += 8;
      len -= 8;
    }

  SSH_PUT_32BIT(ctx->iv, iv[0]);
  SSH_PUT_32BIT(ctx->iv + 4, iv[1]);
  return SSH_CRYPTO_OK;
}
#endif /* !HAVE_3DES */
