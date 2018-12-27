/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains functions for creating and
   manipulating bit vectors. Bit vector is an arbitrary
   sized "boolean" array. You can set/get/query bit status on
   the array.
*/

#include "sshincludes.h"
#include "sshbitvector.h"

struct SshBitVectorRec {

  Boolean fixed_size;     /* is vector fixed_size */
  SshUInt32 size;         /* Current size in bytes */
  SshUInt32 bit_count;    /* Current size in bits (may be lower than 8*size) */
  unsigned char *bytes;   /* bit data in byte array. 8 bits per byte */

};

SshBitVector ssh_bitvector_create(SshUInt32 initial_size)
{
  int i;
  SshBitVector v;

  if (!(v = (SshBitVector)ssh_malloc(sizeof(*v))))
    {
      return NULL;
    }

  if (initial_size > 0)
    {
      v->fixed_size = 1;
      v->bit_count = initial_size;
      v->size = (initial_size + 7) / 8;
      v->bytes = (unsigned char *)ssh_malloc(v->size);
      if (!v->bytes)
        {
          ssh_free(v);
          return NULL;
        }
      for (i=0; i<v->size; i++) v->bytes[i] = 0;
    }
  else
    {
      v->bit_count = 0;
      v->size = 0;
      v->fixed_size = 0;
      v->bytes = NULL;
    }
  return v;
}

static const unsigned char swap_table[256] = {
  0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0,
  0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
  0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8,
  0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
  0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4,
  0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
  0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC,
  0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
  0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2,
  0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
  0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA,
  0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
  0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6,
  0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
  0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE,
  0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
  0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1,
  0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
  0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9,
  0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
  0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5,
  0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
  0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED,
  0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
  0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3,
  0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
  0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB,
  0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
  0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7,
  0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
  0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF,
  0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};

SshBitVector ssh_bitvector_import(unsigned char *byte_array,
                                  SshUInt32 bit_count,
                                  Boolean fixed_size,
                                  Boolean swap_bits)
{
  SshUInt32 i;
  SshBitVector v;

  if (!(v = (SshBitVector)ssh_calloc(1, sizeof(*v))))
    {
      return NULL;
    }
  v->bit_count = bit_count;
  v->size = (bit_count + 7) / 8;
  v->fixed_size = fixed_size;

  if (v->size)
    {
      v->bytes = (unsigned char *)ssh_malloc(v->size);
      if (!v->bytes)
        {
          ssh_free(v);
          return NULL;
        }
      for (i=0; i<v->size; i++)
        v->bytes[i] = ((swap_bits)?
                       (swap_table[byte_array[i]]):(byte_array[i]));
    }
  return v;
}

SshBitStatus ssh_bitvector_export(SshBitVector v,
                                  unsigned char **byte_array,
                                  SshUInt32 *bit_count,
                                  Boolean swap_bits)
{
  SshUInt32 i;

  *bit_count = v->bit_count;
  *byte_array = (unsigned char *)ssh_malloc(v->size);

  if (!*byte_array)
    {
      return SSH_BITVEC_ALLOC_ERROR;
    }

  for (i=0; i<v->size; i++)
    (*byte_array)[i] = ((swap_bits)?(swap_table[v->bytes[i]]):(v->bytes[i]));

  return SSH_BITVEC_OK;
}

void ssh_bitvector_destroy(SshBitVector v)
{
  if (v)
    {
      ssh_free(v->bytes);
      ssh_free(v);
    }
}

SshBitStatus ssh_bitvector_resize(SshBitVector v, SshUInt32 bit_count)
{
  unsigned char *t;
  SshUInt32 size;

  size = (bit_count + 7) / 8;
  if (size != v->size)
    {
      t = (unsigned char *)ssh_realloc(v->bytes, v->size, size);
      if (!t)
        {
          return SSH_BITVEC_ALLOC_ERROR;
        }
      v->bytes = t;
      if (size > v->size)
        memset(&v->bytes[v->size], 0, size - v->size);
      v->size = size;
      v->bit_count = bit_count;
    }
  return SSH_BITVEC_OK;
}

/*
 * Internally used function to check bit indexes and also to allocate
 * more space for bits.
 *
 */
static SshBitStatus handle_bit_index(SshBitVector v,
                                     SshUInt32 bit_num,
                                     Boolean can_alloc)
{
  SshUInt32 size;
  unsigned char *t;

  if (bit_num + 1 > v->bit_count)
    {
      if (!can_alloc)
        {
          return SSH_BITVEC_INVALID_INDEX;
        }
      size = bit_num / 8 + 1; /* Note: bit bit_num is included in size */
      if (size > v->size)
        {
          /* Increase a bit more, to reduce the worst case number of reallocs
             when adding *many* bits. */
          size += size / 4 + 64;
          t = ssh_realloc(v->bytes, v->size, size);
          if (!t)
            {
              return SSH_BITVEC_ALLOC_ERROR;
            }
          v->bytes = t;
          memset(&v->bytes[v->size], 0, size - v->size);
          v->size = size;
        }
      v->bit_count = bit_num + 1;
    }
  return SSH_BITVEC_OK;
}

SshBitStatus ssh_bitvector_set_bit(SshBitVector v, SshUInt32 bit_num)
{
  SshBitStatus r = handle_bit_index(v, bit_num, !v->fixed_size);
  if (r != SSH_BITVEC_OK)
    {
      return r;
    }
  v->bytes[bit_num / 8] |= (1 << (bit_num % 8));
  return SSH_BITVEC_OK;
}


SshBitStatus ssh_bitvector_clear_bit(SshBitVector v, SshUInt32 bit_num)
{
  SshBitStatus r = handle_bit_index(v, bit_num, 0);

  if (r != SSH_BITVEC_OK)
    {
      if (v->fixed_size)
        return SSH_BITVEC_INVALID_INDEX;
    }
  else
    {
      v->bytes[bit_num / 8] &= ~(1 << (bit_num % 8));
    }
  return SSH_BITVEC_OK;
}

SshBitStatus ssh_bitvector_query_bit(SshBitVector v, SshUInt32 bit_num)
{
  SshBitStatus r = handle_bit_index(v, bit_num, 0);

  if (r != SSH_BITVEC_OK)
    {
      if (v->fixed_size)
        return SSH_BITVEC_INVALID_INDEX;
      else
        return SSH_BITVEC_BIT_OFF;
    }
  else
    {
      if (v->bytes[bit_num / 8] & (1 << (bit_num % 8)))
        return SSH_BITVEC_BIT_ON;
      else
        return SSH_BITVEC_BIT_OFF;
    }
}

SshUInt32 ssh_bitvector_get_bit_count(SshBitVector v)
{
  return v->bit_count;
}

SshUInt32 ssh_bitvector_count_value(SshBitVector v, SshUInt32 bit_value)
{
  unsigned char none_value, all_value, x;
  SshUInt32 i, j, count;

  none_value = bit_value ? 0x00 : 0xff;
  all_value = bit_value ? 0xff : 0x00;
  count = 0;
  for (i = 0; i < v->bit_count; i += 8)
    {
      x = v->bytes[i / 8];
      if (x == none_value)
        continue;
      if (x == all_value)
        {
          count += 8;
          continue;
        }
      if (bit_value)
        {
          for (j = 0; j < 8; j++)
            if (x & (1 << j))
              count++;
        }
      else
        {
          for (j = 0; j < 8; j++)
            if (!(x & (1 << j)))
              count++;
        }
    }
  return count;
}

SshInt32 ssh_bitvector_find_bit(SshBitVector v, SshUInt32 startpos,
                                SshUInt32 bit_value)
{
  unsigned char none_value, x;
  SshUInt32 i, j;

  none_value = bit_value ? 0x00 : 0xff;
  while (startpos & 7)
    {
      if (bit_value)
        {
          if (startpos >= v->bit_count)
            return -1;
          if (v->bytes[startpos / 8] & (1 << (startpos & 7)))
            return startpos;
        }
      else
        {
          if (startpos >= v->bit_count)
            return startpos;
          if (!(v->bytes[startpos / 8] & (1 << (startpos & 7))))
            return startpos;
        }
      startpos++;
    }
  for (i = startpos; i < v->bit_count; i += 8)
    {
      x = v->bytes[i / 8];
      if (x == none_value)
        continue;
      if (bit_value)
        {
          for (j = 0; j < 8; j++)
            if (x & (1 << j))
              return i + j;
        }
      else
        {
          for (j = 0; j < 8; j++)
            if (!(x & (1 << j)))
              return i + j;
        }
    }
  if (bit_value)
    return -1;
  else
    return i;
}

SshBitStatus ssh_bitvector_or(SshBitVector v, SshBitVector v2)
{
  SshBitStatus r;
  SshUInt32 i, num_bytes;

  /* Increase the size of v enough to hold v2's bits. */
  r = handle_bit_index(v, (v2->bit_count > 0 ? v2->bit_count - 1 : 0),
                       !v->fixed_size);
  if (r != SSH_BITVEC_OK)
    return r;

  /* Or v2's bytes to v's bytes. */
  num_bytes = (v2->bit_count + 7) / 8;
  for (i = 0; i < num_bytes; i++)
    v->bytes[i] |= v2->bytes[i];

  return SSH_BITVEC_OK;
}
