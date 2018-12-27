/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sshencode/type specific encodes for debug builds. These functions
   are used by encoding macros and they produce compiler
   warnings/errors if invalid type is given to encoder VA list.
*/

#include "sshincludes.h"
#include "sshencode.h"

/* This stuff does not get compiled if we are building unified-kernel
   module for quicksec, as that inherits these symbols from
   libssh.a */
#ifndef SSH_IPSEC_UNIFIED_KERNEL

#ifdef DEBUG_LIGHT

unsigned char *ssh_xxcode_unsigned_char_ptr(unsigned char *ptr)
{
  return ptr;
}

const unsigned char *
ssh_xxcode_const_unsigned_char_ptr(const unsigned char *ptr)
{
  return ptr;
}

const char *
ssh_xxcode_const_char_ptr(const char *ptr)
{
  return ptr;
}

char **ssh_xxcode_char_ptr_ptr(char **ptr)
{
  return ptr;
}

unsigned char **ssh_xxcode_unsigned_char_ptr_ptr(unsigned char **ptr)
{
  return ptr;
}

const unsigned char **
ssh_xxcode_const_unsigned_char_ptr_ptr(const unsigned char **ptr)
{
  return ptr;
}

size_t ssh_xxcode_size_t(size_t size)
{
  return size;
}

size_t *ssh_xxcode_size_t_ptr(size_t *size)
{
  return size;
}

SshUInt32 ssh_xxcode_uint32(SshUInt32 num)
{
  return num;
}

SshUInt32 *ssh_xxcode_uint32_ptr(SshUInt32 *ptr)
{
  return ptr;
}

SshUInt64 ssh_xxcode_uint64(SshUInt64 num)
{
  return num;
}

SshUInt64 *ssh_xxcode_uint64_ptr(SshUInt64 *ptr)
{
  return ptr;
}

SshUInt16 ssh_xxcode_uint16(SshUInt16 num)
{
  return num;
}

SshUInt16 *ssh_xxcode_uint16_ptr(SshUInt16 *ptr)
{
  return ptr;
}

Boolean ssh_xxcode_boolean(Boolean num)
{
  return num;
}

Boolean *ssh_xxcode_boolean_ptr(Boolean *ptr)
{
  return ptr;
}

void *ssh_xxcode_void_ptr(void *ptr)
{
  return ptr;
}

const void *ssh_xxcode_const_void_ptr(const void *ptr)
{
  return ptr;
}

void **ssh_xxcode_void_ptr_ptr(void **ptr)
{
  return ptr;
}

SshEncodeDatum ssh_xxcode_encode_datum(SshEncodeDatum datum)
{
  return datum;
}

SshDecodeDatum ssh_xxcode_decode_datum(SshDecodeDatum datum)
{
  return datum;
}

SshDecodeDatumNoAlloc
ssh_xxcode_decode_datum_noalloc(SshDecodeDatumNoAlloc datum)
{
  return datum;
}

unsigned int ssh_xxcode_unsigned_int(unsigned int num)
{
  return num;
}

unsigned int *ssh_xxcode_unsigned_int_ptr(unsigned int *ptr)
{
  return ptr;
}

#endif /* DEBUG_LIGHT */
#endif /* SSH_IPSEC_UNIFIED_KERNEL */
