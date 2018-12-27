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

#ifndef _SSH_BIT_VECTOR_
#define _SSH_BIT_VECTOR_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SSH_BITVEC_OK,            /* returned by: any */
  SSH_BITVEC_BIT_ON,        /* returned by: query */
  SSH_BITVEC_BIT_OFF,       /* returned by: query */
  SSH_BITVEC_INVALID_INDEX, /* returned by: set/clear/query */
  SSH_BITVEC_ALLOC_ERROR,   /* returned by: set/resize */
  SSH_BITVEC_FIXED_SIZE,    /* returned by: resize */
  SSH_BITVEC_NOT_FOUND      /* returned by: find_first_clear */

} SshBitStatus;

typedef struct SshBitVectorRec *SshBitVector;

/* internally the bits are arranged as a byte array in the following way:
 *
 *       BYTE 0                  BYTE 1
 *
 * [ 7 6 5 4 3 2 1 0 ]  [ 15 14 13 12 11 10 9 8 ]  etc...
 *
 */



/*
 * Creates a bitvector context. If the initial_size is zero, the
 * bitvector will be a dynamically sized bitvector. Othwerwise it
 * will be fixed size and all references above the initial_size - 1
 * index will cause an error value to be returned.
 */
SshBitVector ssh_bitvector_create(SshUInt32 initial_size);

/*
 * Creates a bitvector context from a byte array. Bits in bytes are in
 * most significant bit first order and bytes in the array are in the
 * least significant byte first order. bit_count tells how many bits are
 * contained in the byte array. fixed_size is true if you want to create
 * a fixed size bit vector context (the size is 'bit_count').
 *
 */
SshBitVector ssh_bitvector_import(unsigned char *byte_array,
                                  SshUInt32 bit_count,
                                  Boolean fixed_size,
                                  Boolean swap_bits);

/*
 * Creates a byte array from the internal bit status of the bitvector.
 * byte_array is allocated and have to be freed with ssh_xfree by the
 * caller. Bytes in the byte_array are in least significant byte first
 * order and the bits in the byte are in the most significant bit
 * first order. The size of the allocated byte_array can be calculated in the
 * following way: (bit_count + 7) / 8.
 *
 */
SshBitStatus ssh_bitvector_export(SshBitVector v,
                                  unsigned char **byte_array,
                                  SshUInt32 *bit_count,
                                  Boolean swap_bits);
/*
 * Destroys a bit vector context
 *
 */
void ssh_bitvector_destroy(SshBitVector v);

/*
 * Sets a bit 'bit_num' to "on" state in the bit vector. If bit_num
 * is greater than the size of the bitvector in bits and
 * bit vector is fixed sized, this function will return an
 * error code.
 *
 */
SshBitStatus ssh_bitvector_set_bit(SshBitVector v, SshUInt32 bit_num);

/*
 * Clears a bit 'bit_num' to "off" state in the bit vector. If bit_num
 * is greater than the size of the bitvector in bits and
 * bit vector is fixed sized, this function will return an
 * error code.
 *
 */
SshBitStatus ssh_bitvector_clear_bit(SshBitVector v, SshUInt32 bit_num);

/*
 * Returns the status of a bit 'bit_num'. If bit vector
 * is dynamically sized, querying bits outside of the range
 * (0..num_bits-1) returns BIT_OFF status, but if the vector is fixed sized
 * this function will return INVALID_INDEX error
 *
 */
SshBitStatus ssh_bitvector_query_bit(SshBitVector v, SshUInt32 bit_num);

/*
 * Resizes the bitvector. When size is reduced bit data outside the
 * new size is lost
 *
 */
SshBitStatus ssh_bitvector_resize(SshBitVector v, SshUInt32 bit_count);

/*
 * returns the current size in bits of the bit vector
 *
 */
SshUInt32 ssh_bitvector_get_bit_count(SshBitVector v);

/*
 * Counts the number of zeroes or ones in the bit vector.  `bit_value'
 * should be either 0 or 1.
 */
SshUInt32 ssh_bitvector_count_value(SshBitVector v, SshUInt32 bit_value);

/*
 * Finds the lowest numbered bit, starting from `startpos', that has the
 * specified value `bit_value'.  This returns the index of the bit, or
 * -1 if no such bit is found.  (Zero bits will always be found, because
 * there are infinitely many implicit zero bits at the end of the vector.)
 */
SshInt32 ssh_bitvector_find_bit(SshBitVector v, SshUInt32 startpos,
                                SshUInt32 bit_value);

/*
 * Adds all one bits from `v2' to `v' (i.e., computes the logical "or" of
 * the two bit vectors, and stores the result in `v').
 */
SshBitStatus ssh_bitvector_or(SshBitVector v, SshBitVector v2);

#ifdef __cplusplus
}
#endif

#endif /* _SSH_BIT_VECTOR_ */
