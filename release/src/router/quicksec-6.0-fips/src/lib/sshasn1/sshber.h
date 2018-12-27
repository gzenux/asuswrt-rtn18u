/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   BER encoding.
*/

#ifndef SSHBER_H
#define SSHBER_H

#include "sshasn1.h"
#include "sshobstack.h"

/* Status reports from BER/DER routines. */

typedef enum
{
  /* BER/DER operation succeeded as planned. */
  SSH_BER_STATUS_OK,

  /* BER/DER operation failed. */
  SSH_BER_STATUS_ERROR,

  /* BER/DER decode failed. */
  SSH_BER_STATUS_DECODE_FAILED,
  /* BER/DER encode failed. */
  SSH_BER_STATUS_ENCODE_FAILED,

  /* Buffer contains too little space. */
  SSH_BER_STATUS_BUFFER_TOO_SMALL,
  /* Buffer size was too small and contained data that implied otherwise. */
  SSH_BER_STATUS_BUFFER_OVERFLOW,

  /* Given table is too small. */
  SSH_BER_STATUS_TABLE_TOO_SMALL,

  /* This feature is not available. */
  SSH_BER_STATUS_NOT_AVAILABLE,

  /* Tag of the object is too large (larger than 32 bits). */
  SSH_BER_STATUS_TAG_TOO_LARGE,

  /* Data area is way too large (larger than 32 bits). */
  SSH_BER_STATUS_DATA_TOO_LONG,

  /* This method is not implemented yet in this revision. */
  SSH_BER_STATUS_NOT_IMPLEMENTED
} SshBerStatus;

/* The freelist interface. The freelist here doesn't mean optimization for
   allocation but rather storage for allocated data, which we need to
   remember to free if failure occurs at some point.

   This list is used by the ASN.1 parser. It would be possible to use
   the stack, which we use anyway, to retrack what has been allocated.
   However, it would be very cumbersome. This way we don't need to touch
   the stack anymore. */
/* Routines for freeing from the list of allocated things data. */

struct SshBerFreeListRec
{
  /* Array of pointers that are to be freed */
  unsigned char *elements_static[5];
  unsigned char **elements;

  /* number of elements at elements/elements_static arrays */
  size_t num_elements;
  /* sizeof of elements or elements_static array */
  size_t num_elements_alloc;
};

typedef struct SshBerFreeListRec **SshBerFreeList;
typedef struct SshBerFreeListRec SshBerFreeListStruct;

/* Allocate a freelist. Currently just returns NULL! */
SshBerFreeList ssh_ber_freelist_allocate(void);

/* Free the freelist. If 'free_data' is true then also the data stored
   in the freelist is freed. */
void ssh_ber_freelist_free(SshBerFreeList list, Boolean free_data);

/* The ber interface. */

/* Compute the length of tag for certain ASN.1 type. Returns bytes needed
   to encode this tag (not the contents). */

size_t ssh_ber_compute_tag_length(SshAsn1Class a_class,
                                  SshAsn1Encoding encoding,
                                  SshAsn1Tag tag_number,
                                  SshAsn1LengthEncoding lenght_encoding,
                                  size_t length);

/* Set the tag octets to the given buffer (buf). Encoding is performed
   in DER. */

SshBerStatus ssh_ber_set_tag(unsigned char *buf, size_t len,
                             SshAsn1Class a_class, SshAsn1Encoding encoding,
                             SshAsn1Tag tag_number,
                             SshAsn1LengthEncoding length_encoding,
                             size_t length);

/* Opens given buffer, if it can be understood. data will point to the
   given buffer. */

SshBerStatus ssh_ber_open_element(unsigned char *buf, size_t len,
                                  SshAsn1Class *a_class,
                                  SshAsn1Encoding *encoding,
                                  SshAsn1Tag *tag_number,
                                  SshAsn1LengthEncoding *length_encoding,
                                  size_t *tag_length,
                                  unsigned char **tag,
                                  size_t *length,
                                  unsigned char **data);

/* Return size of the ber object in the buffer. Returns 0 if the
   length is indefinite, and (size_t)-1 if error (buffer too short),
   Otherwise returns number of bytes used by the asn1 object. */
size_t ssh_ber_get_size(const unsigned char *buf, size_t len);

/* About encoding/decoding prototypes.

   These prototypes are used by asn1create.c and are not intended to
   be used elsewhere. .

   Encoding routines are called with
     cmalloc context
     type's class, encoding, tag-number, length-encoding
     and type specific arguments (optional value, optional len)

     returned is
      data, length, tag, and tag_length

   Decoding routines are called with
     data, length

   returned is
     optional data and optional length are written into
     last two void input pointers.


   This prototype is very useful, nobody wants to write this large
   prototypes ;) */

#define SSH_BER_ENCODE_PROTOTYPE(name, arg1, arg2) \
SshBerStatus ssh_ber_encode_##name(SshObStackContext context,   \
                                   SshAsn1Class a_class,        \
                                   SshAsn1Encoding encoding,    \
                                   SshAsn1Tag tag_number,       \
                                   SshAsn1LengthEncoding length_encoding,  \
                                   unsigned char **data,        \
                                   size_t *length,              \
                                   unsigned char **tag,         \
                                   size_t *tag_length,          \
                                   arg1, arg2)

/* Encoding ASN.1 BER types. */

/* Encoding boolean type. va_list contains Boolean value that is encoded.
   ap is advanced over the boolean value. */
SSH_BER_ENCODE_PROTOTYPE(boolean,
                         void *pbool, void *ignore);

/* Encoding a Multiple Precision integer. */
SSH_BER_ENCODE_PROTOTYPE(integer,
                         void *pinteger, void *ignore);

/* Encoding a bit string. */
SSH_BER_ENCODE_PROTOTYPE(bit_string,
                         void *pbit_string, void *pbit_length);

/* Encoding an octet string. */
SSH_BER_ENCODE_PROTOTYPE(octet_string,
                         void *poctet_string, void *poctet_length);

/* Encoding a null value. */
SSH_BER_ENCODE_PROTOTYPE(null,
                         void *ignore1, void *ignore2);

/* Encoding a empty value. */
SSH_BER_ENCODE_PROTOTYPE(empty,
                         void *ignore1, void *ignore2);

/* Encoding an object identifier values. */
SSH_BER_ENCODE_PROTOTYPE(oid_type,
                         void *poid_str, void *ignore);

/* Encoding an universal time value. */
SSH_BER_ENCODE_PROTOTYPE(universal_time,
                         void *ptimeval, void *ignore);

/* Encoding an generalized time value. */
SSH_BER_ENCODE_PROTOTYPE(generalized_time,
                         void *ptimeval, void *ignore);


/* Encoding a SshWord. */
SSH_BER_ENCODE_PROTOTYPE(integer_short,
                         void *pword, void *ignore);

/* Decoding ASN.1 BER types. */

/* Decoding a boolean value. */
SshBerStatus
ssh_ber_decode_boolean(unsigned char *data, size_t length,
                       SshBerFreeList list,
                       void *boolean, void *ignore);

/* Decoding an integer (multiple precision) value. */
SshBerStatus
ssh_ber_decode_integer(unsigned char *data, size_t length,
                       SshBerFreeList list,
                       void *integer, void *ignore);

/* Decoding a bit string. data is decoded to the pair (unsigned char
   **, unsigned int *) */
SshBerStatus
ssh_ber_decode_bit_string(unsigned char *data, size_t length,
                          SshBerFreeList list,
                          void *bit_string, void *bit_length);

/* Decoding a octet string. data is decoded to pair (unsigned char **,
   size_t *). */
SshBerStatus
ssh_ber_decode_octet_string(unsigned char *data, size_t length,
                            SshBerFreeList list,
                            void *octet_string, void *octet_length);

/* Decoding a null value. This is a bit simple, but included here for
   completeness.. */
SshBerStatus
ssh_ber_decode_null(unsigned char *data, size_t length,
                    SshBerFreeList list,
                    void *ignore1, void *ignore2);

/* Decoding a empty value. This is a bit simple, but included here for
   completeness. */
SshBerStatus
ssh_ber_decode_empty(unsigned char *data, size_t length,
                     SshBerFreeList list,
                     void *ignore1, void *ignore2);

/* Decoding a object identifier values. */
SshBerStatus
ssh_ber_decode_oid_type(unsigned char *data, size_t length,
                        SshBerFreeList list,
                        void *oid_str, void *ignore);

/* Decoding an universal time value. */
SshBerStatus
ssh_ber_decode_universal_time(unsigned char *data, size_t length,
                              SshBerFreeList list,
                              void *timeval, void *ignore);

/* Decoding a generalized time value. */
SshBerStatus
ssh_ber_decode_generalized_time(unsigned char *data, size_t length,
                                SshBerFreeList list,
                                void *timeval, void *ignore);

/* Decoding an integer_short (SshWord) value. */
SshBerStatus
ssh_ber_decode_integer_short(unsigned char *data, size_t length,
                             SshBerFreeList list,
                             void *return_word, void *ignore);

#endif /* SSHBER_H */
