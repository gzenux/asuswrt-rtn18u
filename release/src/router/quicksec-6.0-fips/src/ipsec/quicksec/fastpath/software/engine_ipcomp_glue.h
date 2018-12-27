/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP payload compression (IPComp) support.

   <keywords IPComp (IP payload compression), IP payload compression (IPComp),
   payload compression, compression/payload>
*/

#ifdef SSHDIST_IPSEC_IPCOMP
#ifndef ENGINE_IPCOMP_GLUE_H
#define ENGINE_IPCOMP_GLUE_H






#ifdef SSHDIST_ZLIB
#include "zlib.h"
#endif /* SSHDIST_ZLIB */

 /** Definition structure for all compression algorithms. */
typedef struct SshCompressDefRec
{
  /** The name of the compression algorithm. */
  const char * name;

  /** Returns the maximum buffer needed to _compress_ an input of length
      'input_len'. */
  size_t (*maxbuf)(size_t input_len);

  /** Gets compression context from a preallocated list. */
  void * (*get_context)(SshFastpath fastpath,
                        Boolean for_compression);

  /**  Returns compression context to the preallocated list */
  void (*release_context)(SshFastpath fastpath,
                          void * contex);

  /** Performs compression or decompression transform. */
  Boolean (*transform)(void * context,
                       unsigned char *dst,
                       size_t * dst_len,
                       const unsigned char *src,
                       size_t src_len);
} SshCompressDefStruct, *SshCompressDef;


/** A simple linked list for maintaining buffers used
    during IP payload compression and decompression. */

typedef struct SshFastpathIpcompListRec
{
  SshUInt32 num_refs;
  SshUInt16 num_buffers;
  SshUInt16 num_allocated;
  struct
  {
    unsigned char *space;
    size_t size;
    Boolean in_use;
  } *buffers;
} SshFastpathIpcompListStruct, *SshFastpathIpcompList;

/* Initializes the buffers used during IPComp deflate operation. These
   buffers are shared across all transforms. */
Boolean ssh_fastpath_ipcomp_buffer_list_init(SshFastpathIpcompList list);

/* Deallocates all memory assigned for performing IPComp operations. */
void ssh_fastpath_ipcomp_buffer_list_free(SshFastpathIpcompList list);















































#ifdef SSHDIST_ZLIB

/** The default memory level. */
#define SSH_COMPRESS_DEF_MEM_LEVEL 8

/** Number of preallocated buffers to be used in deflate algorithm */



#define SSH_COMPRESS_ZLIB_NUM_BUFFERS 35

typedef struct SshCompressDeflateContextRec
{
#ifdef DEBUG_LIGHT
  SshUInt32 self_index;
#endif /* DEBUG_LIGHT */
  Boolean for_compression;
  Boolean in_use;
  z_stream zlib_stream;
}SshCompressDeflateContextStruct, *SshCompressDeflateContext;

/** Returns the maximum buffer needed to _compress_ an input of length
    'input_len' with deflate. */
size_t ssh_compression_deflate_maxbuf(size_t input_len);


/** Finds an unused transform context from a preallocated list of transform
    contexts */

void * ssh_compression_deflate_get_context(SshFastpath fastpath,
                                           Boolean for_compression);

/** Releases the transform context to the preallocated list */

void ssh_compression_deflate_release_context(SshFastpath fastpath,
                                             void *context);

/** Performs a compression or decompression transform. */
Boolean ssh_compression_deflate_transform(void *context,
                                          unsigned char *dest,
                                          size_t *dest_len,
                                          const unsigned char *src,
                                          size_t src_len);

/* Initializes the buffers used during zlib operations. All runtime
   memory calls will be handled by this buffer. */
Boolean ssh_fastpath_ipcomp_zlib_buffer_init(SshFastpathIpcompList list,
                                           SshUInt32 num_cpus);

/* Allocates and initializes the zlib compression context array.*/
Boolean ssh_fastpath_ipcomp_zlib_context_allocate(SshFastpath fastpath);

/* Deallocates memory reserved for zlib compression contexts */
void ssh_fastpath_ipcomp_zlib_context_free(SshFastpath fastpath);
#endif /* SSHDIST_ZLIB */

/** Describes the status of the outbound compression operation. */
typedef enum
{
  /** Payload was successfully compressed/decmpressed. */
  SSH_FASTPATH_IPCOMP_SUCCESS,
  /** Payload cannot be compressed. However further
      transforms can be applied. */
  SSH_FASTPATH_IPCOMP_PASSBY,
  /** Memory is not available for the (de)compression routine. */
  SSH_FASTPATH_IPCOMP_NO_MEMORY,
  /** Error encountered while performing (de)compression. Drop
      the packet. */
  SSH_FASTPATH_IPCOMP_DROP
} SshFastpathTransformIpcompStatus;

/** This is the output from the adaptive algorithm. This tells whether
    IPComp should be applied or not. The algorithm is consulted before
    any IPComp operation is attempted. */
typedef enum
{
  /** No compression should be attempted on this packet. */
  SSH_FASTPATH_TRANSFORM_NO_COMPRESS = 0,
  /** The packet can be compressed. */
  SSH_FASTPATH_TRANSFORM_DO_COMPRESS = 1,
  /** Attempt compression on the packet. The compression might
      not yield good results. */
  SSH_FASTPATH_TRANSFORM_TRY_COMPRESS = 2
} SshFastpathTransformIpcompState;

#endif /* ENGINE_IPCOMP_GLUE_H */
#endif /* SSHDIST_IPSEC_IPCOMP */

