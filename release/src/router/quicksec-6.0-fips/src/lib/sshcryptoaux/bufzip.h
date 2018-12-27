/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Compression of data in buffers.
*/

#ifndef BUFZIP_H
#define BUFZIP_H

#include "sshbuffer.h"

/* Data type for a compression context. */
typedef struct SshCompressionRec *SshCompression;

/* Allocates and initializes a compression context.  `name' is the
   name of the compression method to use.  This returns NULL if the
   given name is not valid.  The returned object must be freed with
   ssh_compress_free when no longer needed.  The `for_compression'
   flag should be TRUE if the object is to be used for compression,
   and FALSE if it is for uncompression. `level' is the compression
   level to be used. If it is set to `-1', the default level is
   used. */
SshCompression ssh_compress_allocate(const char *name,
                                     int level,
                                     Boolean for_compression);

/* Frees the given compression context. */
void ssh_compress_free(SshCompression z);

/* Returns the names of the supported algorithms as a comma-separated
   list. The caller must free the returned string with ssh_xfree when no
   longer needed. */
char *ssh_compress_get_supported(void);

/* Returns true if the given compression method does not actually compress
   (it just returns the input data). */
Boolean ssh_compress_is_none(SshCompression z);

#ifdef SSHDIST_ZLIB
#ifdef SSHDIST_ZLIB_LEVEL_DETECTION

/* Syncronize in incoming deflated i stream with an outgoing inflated
   stream o.  After this function has been called, o will have roughly
   the same compression level as i until it is changed by hand.  If
   any of the two streams has compression level other than "zlib",
   this function does nothing at all. */
void ssh_compress_sync_levels(SshCompression i, SshCompression o);

#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */
#endif /* SSHDIST_ZLIB */

/* Compresses or uncompresses the given data into output_buffer.  The
   performed operations depends on whether the object was created for
   compression or for uncompression.  All data compressed using the
   same object will form a single data stream; however, data will be
   flushed at the end of every call so that each compressed
   `output_buffer' can be decompressed independently by the receiver
   (but in the appropriate order since they together form a single
   compression stream).  This appends the compressed data to the
   output buffer. */
void ssh_compress_buffer(SshCompression z, const unsigned char *data,
                         size_t len, SshBuffer output_buffer);

#endif /* BUFZIP_H */
