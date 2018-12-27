/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A generic wrapper for various compression methods.
*/

#include "sshincludes.h"
#include "bufzip.h"
#ifdef SSHDIST_ZLIB
#include "zlib.h"
#endif /* SSHDIST_ZLIB */

#if defined SSHDIST_ZLIB_LEVEL_DETECTION && !defined SSHDIST_ZLIB
#error "zlib level detection requires zlib."
#endif

#define SSH_DEBUG_MODULE "SshBufZIP"

typedef enum {
  SSH_COMPRESS_NONE,
  SSH_COMPRESS_ZLIB
} SshCompressionMethod;

struct SshCompressionRec
{
  SshCompressionMethod method;
  Boolean for_compression;
  SshBuffer buffer;
#ifdef SSHDIST_ZLIB
  z_stream z_stream;
#ifdef SSHDIST_ZLIB_LEVEL_DETECTION
  struct SshCompressionRec *peer;  /* see ssh_compress_sync_levels */
#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */
#endif /* SSHDIST_ZLIB */
};

const struct {
  const char *name;
  SshCompressionMethod method;
  unsigned int level;
  unsigned int min_level;
  unsigned int max_level;
} ssh_compression_methods[] =
  {
    { "none", SSH_COMPRESS_NONE, 0, 0, 0 },
#ifdef SSHDIST_ZLIB
    { "zlib", SSH_COMPRESS_ZLIB, 6, 0, 9 },
#endif /* SSHDIST_ZLIB */
    { NULL }
  };


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
                                     Boolean for_compression)
{
  SshCompression z;
  int i;

  /* Find the compression method from the table. */
  for (i = 0; ssh_compression_methods[i].name != NULL; i++)
    if (strcmp(ssh_compression_methods[i].name, name) == 0)
      break;
  if (ssh_compression_methods[i].name == NULL)
    return NULL;

  if (level == -1)
    level = ssh_compression_methods[i].level;

  if (level < ssh_compression_methods[i].min_level ||
      level > ssh_compression_methods[i].max_level)
    return NULL;

  if (ssh_compression_methods[i].method != SSH_COMPRESS_NONE)
    SSH_DEBUG(4, ("Setting compression algorithm to %s, compression "
                  "level %d", ssh_compression_methods[i].name, level));

  /* Allocate the context structure. */
  if ((z = ssh_malloc(sizeof(*z))) == NULL)
    return NULL;

  memset(z, 'F', sizeof(*z));
  z->method = ssh_compression_methods[i].method;
  z->for_compression = for_compression;
  z->buffer = ssh_xbuffer_allocate();

  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      break;

#ifdef SSHDIST_ZLIB
    case SSH_COMPRESS_ZLIB:
      /* Initialize the compression stream for the appropriate operation.
         For this algorithm, we use the compression level from the table,
         unless compression level was explicitly specified for
         ssh_compress_allocate() call. */
      z->z_stream.zalloc = Z_NULL;
      z->z_stream.zfree = Z_NULL;
      z->z_stream.opaque = Z_NULL;
      if (for_compression)
        deflateInit(&z->z_stream, level);
      else
        inflateInit(&z->z_stream);
      break;
#endif /* SSHDIST_ZLIB */

    default:
      ssh_fatal("ssh_compress_allocate: bad method %d", (int)z->method);
      /*NOTREACHED*/
    }

#ifdef SSHDIST_ZLIB_LEVEL_DETECTION
  z->peer = NULL;
#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */

  return z;
}

/* Frees the given compression context. */

void ssh_compress_free(SshCompression z)
{
  ssh_buffer_free(z->buffer);
  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      break;

#ifdef SSHDIST_ZLIB
    case SSH_COMPRESS_ZLIB:
      if (z->for_compression)
        deflateEnd(&z->z_stream);
      else
        inflateEnd(&z->z_stream);
#ifdef SSHDIST_ZLIB_LEVEL_DETECTION
      /* Whichever stream gets destroyed first must take care that its
         peer's peer pointer is removed. */
      if (z->peer)
        z->peer->peer = NULL;
#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */
      break;
#endif /* SSHDIST_ZLIB */

    default:
      ssh_fatal("ssh_compress_free: unknown method %d", (int)z->method);
      /*NOTREACHED*/
    }

  /* Fill with garbage to ease debugging. */
  memset(z, 'F', sizeof(*z));

  /* Free the context. */
  ssh_free(z);
}

/* Returns the names of the supported algorithms as a comma-separated
   list.  The caller must free the returned string with ssh_xfree when
   no longer needed. This may return NULL pointer. */

char *ssh_compress_get_supported(void)
{
  SshBufferStruct buffer;
  char *cp = NULL;
  int i;

  /* Construct the list of algorithm names from the array. */
  ssh_buffer_init(&buffer);
  for (i = 0; ssh_compression_methods[i].name != NULL; i++)
    {
      if (i != 0)
        {
          if (ssh_buffer_append(&buffer, (unsigned char *) ",", 1)
              != SSH_BUFFER_OK)
            goto error;
        }

      if (ssh_buffer_append(&buffer, (unsigned char *)
                            ssh_compression_methods[i].name,
                            strlen(ssh_compression_methods[i].name))
          != SSH_BUFFER_OK)
        goto error;
    }
  if (ssh_buffer_append(&buffer, (unsigned char *) "\0", 1) == SSH_BUFFER_OK)
    cp = ssh_strdup(ssh_buffer_ptr(&buffer));
 error:
  ssh_buffer_uninit(&buffer);
  return cp;
}

/* Returns true if the given compression method does not actually compress
   (it just returns the input data). */

Boolean ssh_compress_is_none(SshCompression z)
{
  return z->method == SSH_COMPRESS_NONE;
}

#ifdef SSHDIST_ZLIB
#ifdef SSHDIST_ZLIB_LEVEL_DETECTION

/* Syncronize in incoming deflated i stream with an outgoing inflated
   stream o.  After this function has been called, o will have roughly
   the same compression level as i until it is changed by hand.  If
   any of the two streams has compression level other than "zlib",
   this function does nothing at all. */

void ssh_compress_sync_levels(SshCompression i, SshCompression o)
{
  SSH_ASSERT(!i->for_compression);
  SSH_ASSERT(o->for_compression);

  if (i->method == SSH_COMPRESS_ZLIB && o->method == SSH_COMPRESS_ZLIB)
    {
      i->peer = o;
      o->peer = i;
    }
}

#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */

/* Compresses the given data into output_buffer using zlib.
   This is an internal function. */

void ssh_zlib_compress(z_stream *outgoing_stream, const unsigned char *data,
                       size_t len, SshBuffer output_buffer)
{
  unsigned char buf[4096];




  int status;

  /* Prepare source data. */
  outgoing_stream->next_in = (void *)data;
  outgoing_stream->avail_in = len;

  /* Loop compressing until deflate() returns with avail_out != 0. */
  do
    {
      /* Set up fixed-size output buffer. */
      outgoing_stream->next_out = buf;
      outgoing_stream->avail_out = sizeof(buf);

      /* Compress as much data into the buffer as possible. */
      switch ((status = deflate(outgoing_stream, Z_SYNC_FLUSH)))
        {
        case Z_OK:
          /* Append compressed data to output_buffer. */
          ssh_xbuffer_append(output_buffer, buf,
                             sizeof(buf) - outgoing_stream->avail_out);
          break;
        case Z_STREAM_END:
          ssh_fatal("ssh_zlib_compress: deflate returned Z_STREAM_END");
          /*NOTREACHED*/
        case Z_STREAM_ERROR:
          ssh_fatal("ssh_zlib_compress: deflate returned Z_STREAM_ERROR");
          /*NOTREACHED*/
        case Z_BUF_ERROR:
          ssh_fatal("ssh_zlib_compress: deflate returned Z_BUF_ERROR");
          /*NOTREACHED*/
        default:
          ssh_fatal("ssh_zlib_compress: deflate returned %d", status);
          /*NOTREACHED*/
        }
    }
  while (outgoing_stream->avail_out == 0);
  outgoing_stream->avail_out = 0;
}

/* Uncompresses the given data into output_buffer using zlib.
   This is an internal function. */

void ssh_zlib_uncompress(z_stream *incoming_stream, const unsigned char *data,
                         size_t len, SshBuffer output_buffer)
{
  unsigned char buf[4096];
  int status = 0;

  /* Prepare source data. */
  incoming_stream->next_in = (void *)data;
  incoming_stream->avail_in = len;

  incoming_stream->next_out = buf;
  incoming_stream->avail_out = sizeof(buf);

  for (;;)
    {
      status = inflate(incoming_stream, Z_SYNC_FLUSH);
      switch (status)
        {
        case Z_OK:
          ssh_xbuffer_append(output_buffer, buf,
                             sizeof(buf) - incoming_stream->avail_out);
          incoming_stream->next_out = buf;
          incoming_stream->avail_out = sizeof(buf);
          break;
        case Z_STREAM_END:
          ssh_fatal("ssh_zlib_uncompress: inflate returned Z_STREAM_END");
          /*NOTREACHED*/
        case Z_DATA_ERROR:
          ssh_fatal("ssh_zlib_uncompress: inflate returned Z_DATA_ERROR");
          /*NOTREACHED*/
        case Z_STREAM_ERROR:
          ssh_fatal("ssh_zlib_uncompress: inflate returned Z_STREAM_ERROR");
          /*NOTREACHED*/
        case Z_BUF_ERROR:
          /* Comments in zlib.h say that we should keep calling inflate()
             until we get an error.  This appears to be the error that we
             get. */
          return;
        case Z_MEM_ERROR:
          ssh_fatal("ssh_zlib_uncompress: inflate returned Z_MEM_ERROR");
          /*NOTREACHED*/
        default:
          ssh_fatal("ssh_zlib_uncompress: inflate returned %d", status);
        }
    }
}
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
                         size_t len, SshBuffer output_buffer)
{
  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      ssh_xbuffer_append(output_buffer, data, len);
      break;

#ifdef SSHDIST_ZLIB
    case SSH_COMPRESS_ZLIB:
      if (z->for_compression)
        ssh_zlib_compress(&z->z_stream, data, len, output_buffer);
      else
        {
          ssh_zlib_uncompress(&z->z_stream, data, len, output_buffer);
#ifdef SSHDIST_ZLIB_LEVEL_DETECTION
          if (z->peer)
            {
              int level;
              SSH_ASSERT(z->peer->peer == z);
              SSH_ASSERT(z->peer->method == SSH_COMPRESS_ZLIB);
              SSH_ASSERT(z->peer->for_compression);

              if ((level = inflateCompressionLevel(&z->z_stream)))
                {
                  SSH_DEBUG(5,
                            ("adjusting compression level of outstream to %i.",
                             level));
                  deflateParams(&z->peer->z_stream, level, Z_DEFAULT_STRATEGY);

                  /* whipe out the traces.  (with bufzip interface,
                     the only way of renegotiating the level is to
                     shut down the SshCompression structures and open
                     new ones, so from this point on syncing is not
                     needed any more.)  */
                  z->peer->peer = NULL;
                  z->peer = NULL;
                }
            }
#endif /* SSHDIST_ZLIB_LEVEL_DETECTION */
        }
      break;
#endif /* SSHDIST_ZLIB */

    default:
      ssh_fatal("ssh_compress_buffer: unknown method %d", (int)z->method);
    }
}
