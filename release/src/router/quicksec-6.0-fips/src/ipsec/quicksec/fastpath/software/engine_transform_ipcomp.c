/**
   @copyright
   Copyright (c) 2007 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to implement IPComp transforms for packets.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_ipcomp_glue.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformIpcomp"

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
typedef struct
{
  SshFastpathTransformIpcompState instruction;
  SshUInt32 serial;
} SshFastpathTransformIpcompInsRec;


/* **************************************************************
               Buffer management
 ************************************************************** */

/* Get a buffer. This will return memory buffer of size
   SSH_IPSEC_IPCOMP_BUFSIZE bytes. The buffer should be returned to
   pool when no longer needed.  This function will take the engine
   lock. */
static unsigned char *
ssh_fastpath_ipcomp_buffer_get(SshFastpath fastpath,
                               SshFastpathIpcompList list,
                               size_t min_size,
                               size_t *actual_size)
{
  unsigned char *buffer = NULL;
  unsigned int i;

  /* With the fastpath lock do... */
  ssh_kernel_mutex_lock(fastpath->ipcomp_lock);
  if (list->num_buffers > 0)
    {
      for (i = 0; i < list->num_allocated; i++)
        {
          if (!list->buffers[i].in_use && list->buffers[i].size >= min_size)
            {
              buffer = list->buffers[i].space;
              *actual_size = list->buffers[i].size;
              list->buffers[i].in_use = TRUE;
              list->num_buffers--;
              break;
            }
        }
    }
  ssh_kernel_mutex_unlock(fastpath->ipcomp_lock);
  return buffer;
}

/* Return buffer back to pool pointed by list. This function will take
   the fastpath lock */
static void
ssh_fastpath_ipcomp_buffer_release(SshFastpath fastpath,
                                   SshFastpathIpcompList list,
                                   unsigned char *buffer)
{
  unsigned int i;

  if (buffer)
    {
      ssh_kernel_mutex_lock(fastpath->ipcomp_lock);
      for (i = 0; i < list->num_allocated; i++)
        {
          if (list->buffers[i].in_use &&
              (size_t)list->buffers[i].space == (size_t)buffer)
            {
              list->buffers[i].in_use = FALSE;
              list->num_buffers++;
              break;
            }
        }
      ssh_kernel_mutex_unlock(fastpath->ipcomp_lock);
      /* Must have consumed the buffer if it came from the list. */
      SSH_ASSERT(i != list->num_allocated);
    }
}


/* ********************************************************
      Compression algorithm
 ********************************************************* */
#ifdef SSHDIST_ZLIB
static void *
ssh_compression_deflate_alloc(void *opaque,
                              unsigned int items,
                              unsigned int size)
{
  SshFastpath fastpath = (SshFastpath)opaque;
  size_t actual_len;

  SSH_ASSERT(opaque != NULL);

  return ssh_fastpath_ipcomp_buffer_get(fastpath, fastpath->zlib_buf,
                                      items * size, &actual_len);
}

static void
ssh_compression_deflate_free(void *opaque, void *address)
{
  SshFastpath fastpath = (SshFastpath) opaque;

  SSH_ASSERT(fastpath != NULL);
  ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->zlib_buf, address);
}
#endif /* SSHDIST_ZLIB */


/* **********************************************************
              Public functions
 ********************************************************* */

/* **********************************************************
              Compression algorithm related functions
 ********************************************************* */



























































































































































































#ifdef SSHDIST_ZLIB

#define SSH_ENGINE_IPCOMP_ZLIB_DEFLATE_LEVEL 6

static Boolean
ssh_compression_deflate_init(SshFastpath fastpath,
                             SshCompressDeflateContext ctx,
                             Boolean for_compression,
                             Boolean adler_header)
{
  int status;

  ctx->for_compression = for_compression;

  ctx->zlib_stream.zalloc = ssh_compression_deflate_alloc;
  ctx->zlib_stream.zfree = ssh_compression_deflate_free;
  ctx->zlib_stream.opaque = fastpath;

  if (adler_header)
    {
      if (for_compression)
        status = deflateInit(&ctx->zlib_stream,
                             SSH_ENGINE_IPCOMP_ZLIB_DEFLATE_LEVEL);
      else
        status = inflateInit(&ctx->zlib_stream);
    }
  else
    {
      if (for_compression)
        status = deflateInit2_(&ctx->zlib_stream, Z_DEFAULT_COMPRESSION,
                               Z_DEFLATED, -11, SSH_COMPRESS_DEF_MEM_LEVEL,
                               Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                               sizeof(z_stream));
      else
        status = inflateInit2_(&ctx->zlib_stream,  -15, ZLIB_VERSION,
                               sizeof(z_stream));
    }

  if (status == Z_OK)
    return TRUE;
  else
    /* Possible errors after initializations in zlib 1.1.3 (see zlib.h):
        - Z_MEM_ERROR     not enough memory
        - Z_STREAM_ERROR  invalid compression level (deflateInit, should
                          not happen)
        - ZVERSION_ERROR  version number mismatch (should not happen)
    */
    return FALSE;
}

/* Frees the resources reserved by zlib (not the memory reserved for
 the context).  */
static void
ssh_compression_deflate_destructor(void *context)
{
  SshCompressDeflateContext ctx = (SshCompressDeflateContext)context;

  if (ctx->for_compression)
    deflateEnd(&ctx->zlib_stream);
  else
    inflateEnd(&ctx->zlib_stream);
}



size_t ssh_compression_deflate_maxbuf(size_t input_len)
{
  /* zlib.h says that the output buffer for deflate has to be at
     least 0.1% larger than the input buffer plus 12 bytes. */
  return input_len + (input_len >> 9) + 1 + 12;
}


void * ssh_compression_deflate_get_context(SshFastpath fastpath,
                                           Boolean for_compression)
{
  SshUInt32 lower, upper;
  SshCompressDeflateContext deflate_ctx = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));
  lower = for_compression ? 0 : fastpath->num_cpus;
  upper = for_compression ? fastpath->num_cpus : 2 * fastpath->num_cpus;

  ssh_kernel_mutex_lock(fastpath->ipcomp_lock);
  for (; lower < upper; lower++)
    {
      deflate_ctx = fastpath->zlib_context[lower];
      if (deflate_ctx->in_use != TRUE)
        {
          deflate_ctx->in_use = TRUE;
          ssh_kernel_mutex_unlock(fastpath->ipcomp_lock);
          SSH_DEBUG(SSH_D_LOWOK, ("Getting deflate context with index %d",
                                  deflate_ctx->self_index));
          return deflate_ctx;
        }
    }
  ssh_kernel_mutex_unlock(fastpath->ipcomp_lock);
  return NULL;
}


void ssh_compression_deflate_release_context(SshFastpath fastpath,
                                             void * context)
{
  SshCompressDeflateContext ctx = (SshCompressDeflateContext)context;
  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));

  SSH_ASSERT(ctx->in_use == TRUE);

  SSH_DEBUG(SSH_D_LOWOK, ("Releasing deflate context with index %d",
                           ctx->self_index));
  ssh_kernel_mutex_lock(fastpath->ipcomp_lock);
  ctx->in_use = FALSE;
  ssh_kernel_mutex_unlock(fastpath->ipcomp_lock);
}

/* Performs compression or decompression transform
 */
Boolean
ssh_compression_deflate_transform(void *context,
                                  unsigned char *dest,
                                  size_t *dest_len,
                                  const unsigned char *src,
                                  size_t src_len)
{
  SshCompressDeflateContext ctx = (SshCompressDeflateContext)context;
  z_stream *stream = &ctx->zlib_stream;
  int status;

  SSH_ASSERT(ctx != NULL);
  SSH_DEBUG(SSH_D_LOWOK, ("entered - ctx:%p for_compression:%d.",
                          context, ctx->for_compression));
  stream->next_in = (unsigned char *)src;
  stream->avail_in = (unsigned int)src_len;
  stream->next_out = dest;
  stream->avail_out = (unsigned int)*dest_len;

  if (ctx->for_compression)
    {
      status = deflate(stream, Z_FINISH);

      /* If everything was compressed, deflate returns Z_STREAM_END,
         otherwise the compressed data didn't fit into the output
         buffer and an error message is returned. */
      if (status == Z_STREAM_END)
        {
          *dest_len = stream->total_out;
          deflateReset(stream);
          return TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("compression error: %d.", (int) status));
          deflateReset(stream);
          return FALSE;
        }
    }
  else /* decompression */
    {
      status = inflate(stream, Z_FINISH);

      /* If everything was decompressed, inflate returns Z_STREAM_END,
         otherwise an error occured and error message is returned.
         (see zlib.h for return values). */
      if (status == Z_STREAM_END)
        {
          *dest_len = stream->total_out;
          inflateReset(stream);
          return TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("decompression error: %d.", (int) status));
          status = inflateReset(stream);

          if (status == Z_DATA_ERROR)
            /* the compressed input data is corrupted */
            return FALSE;
          else if (status == Z_BUF_ERROR || status == Z_OK)
            /* the decompressed data didn't fit into the output buffer.
               (Z_OK indicates that there is some more data to be
               processed.) */
            return FALSE;
          else
            /* Some other error occured:
                - Z_NEED_DICT     need a dictionary (should not happen)
                - Z_STREAM_ERROR  error in z_stream (should not happen)
                - Z_MEM_ERROR     not enough memory for zlib (might happen) */
            return FALSE;
        }
    }
  /* Never reached */
  return FALSE;
}

Boolean ssh_fastpath_ipcomp_zlib_buffer_init(SshFastpathIpcompList list,
                                             SshUInt32 num_cpus)
{
  SshUInt32 i;
  size_t size = 0;

  list->num_refs = 1;
  list->num_buffers =
         list->num_allocated =
            SSH_COMPRESS_ZLIB_NUM_BUFFERS * num_cpus;

  list->buffers = ssh_calloc_flags(list->num_allocated,
                                   sizeof(*list->buffers),
                                   SSH_KERNEL_ALLOC_WAIT);
  if (!list->buffers)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to allocate memory for IPComp buffers!"));
      return FALSE;
    }

  for (i = 0; i < list->num_allocated; i++)
    {
      if (i < 8 * num_cpus)  size =  64;
      else if (i < 18 * num_cpus) size =  512;
      else if (i < 21 * num_cpus) size = 1024;
      else if (i < 25 * num_cpus) size = 4096;
      else if (i < 27 * num_cpus) size = 8192;
      else if (i < 29 * num_cpus) size = 12288;
      else if (i < 31 * num_cpus) size = 32768;
      else if (i < SSH_COMPRESS_ZLIB_NUM_BUFFERS * num_cpus) size = 65536;
      else  break;

      list->buffers[i].space = ssh_malloc_flags(size, SSH_KERNEL_ALLOC_WAIT);

      if (!list->buffers[i].space)
        return FALSE;

      list->buffers[i].in_use = FALSE;
      list->buffers[i].size  = size;
    }
  return TRUE;
}

Boolean ssh_fastpath_ipcomp_zlib_context_allocate(SshFastpath fastpath)
{
  SshUInt32 i;

  fastpath->zlib_context =
    ssh_calloc_flags(1, (2 * fastpath->num_cpus
                         * sizeof(SshCompressDeflateContext)),
                     SSH_KERNEL_ALLOC_WAIT);

  if (fastpath->zlib_context == NULL)
    return FALSE;

  for (i = 0; i < 2 * fastpath->num_cpus; i++)
    {
      fastpath->zlib_context[i] =
        ssh_calloc_flags(1, sizeof(SshCompressDeflateContextStruct),
                         SSH_KERNEL_ALLOC_WAIT);

      if (fastpath->zlib_context[i] == NULL)
        goto fail;

      if (!ssh_compression_deflate_init(fastpath,
                                        fastpath->zlib_context[i],
                                        i < fastpath->num_cpus ? TRUE : FALSE,
                                        FALSE))

        return FALSE;

      fastpath->zlib_context[i]->in_use = FALSE;
#ifdef DEBUG_LIGHT
      fastpath->zlib_context[i]->self_index = i;
#endif /* DEBUG_LIGHT */
    }
  return TRUE;

 fail:
  for (i = 0; i < 2 * fastpath->num_cpus; i++)
    if (fastpath->zlib_context[i])
      ssh_free(fastpath->zlib_context[i]);

  ssh_free(fastpath->zlib_context);
  fastpath->zlib_context = NULL;
  return FALSE;
}

void ssh_fastpath_ipcomp_zlib_context_free(SshFastpath fastpath)
{
  SshUInt32 i;
  SshCompressDeflateContext deflate_ctx;

  if (fastpath->zlib_context == NULL)
    return;

  for (i = 0; i < 2 * fastpath->num_cpus; i++)
    {
      deflate_ctx = fastpath->zlib_context[i];
      if (deflate_ctx)
        {
          ssh_compression_deflate_destructor(deflate_ctx);
          ssh_free(deflate_ctx);
        }
    }
  ssh_free(fastpath->zlib_context);
  fastpath->zlib_context = NULL;
}
#endif /* SSHDIST_ZLIB */

/***********************************************************
              Buffer functions
 **********************************************************/
Boolean ssh_fastpath_ipcomp_buffer_list_init(SshFastpathIpcompList list)
{
  SshUInt32 i;
  size_t size = 0;

  list->num_refs = 1;
  list->num_buffers =
         list->num_allocated =
            SSH_ENGINE_IPCOMP_MAX_AVAILABLE_BUFFERS;

  list->buffers = ssh_calloc_flags(list->num_allocated,
                                   sizeof(*list->buffers),
                                   SSH_KERNEL_ALLOC_WAIT);
  if (!list->buffers)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to allocate memory for IPComp buffers!"));
      return FALSE;
    }

  for (i = 0; i < list->num_allocated; i++)
    {
      if (i < 7)  size =  1720;
      else if (i < 10) size =  9230;
      else if (i < 13) size = 36880;
      else if (i < SSH_ENGINE_IPCOMP_MAX_AVAILABLE_BUFFERS) size = 65536;
      else  break;

      list->buffers[i].space = ssh_malloc_flags(size, SSH_KERNEL_ALLOC_WAIT);

      if (!list->buffers[i].space)
        return FALSE;

      list->buffers[i].in_use = FALSE;
      list->buffers[i].size  = size;
    }
  return TRUE;
}


void ssh_fastpath_ipcomp_buffer_list_free(SshFastpathIpcompList list)
{
  SshUInt32 i;

  list->num_refs--;
  SSH_ASSERT(list->num_refs == 0);

  if (!list->buffers)
    return; /* Nothing to be done */

  for (i = 0; i < list->num_allocated; i++)
    {
      if (list->buffers[i].space)
        ssh_free(list->buffers[i].space);
    }
  ssh_free(list->buffers);
}

/* This function does not remove the IPComp header from the packet. */
SshFastpathTransformIpcompStatus
ssh_fastpath_transform_ipcomp_inbound(SshEnginePacketContext pc,
                                      SshFastpathTransformContext tc,
                                      SshUInt32 ipcomp_ofs)
{
  SshEngine engine = pc->engine;
  SshFastpath fastpath = engine->fastpath;
  unsigned char *input, *output;
  size_t payload_len, input_len, output_len;
  SshInterceptorPacket newpp;
  unsigned char ipcomp_hdr[4];
  int status;











#ifdef SSH_IPSEC_STATISTICS
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IPCOMP_IN);
#endif /* SSH_IPSEC_STATISTICS */
  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  /* Calculate the payload length of the compressed packet. */
  if (ipcomp_ofs + 4 > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short to contain IPComp header"));
      return SSH_FASTPATH_IPCOMP_DROP;
    }
  payload_len = pc->packet_len - ipcomp_ofs - 4;

  /* Start parsing the IPComp header. */
  ssh_interceptor_packet_copyout(pc->pp, ipcomp_ofs, ipcomp_hdr,
                                 sizeof(ipcomp_hdr));

  /* Check that the CPI value matches what was negotiated */
  if (SSH_GET_16BIT(ipcomp_hdr + 2) != tc->ipcomp_cpi)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("CPI mismatch in packet sent to IPComp input"));
      return SSH_FASTPATH_IPCOMP_DROP;
    }

  /* Allocate buffers for the decompress operation. */
  input  = ssh_fastpath_ipcomp_buffer_get(fastpath, fastpath->ipcomp_buf,
                                        payload_len, &input_len);

  output = ssh_fastpath_ipcomp_buffer_get(fastpath, fastpath->ipcomp_buf,
                                       65535, &output_len);
  if (!input || !output)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate input or output contiguous memory"));
      if (input)
        ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                           input);
      if (output)
        ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                           output);
      return SSH_FASTPATH_IPCOMP_NO_MEMORY;
    }

  /* Fetch the compressed data. */
  ssh_interceptor_packet_copyout(pc->pp, ipcomp_ofs + 4, input,
                                 payload_len);
  status = (*tc->compress->transform)(tc->compression_context, output,
                                &output_len, input, payload_len);

  ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf, input);

  if (!status)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Decompression failed, packet dropped"));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      return SSH_FASTPATH_IPCOMP_DROP;
    }

  if (output_len < payload_len)
    SSH_DEBUG(SSH_D_NETGARB,
              ("Compressed packet did not expand, remote protocol failure"));

  /* Check that the packet did not expand too much. */
  if (pc->hdrlen + output_len > 65535)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Can not fit %d+%d=%d bytes into IP packet",
                                pc->hdrlen, output_len,
                                pc->hdrlen + output_len));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      return SSH_FASTPATH_IPCOMP_DROP;
    }

  /* Next thing to do is to update the compressed data into output
     packet chain (that we need to allocate). */
  newpp =
    ssh_interceptor_packet_alloc_and_copy_ext_data(engine->interceptor,
                                                   pc->pp,
                                                   ipcomp_ofs + 4 +
                                                   output_len);
  if (newpp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate new packet for uncompressed data."));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      return SSH_FASTPATH_IPCOMP_NO_MEMORY;
    }

  /* Copy the header. */
  if (!ssh_interceptor_packet_copy(pc->pp, 0, ipcomp_ofs + 4, newpp, 0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet copy failed, packet dropped"));
      pc->pp = NULL;
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      return SSH_FASTPATH_IPCOMP_DROP;
    }

  /* Copy uncompressed payload. */
  if (!ssh_interceptor_packet_copyin(newpp, ipcomp_ofs + 4, output,
                                     output_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet copyin failed, packet dropped"));
      pc->pp = NULL;
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      return SSH_FASTPATH_IPCOMP_DROP;
    }
  /* We do not need the original packet or the temporary output buffer
     anymore.  */
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;
  ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf, output);

  /* After this point, `pp' is the new, uncompressed packet. */
  pc->pp = newpp;
  pc->packet_len = ssh_interceptor_packet_len(pc->pp);
  pc->comp_savings = output_len - payload_len;

  return SSH_FASTPATH_IPCOMP_SUCCESS;
}


SshFastpathTransformIpcompStatus
ssh_fastpath_transform_ipcomp_outbound(SshEnginePacketContext pc,
                                       SshFastpathTransformContext tc,
                                       SshUInt32 ipcomp_ofs,
                                       const unsigned char *extra_hdr,
                                       size_t extra_hdr_len)
{
  SshEngine engine = pc->engine;
  SshFastpath fastpath = engine->fastpath;
  SshInterceptorPacket pp = pc->pp;
  unsigned char *input, *output;
  size_t total_len, payload_len, max_exp_len;
  size_t input_len, output_len, new_len;
  int status;











  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));
  SSH_ASSERT(pc->packet_len > ipcomp_ofs);

  payload_len = pc->packet_len - ipcomp_ofs;
  total_len = payload_len + extra_hdr_len;

  /* The stream is expected to be compressable. */
  max_exp_len = (*tc->compress->maxbuf)(total_len);
  input = ssh_fastpath_ipcomp_buffer_get(fastpath, fastpath->ipcomp_buf,
                                        total_len, &input_len);
  output = ssh_fastpath_ipcomp_buffer_get(fastpath, fastpath->ipcomp_buf,
                                        max_exp_len, &output_len);
  if (!input || !output)
    {
      if (input)
        ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                           input);
      if (output)
        ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                           output);
      SSH_DEBUG(SSH_D_FAIL,
                ("Can not allocate input or output contiguous memory: "
                 "passing by"));
      goto passby;
    }

  /* Copy the extra_hdr following by the payload data from the packet
   to the 'input' buffer' */
  if (extra_hdr != NULL)
    memcpy(input, extra_hdr, extra_hdr_len);

  ssh_interceptor_packet_copyout(pp, ipcomp_ofs,
                                 input + extra_hdr_len, payload_len);

  status = (*tc->compress->transform)(tc->compression_context, output,
                                      &output_len, input, total_len);

  /* The temporary input buffer is not needed anymore. */
  ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf, input);

  if (!status)
    {
      /* Compression failed for some reason, the packet is still valid
         and other transforms may be applied into it. */
      SSH_DEBUG(SSH_D_FAIL, ("Compression routine failed: passing by"));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      goto passby;
    }

  /* Assure non-expansion behaviour of compression and submit feedback.
     Include the (to be added) IPComp header when determining
     non-expansion. Note that we compare the length of compressed
     (input + extra) data to uncompressed (input) data. */
  if (output_len + 4 >= payload_len)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Payload expanded to %d+%d=%d bytes, "
                 "original length %d bytes: passing by",
                  4, output_len, 4 + output_len, total_len));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      goto passby;
    }
  else
    SSH_DEBUG(SSH_D_MIDOK, ("Packet compressed successfully"));

  /* The packet actually got smaller. */
  new_len = ipcomp_ofs + output_len;

  /* Insert the compressed payload. */
  SSH_ASSERT(new_len < ssh_interceptor_packet_len(pp));
  if (!ssh_interceptor_packet_copyin(pp, ipcomp_ofs, output, output_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet copyin failed, dropping packet"));
      ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf,
                                         output);
      pc->pp = NULL;
      return SSH_FASTPATH_IPCOMP_DROP;
    }
  /* We do not need the output buffer anymore. */
  ssh_fastpath_ipcomp_buffer_release(fastpath, fastpath->ipcomp_buf, output);

  /* Delete the trailing garbage from the packet.  This is the amount
     we won in the compression. */
  if (!ssh_interceptor_packet_delete(pp, new_len,
                                     ssh_interceptor_packet_len(pp) - new_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet delete failed, packet dropped"));
      pc->pp = NULL;
      return SSH_FASTPATH_IPCOMP_DROP;
    }
  pc->comp_savings = total_len - output_len;
  pc->packet_len = ssh_interceptor_packet_len(pp);

#ifdef SSH_IPSEC_STATISTICS
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IPCOMP_OUT);
#endif /* SSH_IPSEC_STATISTICS */
  return SSH_FASTPATH_IPCOMP_SUCCESS;

passby :
#ifdef SSH_IPSEC_STATISTICS
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NOIPCOMP_OUT);
#endif /* SSH_IPSEC_STATISTICS */
  return SSH_FASTPATH_IPCOMP_PASSBY;
}


SshFastpathTransformIpcompState
ssh_fastpath_ipcomp_state(SshEnginePacketContext pc,
                          SshFastpathTransformContext tc)
{
  if (pc->packet_len < SSH_ENGINE_IPCOMP_SIZE_THRESHOLD)
    return SSH_FASTPATH_TRANSFORM_NO_COMPRESS;



  /* implement the adaptive algorithm here */
  return SSH_FASTPATH_TRANSFORM_DO_COMPRESS;
}
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */
