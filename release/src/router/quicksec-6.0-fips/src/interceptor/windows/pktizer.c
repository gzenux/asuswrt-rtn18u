/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements simple generic "packetizer" module, which receives data from a
   continuous stream (such as a character device) and formats this into chunks
   as indicated by the embedded size fields.

   The "packetizer" functions are designed to be called at IRQL lower than
   DISPATCH_LEVEL.
*/

/* #includes */

#include "sshincludes.h"
#include "interceptor_i.h"
#include "pktizer.h"

/* #defines */

#define SSH_DEBUG_MODULE "SshPacketizer"


/* Exported functions */

#ifdef WINNT
#pragma NDIS_PAGABLE_FUNCTION(ssh_interceptor_pktizer_init)
#pragma NDIS_PAGABLE_FUNCTION(ssh_interceptor_pktizer_uninit)
#pragma NDIS_PAGABLE_FUNCTION(ssh_interceptor_pktizer_receive)
#else /* not WINNT */ 
#define PAGED_CODE()
#endif /* not WINNT */ 


void ssh_interceptor_pktizer_init(SshPacketizer pktizer,
                                  SshPacketizerCallback callback, 
                                  void *callback_context)
{
  PAGED_CODE();

  pktizer->buf = NULL;
  pktizer->pkt_len_bytes_valid = 0;

  pktizer->callback = callback;
  pktizer->callback_context = callback_context;
}


void ssh_interceptor_pktizer_uninit(SshPacketizer pktizer)
{
  PAGED_CODE();

  /*
    The pktizer buffers are released by the callback, so there is usually
    no reason to free them here. But we might be potentially holding a
    partial message, for which the callback has not been called yet.
  */

  if (pktizer->buf != NULL && pktizer->len < pktizer->pkt_len)
    {
      ssh_free(pktizer->buf);
      pktizer->buf = NULL;
    }

  pktizer->callback = NULL;
  pktizer->callback_context = NULL;
}


Boolean ssh_interceptor_pktizer_receive(unsigned int len,
                                        unsigned char *buf,
                                        SshPacketizer pktizer)
{
  unsigned int offset = 0, bytes_copied;

  PAGED_CODE();

  SSH_DEBUG(SSH_D_LOWSTART,
            ("ssh_interceptor_pktizer_receive(len=%d, buf=0x%p)", len, buf));

  while (offset < len)
    {
      while (pktizer->pkt_len_bytes_valid < 4 && offset < len)
        {
          /* */
          pktizer->pkt_len <<= 8;
          pktizer->pkt_len |= buf[offset];
          pktizer->pkt_len_bytes_valid++;
          offset++;
        }

      if (pktizer->pkt_len_bytes_valid < 4)
        /* There was a break in the middle of the size field */
        return TRUE;

      /* Check whether the whole packet is in one buffer. If yes, we don't 
         need to make an unnecessary copy. */
      if ((pktizer->len == 0) && ((offset + pktizer->pkt_len) <= len))
        {
          /* We have a complete packet, call the callback with it */
          SSH_ASSERT(pktizer->callback != NULL);

          pktizer->callback(pktizer->pkt_len, buf + offset,
                            pktizer->callback_context);

          pktizer->buf = NULL;
          pktizer->pkt_len_bytes_valid = 0;
          offset += pktizer->pkt_len;
        }
      else
        {
          if (pktizer->buf == NULL)
            {
              /* We need a larger intermediate buffer */
              pktizer->buf = ssh_malloc(pktizer->pkt_len);
              pktizer->len = 0;

              if (!pktizer->buf)
                {
                  pktizer->pkt_len_bytes_valid = 0;

                  return FALSE;
                }
            }

          /* */

          if (len - offset < pktizer->pkt_len - pktizer->len)
            bytes_copied = len - offset;
          else
            bytes_copied = pktizer->pkt_len - pktizer->len;

          NdisMoveMemory(pktizer->buf + pktizer->len, 
                         buf + offset, bytes_copied);
          pktizer->len += bytes_copied;
          offset += bytes_copied;

          if (pktizer->len == pktizer->pkt_len)
            {
              /* We have a complete packet, call the callback with it */
              SSH_ASSERT(pktizer->callback != NULL);

              pktizer->callback(pktizer->pkt_len, pktizer->buf,
                                pktizer->callback_context);

              ssh_free(pktizer->buf);
              pktizer->buf = NULL;
              pktizer->pkt_len_bytes_valid = 0;
            }
        }
    }

  return TRUE;
}


/* EOF */
